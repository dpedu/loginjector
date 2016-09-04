
import math
import json
import os
import socket
import logging
import argparse

from select import select
from collections import defaultdict, namedtuple
from threading import Thread, Lock
from time import sleep

from docker import Client
from docker import tls  # NOQA

from jinja2 import Environment


DEFAULT_TEMPLATE = """
$PrivDropToUser syslog
$PrivDropToGroup syslog

$template myFormat,"%rawmsg%\\n"
# $ActionFileDefaultTemplate myFormat

#
# Where to place spool and state files
#
$WorkDirectory /var/spool/rsyslog

#
# Provide file listening
#

module(load="imfile")

#
# Begin logs
#

{% for logfile in logfiles %}
#
# {{ logfile }}
#

input(type="imfile"
      File="{{ logfile.path }}"
      statefile="{{ logfile.statefile }}"
      Tag="{{ logfile.program }}-{{ logfile.logname }}"
      Severity="{{ logfile.program }}"
      facility="local0")

if ($syslogtag == "{{ logfile.program }}-{{ logfile.logname }}") then {
    local0.* @{{ logfile.dest_ip }}:{{ logfile.dest_port }};myFormat
}

{% endfor %}

*.*  /var/log/syslog

"""


def shell():
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)-15s %(levelname)-8s %(filename)s:%(lineno)d %(message)s")
    [logging.getLogger(mute).setLevel(logging.ERROR) for mute in ["docker", "requests"]]

    parser = argparse.ArgumentParser(description="Python logging daemon")
    parser.add_argument('-s', '--socket', required=True, help="Path or URL to docker daemon socket")
    # parser.add_argument('-t', '--template', required=False, help="Path to syslog template")
    parser.add_argument('-o', '--output', required=True, help="Path to host log output dir")

    args = parser.parse_args()

    # TODO support ssl
    # client_certs = tls.TLSConfig(client_cert=('/Users/dave/.docker/machine/machines/digio/cert.pem',
    #                                          '/Users/dave/.docker/machine/machines/digio/key.pem'),
    #                             verify='/Users/dave/.docker/machine/machines/digio/ca.pem')
    docker_c = Client(base_url=args.socket, version='auto')  # , tls=client_certs)

    # test connection
    docker_c.containers()

    # TODO support template file from arg
    # with open(args.template) as f:
    #    template_contents = f.read()

    daemon = LogInjectorDaemon(docker_c, output_dir=args.output)

    daemon.run()

    logging.warning("Exiting...")


class LogInjectorDaemon(object):

    EVENT_FILTERS_STOPSTART = {"type": "container",
                               "event": ["stop",
                                         "start"]}

    detector = namedtuple("Detector", "match paths")

    def __init__(self, docker_client, output_dir, syslog_template=DEFAULT_TEMPLATE):
        self.docker = docker_client
        self.alive = True
        self.template = syslog_template
        self.use_builtins = {'nginx', 'php-fpm', 'xxx'}
        self.output_dir = os.path.abspath(output_dir)

        self.docker_bridge_ip = None

        self.detectors = {
            "nginx": LogInjectorDaemon.detector("nginx",
                                                [{"path": "/var/log/nginx/access.log", "level": "info"},
                                                 {"path": "/var/log/nginx/error.log", "level": "error"}]),
            "php-fpm": LogInjectorDaemon.detector(lambda x: 'php-fpm' in x and 'master process' in x,
                                                  [{"path": "/var/log/php5-fpm.log", "level": "info"}]),
        }

        self.loggers = {}
        self.loggers_lock = Lock()
        self.container_names = {}

    def run(self):
        containers = self.docker.containers()

        change_listner = Thread(target=self.listen_events, daemon=True)
        change_listner.start()

        message_recvr = Thread(target=self.listen_udp, daemon=True)
        message_recvr.start()

        for container in containers:
            Thread(target=self.relisten_on, args=(container["Id"],)).start()

        try:
            while self.alive:
                change_listner.join()
        except KeyboardInterrupt:
            pass

        self.docker.close()

        logging.warning("Main thread exiting")

    def listen_udp(self):
        """
        Loop through active loggers. If there's data on the line, read it. This is meant to be ran as a Thread
        """
        while True:
            with self.loggers_lock:
                socket_fnos = list(self.loggers.keys())
                readable, _, dead = select(socket_fnos, [], socket_fnos, 0.2)
                for fno in readable:
                    self.read_udp(fno)

    def read_udp(self, fno):
        """
        Called when there's data on the line on one of the incoming log data sockets. Read the data and write to the
        logger's logfile.
        :param fno: file number of the socket with waiting data. also keys of self.loggers
        """
        logger = self.loggers[fno]

        data = logger["socket"].recv(1024 * 32)

        logging.info("{}: writing {} bytes to {}".format(logger["container_id"], len(data), logger["local_logfile"]))

        # this seems inefficient
        # TODO periodically close/open the file
        with open(logger["local_logfile"], 'ab') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())  # is this necessary since we're closing the file?l

    def listen_events(self):
        try:
            for e in self.docker.events(filters=LogInjectorDaemon.EVENT_FILTERS_STOPSTART):
                event = json.loads(e.decode('UTF-8'))
                # logging.info("event: {}".format(str(event)))
                if event["status"] == "start":
                    logging.info("{}: got start event".format(event["id"]))
                    Thread(target=self.relisten_on, args=(event["id"],)).start()

                elif event["status"] == "stop":
                    logging.info("{}: got stop event".format(event["id"]))
                    Thread(target=self.end_listen_on, args=(event["id"],)).start()

        except KeyboardInterrupt:
            logging.warning("Stopped listening for events")

    def end_listen_on(self, container_id):
        """
        Kill local listener for container_id
        """
        sleep(10)  # kill some time for any straggling log messages to be flushed out
        with self.loggers_lock:
            loggers_to_close = [l for l in self.loggers.keys() if self.loggers[l]["container_id"] == container_id]

            logging.info("{}: was stopped, closing fnos {}".format(container_id, str(loggers_to_close)))

            for logger_fno in loggers_to_close:
                logger = self.loggers[logger_fno]
                del self.loggers[logger_fno]
                logger["socket"].close()

            del self.container_names[container_id]

    def relisten_on(self, container_id):
        """
        Configure and spawn rsyslog in a container
        """
        sleep(2)  # hack

        if container_id not in self.container_names:
            self.container_names[container_id] = self.get_container_name(container_id)

        container_name = self.container_names[container_id]

        logging.info("{}: setup".format(container_id))
        logging.info("{}: is named {}".format(container_id, container_name))

        # Check for commonly know processes in the container
        ps_output = self.exec_in_container(container_id,
                                           "ps --ppid 2 -p 2 --deselect -o cmd --no-headers").decode('utf-8')
        ps_lines = [line.strip() for line in ps_output.split("\n") if line]
        # logging.info("{}: running procs: {}".format(container_id, str(ps_lines)))

        # look at ps, see no syslog
        if any(["rsyslogd" in i for i in ps_lines]):
            logging.warning("{}: killing rsyslogd".format(container_id))
            self.exec_in_container(container_id, "pkill rsyslogd")

        modules_found = self.find_logs(ps_lines)
        logging.info("{}: logs detected: {}".format(container_id, str(modules_found)))

        modules_use = self.use_builtins.intersection({k for k, v in modules_found.items() if v})
        logging.info("{}: using: {}".format(container_id, str(modules_use)))

        logfiles = []
        for mod in modules_use:

            for path in self.detectors[mod].paths:
                original_logname = os.path.basename(path["path"])
                # add local listener
                new_port = self.add_udp_listener(container_id, mod, original_logname)

                logfiles += [{"program": mod,
                              "path": path["path"],
                              "level": path["level"],
                              "logname": original_logname,
                              "statefile":"mod-{}-{}-{}.state".format(mod,
                                                                      original_logname,
                                                                      path["level"]),
                              "dest_ip": self.docker_bridge_ip,
                              "dest_port": new_port,
                              "container_id": container_id}]

        if len(logfiles) == 0:
            logging.info("{}: no log files found, exiting".format(container_id))
            return

        # generate syslog config
        syslog_conf = Environment().from_string(self.template).render(logfiles=logfiles)

        # transfer syslog conf
        self.write_in_container(container_id, "/etc/rsyslog.conf", syslog_conf)

        # start syslog
        logging.info("{}: spawning rsyslogd".format(container_id))
        self.exec_in_container(container_id, '/usr/sbin/rsyslogd')

    def get_container_name(self, container_id):
        container_info = self.docker.inspect_container(container_id)

        raw_name = container_info["Name"]

        # strip leading slash
        raw_name = raw_name[1:]

        # hacky lazy loading
        if not self.docker_bridge_ip:
            self.set_bridge_ip(container_info["NetworkSettings"]["Networks"]["bridge"]["Gateway"])

        return raw_name

    def set_bridge_ip(self, bridge_ip):
        """
        We must listen for udp packets on the docker bridge interface, so we need the IP for binding. Lazily set it
        after the first container is fetched from the docker host, as this will always happen before any udp binding
        """
        logging.info("Found bridge ip: {}".format(bridge_ip))
        self.docker_bridge_ip = bridge_ip

    def add_udp_listener(self, container_id, program, original_logname):
        """
        Listen on a random UDP socket and create a new listener. A listener is an association between a udp port and
        a log file source. Return the port number
        :param container_name: container name
        :param program: program name in the container
        :param container_id: should be obvious
        :return: int port number
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.docker_bridge_ip, 0))

        log_path = os.path.join(self.output_dir, self.container_names[container_id], program, original_logname)
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        self.loggers[s.fileno()] = {"socket": s,
                                    "container_id": container_id,
                                    "program": program,
                                    "logfile": original_logname,
                                    "local_logfile": log_path}

        return s.getsockname()[1]

    def find_logs(self, process_names):
        """
        Given a list of process names, guess common places for their logs to be
        """
        hits = defaultdict(type(False))

        for det_name, det in self.detectors.items():
            for process_name in process_names:
                if (type(det.match) == str and det.match in process_name) or \
                        (hasattr(det.match, '__call__') and det.match(process_name)):
                    hits[det_name] = True

        return {name: hits[name] for name in self.detectors.keys()}

    def exec_in_container(self, container, cmd):
        e = self.docker.exec_create(container=container, cmd=cmd)
        return self.docker.exec_start(e["Id"])

    def write_in_container(self, container, path, contents):
        """
        This is ugly and sucks
        """

        logging.info("{}: writing {} bytes to container's {}".format(container, len(contents), path))

        if type(contents) != bytes:
            contents = contents.encode('UTF-8')

        chunk_size = 1024 * 16
        total_chunks = math.ceil(len(contents) / chunk_size)
        # logging.info("Fsize={}, chunk={}, total_chunks={}".format(len(contents), chunk_size, total_chunks))
        for i in range(0, total_chunks):
            chunk = []
            for byte in contents[chunk_size * i:chunk_size * i + chunk_size]:
                chunk.append('\\\\x' + hex(byte)[2:])
            self.exec_in_container(container,
                                   "bash -c -- 'printf {} {} {}'".format(''.join(chunk),
                                                                         ">" if i == 0 else ">>",
                                                                         path))
