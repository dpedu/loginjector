
import os
import math
import json
import signal
import socket
import logging
import argparse

from time import sleep
from select import select
from threading import Thread, Lock, Timer
from collections import defaultdict, namedtuple

from docker import tls  # NOQA
from docker import Client, errors

from jinja2 import Environment

from loginjector.template import DEFAULT_TEMPLATE


def shell():
    logging.basicConfig(level=logging.DEBUG,
                        format="%(asctime)-15s %(levelname)-8s %(filename)s:%(lineno)d %(message)s")
    [logging.getLogger(mute).setLevel(logging.ERROR) for mute in ["docker", "requests"]]

    parser = argparse.ArgumentParser(description="Python logging daemon")
    parser.add_argument('-s', '--socket', default="unix://var/run/docker.sock",
                        help="Path or URL to docker daemon socket")
    # parser.add_argument('-t', '--template', required=False, help="Path to syslog template")
    parser.add_argument('-o', '--output', default="/var/log/container/", help="Path to host log output dir")

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

    EVENT_FILTERS_STARTDIE = {"type": "container",
                              "event": ["start",
                                        "die"]}

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

        self.rescan_delay = 10
        self.rescans = 1

        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        logging.warning("Got signal {}, setting exit flag".format(signum))
        self.alive = False

    def run(self):
        """
        Start all service threads and init listeners on preexisting containers
        """

        change_listner = Thread(target=self.listen_events, daemon=True)
        change_listner.start()

        message_recvr = Thread(target=self.listen_udp, daemon=True)
        message_recvr.start()

        # Get listing of existing containers and spawn the log listener on each
        containers = self.docker.containers()

        for container in containers:
            Thread(target=self.relisten_on, args=(container["Id"],)).start()

        try:
            while self.alive:
                change_listner.join(0.1)
                message_recvr.join(0.1)
        except KeyboardInterrupt:
            pass

        self.docker.close()

        logging.warning("Main thread exiting")

    def listen_udp(self):
        """
        UDP listener thread. Loop through active loggers. If there's data on the line, read it
        """
        while self.alive:
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
        """
        Docker change listener thread. Subscribes to docker's event api and respond to containers stopping/starting
        """
        for e in self.docker.events(filters=LogInjectorDaemon.EVENT_FILTERS_STARTDIE):
            event = json.loads(e.decode('UTF-8'))
            self.handle_event(event)

    def handle_event(self, event):
        """
        Handle an event received from docker
        """
        logging.info("{}: got {} event".format(event["id"], event["status"]))

        if event["status"] == "start":
            Thread(target=self.relisten_on, args=(event["id"],)).start()

        elif event["status"] == "die":
            Thread(target=self.end_listen_on, args=(event["id"],)).start()

    def end_listen_on(self, container_id):
        """
        Kill local listener for container_id
        """
        sleep(10)  # hack: kill some time for any straggling log messages to be flushed out
        with self.loggers_lock:
            loggers_to_close = [l for l in self.loggers.keys() if self.loggers[l]["container_id"] == container_id]

            logging.info("{}: was stopped, closing fnos {}".format(container_id, str(loggers_to_close)))

            for logger_fno in loggers_to_close:
                logger = self.loggers[logger_fno]
                del self.loggers[logger_fno]
                logger["socket"].close()

            del self.container_names[container_id]

    def relisten_on(self, container_id, rescan_num=None):
        """
        Configure and spawn rsyslog in a container
        """

        try:
            container_info = self.docker.inspect_container(container_id)

            # hack: lazy loading of bridge ip - we must listen for udp packets on the docker bridge interface, so we
            # need the IP for binding. Lazily set it after the first container is fetched from the docker host, as this
            # will always happen before any udp binding
            if not self.docker_bridge_ip:
                bridge_ip = container_info["NetworkSettings"]["Networks"]["bridge"]["Gateway"]
                logging.info("Found bridge ip: {}".format(bridge_ip))
                self.docker_bridge_ip = bridge_ip

            if container_id not in self.container_names:
                # strip leading slash
                raw_name = container_info["Name"][1:]
                self.container_names[container_id] = raw_name
                logging.info("{}: is named {}".format(container_id, raw_name))

        except errors.NotFound:
            logging.info("{}: no longer exists, aborting".format(container_id))
            return

        logging.info("{}: setup".format(container_id))

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

        modules_use = list(self.use_builtins.intersection({k for k, v in modules_found.items() if v}))
        logging.info("{}: using: {}".format(container_id, str(modules_use)))

        if len(modules_use) == 0:

            if rescan_num is None:
                rescan_num = self.rescans

            if rescan_num == 0:
                logging.info("{}: no log files found, ignoring".format(container_id))
                return None

            logging.info("{}: no log files found, scheduling rescan #{} in {} seconds".format(container_id, rescan_num,
                                                                                              self.rescan_delay))
            Timer(self.rescan_delay, self.relisten_on, args=[container_id, rescan_num - 1]).start()
            return None

        syslog_conf = self.render_template(container_id, self.template, modules_use)

        # transfer syslog conf
        self.write_in_container(container_id, "/etc/rsyslog.conf", syslog_conf)

        # start syslog
        logging.info("{}: spawning rsyslogd".format(container_id))
        self.exec_in_container(container_id, '/usr/sbin/rsyslogd')

    def render_template(self, container_id, template_contents, log_modules):
        """
        Create a rsyslog config from template
        """

        # prepare template vars - only a list of detected log files
        logfiles = []

        for mod in log_modules:
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

        # generate syslog config
        return Environment().from_string(template_contents).render(logfiles=logfiles)

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

    def exec_in_container(self, container_id, cmd_str):
        """
        Execute a command in a container
        """
        e = self.docker.exec_create(container=container_id, cmd=cmd_str)
        return self.docker.exec_start(e["Id"])

    def write_in_container(self, container_id, path, contents):
        """
        This is ugly and sucks
        """

        logging.info("{}: writing {} bytes to container's {}".format(container_id, len(contents), path))

        if type(contents) != bytes:
            contents = contents.encode('UTF-8')

        chunk_size = 1024 * 16
        total_chunks = math.ceil(len(contents) / chunk_size)
        # logging.info("Fsize={}, chunk={}, total_chunks={}".format(len(contents), chunk_size, total_chunks))
        for i in range(0, total_chunks):
            chunk = []
            for byte in contents[chunk_size * i:chunk_size * i + chunk_size]:
                chunk.append('\\\\x' + hex(byte)[2:])
            self.exec_in_container(container_id,
                                   "bash -c -- 'printf {} {} {}'".format(''.join(chunk),
                                                                         ">" if i == 0 else ">>",
                                                                         path))
