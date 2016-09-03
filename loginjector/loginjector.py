
import logging
import argparse
from docker import Client, tls
from threading import Thread
from collections import defaultdict, namedtuple
from jinja2 import Environment
import math
import json
import os

from time import sleep, time  # NOQA
import pdb  # NOQA


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
      Tag="{{ logfile.program }}"
      Severity="{{ logfile.program }}"
      facility="local0")

if ($syslogtag == "{{ logfile.program }}") then {
    local0.* @{{ logfile.dest_ip }}:{{ logfile.dest_port }};myFormat
}


{% endfor %}

*.*  /var/log/syslog

"""


def shell():
    logging.basicConfig(level=logging.DEBUG)
    [logging.getLogger(mute).setLevel(logging.ERROR) for mute in ["docker", "requests"]]

    parser = argparse.ArgumentParser(description="Python logging daemon")
    parser.add_argument('-s', '--socket', required=True, help="Path or URL to docker daemon socket")
    parser.add_argument('-t', '--template', required=False, help="Path to syslog template")
    #parser.add_argument('-d', '--dest', required=True, help="Logs destination IP 1.2.3.4:xxxx", type=lambda x: x.split(":"))

    args = parser.parse_args()

    # TODO fixme
    client_certs = tls.TLSConfig(client_cert=('/Users/dave/.docker/machine/machines/digio/cert.pem',
                                              '/Users/dave/.docker/machine/machines/digio/key.pem'),
                                 verify='/Users/dave/.docker/machine/machines/digio/ca.pem')
    docker_c = Client(base_url=args.socket, tls=client_certs)

    # test connection
    docker_c.containers()

    #with open(args.template) as f:
    #    template_contents = f.read()

    daemon = LogInjectorDaemon(docker_c, dest=args.dest)

    daemon.run()

    logging.warning("Exiting...")


class LogInjectorDaemon(object):

    EVENT_FILTERS_STOPSTART = {"type": "container",
                               "event": ["stop",
                                         "start"]}

    detector = namedtuple("Detector", "match paths")

    def __init__(self, docker_client, dest, syslog_template=DEFAULT_TEMPLATE):
        self.docker = docker_client
        self.alive = True
        self.template = syslog_template
        self.dest = dest
        self.use_builtins = {'nginx', 'php-fpm', 'xxx'}

        self.detectors = {
            "nginx": LogInjectorDaemon.detector("nginx",
                                                [{"path": "/var/log/nginx/access.log", "level": "info"},
                                                 {"path": "/var/log/nginx/error.log", "level": "error"}]),
            "php-fpm": LogInjectorDaemon.detector(lambda x: 'php-fpm' in x and 'master process' in x,
                                                  [{"path": "/var/log/php5-fpm.log", "level": "info"}]),
        }

        self.loggers = {}

    def run(self):
        containers = self.docker.containers()

        change_listner = Thread(target=self.listen_events, daemon=True)
        change_listner.start()

        for container in containers:
            Thread(target=self.relisten_on, args=(container["Id"],)).start()
            # self.relisten_on(container['Id'])

        try:
            while self.alive:
                change_listner.join()
        except KeyboardInterrupt:
            pass

        self.docker.close()

        logging.warning("Main thread exiting")

    def listen_events(self):
        try:
            for e in self.docker.events(filters=LogInjectorDaemon.EVENT_FILTERS_STOPSTART):
                event = json.loads(e.decode('UTF-8'))
                logging.info("event: {}".format(str(event)))
                if event["status"] == "start":
                    logging.info("Got start on {}".format(event["id"]))
                    self.relisten_on(event["id"])

                elif event["status"] == "stop":
                    logging.info("Got stop on {}".format(event["id"]))

        except KeyboardInterrupt:
            logging.warning("Stopped listening for events")

    def relisten_on(self, container_id):
        sleep(2)
        logging.info("{}: Checking for logs".format(container_id))

        # Check for commonly know processes in the container
        ps_output = self.exec_in_container(container_id,
                                           "ps --ppid 2 -p 2 --deselect -o cmd --no-headers").decode('utf-8')
        ps_lines = [line.strip() for line in ps_output.split("\n") if line]
        logging.info("{}: running procs: {}".format(container_id, str(ps_lines)))

        # look at ps, see no syslog
        if any(["rsyslogd" in i for i in ps_lines]):
            logging.warning("{}: Syslog already running,..".format(container_id))
            return

        modules_found = self.find_logs(ps_lines)
        logging.info("{}: logs detected: {}".format(container_id, str(modules_found)))

        modules_use = self.use_builtins.intersection({k for k, v in modules_found.items() if v})
        logging.info("{}: using: {}".format(container_id, str(modules_use)))

        logfiles = []
        for mod in modules_use:

            for path in self.detectors[mod].paths:
                logfiles += [{"program": mod,
                              "path": path["path"],
                              "level": path["level"],
                              "statefile":"mod-{}-{}-{}.state".format(mod,
                                                                      os.path.basename(path["path"]),
                                                                      path["level"]),
                              "dest_ip": self.dest[0], # TODO different dest per log
                              "dest_port": self.dest[1]}] # TODO different port per log

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

        logging.info("{}: writing {} bytes to {}".format(container, len(contents), path))

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
