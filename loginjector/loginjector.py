
#import subprocess
import logging
import argparse
from docker import Client, tls


def shell():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="Python logging daemon")
    parser.add_argument('-s', '--socket', required=True, help="Path or URL to docker daemon socket")

    args = parser.parse_args()

    logging.debug("Args: %s", args)

    client_certs = tls.TLSConfig(client_cert=('/Users/dave/.docker/machine/machines/digio/cert.pem',
                                              '/Users/dave/.docker/machine/machines/digio/key.pem'),
                                 verify='/Users/dave/.docker/machine/machines/digio/ca.pem')
    docker_c = Client(base_url=args.socket, tls=client_certs)

    import pdb
    pdb.set_trace()

    print("Exiting...")





class LogInjectorDaemon(object):

    def __init__(self, docker_socket):
        pass

def daemon():
    pass
