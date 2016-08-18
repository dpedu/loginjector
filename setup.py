#!/usr/bin/env python3
from setuptools import setup

from loginjector import __version__

setup(name='loginjector',
      version=__version__,
      description='loginjector daemon',
      url='http://gitlab.xmopx.net/dave/loginjector',
      author='dpedu',
      author_email='dave@davepedu.com',
      packages=['loginjector'],
      entry_points={
          'console_scripts': [
              'loginjector_daemon = loginjector.loginjector:shell',
          ]
      },
      #install_requires=['requests==2.10.0']
      )
