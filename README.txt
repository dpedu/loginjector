*Status:* good idea

```
make a logger-injector using https://docker-py.readthedocs.io/en/latest/api/#execute
- runs on docker host
- lists running containers
- per container, look for processes (optionally, a hint file in the container) that we know where to look for logs for (psutil, or container-fs://.logs)
- generate syslogd confs to broadcast these logs somewhere else
- execute syslogd in the container 
  - just spawn it or if we detect supervisor, try to insert it?
- wait for the container to exit
  - maybe poll for syslogd still running?
  

polling docker for containers seems expensive so
- poll every minute normally
- if a container dies, poll every 5 seconds until it returns
  - but not for more than 5 minutes
```
