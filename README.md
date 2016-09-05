loginjector
===========

**Retrieve logs from docker containers in real time.**

Not all programs support sending logs to a remote server, so logs in containers tend to be lost by lazy sysadmins. This
is a tool that attempts to fix this, by leveraging rsyslog.

By specifying a list of log paths in the container or auto detection from a built-in list, loginjector will generate a
rsyslog config within the container and spawn rsyslogd. Simultaneously, loginjector listens on UDP ports to receive log
entires sent by containers and writes them to disk on the host.

**Assumptions**

* The rsyslogd binary is available in the container at /usr/sbin/rsyslogd (this is stander for ubuntu base images)
* Docker is using it's default networking strategy

**Installation**

* `git clone ssh://git@gitlab.davepedu.com:222/dave/loginjector.git`
* `cd loginjector`
* `python3 setup.py install`


**Running**

* `loginjector -s unix://var/run/docker.sock -o /var/log/container/`

(The above arguments are actually the defaults and need not be specified)


**Specifying custom paths**

Add the `-c <file>` argument where `<file>` is a json or yml file structured like:

```
{
    "container_name": {
        "app_name": ["/log/path.log", "/another/log/path.log"],
        "another_app": [ ... ]
    },
    "another_container": {

    }
}
```


**Container bake-in**

If you're a docker image creator, you can add a file to your image containing log paths.

Add to your image a file at the path `/.loghint` containing:

```
{
    "app_name": ["/log/path.log", "/another/log/path.log"],
    "another_app": [ ... ]
}
```


**TODO**

- Implement the custom path option displayed above
- Implement the loghint file mentioned above
