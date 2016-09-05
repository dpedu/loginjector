
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
