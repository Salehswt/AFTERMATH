#!/usr/bin/env bash
# Victim container entrypoint.
#
# Services are started via their DAEMON BINARIES, not `service …`/systemctl:
# Ubuntu 22.04 ships systemd units (no init.d scripts) for ssh/rsyslog, and a
# container has no systemd, so `service rsyslog start` silently fails — which is
# exactly why /var/log/auth.log never appeared. Each start is tolerant so one
# failure (auditd can't get its kernel netlink socket in a container) doesn't
# take the box down.
set -u

start() { echo "[boot] $1"; shift; "$@" || echo "[boot] ...$1 failed (continuing)"; }

# rsyslogd first, so the auth facility is captured from the moment sshd runs.
# It routes auth,authpriv.* to /var/log/auth.log (via /etc/rsyslog.d/50-default),
# which the Elastic Agent System integration ships.
mkdir -p /var/spool/rsyslog /run
start "rsyslog" rsyslogd                    # daemonizes itself
sleep 1

# sshd needs its privilege-separation dir; -D would foreground it, so start it
# the normal (backgrounding) way via the binary.
mkdir -p /run/sshd
start "sshd" /usr/sbin/sshd

start "auditd" service auditd start         # expected to fail in a container
start "cron"  cron

# Resume the Elastic Agent across restarts if this box was already enrolled.
if [ -f /opt/elastic-agent/.enrolled ]; then
  echo "[boot] resuming Elastic Agent"
  ( cd /opt/elastic-agent && setsid nohup ./elastic-agent run >>/var/log/elastic-agent.log 2>&1 </dev/null & )
fi

echo "[boot] victim ready"
exec tail -f /dev/null
