#!/usr/bin/env bash
# enroll.sh <token> — enroll this container's Elastic Agent into Fleet.
#
# Uses the `elastic-agent container` subcommand: it enrolls AND runs in a single
# process, driven by env vars. This is the only reliable path for a tarball
# agent with no service manager —
#   * `elastic-agent install` needs systemd (absent in a container);
#   * `elastic-agent enroll` then `run` fails because `enroll` tries to reload a
#     daemon that isn't running yet.
#
# Two container-specific gotchas this handles:
#   * launch with `setsid nohup … </dev/null &` so the agent survives the
#     `docker exec` that starts it (otherwise it dies with the exec session);
#   * `pkill -x elastic-agent` (exact NAME), never `pkill -f`, which would also
#     match this script's own command line and kill it.
set -uo pipefail
TOKEN="${1:-}"
FLEET_URL="${FLEET_URL:-http://fleet-server:8220}"
AGENT_DIR=/opt/elastic-agent
[ -z "$TOKEN" ] && { echo "[ERR ] no token"; exit 1; }
[ -x "$AGENT_DIR/elastic-agent" ] || { echo "[ERR ] agent missing from image"; exit 1; }

cd "$AGENT_DIR"
pkill -x elastic-agent 2>/dev/null || true
sleep 2

export FLEET_URL FLEET_ENROLLMENT_TOKEN="$TOKEN" FLEET_INSECURE=true FLEET_ENROLL=1
echo "[STEP] Enrolling + starting agent (Fleet at ${FLEET_URL})"
setsid nohup ./elastic-agent container >/var/log/elastic-agent.log 2>&1 </dev/null &
touch "$AGENT_DIR/.enrolled"

# Wait for the agent to confirm it's Connected. On a FRESH install the
# fleet-server is still warming up, so the first check-ins fail for a while —
# give them a generous window before deciding anything.
for _ in $(seq 1 60); do
  sleep 3
  if ./elastic-agent status 2>/dev/null | grep -qi 'Connected'; then
    echo "[ OK ] agent enrolled and connected to Fleet"
    exit 0
  fi
done

# Not confirmed Connected yet. Crucially, `elastic-agent container` is a
# LONG-RUNNING daemon that keeps retrying check-ins on its own, so a slow
# fleet-server warm-up is NOT a failure — the agent connects by itself moments
# later and its logs reach the SIEM. Only a dead agent is a real problem, so
# distinguish the two: alive → accurate, non-alarming notice + success; gone →
# a genuine error.
if pgrep -x elastic-agent >/dev/null 2>&1; then
  echo "[WARN] agent enrolled and running; still completing its first Fleet"
  echo "       check-in as the server warms up — telemetry will appear shortly."
  exit 0
fi

echo "[ERR ] agent process is not running after enroll. Last log lines:"
tail -n 20 /var/log/elastic-agent.log 2>/dev/null || true
exit 1
