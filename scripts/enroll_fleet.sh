#!/usr/bin/env bash
# enroll_fleet.sh — print the enrollment token for the VICTIM policy to stdout.
#
# The policy itself is preconfigured in siem/kibana.yml (id: victim-policy) with
# the System integration, which is what ships /var/log/auth.log. Do NOT create it
# here as well — a second policy by the same name means the victim can end up
# enrolled somewhere with no integrations, and then no host logs ever arrive.
#
# The token MUST be filtered by policy_id: Fleet lists the fleet-server policy's
# key first, and enrolling the victim with that one is silent and useless.
source "$(dirname "$0")/lib.sh"; load_env
KB="http://localhost:5601"; AUTH="elastic:${ELASTIC_PASSWORD}"
h=(-s -u "$AUTH" -H "kbn-xsrf: true" -H "Content-Type: application/json")
POLICY_ID="victim-policy"

key_for_policy() {
  curl "${h[@]}" -G "$KB/api/fleet/enrollment_api_keys" \
    --data-urlencode "kuery=policy_id:\"${POLICY_ID}\"" \
    | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4
}

# Fleet finishes setting up preconfigured policies a little after Kibana reports
# "available", so give it a bounded wait rather than failing on a race.
for _ in $(seq 1 30); do
  TOKEN="$(key_for_policy)"
  [[ -n "$TOKEN" ]] && { echo "$TOKEN"; exit 0; }
  sleep 4
done

# Fallback: preconfiguration didn't take. Create the policy (with the System
# integration, or the victim ships nothing) and try once more.
log_warn "No enrollment key for '${POLICY_ID}' — creating the policy as a fallback" >&2
curl "${h[@]}" -X POST "$KB/api/fleet/agent_policies?sys_monitoring=true" \
  -d "{\"id\":\"${POLICY_ID}\",\"name\":\"Victim Policy\",\"namespace\":\"default\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}" \
  >/dev/null 2>&1 || true
for _ in $(seq 1 15); do
  TOKEN="$(key_for_policy)"
  [[ -n "$TOKEN" ]] && { echo "$TOKEN"; exit 0; }
  sleep 4
done
die "Could not obtain an enrollment token for policy '${POLICY_ID}'"
