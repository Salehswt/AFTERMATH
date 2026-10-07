#!/usr/bin/env bash
# win_fleet.sh — provision the Fleet policy for the external Windows VM and print
# its enrollment token to stdout. Mirrors the Windows-side logic in install.ps1.
#
# Basic license forbids a per-policy output, so the VM CANNOT have its own ES
# output. It uses the shared default output instead, which install.sh has given
# a second, host-reachable address (LAB_EXTRA_ES) so the VM — which can't resolve
# the in-Docker hostname — fails over to it. Here we only create a plain policy
# and add the System + Windows integrations.
#
# Best-effort; diagnostics go to stderr, only the token to stdout.
source "$(dirname "$0")/lib.sh"; load_env
KB="http://localhost:5601"; AUTH="elastic:${ELASTIC_PASSWORD}"
h=(-s -u "$AUTH" -H "kbn-xsrf: true" -H "Content-Type: application/json")
POLICY="windows-victim"

# 1) plain policy (System integration via sys_monitoring; shared default output)
curl "${h[@]}" -X POST "$KB/api/fleet/agent_policies?sys_monitoring=true" \
  -d "{\"id\":\"${POLICY}\",\"name\":\"Windows Victim Policy\",\"namespace\":\"default\",\"monitoring_enabled\":[\"logs\",\"metrics\"]}" >/dev/null 2>&1 || true

# 2) Windows integration → Sysmon/Operational + PowerShell/Operational.
#    Input key is '<policy_template>-<input_type>' = windows-winlog; channel names
#    come from the package, so enabling the streams is enough.
win_ver="$(curl "${h[@]}" "$KB/api/fleet/epm/packages/windows" | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)"
if [[ -n "$win_ver" ]]; then
  if ! curl "${h[@]}" -X POST "$KB/api/fleet/package_policies" -d "{
    \"name\":\"windows-1\",\"policy_id\":\"${POLICY}\",\"namespace\":\"default\",
    \"package\":{\"name\":\"windows\",\"version\":\"${win_ver}\"},
    \"inputs\":{\"windows-winlog\":{\"enabled\":true,\"streams\":{
      \"windows.sysmon_operational\":{\"enabled\":true},
      \"windows.powershell_operational\":{\"enabled\":true},
      \"windows.powershell\":{\"enabled\":true},
      \"windows.forwarded\":{\"enabled\":true}}}}}" 2>/dev/null | grep -q '"item"'; then
    log_warn "Could not auto-add the Windows integration; add 'Windows' to the '${POLICY}' policy in Kibana for Sysmon + PowerShell channels." >&2
  fi
fi

# 3) print the Windows policy's enrollment token
for _ in $(seq 1 20); do
  tok="$(curl "${h[@]}" -G "$KB/api/fleet/enrollment_api_keys" \
    --data-urlencode "kuery=policy_id:\"${POLICY}\"" \
    | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4)"
  [[ -n "$tok" ]] && { echo "$tok"; exit 0; }
  sleep 3
done
exit 1
