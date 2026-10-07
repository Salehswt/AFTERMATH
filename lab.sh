#!/usr/bin/env bash
# lab.sh - day-to-day control for the AFTERMATH lab (Linux/macOS host).
#
# Runs on the HOST and drives the whole lab from outside - it is NOT run inside
# a victim. On Windows, use the native twin lab.ps1 instead.
#
#   ./lab.sh status               component health
#   ./lab.sh attack <id|scenario> fire a technique/chain LIVE (watch it land)
#   ./lab.sh list-attacks         techniques/scenarios available
#   ./lab.sh new-scenario         scaffold a scenarios/scenario_NN.yml
#   ./lab.sh validate <file.yml>  check technique IDs + YAML before running
#   ./lab.sh validate-detections  assert every answer-key query still returns hits
#   ./lab.sh ssh                  SSH into the Linux victim  (jdoe / Password123)
#   ./lab.sh rdp                  RDP to the Windows victim  (vagrant / vagrant)
#   ./lab.sh winssh               SSH into the Windows victim (vagrant / vagrant)
#   ./lab.sh reset                wipe volumes + rebuild victim, then reseed
#   ./lab.sh down                 stop everything (keeps data)

source "$(dirname "$0")/scripts/lib.sh"
load_env

# Every command must address the same set of compose files the installer used,
# or the Linux victim (and its sensor) look like orphans to `down`/`status`.
CF=(-f docker-compose.yml -f docker-compose.linux-victim.yml)
dc() { docker compose "${CF[@]}" "$@"; }

cmd="${1:-help}"; shift || true

case "$cmd" in
  status)
    log_step "Docker components"
    dc ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}'
    echo
    log_step "SIEM health"
    curl -ksf "http://localhost:5601/api/status" >/dev/null \
      && log_ok "Kibana reachable" || log_warn "Kibana not reachable"
    log_step "Victim"
    dc ps linux-victim 2>/dev/null || ( cd victim && vagrant status ) 2>/dev/null \
      || log_warn "No victim found"
    ;;

  attack)
    [[ $# -ge 1 ]] || die "Usage: ./lab.sh attack <technique-id|scenario_NN>"
    # Same path as the README's live example — the attacker container is the one
    # runner. `attack T1110.001` fires a single technique; `attack scenario_02`
    # replays a whole chain live.
    if [[ "$1" == scenario_* ]]; then
      f="scenarios/${1}.yml"; [[ -f "$f" ]] || die "no such scenario: $f"
      log_step "Replaying $1 LIVE against the victim"
      dc exec -T attacker bash -c \
        'python3 /attacks/runner.py --parse "/scenarios/'"$1"'.yml" | while read -r t n; do /attacks/seed.sh --live "$t" "$n"; done'
    else
      log_step "Firing technique '$1' LIVE against the victim"
      dc exec -T attacker /attacks/seed.sh --live "$1" "${2:-1}"
    fi
    log_ok "Done — check Kibana for fresh alerts"
    ;;

  list-attacks)
    log_step "Scenarios (chains)"
    for f in scenarios/scenario_*.yml; do
      [[ -e "$f" ]] || continue
      name=$(grep -m1 '^name:' "$f" | cut -d'"' -f2)
      printf '  %s  %s\n' "$(basename "$f" .yml)" "$name"
    done
    echo
    log_step "Techniques with a lab implementation"
    dc exec -T attacker python3 -c \
      'import runner; [print("  "+t) for t in sorted(runner.ACTIONS)]' 2>/dev/null \
      || log_info "  (start the lab to list these)"
    ;;

  new-scenario)
    n=$(printf '%02d' "$(( $(ls scenarios/scenario_*.yml 2>/dev/null | wc -l) + 1 ))")
    dest="scenarios/scenario_${n}.yml"
    cp scenarios/scenario_template.yml "$dest"
    log_ok "Created $dest — edit it, then: ./lab.sh validate $dest"
    ;;

  validate)
    [[ $# -ge 1 ]] || die "Usage: ./lab.sh validate <scenarios/file.yml>"
    bash scripts/validate_scenario.sh "$1"
    ;;

  validate-detections)
    # Assert every scenario's expected_detections still returns hits in ES.
    log_step "Validating detections against the seeded telemetry"
    dc exec -T -e ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-}" -e LAB_TARGETS="${LAB_TARGETS:-linux,windows}" \
      attacker python3 /attacks/validate_detections.py /scenarios
    ;;

  reset)
    log_warn "This wipes SIEM data and rebuilds the victim."
    if [[ "${LAB_AUTO:-0}" != "1" ]]; then
      read -r -p "    Continue? [y/N] " a; [[ "$a" =~ ^[Yy]$ ]] || exit 0
    fi
    dc down -v
    ( cd victim && vagrant destroy -f ) 2>/dev/null || true
    log_ok "Torn down. Re-running installer..."
    exec ./install.sh
    ;;

  ssh)
    # The Linux victim publishes 22 on 127.0.0.1:2022 (docker-compose.linux-victim.yml).
    log_step "SSH to the Linux victim (jdoe / Password123)"
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null jdoe@localhost -p 2022
    ;;

  rdp)
    # The Windows box forwards RDP to host 53389 by default ('cd victim; vagrant port').
    log_step "RDP to the Windows victim (localhost:53389, vagrant / vagrant)"
    if command -v xfreerdp >/dev/null 2>&1; then
      xfreerdp /v:localhost:53389 /u:vagrant /p:vagrant +auto-reconnect >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
      open "rdp://localhost:53389"          # macOS: hands off to Microsoft Remote Desktop
    else
      log_warn "No RDP client found. Point any RDP client at localhost:53389 (vagrant / vagrant)."
    fi
    ;;

  winssh)
    # The Windows box forwards guest 22 to host 2222 by default.
    log_step "SSH to the Windows victim (vagrant / vagrant)"
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null vagrant@localhost -p 2222
    ;;

  down)
    dc down
    ( cd victim && vagrant halt ) 2>/dev/null || true
    log_ok "Stopped (data preserved). './lab.sh status' or './install.sh' to resume."
    ;;

  help|*)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
