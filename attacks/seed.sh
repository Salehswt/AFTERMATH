#!/usr/bin/env bash
# seed.sh - execute scenario chains from the single source of truth (YAML).
#   --all           run every scenario_NN.yml (seeded history)
#   --live <id>     run one technique/scenario now (analyst watches it land)
#
# Exit status is honest: if any technique had no emulation or failed to run, the
# script exits non-zero so the installer can't announce a compromise that was
# never staged. Scenarios are mounted read-only at /scenarios.
#
# Output: a single self-overwriting progress bar for the whole seed by default.
# Set LAB_VERBOSE=1 for the full per-technique trace (useful when debugging a
# seed), or LAB_NO_PROGRESS=1 for one plain line per scenario when the output is
# being captured to a log. Failures and warnings are ALWAYS shown, in all modes.
set -uo pipefail
c_cyan=$'\033[36m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_red=$'\033[31m'; c_dim=$'\033[90m'; c_rst=$'\033[0m'
# The progress bar owns the current line, so anything else that prints has to
# wipe it first or it lands on top of a half-drawn bar. Every log helper below
# clears first; the bar is redrawn by the next scenario.
clear_line(){
  [ "${VERBOSE:-0}" = 1 ] && return 0
  [ "${NO_PROGRESS:-0}" = 1 ] && return 0
  printf '\r%*s\r' 78 ''
}
step(){ clear_line;     echo "${c_cyan}[STEP]${c_rst} $*"; }
ok(){   clear_line;     echo "${c_grn}[ OK ]${c_rst} $*"; }
info(){ clear_line;     echo "${c_dim}[INFO]${c_rst} $*"; }
warn(){ clear_line;     echo "${c_yel}[WARN]${c_rst} $*"; }
err(){  clear_line >&2; echo "${c_red}[ERR ]${c_rst} $*" >&2; }

VICTIM="${VICTIM_HOST:-172.30.0.50}"
ATTACKER_IP="${ATTACKER_IP:-172.30.0.100}"
C2_IP="${C2_IP:-172.30.0.99}"
# What this build can actually attack. The Linux-only default cannot run the
# Windows/Office scenarios, and must SKIP them rather than fail on them.
LAB_TARGETS="${LAB_TARGETS:-linux}"
# Seconds to let telemetry flush to Elasticsearch before backdating it.
FLUSH_WAIT="${FLUSH_WAIT:-30}"
# Quiet by default; LAB_VERBOSE=1 restores the per-step trace.
VERBOSE="${LAB_VERBOSE:-0}"
# LAB_NO_PROGRESS=1 falls back to one plain line per scenario. The bar redraws
# with \r, which is right for a terminal but leaves one long smeared line in a
# captured log - set this when piping the seed to a file or CI.
NO_PROGRESS="${LAB_NO_PROGRESS:-0}"
vstep(){ if [ "$VERBOSE" = 1 ]; then step "$@"; fi; }

# Single self-overwriting progress line: [####------] 8/16 mm:ss <scenario>.
# Elapsed is shown because each scenario sleeps FLUSH_WAIT seconds waiting for
# telemetry to flush, so the counter can sit still for ~30s at a time and the
# clock is what proves the seed is alive rather than wedged.
BAR_FULL='####################'   # 20 cells
BAR_NONE='--------------------'
SEED_START=0
progress(){   # <idx> <total> <scenario>
  [ "$VERBOSE" = 1 ] && return 0
  [ "$2" -gt 0 ] || return 0
  if [ "$NO_PROGRESS" = 1 ]; then step "(${1}/${2}) deploying ${3} ..."; return 0; fi
  local filled=$(( $1 * 20 / $2 ))
  local el=$(( $(date +%s) - SEED_START ))
  printf '\r  %s[%s%s]%s  %2d/%-2d  %02d:%02d  %-34s' \
    "$c_cyan" "${BAR_FULL:0:filled}" "${BAR_NONE:0:$((20 - filled))}" "$c_rst" \
    "$1" "$2" "$((el / 60))" "$((el % 60))" "$3"
}

fail_count=0
skip_count=0
scenario_fail=0

run_technique(){   # <technique> <test>
  vstep "Technique $1 (test $2) against ${VICTIM}"
  local rc=0 out=''
  if [ "$VERBOSE" = 1 ]; then
    # Verbose streams live - there is no bar to protect.
    python3 /attacks/runner.py "$1" "$2" "$VICTIM" || rc=$?
  else
    # Buffer instead, so runner.py's own [WARN]/[ERR ] lines are emitted through
    # clear_line rather than printed straight over the bar. A healthy technique
    # prints nothing, so this is silent in the normal case.
    out="$(python3 /attacks/runner.py "$1" "$2" "$VICTIM" 2>&1)" || rc=$?
    if [ -n "$out" ]; then clear_line; printf '%s\n' "$out"; fi
  fi
  if [ "$rc" -ne 0 ]; then
    err "  technique $1 (test $2) produced no telemetry"
    fail_count=$((fail_count + 1))
    scenario_fail=$((scenario_fail + 1))
  fi
}

# After a scenario is seeded, shift its just-created events back by the
# scenario's seed_time_offset so the timeline matches the ticket's dates.
# Non-fatal: a backdating problem never fails the seed.
backdate_scenario(){   # <file> <window_start_epoch>
  local off; off="$(python3 /attacks/runner.py --offset "$1")"
  [ -z "$off" ] && return 0
  vstep "Backdating $(basename "$1") events by ${off} (waiting ${FLUSH_WAIT}s for flush)"
  sleep "$FLUSH_WAIT"
  if [ "$VERBOSE" = 1 ]; then
    python3 /attacks/backdate.py "$off" "$2" "$VICTIM" "$ATTACKER_IP" "$C2_IP" || true
  else
    # backdate.py keeps its routine "[ OK ] backdated N event(s)" line for
    # LAB_VERBOSE only; anything it still prints here is a warning worth seeing,
    # so clear the bar before letting it through.
    local out; out="$(python3 /attacks/backdate.py "$off" "$2" "$VICTIM" "$ATTACKER_IP" "$C2_IP" 2>&1 || true)"
    if [ -n "$out" ]; then clear_line; printf '%s\n' "$out"; fi
  fi
}

# A scenario may declare `requires: windows` (or linux). Skip it when this build
# can't service it.
scenario_supported(){   # <file>
  local req; req="$(python3 /attacks/runner.py --requires "$1")"
  [ -z "$req" ] && return 0
  case ",$LAB_TARGETS," in *",$req,"*) return 0 ;; *) return 1 ;; esac
}

seed_all(){
  local ran=0 seeded=0 tech_total=0 idx=0 total=0
  # Pre-count what this build will actually seed, for an (i/N) progress marker so
  # a long, quiet seed shows where it is instead of looking hung.
  local win_skips=0
  for f in /scenarios/scenario_[0-9]*.yml; do
    [ -e "$f" ] || continue
    if scenario_supported "$f"; then
      total=$((total + 1))
      continue
    fi
    # Resolve skips up here, not in the deploy loop, so the reasons print BEFORE
    # the bar claims the last line instead of interrupting it partway through.
    req="$(python3 /attacks/runner.py --requires "$f")"
    if [ "$req" = windows ]; then
      win_skips=$((win_skips + 1))
      [ "$VERBOSE" = 1 ] && info "$(basename "$f" .yml) is a Windows scenario - seeded on the VM via Atomic Red Team (step 5b), not here. Skipping."
    else
      info "$(basename "$f" .yml) needs a $req victim, which this build doesn't include. Skipping."
    fi
    skip_count=$((skip_count + 1))
  done
  if [ "$VERBOSE" != 1 ]; then
    step "Deploying ${total} scenarios  (set LAB_VERBOSE=1 for per-step detail)"
    [ "$win_skips" -gt 0 ] && info "${win_skips} Windows scenario(s) skipped - seeded on the VM in step 5b"
  fi
  SEED_START="$(date +%s)"
  for f in /scenarios/scenario_[0-9]*.yml; do
    [ -e "$f" ] || continue
    scenario_supported "$f" || continue
    local base; base="$(basename "$f" .yml)"
    idx=$((idx + 1))
    # Announce each scenario as it STARTS so progress is visible during the wait.
    if [ "$VERBOSE" = 1 ]; then step "Seeding $base"; else progress "$idx" "$total" "$base"; fi
    ran=1
    scenario_fail=0
    local tech_count=0
    local win_start; win_start="$(date +%s)"
    while read -r t n; do
      [ -z "$t" ] && continue
      tech_count=$((tech_count + 1))
      run_technique "$t" "$n"
    done < <(python3 /attacks/runner.py --parse "$f")
    backdate_scenario "$f" "$win_start"
    seeded=$((seeded + 1))
    tech_total=$((tech_total + tech_count))
    # Success rolls up into the final tally; only shout about failures here
    # (the specific failing technique was already printed by run_technique).
    if [ "$scenario_fail" -ne 0 ]; then
      err "(${idx}/${total}) ${base} - ${scenario_fail}/${tech_count} technique(s) produced NO telemetry"
    fi
  done

  # Retire the bar before the tally so the summary starts on a clean line.
  clear_line
  echo
  if [ "$ran" = 0 ]; then
    err "No scenario was seeded (all skipped for this build's targets: ${LAB_TARGETS})."
    return 1
  fi
  if [ "$fail_count" -gt 0 ]; then
    err "Linux scenarios: ${seeded} seeded, ${tech_total} technique(s), ${fail_count} FAILED, ${skip_count} skipped."
    return 1
  fi
  ok "Linux scenarios seeded - ${seeded} scenario(s), ${tech_total} technique(s), 0 failed (${skip_count} skipped)."
}

case "${1:-}" in
  --all)  seed_all ;;
  --live) VERBOSE=1; shift; run_technique "${1:?technique id}" "${2:-1}"; [ "$fail_count" = 0 ] ;;
  *) echo "usage: seed.sh --all | --live <id> [test]"; exit 1 ;;
esac
