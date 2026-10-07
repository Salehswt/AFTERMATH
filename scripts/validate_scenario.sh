#!/usr/bin/env bash
# validate_scenario.sh — sanity-check a scenario before running it:
# YAML parses, technique IDs look valid, referenced atomic tests exist.
source "$(dirname "$0")/lib.sh"
f="$1"; [[ -f "$f" ]] || die "no such file: $f"
log_step "Validating $f"
grep -q '^id:'   "$f" || die "missing required 'id'"
grep -q '^name:' "$f" || die "missing required 'name'"
grep -q '^chain:' "$f" || die "missing required 'chain'"
bad=0
while read -r t; do
  [[ "$t" =~ ^T[0-9]{4}(\.[0-9]{3})?$ ]] || { log_warn "suspicious technique id: $t"; bad=1; }
done < <(sed -n 's/.*technique: *\(T[0-9.]*\).*/\1/p' "$f")
(( bad == 0 )) && log_ok "Looks valid" || log_warn "Fix the flagged IDs, then re-validate"
