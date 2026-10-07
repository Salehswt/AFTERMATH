#!/usr/bin/env python3
"""Validate that every scenario's expected_detections actually match the seeded
telemetry. For each detection, run its query against Elasticsearch and assert the
count is > 0. Exit non-zero if any detection returns nothing.

This is the guard against the single worst failure mode of a lab like this: the
answer key promising a query that returns an empty Discover tab. Run it after
seeding; wire it into CI to keep scenarios honest as they evolve.

  validate_detections.py [scenarios_dir]      (default: /scenarios)

Env: ES_HOST (default http://elasticsearch:9200), ELASTIC_PASSWORD, LAB_TARGETS.
"""
import base64
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

import yaml

ES = os.environ.get("ES_HOST", "http://elasticsearch:9200")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ.get("ELASTIC_PASSWORD", "")
TARGETS = [t for t in os.environ.get("LAB_TARGETS", "linux,windows").split(",") if t]
# Seeded telemetry ships to Elasticsearch with a lag (agent poll + bulk flush),
# so a query can legitimately read zero for a minute after the action ran. Rather
# than fail the install on that race, re-check only the still-empty detections a
# few times before giving up.
RETRIES = int(os.environ.get("VALIDATE_RETRIES", "6"))
RETRY_WAIT = int(os.environ.get("VALIDATE_RETRY_WAIT", "15"))

GRN, RED, YEL, RST = "\033[32m", "\033[31m", "\033[33m", "\033[0m"

# Each detection's `description` is answer-key material - "Run key written for
# persistence (the smoking gun)" tells the analyst exactly what to hunt for
# before they have hunted for anything. Default output is therefore a pass/fail
# tally per scenario, using only the scenario title (already published in
# SCENARIOS.md). LAB_VERBOSE=1 restores the per-detection trace for whoever is
# maintaining the answer key. Failures always print in full: a failing check
# means the lab is broken, and fixing it beats keeping the secret.
VERBOSE = os.environ.get("LAB_VERBOSE") == "1"


def es_count(index, query):
    body = json.dumps({"query": {"query_string": {"query": query}}}).encode()
    req = urllib.request.Request(
        f"{ES}/{index}/_count", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    if PASS:
        tok = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
        req.add_header("Authorization", f"Basic {tok}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())["count"], None
    except urllib.error.HTTPError as e:
        return 0, f"HTTP {e.code} {e.read().decode()[:120]}"
    except Exception as exc:                                   # noqa: BLE001
        return 0, str(exc)


def main():
    sdir = sys.argv[1] if len(sys.argv) > 1 else "/scenarios"
    files = sorted(glob.glob(os.path.join(sdir, "scenario_*.yml")))
    skipped = 0
    checks = []            # one dict per detection we will actually query
    scenarios = []         # ordered (id, name) of everything we validate

    if not VERBOSE:
        print("Validating the answer key against the seeded telemetry "
              "(set LAB_VERBOSE=1 for per-detection detail)")

    for f in files:
        if f.endswith("scenario_template.yml"):
            continue
        doc = yaml.safe_load(open(f))
        req = doc.get("requires")
        sid, name = doc.get("id"), doc.get("name", "")
        if req and req not in TARGETS:
            print(f"{YEL}SKIP{RST} {sid} (requires {req}; not in this build)")
            skipped += 1
            continue

        scenarios.append((sid, name))
        if VERBOSE:
            print(f"\n== {sid} — {name} ==")
        for d in doc.get("expected_detections", []):
            idx, q = d.get("index"), d.get("query")
            desc = d.get("description", "")
            if not idx or not q:
                if VERBOSE:
                    print(f"  {YEL}[SKIP]{RST} {desc} (detection has no index/query)")
                continue
            n, err = es_count(idx, q)
            checks.append({"sid": sid, "idx": idx, "q": q,
                           "desc": desc, "n": n, "err": err})
            if VERBOSE:
                if not err and n > 0:
                    print(f"  {GRN}[ OK ]{RST} {n:>6}  {desc}")
                else:
                    print(f"  {YEL}[....]{RST}      0  {desc} (will re-check)")

    # Re-check only the empty/errored detections: seeded telemetry lands with a
    # lag, so an early zero is usually ingestion, not a broken answer key.
    pending = [c for c in checks if c["err"] or c["n"] == 0]
    rounds = 0
    while pending and rounds < RETRIES:
        rounds += 1
        print(f"\n{YEL}[wait]{RST} {len(pending)} detection(s) still empty; "
              f"re-checking in {RETRY_WAIT}s (round {rounds}/{RETRIES})…")
        time.sleep(RETRY_WAIT)
        for c in pending:
            c["n"], c["err"] = es_count(c["idx"], c["q"])
        cleared = [c for c in pending if not c["err"] and c["n"] > 0]
        if VERBOSE:
            for c in cleared:
                print(f"  {GRN}[ OK ]{RST} {c['n']:>6}  {c['desc']} (after retry)")
        pending = [c for c in pending if c["err"] or c["n"] == 0]

    # Per-scenario tally. Only the scenario title is shown - it is the briefing
    # in SCENARIOS.md, not the answer - so a clean run reveals nothing about
    # WHICH artifacts prove the compromise.
    if not VERBOSE:
        tally = {sid: {"total": 0, "bad": 0} for sid, _ in scenarios}
        for c in checks:
            tally[c["sid"]]["total"] += 1
        for c in pending:
            tally[c["sid"]]["bad"] += 1
        print()
        for sid, name in scenarios:
            st = tally[sid]
            good = st["total"] - st["bad"]
            mark = f"{GRN}[ OK ]{RST}" if st["bad"] == 0 else f"{RED}[FAIL]{RST}"
            print(f"  {mark} {sid}  {good}/{st['total']}  {name}")

    failed = 0
    for c in pending:
        failed += 1
        if c["err"]:
            print(f"  {RED}[FAIL]{RST} {c['desc']} -> {c['err']}")
        else:
            print(f"  {RED}[FAIL]{RST}      0  {c['desc']}")
            print(f"           {c['idx']}  ::  {c['q']}")

    print(f"\n{len(checks)} detection(s) checked, {failed} failed, "
          f"{skipped} scenario(s) skipped.")
    if failed:
        print(f"{RED}Answer key does not match the telemetry — fix the query or "
              f"the scenario.{RST}")
    else:
        print(f"{GRN}All detections match the seeded telemetry.{RST}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
