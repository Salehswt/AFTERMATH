#!/usr/bin/env python3
"""Shift the @timestamp of freshly-seeded events into the past.

The seeded actions are real (nmap, ssh, curl), so their telemetry lands at
"now". The scenario backstories, however, say things like "on the 3rd" — they
carry a `seed_time_offset` (e.g. "-3d"). After a scenario is seeded, this script
runs an Elasticsearch _update_by_query that moves the just-created events back by
that offset, so the timeline an analyst sees matches the ticket.

  backdate.py <offset> <since_epoch_seconds> [ip_or_host ...]

  offset            like -3d / -12h / -90m / -3600s (leading '-' optional)
  since_epoch       only touch docs with @timestamp >= this (the seed window)
  ip_or_host        restrict to docs mentioning these (source/dest ip or host);
                    if omitted, every doc in the window is shifted

Best-effort by design: events that arrive AFTER this runs (agent/logstash lag)
won't be shifted. seed.sh waits before calling this to minimise that.
Never fatal — a backdating failure must not fail the seed.
"""
import json
import re
import sys
import time
import urllib.error
import urllib.request
import os

ES = os.environ.get("ES_HOST", "http://elasticsearch:9200")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ.get("ELASTIC_PASSWORD", "")
# Indices that hold seeded telemetry: Logstash edge data + Elastic Agent logs.
INDICES = os.environ.get("LAB_INDICES", "lab-edge-*,logs-*")
# Overriding the pipeline with an empty one is REQUIRED: the logs-* data streams
# carry a default_pipeline that re-parses the event on _update_by_query and, for
# system.auth, DROPS the `message` field — which is where the sudo COMMAND lives.
# Passing an explicit no-op pipeline preserves the raw fields.
NOOP_PIPELINE = "aftermath-noop"
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_offset(text):
    t = text.strip().lstrip("-") or "0s"
    unit = t[-1].lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit)
    if mult is None:                       # bare number → seconds
        return int(float(t))
    return int(float(t[:-1]) * mult)


def es_req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{ES}/{path}", data=data,
        headers={"Content-Type": "application/json"}, method=method)
    if PASS:
        import base64
        tok = base64.b64encode(f"{USER}:{PASS}".encode()).decode()
        req.add_header("Authorization", f"Basic {tok}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def es_post(path, body):
    return es_req("POST", path, body)


def ensure_noop_pipeline():
    try:
        es_req("PUT", f"_ingest/pipeline/{NOOP_PIPELINE}",
               {"description": "no-op: backdating must not re-run the parse pipeline",
                "processors": []})
    except Exception:                                          # noqa: BLE001
        pass


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 0
    if not PASS:
        print("  [WARN] ELASTIC_PASSWORD not set — skipping backdating")
        return 0

    secs = parse_offset(sys.argv[1])
    since_ms = int(float(sys.argv[2])) * 1000
    selectors = sys.argv[3:]
    if secs <= 0:
        print("  [INFO] zero offset — nothing to backdate")
        return 0

    filters = [{"range": {"@timestamp": {"gte": since_ms, "format": "epoch_millis"}}}]
    query = {"bool": {"filter": filters}}
    if selectors:
        shoulds = []
        for s in selectors:
            # Route by type: an IP into IP fields, a hostname into name fields.
            # A hostname in an IP field throws 'not an IP string literal' and
            # fails the whole query.
            if IP_RE.match(s):
                fields = ("source.ip", "destination.ip", "host.ip", "related.ip")
            else:
                fields = ("host.name", "related.hosts", "host.hostname")
            for field in fields:
                shoulds.append({"term": {field: s}})
        query["bool"]["must"] = [{"bool": {"should": shoulds, "minimum_should_match": 1}}]

    body = {
        "query": query,
        "script": {
            "lang": "painless",
            # @timestamp comes through as an ISO string in _source; shift and
            # write it back as ISO so it re-indexes cleanly.
            "source": (
                "def t = ZonedDateTime.parse(ctx._source['@timestamp']);"
                "ctx._source['@timestamp'] = t.minusSeconds(params.secs).toString();"
            ),
            "params": {"secs": secs},
        },
    }

    ensure_noop_pipeline()
    try:
        res = es_post(
            f"{INDICES}/_update_by_query?pipeline={NOOP_PIPELINE}"
            "&conflicts=proceed&refresh=true&wait_for_completion=true", body)
        updated = res.get("updated", 0)
        # Routine success is rolled up by seed.sh's progress bar; printing it
        # per scenario would break that single line. Warnings below still print.
        if os.environ.get("LAB_VERBOSE") == "1":
            print(f"  [ OK ] backdated {updated} event(s) by {secs}s")
        return 0
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:300]
        print(f"  [WARN] backdating HTTP {e.code}: {detail}")
        return 0
    except Exception as exc:                                   # noqa: BLE001
        print(f"  [WARN] backdating skipped: {exc}")
        return 0


if __name__ == "__main__":
    # tiny grace so the very last events are queryable
    time.sleep(1)
    sys.exit(main())
