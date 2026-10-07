#!/usr/bin/env python3
"""Render SOLUTIONS.md from scenarios/*.yml — the single source of truth, so the
seeded attack and its answer key can never drift.

Writes SOLUTIONS.md directly (UTF-8) rather than relying on a shell redirect,
which mangles non-ASCII on Windows PowerShell. Reads the YAMLs as UTF-8 too, so
it produces identical output on Windows, Linux and macOS.

  python3 scripts/render_solutions.py            # writes ./SOLUTIONS.md
  python3 scripts/render_solutions.py out.md     # or a path you choose
"""
import glob
import io
import os
import sys

import yaml

out = []


def w(line=""):
    out.append(line)


w("# Solutions (spoilers)\n")
w("> Each scenario is collapsed. Expand only after your own attempt.\n")

for path in sorted(glob.glob(os.path.join("scenarios", "scenario_*.yml"))):
    if path.endswith("scenario_template.yml"):
        continue
    with open(path, encoding="utf-8") as fh:
        s = yaml.safe_load(fh)
    w(f"<details>\n<summary><b>{s['id']} — {s['name']}</b></summary>\n")
    chain = " -> ".join(step["technique"] for step in s.get("chain", []))
    w(f"**Kill chain:** {chain}\n")
    w("**Steps:**\n")
    for step in s.get("chain", []):
        w(f"- `{step['technique']}` (test {step.get('test', 1)}) — {step.get('note', '')}")
    w("\n**How to detect it** (every query is validated against the seeded "
      "telemetry; switch Discover to Lucene, or read them as KQL):\n")
    for d in s.get("expected_detections", []):
        w(f"- {d.get('description', '')}")
        if d.get("index"):
            w(f"  - data view: `{d['index']}`")
        if d.get("query"):
            w(f"  ```\n  {d['query']}\n  ```")
    w("\n**IOCs:**\n")
    for i in s.get("iocs", []):
        w(f"- {i.get('type', '')}: `{i.get('value', '')}`")
    w(f"\n**Summary:** {s.get('answer_summary', '').strip()}\n")
    w("</details>\n")

dest = sys.argv[1] if len(sys.argv) > 1 else "SOLUTIONS.md"
with io.open(dest, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(out))
print(f"Wrote {dest} ({len(out)} lines)")
