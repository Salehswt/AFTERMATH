# Kibana saved objects

These `*.ndjson` files are imported automatically by the `kibana-setup` service
on every install, so you land on a triage board instead of an empty Discover tab.

| File | What it is | Imported via |
|---|---|---|
| `soc-lab.ndjson` | **AFTERMATH - Triage** dashboard + 6 saved searches + their data views | Saved Objects API |
| `detection-rules.ndjson` | 5 Elastic Security detection rules (MITRE-mapped) for the two scenarios | Detection Engine API |

After install:
- **Dashboard:** Kibana → Dashboards → *AFTERMATH - Triage* (or `/app/dashboards#/view/soc-lab-triage`). Set the time picker to **Last 7 days** — the telemetry is backdated.
- **Alerts:** Kibana → Security → Rules. The rules run on a 30-minute interval and alert on the backdated data; Security → Alerts shows the hits.

## Regenerating these files

Build/adjust the objects in Kibana, then export:

```bash
# saved objects (dashboard + searches + data views)
curl -u elastic:$ELASTIC_PASSWORD -H "kbn-xsrf: true" \
  -X POST http://localhost:5601/api/saved_objects/_export \
  -H "Content-Type: application/json" \
  -d '{"objects":[{"type":"dashboard","id":"soc-lab-triage"}],"includeReferencesDeep":true}' \
  > dashboards/soc-lab.ndjson

# detection rules
curl -u elastic:$ELASTIC_PASSWORD -H "kbn-xsrf: true" \
  -X POST "http://localhost:5601/api/detection_engine/rules/_export?exclude_export_details=false" \
  -H "Content-Type: application/json" -d '{"objects":[]}' \
  > dashboards/detection-rules.ndjson
```

The data views use **fixed IDs** (`lab-logs`, `lab-edge`) and are bundled inside
`soc-lab.ndjson`, so the dashboard's panel references resolve on a fresh install.
