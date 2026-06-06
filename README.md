# FoundStone

**FoundStone** is a detection rule verification tool for SentinelOne. It takes real log events, overlays only the fields each detection rule requires, replays the synthetic events into the Singularity Data Lake (SDL), and verifies that alerts fire — giving you a ground-truth pass/fail result for every rule in your deployed library.

---

## How it works

For each detection rule, FoundStone:

1. Reads the rule's filter logic (`pair_list`) to determine the minimal set of fields required to trigger it
2. Takes a real ingested event as a base template (uploaded by you, or pulled from SDL)
3. Overlays **only** the detection-required field values onto the real event — everything else stays genuine
4. Ingests the synthetic event(s) into SDL
5. Waits and queries the `alert` dataset to confirm the rule fired

> **Change only what the detection reads. Keep everything else real.**

This approach was validated against the full Okta detection library — 41/42 rules fired on first pass using real Okta event templates.

---

## Requirements

- Docker + Docker Compose (OrbStack works great on macOS)
- A `data/extracted.json` file — the parsed detection library (see [Data setup](#data-setup))
- A SentinelOne tenant for testing (POC/demo only — never production)

---

## Quick start

```bash
git clone https://github.com/mickbrowns1/foundstone
cd foundstone

# Add your extracted.json to data/
cp /path/to/extracted.json data/

# Start the container
docker compose up -d
```

Open **http://localhost:8080**

---

## Data setup

`data/extracted.json` is the parsed detection library. It is **not** included in this repo (it contains proprietary rule logic). It should have this shape:

```json
{
  "results": [
    {
      "id": "uuid",
      "name": "Rule Name",
      "description": "...",
      "app": "STAR",
      "file": "/rules/...",
      "queries": [
        {
          "query": "dataSource.name = 'Okta' and ...",
          "pair_list": [
            { "key": "dataSource.name", "op": "=", "value": "Okta" }
          ]
        }
      ]
    }
  ]
}
```

---

## Configuration

All configuration is done through the **Environments** tab in the UI. No editing files.

### Add an environment

1. Go to **Environments → New Environment**
2. Fill in:
   - **Name** — e.g. `POC - Acme Corp`
   - **Console Base URL** — e.g. `https://your-tenant.sentinelone.net`
   - **SDL Read Token** — Singularity Data Lake log read key
   - **SDL Write Token** — Singularity Data Lake log write key
   - **SDL Account ID**
   - **S1 API Token** — account-level API token (for library sync)
3. Set as active and save

### Sync the detection library

Click **↓ Sync from Active Environment** — this pulls all deployed rules from `/web/api/v2.1/detection-library/platform-rules` and filters the Rules tab to show only what's active on your tenant.

The sync result persists across restarts (stored in SQLite).

### Upload real log templates (recommended)

Instead of pulling templates from SDL (which may contain private data), upload your own:

1. Go to **Environments → Real Log Templates**
2. Drag-drop a `.jsonl` or `.json` file of real log events
3. Events are indexed by `dataSource.name` automatically

Supported formats:
- JSONL (one JSON object per line)
- JSON array (`[{...}, {...}]`)
- JSON object with `events` or `results` key (`{"events": [...]}`)

---

## Running verifications

1. Go to **Rules** — rules are grouped by data source, collapsed by default
2. Check individual rules or select all rules for a source
3. Click **Run →** or go to the **Run** tab
4. Enable **Dry Run** to preview what would be ingested without sending anything
5. Hit **Run** — progress updates live, results show fired/not fired per rule

---

## Port

The container runs on **port 8080** by default. Change in `docker-compose.yml`:

```yaml
ports:
  - "8080:8000"
```

---

## Data persistence

The following are mounted from your host into the container so they survive rebuilds:

| Path | Contents |
|---|---|
| `data/foundstone.db` | SQLite — environments, deployed rule names |
| `.env` | Fallback env vars (config via UI is preferred) |

`data/extracted.json` is baked into the image at build time.

---

## Architecture

```
foundstone/
  api.py                  # FastAPI backend
  foundstone/
    classifier.py         # Rule class detection (simple/volume/correlation/first_seen/scheduled)
    rule_parser.py        # pair_list → minimal field overlay
    event_builder.py      # Deep-merge overlay onto real template
    ingester.py           # SDL addEvents
    verifier.py           # Query alert dataset, match rule names
    runner.py             # Full pipeline orchestrator
    template_fetcher.py   # SDL V1 query for real event templates
    db.py                 # SQLite — environments + deployed rule names
  ui/                     # React + Vite + Tailwind frontend
  Dockerfile              # Multi-stage: Node builds UI, Python serves it
  docker-compose.yml
```

---

## Guardrails

- All synthetic events are tagged `_foundstone_test: true` for easy cleanup
- Config UI warns when no active environment is set
- Dry run mode is on by default — no events are ingested until you explicitly disable it
- Never use against a production tenant

---

## License

Internal tooling — SentinelOne.
