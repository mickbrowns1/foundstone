# FoundStone

**FoundStone** is a detection rule verification tool for SentinelOne. It takes real log events, overlays only the fields each detection rule requires, replays the synthetic events into the Singularity Data Lake (SDL), and verifies that alerts fire — giving you a ground-truth pass/fail result for every rule in your deployed library.

This repo also ships the **Treadstone Log Simulator** — a standalone synthetic security-event generator (Jason Bourne universe themed) that continuously feeds realistic on-prem *and* AWS telemetry through SentinelOne DataPipeline into SDL, for building and testing detections against a living dataset instead of one-off overlays. See [Treadstone Log Simulator](#treadstone-log-simulator) below.

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
- `SDL_BASE_URL` must point at your tenant's actual **SDL/XDR host** (e.g. `https://xdr.us1.sentinelone.net`), **not** the Management Console URL — the two are different hosts, and pointing at the console will silently break ingestion (404s on `/api/query` / `/api/addEvents`)

---

## Quick start

```bash
git clone https://github.com/mickbrowns1/foundstone
cd foundstone

# Add your extracted.json to data/
cp /path/to/extracted.json data/

# Fill in .env — see .env.example (SDL_BASE_URL/tokens, and optionally
# HEC_URL/HEC_TOKEN if you also want the Treadstone Log Simulator running)
cp .env.example .env

# Start the FoundStone container (add the Treadstone services too if you want them —
# see "Treadstone Log Simulator" below)
docker compose up -d foundstone
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

> **Note:** the actual `/api/run` verification pipeline reads its SDL connection from `.env` (`SDL_BASE_URL`/`SDL_READ_TOKEN`/`SDL_WRITE_TOKEN`/`SDL_ACCOUNT_ID`/`DRY_RUN`), not from the DB-stored environment above — that UI environment is used for template fetching and status display. Keep both in sync. `SDL_BASE_URL` is the **SDL/XDR host**, not the console host — see [Requirements](#requirements).

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

## Treadstone Log Simulator

A separate, always-on synthetic security-event generator — Jason Bourne universe themed — that ships a steady stream of realistic telemetry through SentinelOne DataPipeline into SDL. Use it to build and validate PowerQuery detections against a living dataset (with scripted, correlated attack scenarios you can fire on demand) rather than one-off overlaid events.

```
log-generator ──RFC 5424/6587 over TCP──▶ syslog-ng ──HEC (one POST/event)──▶ DataPipeline ──▶ SDL
```

### What it generates

**On-prem / SaaS security sources:** Cisco Firewall Threat Defense, Linux Audit (sshd/sudo/PAM/cron/kernel), Apache HTTP Server access logs, Cisco Duo MFA, Zscaler Internet Access, ISC BIND DNS, Mimecast email security, PostgreSQL, Windows Event Logs. Every source is tagged with a real `dataSource.name`/`dataSource.category` grounded in this tenant's own deployed rule library where a match exists (see `TREADSTONE_PIPELINE.md`'s tagging table).

**AWS (CloudTrail):** modeled as a **hardened** AWS Organization on purpose — MFA-enforced `AssumeRole` sessions only (no root usage, no long-lived access keys in normal traffic), encrypted S3 (SSE-KMS), least-privilege roles per program, and API calls only ever from known corporate egress IPs. Root usage, disabled logging, privilege escalation, and MFA-less logins are deliberately **never** ambient — they only appear inside the dedicated attack scenarios, so a detection firing on them means something actually happened.

**SentinelOne EDR:** schema grounded directly in this tenant's own deployed detection library (746 real `SentinelOne`-sourced rules in `data/extracted.json`) rather than guessed — `event.type` distribution mirrors real usage (`Process Creation` dominant, plus File/Registry/Task/Network/DNS/Behavioral Indicator events). Ambient traffic is signed, known-publisher, ordinary parent/child process trees; credential dumping, reverse shells, and persistence mechanisms only appear in dedicated scenarios.

35 scripted, correlated attack scenarios spanning all 5 Bourne films, the 2019 *Treadstone* TV series, AWS, and SentinelOne EDR — each emits a short burst of events across multiple sources sharing actors/hosts/IPs, so you can pivot host→user→IP across firewall, identity, proxy, DB, cloud, and EDR telemetry. Several EDR scenarios are direct companions to existing storylines (e.g. `edr_mimikatz_langley` alongside `lateral_langley`). Full list and detection mappings: [TREADSTONE_DETECTIONS.md](TREADSTONE_DETECTIONS.md).

### Starting it

```bash
# In .env, add (found in DataPipeline UI: Pipelines > Sources > + Add Source > HTTP Event Collector):
HEC_URL=https://ingest.<region>.sentinelone.net/services/collector/event
HEC_TOKEN=<your DataPipeline HEC token>
HEC_INDEX=treadstone

docker compose up -d --build syslog-ng log-generator
```

You'll also need a **Lua processor stage** in the DataPipeline pipeline itself — the built-in `parse_json` step has no per-source gating and throws on the plain-text sources. Use [datapipeline/parse_json_by_msgid.lua](datapipeline/parse_json_by_msgid.lua) (verified locally with `datapipeline/test_parse_json_by_msgid.lua`); see [TREADSTONE_PIPELINE.md](TREADSTONE_PIPELINE.md) for the full integration notes (field collisions, sourcetype routing, reliability behavior).

**SentinelOne EDR events don't go through any of this** — they bypass syslog-ng/DataPipeline entirely and post straight into SDL (matching how real EDR telemetry actually arrives), reusing the `SDL_BASE_URL`/`SDL_WRITE_TOKEN` already in `.env` for FoundStone itself. No console changes needed for these.

### Firing scenarios on demand

Ambient scenario firing is rare (`SCENARIO_CHANCE=0.02`). To test/demo a detection immediately:

```bash
docker exec treadstone-log-generator python3 fire_scenario.py                 # list all scenarios
docker exec treadstone-log-generator python3 fire_scenario.py kerberoast      # fire one (partial name OK)
docker exec treadstone-log-generator python3 fire_scenario.py all            # fire every scenario once
```

See [TREADSTONE_DETECTIONS.md](TREADSTONE_DETECTIONS.md) for the full PowerQuery detection library and the scenario → detection mapping table.

---

## Ports

| Service | Port | Purpose |
|---|---|---|
| `foundstone` | 8080 → 8000 | Web UI / API |
| `syslog-ng` | 514/udp, 601/tcp | Treadstone Log Simulator ingest |

Change in `docker-compose.yml`.

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
    rule_parser.py         # pair_list → minimal field overlay
    event_builder.py       # Deep-merge overlay onto real template
    ingester.py            # SDL addEvents
    verifier.py            # Query alert dataset, match rule names (PowerQuery via /api/powerQuery)
    runner.py              # Full pipeline orchestrator
    template_fetcher.py    # SDL V1 query for real event templates
    db.py                  # SQLite — environments + deployed rule names
  ui/                     # React + Vite + Tailwind frontend
  Dockerfile              # Multi-stage: Node builds UI, Python serves it
  docker-compose.yml

log-generator/            # Treadstone Log Simulator — synthetic event generator
  generate_logs.py         # Ambient generators + 35 scripted scenarios
  fire_scenario.py         # CLI to fire scenarios on demand
  preview.py

syslog-ng/                 # Receives generator output, forwards to DataPipeline via HEC
  syslog-ng.conf

datapipeline/               # DataPipeline pipeline processor stage
  parse_json_by_msgid.lua   # Per-source JSON parsing/field-promotion Lua stage
  test_parse_json_by_msgid.lua  # Local verification harness

TREADSTONE_DETECTIONS.md   # PowerQuery detection library + scenario mapping
TREADSTONE_PIPELINE.md     # DataPipeline integration notes (hard-won)
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
