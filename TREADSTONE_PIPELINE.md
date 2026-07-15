# DataPipeline Integration Notes

Hard-won rules for how this simulator's events flow into SentinelOne DataPipeline
and the Singularity Data Lake. Read this before rebuilding the DataPipeline
pipeline — most of these were discovered the hard way.

**This covers every source except SentinelOne EDR** (`msgid = S1EDR`), which
deliberately bypasses DataPipeline entirely — see
[SentinelOne EDR: direct-to-SDL, not DataPipeline](#sentinelone-edr-direct-to-sdl-not-datapipeline)
at the bottom.

## Flow

```
log-generator ──RFC 5424 / RFC 6587 octet-counting──▶ syslog-ng ──HEC (one POST/event)──▶ DataPipeline ──▶ SDL
```

## What syslog-ng sends (HEC body)

A minimal HEC envelope per event (see [`syslog-ng/syslog-ng.conf`](syslog-ng/syslog-ng.conf)):

```json
{ "time": <epoch>, "host": "...", "event": "<raw log line>",
  "fields": { "sourcetype": "...", "datasource": "...", "msgid": "...",
              "agent": "...", "tags": "...", "syslog_severity": "...", "syslog_facility": "..." } }
```

`event` is the raw log line — **plain text** for most sources, a **JSON string**
for the JSON sources (Duo / Abnormal email / Windows).

## How DataPipeline reshapes it (verified on the wire)

- `fields.*` are **flattened to top-level** fields: `msgid`, `datasource`, `sourcetype`, `agent`, `tags`, `syslog_severity`, `syslog_facility`.
- `event` → **`message`**.
- `time` → normalized into the canonical **`timestamp`** (this is the field "rewrite" you see in the pipeline UI — expected, not a bug).

**`msgid` is the routing key.** It's set explicitly per source and survives intact, so use it to scope everything (queries *and* pipeline conditionals):

| `msgid` | source | `message` is |
|---|---|---|
| `DUO`, `EMAIL`, `WINEVENT`, `CLOUDTRAIL` | Cisco Duo, Abnormal email, Windows Security, AWS CloudTrail | **JSON** |
| `ASA302013`/`…`/`ASA400`, `SSHD`, `SUDO`, `PAM`, `HTTP`, `CRON`, `AUDIT`, `DNS`, `DBAUDIT`, `PROXY` | everything else | **plain text** |

## Pipeline requirements (DataPipeline side)

### 1. Keep `message` — don't drop it
The text sources carry all their content in `message`. Dropping it empties them in
SDL (and the message-based detections stop working). Keep `message` for every source.

### 2. Gate parse-json — don't run it on text sources
A parse-json applied to the whole feed throws
`unable to parse json: expected value at line 1 column 1` on every text source
(their `message` starts with `%ASA-…`, `client @…`, etc., not `{`). Run it **only** on JSON:

```
parse_json(message)  WHEN  msgid in ('DUO','EMAIL','WINEVENT','CLOUDTRAIL')
# or, source-agnostic (auto-handles future JSON sources):
parse_json(message)  WHEN  message starts_with '{'
```

### 3. Avoid root-merge field collisions
DataPipeline merges the parsed JSON onto the document root, so any JSON key that
matches an envelope/reserved key collides (type conflicts, duplicate keys).

- Reserved/envelope keys to avoid in any JSON payload root: `timestamp`, `time`, `host`, `message`, `datasource`, `msgid`, `sourcetype`, `tags`, `agent`, `syslog_facility`, `syslog_severity`, `dataPipeline`.
- Already handled in the generator: Duo's native epoch field was renamed `timestamp` → **`auth_timestamp`** to dodge the `timestamp` collision. Email and Windows payloads are already collision-free.
- If you prefer, parse JSON into a **single shared subtree** (e.g. `event`) instead of root — one uniform rule, no per-source branching, and collisions become impossible (`event.timestamp` ≠ envelope `timestamp`). Detections would then use `event.result`, `event.EventID`, etc.

## What the repo already handles (syslog-ng side — don't re-fix these)

- **Newline-delimited HEC:** the `http()` `body()` ends with `\n` so batched records never concatenate/merge.
- **No batch coalescing:** `batch-lines(1)` — one event per POST, so every syslog line is a distinct DataPipeline event. (Raise to `batch-lines(10–20)` only if you need very high sustained EPS; safe now that the `\n` delimiter is in place.)
- **Octet-counting framing:** generator → syslog-ng uses RFC 6587 octet counts with **no trailing delimiter** (a trailing `\n` desyncs the strict `syslog()` source).
- **Reliability:** 256 MB disk-buffer + retries absorb DataPipeline outages.

## Identity correlation

For cross-source identity joins (e.g. phish → suspicious auth), the canonical identity is
`<name>@cia.gov`: Duo `email`, Abnormal `recipientAddress`, and Windows `TargetUserName`
all align on it. Duo's `user.name` retains the **cover identity** (alias) for flavor —
don't join on it.

## SentinelOne EDR: direct-to-SDL, not DataPipeline

```
log-generator ──POST /api/addEvents (SDL_WRITE_TOKEN)──▶ SDL   (no syslog-ng, no DataPipeline)
```

Real SentinelOne EDR telemetry never flows through a customer's DataPipeline
HEC pipeline — the agent reports straight to the S1 backend and into SDL.
DataPipeline HEC is for *third-party* log sources (AWS, Okta, Duo, etc.), not
native agent telemetry. Modeling EDR events the same way would be both less
realistic and would require console-side Lua maintenance every time a new
`event.type` gets added.

So `msgid = S1EDR` events skip `syslog-ng`/DataPipeline entirely:
`generate_logs.py`'s `_edr_line()` flattens the nested event dict into SDL's
dotted-key `attrs` shape (`_flatten()` — same shape FoundStone's own
`ingester.py` uses, e.g. `tgt.process.cmdline`) and POSTs directly to
`{SDL_BASE_URL}/api/addEvents` using `SDL_WRITE_TOKEN` — the same credential
already configured for FoundStone itself (see `docker-compose.yml`'s
`log-generator` service). No console pipeline changes needed when adding new
EDR event types.

Because there's no envelope/root-merge step for these events, the field
collision rules above don't apply to EDR — whatever key names appear in
`generate_logs.py`'s `_edr_event()` builder are exactly what lands in SDL.

## See also

- [`DETECTIONS.md`](DETECTIONS.md) — PowerQuery detections, scoped by `msgid`.
- [`syslog-ng/syslog-ng.conf`](syslog-ng/syslog-ng.conf) — the forwarder config (sourcetype mapping, HEC destination). Not used by `S1EDR`.
