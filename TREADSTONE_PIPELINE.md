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
for the JSON sources (Duo, Mimecast, Windows, CloudTrail, Zscaler, Palo Alto).

## How DataPipeline reshapes it (verified on the wire)

- `fields.*` are **flattened to top-level** fields: `msgid`, `datasource`, `sourcetype`, `agent`, `tags`, `syslog_severity`, `syslog_facility`.
- `event` → **`message`**.
- `time` → normalized into the canonical **`timestamp`** (this is the field "rewrite" you see in the pipeline UI — expected, not a bug).

**`msgid` is the routing key.** It's set explicitly per source and survives intact, so use it to scope everything (queries *and* pipeline conditionals):

| `msgid` | source | `message` is |
|---|---|---|
| `DUO`, `EMAIL`, `WINEVENT`, `CLOUDTRAIL`, `PROXY`, `PANW` | Cisco Duo, Mimecast, Windows Security, AWS CloudTrail, Zscaler Internet Access, Palo Alto Networks Firewall | **JSON** |
| `SSHD`, `SUDO`, `PAM`, `HTTP`, `CRON`, `AUDIT`, `DNS`, `DBAUDIT` | everything else | **plain text** |

## Pipeline requirements (DataPipeline side)

### 1. Keep `message` — don't drop it
The text sources carry all their content in `message`. Dropping it empties them in
SDL (and the message-based detections stop working). Keep `message` for every source.

### 2. Gate parse-json — don't run it on text sources
A parse-json applied to the whole feed throws
`unable to parse json: expected value at line 1 column 1` on every text source
(their `message` starts with `client @…`, `Accepted publickey…`, etc., not `{`). Run it **only** on JSON:

```
parse_json(message)  WHEN  msgid in ('DUO','EMAIL','WINEVENT','CLOUDTRAIL','PROXY','PANW')
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

## dataSource.name / dataSource.category tagging

Every source gets `dataSource.name` (grounded in this tenant's own deployed
rule library where a real value exists -- see `data/extracted.json`) and
`dataSource.category = "security"` (not used by any deployed rule as a
filter, but drives SDL's own data-view bucketing).

This is applied **centrally in the Lua processor stage**
(`datapipeline/parse_json_by_msgid.lua`'s `DATASOURCE_BY_MSGID` lookup),
not in the Python generator, and applies to *every* msgid -- JSON or plain
text -- before the JSON-only gating happens. This was a deliberate choice
over setting it via syslog-ng's `fields.*` HEC mechanism: that would create
the field at the envelope level for every event (including JSON ones,
which build their own nested `dataSource` structure via `parse_json`),
risking a duplicate/conflicting `dataSource.name` value between the
envelope and the parsed JSON. Centralizing it in the one Lua stage that
already runs last avoids that risk entirely, and means adding a new source
only requires one line in `DATASOURCE_BY_MSGID`.

SentinelOne EDR is the exception (see below) -- it sets `dataSource`
directly in the Python event builder, since it bypasses this Lua stage
(and DataPipeline) entirely.

| `msgid` | `dataSource.name` | Real rule match? |
|---|---|---|
| `S1EDR` | `SentinelOne` | Yes (973 rules) -- name and field shape both match |
| `CLOUDTRAIL` | `CloudTrail` | Yes (435 rules) -- name and field shape both match |
| `WINEVENT` | `Windows Event Logs` | Yes (59 rules) -- name and field shape both match (nested `winEventLog.*`) |
| `DUO` | `Cisco Duo` | Yes (24 rules) -- name and field shape both match (`status`/`status_detail`/`unmapped.*`) |
| `PANW` | `Palo Alto Networks Firewall` | Yes (16 rules) -- name and field shape both match (`metadata.log_name`, `unmapped.*`) |
| `PROXY` | `Zscaler Internet Access` | Yes (49 rules) -- name and field shape both match |
| `EMAIL` | `Mimecast` | Yes (15 rules) -- name and field shape both match |
| `SSHD`, `SUDO`, `PAM`, `CRON`, `AUDIT` | `Linux Audit` | No real match in this tenant's library -- invented |
| `HTTP` | `Apache HTTP Server` | No real match -- invented |
| `DNS` | `ISC BIND` | No real match -- invented |
| `DBAUDIT` | `PostgreSQL` | No real match -- invented |

`PANW` replaced the earlier `ASA*`-prefixed Cisco ASA/FTD text events: this
tenant's real 26 Cisco Firewall Threat Defense rules turned out to expect
Cisco's actual FTD "Security Event" schema (`event.type` in `Intrusion
event`/`File events`/`Open`, `unmapped.SID`/`ApplicationProtocol`/`FileType`/...)
-- not classic `%ASA-6-302013` syslog text, which none of those rules could
ever match. Palo Alto Networks Firewall was substituted instead (16 real
deployed rules, well-documented public PAN-OS syslog field reference).

## Text-source field extraction (pipeline-side parsing)

The 8 plain-text sources (`SSHD`, `SUDO`, `PAM`, `HTTP`, `CRON`, `AUDIT`,
`DNS`, `DBAUDIT`) used to require a PowerQuery `parse '...' from message`
clause in every detection that needed a structured field out of them (see
A2/A3/A5's history in `TREADSTONE_DETECTIONS.md`) -- fine for a one-off hunt,
but it means re-deriving the same parse logic in every query, and paying that
parse cost on every query execution instead of once at ingest.

`parse_json_by_msgid.lua` now parses these too, right alongside its existing
JSON-decode path: each text `msgid` has a dedicated Lua pattern-match function
(`parseSSHD`, `parseSUDO`, `parsePAM`, `parseHTTP`, `parseCRON`, `parseAUDIT`,
`parseDNS`, `parseDBAUDIT`) that extracts the fields generate_logs.py actually
emits and attaches them as a **namespaced field table** on the event --
`dns.qname`, `dbaudit.rows`, `sshd.sourceIp`, etc. -- rather than merging at
root (avoids collision risk and keeps each source's fields visually grouped).
`message` is left intact either way, so raw-text fallback queries (and any
in-flight hunts using the old `parse` style) still work.

If a message doesn't match its parser's expected pattern, the parser returns
nil and the event just doesn't get that field table -- no crash, no dropped
event, same posture as a JSON decode failure.

| `msgid` | Namespaced fields | Real format modeled |
|---|---|---|
| `SSHD` | `sshd.result`, `.method`, `.user`, `.sourceIp`, `.port`, `.invalidUser` | genuine OpenSSH auth log |
| `SUDO` | `sudo.user`, `.tty`, `.pwd`, `.runAsUser`, `.command` | genuine sudo log |
| `PAM` | `pam.service`, `.action`, `.user` | genuine PAM session log |
| `HTTP` | `http.clientIp`, `.user`, `.method`, `.path`, `.status`, `.bytes`, `.userAgent` | genuine Apache Combined Log Format |
| `CRON` | `cron.user`, `.command` | genuine cron syslog line |
| `AUDIT` | `audit.srcIp`, `.dstIp`, `.proto`, `.srcPort`, `.dstPort` | UFW/netfilter kernel log (not true auditd -- see the `Linux Audit` naming note above) |
| `DNS` | `dns.clientIp`, `.qname`, `.qtype`, `.resolver`, `.port` | genuine ISC BIND querylog |
| `DBAUDIT` | `dbaudit.user`, `.db`, `.class`, `.command`, `.table`, `.statement`, `.rows`, `.sessionId` | genuine pgAudit log line |

## Identity correlation

For cross-source identity joins (e.g. phish → suspicious auth), the canonical identity is
`<name>@cia.gov`: Duo `email`, Mimecast `email.to`, and Windows
`winEventLog.data.event.eventData.targetUserName` all align on it. Duo's `user.name`
retains the **cover identity** (alias) for flavor — don't join on it.

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

- [`TREADSTONE_DETECTIONS.md`](TREADSTONE_DETECTIONS.md) — PowerQuery detections, scoped by `msgid`.
- [`syslog-ng/syslog-ng.conf`](syslog-ng/syslog-ng.conf) — the forwarder config (sourcetype mapping, HEC destination). Not used by `S1EDR`.
