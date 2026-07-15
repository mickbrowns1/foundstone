# Treadstone Detections — SentinelOne PowerQuery

Detections for the simulator scenarios. **Scope every query by `msgid`** (the
in-band router that survives DataPipeline on every event, text or JSON), then:
- **JSON sources** (Duo/Email/Windows) → query the **expanded fields**
- **Text sources** (ASA/DNS/pgAudit/Squid/…) → match/`parse` the raw **`message`**

## Field reference

DataPipeline expands the JSON sources' keys to top-level fields (confirmed from a
live Duo event); Email and Windows expand the same way. Text sources keep the raw
line in `message`.

| Source (`msgid`) | Fields you query |
|---|---|
| `DUO` | `result`, `reason`, `factor`, `email`, `user.name`, `access_device.ip`, `access_device.location.country`, `auth_device.ip`, `application.name` |
| `EMAIL` (Mimecast) | `direction`, `status_detail`, `actor.invoked_by`, `event.type`, `email.from`, `email.to`, `email.subject`, `unmapped.category`, `unmapped.action`, `unmapped.taggedMalicious`, `file.type`, `file.name` |
| `WINEVENT` | `EventID`, `TicketEncryptionType`, `TargetUserName`, `ServiceName`, `IpAddress`, `LogonType`, `CommandLine`, `SubjectUserName`, `Computer` |
| `CLOUDTRAIL` | `eventName`, `eventSource`, `sourceIPAddress`, `recipientAccountId`, `errorCode`, `userIdentity.type`, `userIdentity.arn`, `userIdentity.sessionContext.attributes.mfaAuthenticated`, `requestParameters.*` |
| `PROXY` (Zscaler) | `action`, `app_name`, `risk_details`, `http_request.url.hostname`, `http_request.url.categories`, `malware.name`, `unmapped.event.threatcat` |
| `S1EDR` | `event.type`, `endpoint.os`, `endpoint.name`, `tgt.process.cmdline`, `tgt.process.name`, `src.process.cmdline`, `src.process.parent.name`, `tgt.file.path`, `registry.keyPath`, `task.path`, `module.path`, `cmdScript.content`, `event.dns.request`, `indicator.name` |
| text (`ASA*`,`DNS`,`DBAUDIT`,`SSHD`,`SUDO`,`PAM`,`HTTP`,`CRON`,`AUDIT`) | raw line in `message` |
| every source | `dataSource.name`, `dataSource.category` — see `TREADSTONE_PIPELINE.md`'s tagging table |

> **If a JSON-source query returns zero, it's one of two things:**
> 1. **`EventID` typed as a string** → change `EventID = 4769` to `EventID = '4769'`. (Probe: `msgid='WINEVENT' | group n=count() by EventID`.)
> 2. **Keys nested under a prefix** (e.g. `event.result` not `result`) → prefix the field paths. (Probe: `msgid='DUO' | group n=count() by result`.)
>
> Both are also dodgeable entirely by matching the kept raw `message`, e.g.
> `msgid='WINEVENT' | filter message contains '"EventID":4769'` — works regardless of parsed type.

---

## A. Technique detections

### A1 — Spearphish: malicious inbound email delivered without being blocked  ·  T1566
> `unmapped.action` always has a concrete value in this simulator (`none` vs
> `hold`/`block`/`bounce`), never omitted, so "not blocked" is a clean filter
> rather than a check for field absence.
```
msgid = 'EMAIL' direction = 'inbound' status_detail = 'malicious' unmapped.action contains 'none'
| group threats=count(),
        categories=array_agg_distinct(unmapped.category, 5),
        senders=array_agg_distinct(email.from, 5)
  by email.to
| sort -threats
```

### A1b — Internal impersonation email not blocked  ·  T1656
```
msgid = 'EMAIL' event.type = 'TTP Impersonation Protection' unmapped.taggedMalicious = true unmapped.action contains 'none'
| group hits=count() by email.from, email.to
| sort -hits
```

### A2 — DNS beaconing to a C2 / dead-drop domain  ·  T1071.004  *(text → message)*
> `parse` treats its literals as regex, so we anchor on paren-free landmarks
> (`#` and ` query: … IN`) instead of the `(qname)` parens.
```
msgid = 'DNS'
| filter message contains ('beacon.', 'c2.', 'deaddrop', 'sigint-cache', 'exfil-relay')
| parse 'client @$cid$ $client_ip$#' from message
| parse 'query: $qname$ IN' from message
| group queries=count() by client_ip, qname
| filter queries >= 3
| sort -queries
```

### A3 — DNS tunneling exfiltration (long high-entropy labels)  ·  T1048.003  *(text)*
```
msgid = 'DNS'
| parse 'client @$cid$ $client_ip$#' from message
| parse 'query: $qname$ IN $qtype$' from message
| filter qname matches '[a-z2-7]{20,}\\.[a-z2-7]{6,}\\.exfil'
| group lookups=count(), sample=any(qname) by client_ip
| sort -lookups
```

### A4 — Kerberoasting (RC4 service ticket)  ·  T1558.003
```
msgid = 'WINEVENT' EventID = 4769 TicketEncryptionType = '0x17'
| group tickets=count(), services=array_agg_distinct(ServiceName, 10) by TargetUserName
| sort -tickets
```

### A5 — Mass database extraction  ·  T1213  *(text → message)*
```
msgid = 'DBAUDIT'
| filter message contains ',SELECT,' && message matches 'rows=[0-9]{4,}'
| parse '$dbuser$@$db$ LOG:' from message
| parse ',TABLE,$obj$,' from message
| group big_reads=count(), tables=array_agg_distinct(obj, 10) by dbuser
| sort -big_reads
```

### A6a — Password spray (one source IP, many accounts failing)  ·  T1110.003
```
msgid = 'WINEVENT' EventID = 4625
| group fails=count() by IpAddress, TargetUserName
| group distinct_users=count(), total_fails=sum(fails) by IpAddress
| filter distinct_users >= 3
| sort -total_fails
```

### A6b — Credential dumping (mimikatz)  ·  T1003
```
msgid = 'WINEVENT' EventID = 4688
| filter CommandLine contains 'mimikatz' || CommandLine contains 'sekurlsa'
| group hits=count(), commands=array_agg_distinct(CommandLine, 5) by Computer, SubjectUserName
| sort -hits
```

---

## B. Cross-source correlations

### B1 — Impossible travel: one identity, successful MFA from 2+ countries  ·  T1078
```
msgid = 'DUO' result = 'success'
| group logins=count() by email, country=access_device.location.country
| group distinct_countries=count(), countries=array_agg_distinct(country, 10) by email
| filter distinct_countries >= 2
| sort -distinct_countries
```

### B2 — Phish → suspicious auth (same mailbox)  ·  T1566 → T1078
> Joins on `email`. Works now that Duo's `email` is the canonical corporate
> identity (matches Mimecast `email.to`).
```
| join
    (msgid = 'EMAIL'
       | group 1 by email=email.to),
    (msgid = 'DUO'
       | filter result = 'fraud' || reason = 'anomalous_push'
       | group bad_auths=count() by email)
  on email
```

### B3 — Beacon + fraud from the same foreign IP
```
| join
    (msgid contains 'ASA'
       | filter message contains 'Treadstone Asset Beacon Detected'
       | parse 'Detected from $ip$ to' from message
       | group beacons=count() by ip),
    (msgid = 'DUO' result = 'fraud'
       | group frauds=count() by ip=access_device.ip)
  on ip
```

### B4 — Exfil chain: large DB read → large outbound proxy transfer  ·  T1213 → T1041
> `bytes` is a real numeric field on the Zscaler event (not a string to regex-match),
> so this uses a numeric threshold instead of the old digit-count regex.
```
| join
    (msgid = 'DBAUDIT'
       | filter message matches 'rows=[0-9]{4,}'
       | parse '$dbuser$@$db$ LOG:' from message
       | group reads=count() by dbuser),
    (msgid = 'PROXY'
       | filter action = 'Allowed' && bytes >= 1000000
       | group egress=count(), hosts=array_agg_distinct(http_request.url.hostname, 5) by user=user.name)
  on dbuser = user
```

---

## C. Film-scenario signatures  *(text → message)*

### C1 — Blackbriar kill-order C2 channel  (*Waterloo / Paris / Tangier*)
```
msgid contains 'ASA'
| filter message contains 'Blackbriar Kill-Order C2 Channel'
| parse 'Channel from $src$ to $dst$ on' from message
| group hits=count(), dsts=array_agg_distinct(dst, 5) by src
| sort -hits
```

### C2 — Authorize-kill command on a handler workstation
```
msgid = 'SUDO'
| filter message contains 'authorize_kill.py'
| group hits=count(), commands=array_agg_distinct(message, 5) by host
| sort -hits
```

### C3 — Neski files: access, exfil, or destruction  (*Berlin*)
```
message contains 'neski'
| group hits=count(), samples=array_agg_distinct(message, 3) by msgid, host
| sort -hits
```

### C4 — Reykjavik breach / Deep Dream backdoor / Iron Hand  (*Reykjavik / Vegas*)
```
message contains 'Reykjavik Mainframe Breach' || message contains 'Deep Dream Backdoor Callback'
   || message contains 'ironhand/dump' || message contains 'deepdream'
| group hits=count(), samples=array_agg_distinct(message, 3) by msgid, host
| sort -hits
```

---

## D. AWS (CloudTrail) detections

The simulated AWS org is intentionally hardened by default (MFA-enforced
AssumedRole sessions, no long-lived keys, encrypted S3, trusted-IP-only
egress) — see `generate_logs.py`'s `AWS_*` constants. Every query below
should return **zero** hits against ambient traffic; a hit means one of the
two AWS attack scenarios actually fired.

### D1 — Root account usage  ·  T1078.004
```
msgid = 'CLOUDTRAIL' userIdentity.type = 'Root'
| group actions=count(), events=array_agg_distinct(eventName, 10) by recipientAccountId
| sort -actions
```

### D2 — CloudTrail logging disabled or deleted  ·  T1562.008
```
msgid = 'CLOUDTRAIL' (eventName = 'StopLogging' || eventName = 'DeleteTrail' || eventName = 'UpdateTrail')
| group actions=count(), events=array_agg_distinct(eventName, 10) by recipientAccountId, sourceIPAddress
| sort -actions
```

### D3 — IAM privilege escalation via policy attachment  ·  T1098.003
```
msgid = 'CLOUDTRAIL' (eventName = 'AttachUserPolicy' || eventName = 'AttachRolePolicy' || eventName = 'PutRolePolicy' || eventName = 'PutUserPolicy')
| group actions=count(), events=array_agg_distinct(eventName, 10) by userIdentity.arn
| sort -actions
```

### D4 — Console login without MFA  ·  T1078
```
msgid = 'CLOUDTRAIL' eventName = 'ConsoleLogin' userIdentity.sessionContext.attributes.mfaAuthenticated = 'false'
| group logins=count() by userIdentity.arn, sourceIPAddress
| sort -logins
```

---

## E. SentinelOne EDR detections

Field names and the `event.type` set here are grounded directly in this
tenant's own deployed detection library (746 real `SentinelOne`-sourced
rules in `data/extracted.json`) rather than guessed — `event.type` is
overwhelmingly `Process Creation` in practice. Ambient traffic is signed,
known-publisher, ordinary parent/child process trees (see `EDR_BENIGN_PROCS`
in `generate_logs.py`); credential dumping, reverse shells, and persistence
only ever appear in the dedicated EDR scenarios.

Unlike every other source in this simulator, `S1EDR` events bypass
syslog-ng/DataPipeline and are ingested directly into SDL — see
[TREADSTONE_PIPELINE.md](TREADSTONE_PIPELINE.md#sentinelone-edr-direct-to-sdl-not-datapipeline).
No console pipeline changes are needed for these queries to work.

### E1 — Credential dumping via mimikatz  ·  T1003.001
```
dataSource.name = 'SentinelOne' event.type = 'Process Creation' tgt.process.cmdline contains 'sekurlsa::logonpasswords'
| group hits=count(), hosts=array_agg_distinct(endpoint.name, 5) by tgt.process.user
| sort -hits
```

### E2 — Reverse shell via netcat  ·  T1059
```
dataSource.name = 'SentinelOne' event.type = 'Process Creation' tgt.process.name = 'nc' tgt.process.cmdline contains ' -e'
| group hits=count(), targets=array_agg_distinct(tgt.process.cmdline, 5) by endpoint.name
| sort -hits
```

### E3 — Suspicious scheduled task registration  ·  T1053.005
```
dataSource.name = 'SentinelOne' event.type = 'Task Register'
| group hits=count(), tasks=array_agg_distinct(task.path, 5) by src.process.user
| sort -hits
```

### E4 — DNS resolution to known exfil infrastructure (EDR view)  ·  T1071.004
```
dataSource.name = 'SentinelOne' event.type = 'DNS Resolved' event.dns.request contains ('exfil-relay', 'deaddrop', 'sigint-cache', 'beacon.treadstone')
| group hits=count() by endpoint.name, event.dns.request
| sort -hits
```

---

## Promoting to detection rules

To turn a hunt into a STAR / Custom Detection / PowerQuery Alert:
- **Must include a `group` command** — the alert engine thresholds on its count.
  A body that ends in `columns … | limit` (hunt style) is rejected with
  *"This PowerQuery cannot be used in an alert: must include a 'group' command."*
  All detections here now end in `group … | sort`, so they're alert-ready.
- Keep intermediate and output ≤ **1,000 rows / 1 MB**; no `nolimit`, `compare`, `transpose`.
- Emit **one row per finding** with stable columns the engine maps to alert fields
  (e.g. `timestamp`, `host`, and the entity — `email` / `IpAddress` / `dbuser`).
- Keep the initial filter tight (`msgid = '…'` is exactly that) — it gates cost.
- Tune the thresholds (`queries >= 3`, `distinct_users >= 3`, `rows >= 1000`,
  `distinct_countries >= 2`) to your baseline once you see normal volume.

## Firing detections on demand

Ambient scenarios are rare (`SCENARIO_CHANCE=0.02`), so to test/demo a detection
without waiting, fire its scenario straight into syslog-ng:

```bash
docker exec log-generator python3 fire_scenario.py            # list all scenarios
docker exec log-generator python3 fire_scenario.py db_mass_extract 5   # fire 5x
docker exec log-generator python3 fire_scenario.py all        # fire every scenario once
```

Scenario → detection it lights up:

| Fire this scenario | Triggers |
|---|---|
| `phish_landy` | A1 (phish), **B2** (phish→auth) |
| `langley_insider_leak` | **A1b** (internal impersonation not blocked), A5 (DB read ≥1000 rows) |
| `dns_beacon` | **A2** (beaconing) |
| `dns_tunnel_exfil` | **A3** (tunneling), A5 (DB read), **C3** (references `neski_files`) |
| `kerberoast` | **A4** (kerberoasting) |
| `db_mass_extract` | A5 (mass read), **B4** (DB→proxy exfil) |
| `lateral_langley` | **A6a** (spray), **A6b** (mimikatz) |
| `goa_kirill` / `zurich_bank` / `amsterdam_deaddrop` / `vienna_rendezvous` | **B3** (beacon+fraud), C-series |
| `waterloo_ross` / `paris_safehouse` / `petra_handler_betrayal` | **C1/C2** (kill-order C2, authorize-kill) |
| `tangier_desh` | **C1** only (kill-order C2 channel; no `authorize_kill.py` call, so C2 doesn't fire) |
| `berlin_neski` | **C3** (Neski files) |
| `reykjavik_hack` / `vegas_dewey` / `deepdream_cyberops` | **C4** (Reykjavik/Deep Dream) |
| (any with Duo logins across cities) | **B1** (impossible travel) — fire 2+ different-city scenarios |
| `aws_privesc_kublinski` | **D3** (IAM privilege escalation via policy attachment) |
| `aws_defense_evasion_petra` | **D1** (root usage), **D2** (logging disabled), **D4** (console login without MFA) |
| `edr_mimikatz_langley` | **E1** (mimikatz) — EDR companion to `lateral_langley` |
| `edr_reverse_shell_petra` | **E2** (reverse shell) — EDR companion to `petra_handler_betrayal` |
| `edr_task_persistence_mckenna` | **E3** (scheduled task) — EDR companion to `mckenna_awakening` |
| `edr_dns_exfil_neski` | **E4** (DNS exfil) — EDR companion to `dns_tunnel_exfil` |
| `rome_extraction_blown` / `copenhagen_sigint` / `ny_treadstone_induction` / `larx_handoff` / `east_berlin_origin` / `mckenna_awakening` / `seoul_pak_awakening` | story color — no dedicated detection yet (same as `goa_kirill`/`athens_riots`) |

Then run the detection over the last few minutes and confirm the hits.
```
