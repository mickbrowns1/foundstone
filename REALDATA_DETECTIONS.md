# FoundStone — Generating Real-Data-Grounded Detection Test Logs

**Goal:** for each detection rule, produce a synthetic log that will *fire that rule* by starting from a **genuine ingested event** and overwriting **only the field values the detection requires** — leaving every other field as real logged data.

This is the method used to validate the Okta library (41/42 rules fired on real data). It generalizes to any source for which you have (a) real sample events and (b) the rule definitions.

---

## Inputs FoundStone needs

1. **Rule definitions** — the detection library with each rule's *streaming filter logic*. Source: `detections.json` (a.k.a. `extracted.json`). Each rule has `name`, `file`, `description`, `queries[].query`, and a parsed `pair_list` (`{key, op, value}`).
2. **Real event templates** — a handful of genuine ingested events for the target `dataSource.name`, pulled live from the data lake (SDL V1 query, token in body):
   ```
   POST {SDL_XDR_URL}/api/query
   { "token": "<log-read-key>", "queryType": "log",
     "filter": "dataSource.name == '<Source>'", "startTime": <ms>, "endTime": <ms>, "maxCount": 20 }
   ```
   Each match's `attributes` is the flat, dotted-key event (e.g. `unmapped.eventType`, `actor.user.name`). Keep several for variety.
3. **Write access** to ingest the result (SDL `addEvents`, Log Write key) — only against a POC/demo tenant.

---

## The core principle

> **Change only what the detection reads. Keep everything else real.**

A rule fires on a small set of fields. Compute that minimal set from the rule's filter, overlay it onto a real event, and the synthetic log is indistinguishable from genuine traffic except for the few values that trigger the detection.

---

## Algorithm (per rule)

### 1. Parse the streaming filter
Use only the portion **before the first `|`** (the streaming filter). The pipeline (`| group`, `| filter count > N`, `| let`) is aggregation, handled in step 5 — it does not describe per-event fields.

### 2. Compute the minimal satisfying value for each non-negated clause

| Clause | What to set |
|---|---|
| `field = 'X'` / `field == 'X'` | `field = X` |
| `field in ('A','B')` | `field = A` (any one member) |
| `field contains 'X'` | any value **containing** `X` (e.g. `X` itself) |
| `field matches '<regex>'` | a string that **matches** the regex (walk the regex AST; honor anchors like `\.exe$` and literal backslashes in Windows paths) |
| `field in:anycase ('X')` | `field = X` (case-insensitive target) |
| `field != 'X'` | any value **other than** `X` (field must be **present**) |
| `field > N` / `>=` | `N+1` / `N` |
| `field < N` / `<=` | `N-1` / `N` |
| `field[0].sub = 'X'` | build a real array: `field = [ { sub: X } ]` |
| same field, multiple clauses | combine into one value satisfying **all** (e.g. `contains '.zip'` **and** `contains '.bat'` → `".bat.zip"`) |

### 3. Handle negation correctly — this is the subtle part
- `field != 'X'` → field **present**, value ≠ X. (A *missing* field does **not** satisfy `!= 'X'`.)
- `not (field = *)` / `not (field contains 'X')` → field must be **absent** → do **not** set it.
- A field that is **both** required and partially negated (e.g. `cmdline contains '.zip' AND not (cmdline contains 'program files')`) → set it to satisfy the positive clause while **avoiding** the negated substring (`".bat.zip"`, never containing `program files`).
- Strip `not (...)` regions first; a clause is "active" only if its field/value appears in the **positive** (negation-stripped) filter.

### 4. Overlay onto a real event (the key step)
- Take one real template event (rotate templates across rules for variety).
- Nest its flat dotted attributes into an object.
- **Deep-merge** the step-2/3 fields on top — rule values win, everything else stays real.
- Report "modified fields" as a **true diff** vs the template (so a clause like `dataSource.name = 'Okta'` on an already-Okta event shows as *no change*, not a modification).

### 5. Adjust for the rule class (from the rule's `file` path / name)

| Class | How to detect | Adjustment |
|---|---|---|
| **Volume / aggregation** | `| group … count() > N`, or name has "multiple/bulk/excessive…", or `/correlation/` path | Replicate **N+2** copies; stamp a **shared group-by entity** (same `actor.user.*` / host / IP across copies) so the count closes |
| **Distinct-count** | `estimate_distinct(field) > N` / `array_agg_distinct(field)` | Replicate; iterate the **counted field** to **N distinct values** (keep any required prefix so it still matches the filter) |
| **Correlation / multi-stage** | `len(queries) > 1`, `/correlation/` | One event **per stage**; stamp the **same join entity** across stages; give later stages **newer timestamps** so "A followed by B" sequences resolve |
| **First-seen (anomaly)** | `/first_seen/` | Stamp a **unique-per-send novel entity** (and append a novel token to `contains`-matched fields) so the event is genuinely "new" |
| **Scheduled** | `/rules/scheduled/` | Spread copy timestamps across the rule's window (e.g. 24h); will fire on the next cron, not instantly |

### 6. Ingest
Send the resulting event(s) via SDL `addEvents` through your parser (gron-style flatten). Tag them (e.g. `parallax_test_log: true`) so they're easy to find/clean up.

### 7. Verify
Read the `alert` dataset back over a lookback window:
```
dataSource.name='alert' | filter finding_info.title != '' | group n=count() by finding_info.title
```
Match `finding_info.title` to the rule `name` (strip console decorations like a trailing ` - OOTB`). A rule is **fired** when its alert count > 0.

---

## Worked example (Okta)

**Rule:** `Okta Access to Admin App Failed`
**Logic:** `dataSource.name = 'Okta' and (unmapped.eventType contains 'user.session.access_admin_app' or unmapped.legacyEventType contains 'user.session.access_admin_app') and status = 'FAILURE'`

**Minimal fields to set:** `unmapped.eventType = user.session.access_admin_app`, `status = FAILURE` (`dataSource.name` is already `Okta` in the template → no change).

**Result:** a real Okta event (genuine `actor`, `client.geographicalContext`, `userAgent`, `authenticationContext`, `src_endpoint`, `metadata`) with just those two fields overwritten. Fires the rule; looks like real traffic.

---

## Output FoundStone should emit

For each rule, emit:
- `rule_name`
- `modified_fields` — the true diff vs the real template (field → value)
- `event` — the full synthetic event (real template + overlay)
- `class` and `copies` (for volume/correlation/first-seen)

Plus a verification summary: `fired / total` and per-rule alert counts.

---

## Notes & guardrails

- **Real field schema is the contract.** Discover it per source via the V1 query (returns full `attributes`); rule logic keys on those exact paths (`unmapped.eventType`, not a guessed field).
- Some fields the rule references are produced by an enrichment pipeline, not raw events — those can't be faked; flag them.
- `detections.json` is **proprietary** (un-redacted rule logic, including console "Logic Hidden" rules). Keep it gitignored; never commit it.
- Only ingest against POC/demo tenants, via an explicit, user-initiated action.
