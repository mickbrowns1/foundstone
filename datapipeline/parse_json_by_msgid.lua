-- DataPipeline pipeline processor stage (NOT a source collector).
--
-- Fixes the gap documented in TREADSTONE_PIPELINE.md: the console's built-in
-- parse-json step has no per-source gating, so running it on every event
-- throws "unable to parse json: expected value at line 1 column 1" on the
-- text sources (ASA*, DNS, SSHD, SUDO, PAM, HTTP, CRON, AUDIT, DBAUDIT,
-- PROXY) whose message is plain text, not JSON.
--
-- This stage only parses `message` when `msgid` is one of the JSON sources
-- (DUO, EMAIL, WINEVENT, CLOUDTRAIL, PROXY) and promotes the decoded keys to
-- top-level fields so TREADSTONE_DETECTIONS.md queries (EventID,
-- TargetUserName, result, userIdentity.type, ...) work without the
-- raw-message fallback syntax. Every other event passes through unchanged.
--
-- Entry point contract: one record in, one record out (same shape as the
-- OCSF serializer stage in the dpm-lua-creation skill's ocsf_serializer.lua
-- template) -- just without the OCSF remapping.

local json = require('json')
local log = require('log')

-- msgid values whose message field is a JSON string, per TREADSTONE_PIPELINE.md.
-- (SentinelOne EDR events never reach this pipeline at all -- they're ingested
-- directly into SDL, bypassing DataPipeline entirely. See TREADSTONE_PIPELINE.md.)
local JSON_MSGIDS = { DUO = true, EMAIL = true, WINEVENT = true, CLOUDTRAIL = true, PROXY = true }

-- Real dataSource.name values, grounded in this tenant's own deployed rule
-- library (data/extracted.json) where a real match exists; otherwise a
-- reasonable invented name. Applied centrally here (not in the Python
-- generator) so every source -- JSON or plain-text -- gets a consistent
-- dataSource.name/category without any risk of an envelope-level field
-- colliding with the JSON-decoded one. dataSource.category isn't filtered by
-- any deployed rule, but drives SDL's own data-view bucketing.
local DATASOURCE_BY_MSGID = {
    SSHD = "Linux Audit", SUDO = "Linux Audit", PAM = "Linux Audit",
    CRON = "Linux Audit", AUDIT = "Linux Audit",
    HTTP = "Apache HTTP Server", DNS = "ISC BIND", DBAUDIT = "PostgreSQL",
    PROXY = "Zscaler Internet Access", DUO = "Cisco Duo",
    EMAIL = "Mimecast", WINEVENT = "Windows Event Logs", CLOUDTRAIL = "CloudTrail",
}

local function resolveDatasourceName(msgid)
    if type(msgid) ~= "string" then return nil end
    if DATASOURCE_BY_MSGID[msgid] then return DATASOURCE_BY_MSGID[msgid] end
    if msgid:sub(1, 3) == "ASA" then return "Cisco Firewall Threat Defense" end
    return nil
end

-- Envelope/reserved keys DataPipeline already owns at the document root.
-- A decoded key that collides with one of these is kept under jsonkeyed
-- instead of overwriting the envelope field, per TREADSTONE_PIPELINE.md's
-- "Avoid root-merge field collisions" section.
local RESERVED_KEYS = {
    timestamp = true, time = true, host = true, message = true,
    datasource = true, msgid = true, sourcetype = true, tags = true,
    agent = true, syslog_facility = true, syslog_severity = true,
    dataPipeline = true,
    -- "event" is the original HEC body field name (pre-rename to "message")
    -- -- confirmed live: a top-level {"event": {...}} object in a JSON
    -- payload gets silently dropped rather than promoted. Sources needing a
    -- real event.type field should emit it as a flat "event.type" string key
    -- instead of nesting it (see generate_logs.py's _mimecast_event).
    event = true,
}

-- JSON null decodes to a non-nil userdata sentinel in this runtime; strip it
-- recursively so downstream field access sees plain nil instead of userdata.
local function stripNulls(value)
    if type(value) ~= "table" then
        if type(value) == "userdata" then return nil end
        return value
    end
    local cleaned = {}
    for k, v in pairs(value) do
        local cv = stripNulls(v)
        if cv ~= nil then cleaned[k] = cv end
    end
    return cleaned
end

-- Entry point: one record in, one record out.
function processEvent(event)
    if event == nil then return {} end

    local dsName = resolveDatasourceName(event.msgid)
    if dsName then
        event.dataSource = { name = dsName, category = "security" }
    end

    if not JSON_MSGIDS[event.msgid] then
        return event
    end
    if type(event.message) ~= "string" or event.message == "" then
        return event
    end

    local ok, decoded = pcall(json.decode, event.message)
    if not ok or type(decoded) ~= "table" then
        log.warn("parse_json_by_msgid: could not decode message for msgid=" .. tostring(event.msgid))
        return event
    end
    decoded = stripNulls(decoded)

    for key, value in pairs(decoded) do
        if RESERVED_KEYS[key] then
            event["json" .. key] = value
        else
            event[key] = value
        end
    end

    return event
end
