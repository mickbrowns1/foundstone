-- DataPipeline pipeline processor stage (NOT a source collector).
--
-- Fixes the gap documented in TREADSTONE_PIPELINE.md: the console's built-in
-- parse-json step has no per-source gating, so running it on every event
-- throws "unable to parse json: expected value at line 1 column 1" on the
-- text sources (ASA*, DNS, SSHD, SUDO, PAM, HTTP, CRON, AUDIT, DBAUDIT,
-- PROXY) whose message is plain text, not JSON.
--
-- This stage only parses `message` when `msgid` is one of the JSON sources
-- (DUO, EMAIL, WINEVENT, CLOUDTRAIL) and promotes the decoded keys to
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
local JSON_MSGIDS = { DUO = true, EMAIL = true, WINEVENT = true, CLOUDTRAIL = true }

-- Envelope/reserved keys DataPipeline already owns at the document root.
-- A decoded key that collides with one of these is kept under jsonkeyed
-- instead of overwriting the envelope field, per TREADSTONE_PIPELINE.md's
-- "Avoid root-merge field collisions" section.
local RESERVED_KEYS = {
    timestamp = true, time = true, host = true, message = true,
    datasource = true, msgid = true, sourcetype = true, tags = true,
    agent = true, syslog_facility = true, syslog_severity = true,
    dataPipeline = true,
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
