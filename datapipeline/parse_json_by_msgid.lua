-- DataPipeline pipeline processor stage (NOT a source collector).
--
-- Fixes the gap documented in TREADSTONE_PIPELINE.md: the console's built-in
-- parse-json step has no per-source gating, so running it on every event
-- throws "unable to parse json: expected value at line 1 column 1" on the
-- text sources (DNS, SSHD, SUDO, PAM, HTTP, CRON, AUDIT, DBAUDIT) whose
-- message is plain text, not JSON.
--
-- This stage only parses `message` when `msgid` is one of the JSON sources
-- (DUO, EMAIL, WINEVENT, CLOUDTRAIL, PROXY, PANW) and promotes the decoded keys to
-- top-level fields so TREADSTONE_DETECTIONS.md queries (EventID,
-- TargetUserName, result, userIdentity.type, ...) work without the
-- raw-message fallback syntax. Every other event passes through unchanged.
--
-- The remaining plain-text sources (SSHD, SUDO, PAM, HTTP, CRON, AUDIT, DNS,
-- DBAUDIT) get the same treatment via pattern-matching instead of JSON decode:
-- each one's `message` is parsed into a namespaced field table (e.g.
-- `event.dns.qname`, `event.dbaudit.rows`) so detections query real fields
-- instead of running `parse '...' from message` at query time in SDL --
-- pushing the parsing into the pipeline, where it only happens once per
-- event, rather than on every query. See "Text-source field extraction" below.
--
-- Entry point contract: one record in, one record out (same shape as the
-- OCSF serializer stage in the dpm-lua-creation skill's ocsf_serializer.lua
-- template) -- just without the OCSF remapping.

local json = require('json')
local log = require('log')

-- msgid values whose message field is a JSON string, per TREADSTONE_PIPELINE.md.
-- (SentinelOne EDR events never reach this pipeline at all -- they're ingested
-- directly into SDL, bypassing DataPipeline entirely. See TREADSTONE_PIPELINE.md.)
local JSON_MSGIDS = { DUO = true, EMAIL = true, WINEVENT = true, CLOUDTRAIL = true, PROXY = true, PANW = true }

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
    PANW = "Palo Alto Networks Firewall",
}

local function resolveDatasourceName(msgid)
    if type(msgid) ~= "string" then return nil end
    return DATASOURCE_BY_MSGID[msgid]
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

-- ─── Text-source field extraction ──────────────────────────────────────────
--
-- Each parser takes a raw `message` string and returns a flat field table, or
-- nil if the message doesn't match the expected shape (message stays intact
-- either way -- these never raise on unexpected input). Field names here are
-- what generate_logs.py actually emits (see the docstring above each
-- generator in that file), not a real vendor's parser output -- SSHD/PAM/CRON
-- are genuine OpenSSH/PAM/cron formats already; AUDIT is UFW/netfilter, not
-- true auditd, per TREADSTONE_PIPELINE.md's Linux Audit naming note.

-- NOTE: uses string.match(s, p) (plain function call) everywhere below, NOT
-- s:match(p) (OOP method-call sugar). The two are equivalent in standard Lua,
-- but method-call syntax depends on the string library being wired into the
-- string metatable -- not guaranteed in every embedded/sandboxed Lua runtime.
-- json.decode() above is called the same "plain function" way; this keeps
-- every pattern-matcher on the same, more portable footing.

local function parseSSHD(message)
    local user, ip, port = string.match(message,
        "^Accepted publickey for (%S+) from (%S+) port (%d+) ssh2")
    if user then
        return { result = "accepted", method = "publickey", user = user, sourceIp = ip, port = tonumber(port) }
    end
    user, ip, port = string.match(message,
        "^Failed password for invalid user (%S+) from (%S+) port (%d+) ssh2")
    if user then
        return { result = "failed", method = "password", user = user, sourceIp = ip,
                 port = tonumber(port), invalidUser = true }
    end
    user, ip, port = string.match(message,
        "^Failed password for (%S+) from (%S+) port (%d+) ssh2")
    if user then
        return { result = "failed", method = "password", user = user, sourceIp = ip,
                 port = tonumber(port), invalidUser = false }
    end
    return nil
end

local function parseSUDO(message)
    local user, tty, pwd, runAsUser, command = string.match(message,
        "^(%S+) : TTY=(%S+) ; PWD=(%S+) ; USER=(%S+) ; COMMAND=(.+)$")
    if not user then return nil end
    return { user = user, tty = tty, pwd = pwd, runAsUser = runAsUser, command = command }
end

local function parsePAM(message)
    local service, action, user = string.match(message,
        "^pam_unix%((%a+):session%): session (%a+) for user (%S+) by")
    if not service then return nil end
    return { service = service, action = action, user = user }
end

local function parseHTTP(message)
    -- Avoids %b[] (Lua's "balanced match" extension) -- not guaranteed to be
    -- supported by every embedded Lua sandbox; [^%]]* (plain negated char
    -- class) does the same job of skipping the [timestamp] bracket and is
    -- universally-supported basic pattern syntax.
    local clientIp, user, method, path, status, bytes, userAgent = string.match(message,
        '^(%S+) %S+ (%S+) %[[^%]]*%] "(%S+) (%S+) HTTP/1%.1" (%d+) (%d+) "%-" "(.-)"$')
    if not clientIp then return nil end
    return { clientIp = clientIp, user = user, method = method, path = path,
             status = tonumber(status), bytes = tonumber(bytes), userAgent = userAgent }
end

local function parseCRON(message)
    local user, command = string.match(message, "^(%S+) CMD %((.+)%)$")
    if not user then return nil end
    return { user = user, command = command }
end

local function parseAUDIT(message)
    local srcIp, dstIp, proto, spt, dpt = string.match(message,
        "SRC=(%S+) DST=(%S+).-PROTO=(%S+) SPT=(%d+) DPT=(%d+)")
    if not srcIp then return nil end
    return { srcIp = srcIp, dstIp = dstIp, proto = proto, srcPort = tonumber(spt), dstPort = tonumber(dpt) }
end

local function parseDNS(message)
    local clientIp, port, domain, qtype, resolver = string.match(message,
        "client @%S+ (%S+)#(%d+) %((%S+)%): query: %S+ IN (%S+) %+E%(0%) %((%S+)%)")
    if not clientIp then return nil end
    return { clientIp = clientIp, port = tonumber(port), qname = domain, qtype = qtype, resolver = resolver }
end

local function parseDBAUDIT(message)
    local user, db, sessionId, class, command, tableName, statement, rows = string.match(message,
        '^(%S+)@(%S+) LOG:%s+AUDIT: SESSION,(%d+),%d+,(%a+),(%a+),TABLE,(%S+),"(.-)",<not logged> rows=(%d+)')
    if not user then return nil end
    return { user = user, db = db, sessionId = tonumber(sessionId), class = class, command = command,
             ["table"] = tableName, statement = statement, rows = tonumber(rows) }
end

-- msgid -> (parser function, field name to nest the result under).
local TEXT_PARSERS = {
    SSHD = { fn = parseSSHD, key = "sshd" },
    SUDO = { fn = parseSUDO, key = "sudo" },
    PAM = { fn = parsePAM, key = "pam" },
    HTTP = { fn = parseHTTP, key = "http" },
    CRON = { fn = parseCRON, key = "cron" },
    AUDIT = { fn = parseAUDIT, key = "audit" },
    DNS = { fn = parseDNS, key = "dns" },
    DBAUDIT = { fn = parseDBAUDIT, key = "dbaudit" },
}

-- Entry point: one record in, one record out.
function processEvent(event)
    if event == nil then return {} end

    local dsName = resolveDatasourceName(event.msgid)
    if dsName then
        event.dataSource = { name = dsName, category = "security" }
    end

    if JSON_MSGIDS[event.msgid] then
        if type(event.message) == "string" and event.message ~= "" then
            local ok, decoded = pcall(json.decode, event.message)
            if ok and type(decoded) == "table" then
                decoded = stripNulls(decoded)
                for key, value in pairs(decoded) do
                    if RESERVED_KEYS[key] then
                        event["json" .. key] = value
                    else
                        event[key] = value
                    end
                end
            else
                log.warn("parse_json_by_msgid: could not decode message for msgid=" .. tostring(event.msgid))
            end
        end
        return event
    end

    local parser = TEXT_PARSERS[event.msgid]
    if parser and type(event.message) == "string" then
        local ok, parsed = pcall(parser.fn, event.message)
        if ok and parsed then
            event[parser.key] = parsed
        elseif not ok then
            log.warn("parse_json_by_msgid: text parser error for msgid=" .. tostring(event.msgid)
                      .. ": " .. tostring(parsed))
        end
    end

    return event
end
