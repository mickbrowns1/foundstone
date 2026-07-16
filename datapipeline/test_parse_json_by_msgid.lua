-- Local verification harness (not shipped). Stubs the runtime's `json`/`log`
-- modules and feeds processEvent() realistic DataPipeline-shaped records to
-- confirm: JSON msgids get fields promoted, collisions are preserved under
-- json<key>, nulls are stripped, and non-JSON msgids pass through untouched.

local fixtures = {
    duo_json = '{"status":"denied","status_detail":"locked_out","unmapped":{"event_type":"authentication","factor":"duo_push"},"auth_timestamp":1784140000,"email":"noah.vosen@cia.gov","user":{"name":"n.vosen","key":"DUABC","groups":["BLACKBRIAR"]},"nested":{"drop_me":null}}',
    duo_admin_json = '{"unmapped":{"eventtype":"administrator","action":"admin_login_error","description":"Invalid password attempt"},"user":{"name":"noah.vosen"}}',
    winevent_json = '{"winEventLog":{"channel":"Security","id":4769,"providerName":"Microsoft-Windows-Security-Auditing","description":"A Kerberos service ticket was requested.","data":{"event":{"system":{"eventID":4769,"provider":{"name":"Microsoft-Windows-Security-Auditing"}},"eventData":{"targetUserName":"noah.vosen@CIA.LOCAL","serviceName":"MSSQLSvc/blackbriar-db01","ticketEncryptionType":"0x17","ipAddress":"10.1.0.50"}}}},"Computer":"LANGLEY-DC01.CIA.LOCAL","timestamp":"collision-should-not-clobber-envelope"}',
    cloudtrail_json = '{"eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com","userIdentity":{"type":"Root","arn":"arn:aws:iam::778812340092:root"},"sourceIPAddress":"160.153.0.12","responseElements":null}',
    proxy_json = '{"app_name":"Suspicious Web Activity","action":"Blocked","http_request":{"url":{"hostname":"exfil-relay.example.com","categories":["Suspicious Destinations"]}},"malware":{"name":"cobaltstrike"}}',
    mimecast_json = '{"direction":"outbound","status_detail":"malicious","event.type":"TTP Impersonation Protection","unmapped":{"taggedMalicious":true}}',
    nested_event_json = '{"event":{"type":"should not survive nested"},"foo":"bar"}',
    panw_json = '{"metadata":{"log_name":"THREAT"},"app_name":"tor","action":"allow","src_endpoint":{"ip":"185.220.101.45"},"dst_endpoint":{"ip":"10.0.1.10"},"threat":{"name":"Treadstone Asset Beacon Detected"},"unmapped":{"action":"allow","sub_type":"vulnerability","severity":"critical"}}',
}

-- Minimal fixture-driven decoder: good enough to exercise processEvent's
-- merge/collision/null-strip logic without a general-purpose JSON parser.
local function fake_decode(str)
    if str == fixtures.duo_json then
        return {
            status = "denied", status_detail = "locked_out",
            unmapped = { event_type = "authentication", factor = "duo_push" },
            auth_timestamp = 1784140000, email = "noah.vosen@cia.gov",
            user = { name = "n.vosen", key = "DUABC", groups = { "BLACKBRIAR" } },
            nested = { drop_me = io.stdin },  -- io.stdin: type()=="userdata", stands in for a decoded JSON null
        }
    elseif str == fixtures.duo_admin_json then
        return {
            unmapped = { eventtype = "administrator", action = "admin_login_error",
                         description = "Invalid password attempt" },
            user = { name = "noah.vosen" },
        }
    elseif str == fixtures.winevent_json then
        return {
            winEventLog = {
                channel = "Security", id = 4769,
                providerName = "Microsoft-Windows-Security-Auditing",
                description = "A Kerberos service ticket was requested.",
                data = { event = {
                    system = { eventID = 4769, provider = { name = "Microsoft-Windows-Security-Auditing" } },
                    eventData = { targetUserName = "noah.vosen@CIA.LOCAL",
                                  serviceName = "MSSQLSvc/blackbriar-db01",
                                  ticketEncryptionType = "0x17", ipAddress = "10.1.0.50" },
                } },
            },
            Computer = "LANGLEY-DC01.CIA.LOCAL",
            timestamp = "collision-should-not-clobber-envelope",
        }
    elseif str == fixtures.cloudtrail_json then
        return {
            eventName = "StopLogging", eventSource = "cloudtrail.amazonaws.com",
            userIdentity = { type = "Root", arn = "arn:aws:iam::778812340092:root" },
            sourceIPAddress = "160.153.0.12",
            responseElements = io.stdin,  -- stands in for a decoded top-level JSON null
        }
    elseif str == fixtures.proxy_json then
        return {
            app_name = "Suspicious Web Activity", action = "Blocked",
            http_request = { url = { hostname = "exfil-relay.example.com", categories = { "Suspicious Destinations" } } },
            malware = { name = "cobaltstrike" },
        }
    elseif str == fixtures.mimecast_json then
        return {
            direction = "outbound", status_detail = "malicious",
            ["event.type"] = "TTP Impersonation Protection",
            unmapped = { taggedMalicious = true },
        }
    elseif str == fixtures.nested_event_json then
        return { event = { type = "should not survive nested" }, foo = "bar" }
    elseif str == fixtures.panw_json then
        return {
            metadata = { log_name = "THREAT" }, app_name = "tor", action = "allow",
            src_endpoint = { ip = "185.220.101.45" }, dst_endpoint = { ip = "10.0.1.10" },
            threat = { name = "Treadstone Asset Beacon Detected" },
            unmapped = { action = "allow", sub_type = "vulnerability", severity = "critical" },
        }
    elseif str == "not json" then
        error("expected value at line 1 column 1")
    end
    error("unknown fixture")
end

local json_stub = { decode = fake_decode }
local log_stub = { warn = function(msg) print("[WARN] " .. msg) end }
package.preload['json'] = function() return json_stub end
package.preload['log'] = function() return log_stub end

dofile("parse_json_by_msgid.lua")

local function assert_eq(actual, expected, label)
    if actual ~= expected then
        error(string.format("FAIL %s: expected %s, got %s", label, tostring(expected), tostring(actual)))
    end
    print("ok - " .. label)
end

-- 1. WINEVENT: nested winEventLog.* promoted as one object, envelope
-- `timestamp` collision preserved separately from the colliding json one.
local winevent_event = {
    msgid = "WINEVENT", datasource = "Security", tags = "treadstone-simulation",
    agent = "syslog-ng-forwarder", timestamp = "2026-07-15T18:42:21Z",
    message = fixtures.winevent_json,
}
local r1 = processEvent(winevent_event)
assert_eq(r1.winEventLog.id, 4769, "WINEVENT winEventLog.id promoted")
assert_eq(r1.winEventLog.channel, "Security", "WINEVENT winEventLog.channel promoted")
assert_eq(r1.winEventLog.data.event.eventData.targetUserName, "noah.vosen@CIA.LOCAL",
          "WINEVENT nested eventData.targetUserName promoted")
assert_eq(r1.winEventLog.data.event.eventData.ticketEncryptionType, "0x17",
          "WINEVENT nested eventData.ticketEncryptionType promoted")
assert_eq(r1.Computer, "LANGLEY-DC01.CIA.LOCAL", "WINEVENT Computer promoted")
assert_eq(r1.timestamp, "2026-07-15T18:42:21Z", "WINEVENT envelope timestamp NOT clobbered")
assert_eq(r1.jsontimestamp, "collision-should-not-clobber-envelope", "WINEVENT colliding json timestamp kept under jsontimestamp")
assert_eq(r1.message, fixtures.winevent_json, "WINEVENT message left intact")
assert_eq(r1.msgid, "WINEVENT", "WINEVENT msgid untouched")
assert_eq(r1.dataSource.name, "Windows Event Logs", "WINEVENT dataSource.name set")
assert_eq(r1.dataSource.category, "security", "WINEVENT dataSource.category set")

-- 2. DUO (authentication): nested unmapped.* + top-level status/status_detail
-- promoted, null stripped.
local duo_event = { msgid = "DUO", message = fixtures.duo_json }
local r2 = processEvent(duo_event)
assert_eq(r2.status, "denied", "DUO status promoted")
assert_eq(r2.status_detail, "locked_out", "DUO status_detail promoted")
assert_eq(r2.unmapped.event_type, "authentication", "DUO nested unmapped.event_type promoted")
assert_eq(r2.unmapped.factor, "duo_push", "DUO nested unmapped.factor promoted")
assert_eq(r2.email, "noah.vosen@cia.gov", "DUO email promoted")
assert_eq(r2.user.name, "n.vosen", "DUO nested user.name promoted")
assert_eq(r2.nested.drop_me, nil, "DUO nested null stripped to nil")
assert_eq(r2.dataSource.name, "Cisco Duo", "DUO dataSource.name set")

-- 2a. DUO (administrator): the second real Duo log type.
local duo_admin_event = { msgid = "DUO", message = fixtures.duo_admin_json }
local r2a = processEvent(duo_admin_event)
assert_eq(r2a.unmapped.eventtype, "administrator", "DUO admin nested unmapped.eventtype promoted")
assert_eq(r2a.unmapped.action, "admin_login_error", "DUO admin nested unmapped.action promoted")
assert_eq(r2a.dataSource.name, "Cisco Duo", "DUO admin dataSource.name set")

-- 2b. CLOUDTRAIL: nested userIdentity promoted, top-level null stripped, no envelope collision.
local ct_event = { msgid = "CLOUDTRAIL", message = fixtures.cloudtrail_json, sourceIPAddress = "unset" }
local r2b = processEvent(ct_event)
assert_eq(r2b.eventName, "StopLogging", "CLOUDTRAIL eventName promoted")
assert_eq(r2b.userIdentity.type, "Root", "CLOUDTRAIL nested userIdentity.type promoted")
assert_eq(r2b.sourceIPAddress, "160.153.0.12", "CLOUDTRAIL sourceIPAddress promoted (no collision, overwrote placeholder)")
assert_eq(r2b.responseElements, nil, "CLOUDTRAIL top-level null stripped to nil")
assert_eq(r2b.dataSource.name, "CloudTrail", "CLOUDTRAIL dataSource.name set")

-- 2c. PROXY (Zscaler): now a JSON source (was plain-text Squid before).
local proxy_event = { msgid = "PROXY", message = fixtures.proxy_json }
local r2c = processEvent(proxy_event)
assert_eq(r2c.action, "Blocked", "PROXY action promoted")
assert_eq(r2c.http_request.url.hostname, "exfil-relay.example.com", "PROXY nested http_request.url.hostname promoted")
assert_eq(r2c.dataSource.name, "Zscaler Internet Access", "PROXY dataSource.name set")

-- 2d. Mimecast: flat "event.type" dotted key promoted correctly (the fixed shape).
local mc_event = { msgid = "EMAIL", message = fixtures.mimecast_json }
local r2d = processEvent(mc_event)
assert_eq(r2d["event.type"], "TTP Impersonation Protection", "Mimecast flat event.type key promoted")
assert_eq(r2d.unmapped.taggedMalicious, true, "Mimecast nested unmapped.taggedMalicious promoted")

-- 2e. Regression guard: a nested top-level {"event":{...}} object (the bug we
-- hit live -- DataPipeline's own envelope-reserved "event" key silently drops
-- it) must now be caught by RESERVED_KEYS and kept under jsonevent instead.
local nested_event = { msgid = "DUO", message = fixtures.nested_event_json }
local r2e = processEvent(nested_event)
assert_eq(r2e.foo, "bar", "nested_event sibling key promoted normally")
assert_eq(r2e.jsonevent.type, "should not survive nested", "colliding nested 'event' key rescued under jsonevent")

-- 2f. PANW (Palo Alto Networks Firewall): replaces the old Cisco ASA/FTD text
-- format -- now a JSON source matching this tenant's real deployed PANW rules.
local panw_event = { msgid = "PANW", message = fixtures.panw_json }
local r2f = processEvent(panw_event)
assert_eq(r2f.metadata.log_name, "THREAT", "PANW nested metadata.log_name promoted")
assert_eq(r2f.unmapped.sub_type, "vulnerability", "PANW nested unmapped.sub_type promoted")
assert_eq(r2f.threat.name, "Treadstone Asset Beacon Detected", "PANW nested threat.name promoted")
assert_eq(r2f.dataSource.name, "Palo Alto Networks Firewall", "PANW dataSource.name set")

-- 3. Text sources: message passes through unchanged (still present verbatim),
-- gets tagged with dataSource.name/category, AND now gets a namespaced field
-- table extracted by pattern-match -- so detections query real fields
-- instead of `parse '...' from message` at query time in SDL.
-- (S1EDR isn't covered here -- those events never reach this pipeline at
-- all; they're ingested directly into SDL. See TREADSTONE_PIPELINE.md.)
local sshd_accepted = { msgid = "SSHD", message = "Accepted publickey for noah.vosen from 10.0.1.10 port 51022 ssh2: RSA SHA256:abc" }
local r3a = processEvent(sshd_accepted)
assert_eq(r3a.dataSource.name, "Linux Audit", "SSHD dataSource.name set")
assert_eq(r3a.sshd.result, "accepted", "SSHD accepted result parsed")
assert_eq(r3a.sshd.user, "noah.vosen", "SSHD accepted user parsed")
assert_eq(r3a.sshd.sourceIp, "10.0.1.10", "SSHD accepted sourceIp parsed")
assert_eq(r3a.sshd.port, 51022, "SSHD accepted port parsed (numeric)")
assert_eq(r3a.message, sshd_accepted.message, "SSHD message left intact")

local sshd_failed = { msgid = "SSHD", message = "Failed password for invalid user v.szabo from 194.9.108.22 port 50877 ssh2" }
local r3b = processEvent(sshd_failed)
assert_eq(r3b.sshd.result, "failed", "SSHD failed result parsed")
assert_eq(r3b.sshd.user, "v.szabo", "SSHD failed user parsed")
assert_eq(r3b.sshd.invalidUser, true, "SSHD failed invalidUser=true parsed (invalid-user variant)")

local sudo_event = { msgid = "SUDO", message = "petra : TTY=pts/2 ; PWD=/root ; USER=root ; COMMAND=/opt/blackbriar/bin/authorize_kill.py --target doug.mckenna --asset ASSET-MCKENNA" }
local r3c = processEvent(sudo_event)
assert_eq(r3c.sudo.user, "petra", "SUDO user parsed")
assert_eq(r3c.sudo.command, "/opt/blackbriar/bin/authorize_kill.py --target doug.mckenna --asset ASSET-MCKENNA", "SUDO command parsed (with spaces/flags intact)")

local pam_event = { msgid = "PAM", message = "pam_unix(sshd:session): session opened for user petra by (uid=0)" }
local r3d = processEvent(pam_event)
assert_eq(r3d.pam.service, "sshd", "PAM service parsed")
assert_eq(r3d.pam.action, "opened", "PAM action parsed")
assert_eq(r3d.pam.user, "petra", "PAM user parsed")

local http_event = { msgid = "HTTP", message = '82.145.67.201 - jason.bourne [16/Jul/2026:15:25:28 +0000] "GET /intel/db/passport?name=john+michael+kane HTTP/1.1" 200 4096 "-" "curl/8.1.2"' }
local r3e = processEvent(http_event)
assert_eq(r3e.http.clientIp, "82.145.67.201", "HTTP clientIp parsed")
assert_eq(r3e.http.user, "jason.bourne", "HTTP user parsed")
assert_eq(r3e.http.method, "GET", "HTTP method parsed")
assert_eq(r3e.http.path, "/intel/db/passport?name=john+michael+kane", "HTTP path parsed")
assert_eq(r3e.http.status, 200, "HTTP status parsed (numeric)")
assert_eq(r3e.http.bytes, 4096, "HTTP bytes parsed (numeric)")
assert_eq(r3e.http.userAgent, "curl/8.1.2", "HTTP userAgent parsed")

local cron_event = { msgid = "CRON", message = "root CMD (/opt/blackbriar/bin/authorize_kill.py --target jason.bourne)" }
local r3f = processEvent(cron_event)
assert_eq(r3f.cron.user, "root", "CRON user parsed")
assert_eq(r3f.cron.command, "/opt/blackbriar/bin/authorize_kill.py --target jason.bourne", "CRON command parsed")

local audit_event = { msgid = "AUDIT", message = "kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=185.220.101.45 DST=10.0.1.10 LEN=500 TOS=0x00 PREC=0x00 TTL=64 ID=1234 DF PROTO=TCP SPT=51234 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0" }
local r3g = processEvent(audit_event)
assert_eq(r3g.audit.srcIp, "185.220.101.45", "AUDIT srcIp parsed")
assert_eq(r3g.audit.dstIp, "10.0.1.10", "AUDIT dstIp parsed")
assert_eq(r3g.audit.proto, "TCP", "AUDIT proto parsed")
assert_eq(r3g.audit.srcPort, 51234, "AUDIT srcPort parsed (numeric)")
assert_eq(r3g.audit.dstPort, 443, "AUDIT dstPort parsed (numeric)")

local dns_event = { msgid = "DNS", message = "client @0x1a2b3c 10.2.5.100#54321 (c2.blackbriar.example.net): query: c2.blackbriar.example.net IN A +E(0) (10.0.0.53)" }
local r3h = processEvent(dns_event)
assert_eq(r3h.dns.clientIp, "10.2.5.100", "DNS clientIp parsed")
assert_eq(r3h.dns.qname, "c2.blackbriar.example.net", "DNS qname parsed")
assert_eq(r3h.dns.qtype, "A", "DNS qtype parsed")
assert_eq(r3h.dns.resolver, "10.0.0.53", "DNS resolver parsed")

local dbaudit_event = { msgid = "DBAUDIT", message = 'ward.abbott@intel_classified LOG:  AUDIT: SESSION,12345,1,READ,SELECT,TABLE,public.neski_files,"SELECT * FROM neski_files WHERE case_year=2003",<not logged> rows=1847' }
local r3i = processEvent(dbaudit_event)
assert_eq(r3i.dbaudit.user, "ward.abbott", "DBAUDIT user parsed")
assert_eq(r3i.dbaudit.db, "intel_classified", "DBAUDIT db parsed")
assert_eq(r3i.dbaudit.class, "READ", "DBAUDIT class parsed")
assert_eq(r3i.dbaudit.command, "SELECT", "DBAUDIT command parsed")
assert_eq(r3i.dbaudit["table"], "public.neski_files", "DBAUDIT table parsed")
assert_eq(r3i.dbaudit.statement, "SELECT * FROM neski_files WHERE case_year=2003", "DBAUDIT statement parsed (internal quotes intact)")
assert_eq(r3i.dbaudit.rows, 1847, "DBAUDIT rows parsed (numeric)")

-- 3j. Text parser given a message that doesn't match its pattern: no crash,
-- no field table attached, dataSource still set.
local sshd_garbage = { msgid = "SSHD", message = "not a real sshd line" }
local r3j = processEvent(sshd_garbage)
assert_eq(r3j.sshd, nil, "SSHD non-matching message gets no sshd field table")
assert_eq(r3j.dataSource.name, "Linux Audit", "SSHD dataSource.name still set even when text doesn't parse")

local unknown_event = { msgid = "SOMETHING_UNRECOGNIZED", message = "n/a" }
local r3k = processEvent(unknown_event)
assert_eq(r3k.dataSource, nil, "unrecognized msgid gets no dataSource (avoid mislabeling)")

-- 4. JSON msgid but malformed message: falls back to returning event untouched (no crash).
local broken_event = { msgid = "EMAIL", message = "not json" }
local r4 = processEvent(broken_event)
assert_eq(r4.message, "not json", "malformed JSON falls back to untouched event")

-- 5. Missing message field on a JSON msgid: no crash.
local no_message_event = { msgid = "DUO" }
local r5 = processEvent(no_message_event)
assert_eq(r5.msgid, "DUO", "missing message on JSON msgid does not crash")

print("\nALL TESTS PASSED")
