-- Local verification harness (not shipped). Stubs the runtime's `json`/`log`
-- modules and feeds processEvent() realistic DataPipeline-shaped records to
-- confirm: JSON msgids get fields promoted, collisions are preserved under
-- json<key>, nulls are stripped, and non-JSON msgids pass through untouched.

local fixtures = {
    duo_json = '{"result":"success","reason":"user_approved","factor":"duo_push","auth_timestamp":1784140000,"email":"noah.vosen@cia.gov","user":{"name":"n.vosen","key":"DUABC","groups":["BLACKBRIAR"]},"nested":{"drop_me":null}}',
    winevent_json = '{"EventID":4769,"Channel":"Security","Computer":"LANGLEY-DC01.CIA.LOCAL","TargetUserName":"noah.vosen@CIA.LOCAL","ServiceName":"MSSQLSvc/blackbriar-db01","TicketEncryptionType":"0x17","IpAddress":"10.1.0.50","timestamp":"collision-should-not-clobber-envelope"}',
    cloudtrail_json = '{"eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com","userIdentity":{"type":"Root","arn":"arn:aws:iam::778812340092:root"},"sourceIPAddress":"160.153.0.12","responseElements":null}',
}

-- Minimal fixture-driven decoder: good enough to exercise processEvent's
-- merge/collision/null-strip logic without a general-purpose JSON parser.
local function fake_decode(str)
    if str == fixtures.duo_json then
        return {
            result = "success", reason = "user_approved", factor = "duo_push",
            auth_timestamp = 1784140000, email = "noah.vosen@cia.gov",
            user = { name = "n.vosen", key = "DUABC", groups = { "BLACKBRIAR" } },
            nested = { drop_me = io.stdin },  -- io.stdin: type()=="userdata", stands in for a decoded JSON null
        }
    elseif str == fixtures.winevent_json then
        return {
            EventID = 4769, Channel = "Security", Computer = "LANGLEY-DC01.CIA.LOCAL",
            TargetUserName = "noah.vosen@CIA.LOCAL", ServiceName = "MSSQLSvc/blackbriar-db01",
            TicketEncryptionType = "0x17", IpAddress = "10.1.0.50",
            timestamp = "collision-should-not-clobber-envelope",
        }
    elseif str == fixtures.cloudtrail_json then
        return {
            eventName = "StopLogging", eventSource = "cloudtrail.amazonaws.com",
            userIdentity = { type = "Root", arn = "arn:aws:iam::778812340092:root" },
            sourceIPAddress = "160.153.0.12",
            responseElements = io.stdin,  -- stands in for a decoded top-level JSON null
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

-- 1. WINEVENT: fields promoted, envelope `timestamp` collision preserved separately.
local winevent_event = {
    msgid = "WINEVENT", datasource = "Security", tags = "treadstone-simulation",
    agent = "syslog-ng-forwarder", timestamp = "2026-07-15T18:42:21Z",
    message = fixtures.winevent_json,
}
local r1 = processEvent(winevent_event)
assert_eq(r1.EventID, 4769, "WINEVENT EventID promoted")
assert_eq(r1.TargetUserName, "noah.vosen@CIA.LOCAL", "WINEVENT TargetUserName promoted")
assert_eq(r1.TicketEncryptionType, "0x17", "WINEVENT TicketEncryptionType promoted")
assert_eq(r1.timestamp, "2026-07-15T18:42:21Z", "WINEVENT envelope timestamp NOT clobbered")
assert_eq(r1.jsontimestamp, "collision-should-not-clobber-envelope", "WINEVENT colliding json timestamp kept under jsontimestamp")
assert_eq(r1.message, fixtures.winevent_json, "WINEVENT message left intact")
assert_eq(r1.msgid, "WINEVENT", "WINEVENT msgid untouched")

-- 2. DUO: nested table + null stripped.
local duo_event = { msgid = "DUO", message = fixtures.duo_json }
local r2 = processEvent(duo_event)
assert_eq(r2.result, "success", "DUO result promoted")
assert_eq(r2.email, "noah.vosen@cia.gov", "DUO email promoted")
assert_eq(r2.user.name, "n.vosen", "DUO nested user.name promoted")
assert_eq(r2.nested.drop_me, nil, "DUO nested null stripped to nil")

-- 2b. CLOUDTRAIL: nested userIdentity promoted, top-level null stripped, no envelope collision.
local ct_event = { msgid = "CLOUDTRAIL", message = fixtures.cloudtrail_json, sourceIPAddress = "unset" }
local r2b = processEvent(ct_event)
assert_eq(r2b.eventName, "StopLogging", "CLOUDTRAIL eventName promoted")
assert_eq(r2b.userIdentity.type, "Root", "CLOUDTRAIL nested userIdentity.type promoted")
assert_eq(r2b.sourceIPAddress, "160.153.0.12", "CLOUDTRAIL sourceIPAddress promoted (no collision, overwrote placeholder)")
assert_eq(r2b.responseElements, nil, "CLOUDTRAIL top-level null stripped to nil")

-- 3. Non-JSON msgid: pass through completely unchanged, no decode attempted.
local asa_event = { msgid = "ASA302013", message = "%ASA-6-302013: Built inbound TCP connection ..." }
local r3 = processEvent(asa_event)
assert_eq(r3.message, asa_event.message, "ASA message passed through unchanged")
assert_eq(r3.EventID, nil, "ASA has no promoted JSON fields")

-- 4. JSON msgid but malformed message: falls back to returning event untouched (no crash).
local broken_event = { msgid = "EMAIL", message = "not json" }
local r4 = processEvent(broken_event)
assert_eq(r4.message, "not json", "malformed JSON falls back to untouched event")

-- 5. Missing message field on a JSON msgid: no crash.
local no_message_event = { msgid = "DUO" }
local r5 = processEvent(no_message_event)
assert_eq(r5.msgid, "DUO", "missing message on JSON msgid does not crash")

print("\nALL TESTS PASSED")
