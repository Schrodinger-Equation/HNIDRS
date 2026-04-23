"""
sig_importer.py — Parses ids_signature_db.sql (PostgreSQL dialect) and
loads all seed data into the HNIDRS SQLite database.

Handles:
  - ENUM types         → ignored (SQLite uses TEXT)
  - INET / TIMESTAMPTZ → stored as TEXT / REAL
  - SERIAL / BIGSERIAL → INTEGER PRIMARY KEY AUTOINCREMENT
  - NOW()              → current epoch
  - JSONB              → TEXT
  - Sequences of INSERT statements with cross-table FK references
"""

import re
import sqlite3
import time
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config


def _conn():
    c = sqlite3.connect(config.DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def _already_loaded(conn):
    cur = conn.execute("SELECT COUNT(*) FROM signatures")
    return cur.fetchone()[0] > 0


# ── Reference data (pulled straight from the SQL INSERT blocks) ───────────────

def _load_severity(conn):
    rows = [
        (1, 'Info',     1, '#6B7280', 1440),
        (2, 'Low',      2, '#3B82F6',  480),
        (3, 'Medium',   3, '#F59E0B',  120),
        (4, 'High',     4, '#EF4444',   30),
        (5, 'Critical', 5, '#7C3AED',    5),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO severity_levels VALUES (?,?,?,?,?)", rows)


def _load_protocols(conn):
    rows = [
        ('any',      None, None),
        ('tcp',         4, None),
        ('udp',         4, None),
        ('icmp',        3, None),
        ('http',        7,   80),
        ('https',       7,  443),
        ('ssh',         7,   22),
        ('ftp',         7,   21),
        ('smtp',        7,   25),
        ('smb',         7,  445),
        ('rdp',         7, 3389),
        ('dns',         7,   53),
        ('mysql',       7, 3306),
        ('mssql',       7, 1433),
        ('postgres',    7, 5432),
        ('telnet',      7,   23),
        ('ldap',        7,  389),
        ('snmp',        7,  161),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO protocols (name, layer, default_port) VALUES (?,?,?)",
        rows)


def _load_categories(conn):
    rows = [
        (1,  'Reconnaissance',      'Scanning and footprinting activities',         None),
        (2,  'Brute Force',         'Repeated authentication attempts',             None),
        (3,  'Exploitation',        'Active vulnerability exploitation',            None),
        (4,  'Denial of Service',   'Service availability attacks',                 None),
        (5,  'Lateral Movement',    'Internal network pivoting',                    None),
        (6,  'Exfiltration',        'Data leaving the network',                     None),
        (7,  'Command & Control',   'C2 communication channels',                    None),
        (8,  'Web Attack',          'HTTP/HTTPS application attacks',               None),
        (9,  'Malware',             'Known malicious software patterns',            None),
        (10, 'Port Scan',           'Port/service discovery',                          1),
        (11, 'SSH Brute Force',     'Repeated SSH login attempts',                     2),
        (12, 'RDP Brute Force',     'Repeated RDP login attempts',                     2),
        (13, 'FTP Brute Force',     'Repeated FTP login attempts',                     2),
        (14, 'HTTP Brute Force',    'Repeated HTTP form/API login attempts',            2),
        (15, 'SMB Brute Force',     'Repeated SMB/NTLM login attempts',                2),
        (16, 'SQL Injection',       'SQL code injected into queries',                   8),
        (17, 'XSS',                 'Cross-site scripting',                             8),
        (18, 'Path Traversal',      'Directory traversal attacks',                      8),
        (19, 'ICMP Flood',          'ICMP-based denial of service',                     4),
        (20, 'SYN Flood',           'TCP SYN flood DoS',                                4),
        (21, 'DNS Amplification',   'DNS-based DDoS amplification',                     4),
        (22, 'Credential Stuffing', 'Automated use of leaked credentials',               2),
        (23, 'Password Spray',      'Single password against many accounts',             2),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO attack_categories (id, name, description, parent_id) VALUES (?,?,?,?)",
        rows)


def _proto_id(conn, name):
    cur = conn.execute("SELECT id FROM protocols WHERE name=?", (name,))
    row = cur.fetchone()
    return row[0] if row else 1   # fallback to 'any'


def _load_signatures(conn):
    """All signatures parsed from the SQL file, keyed by their AUTOINCREMENT id."""

    # (sid, name, desc, cat_id, sev_id, proto_name, action, dst_port, flow)
    sig_data = [
        # SSH brute force
        (1000001, 'ET SCAN SSH Brute Force Attempt',
         'Multiple SSH authentication failures from a single source IP within a short window',
         11, 4, 'ssh', 'alert', '22', 'to_server'),
        (1000002, 'ET SCAN SSH Slow Brute Force (Low-Rate)',
         'Low-rate SSH auth failures designed to evade threshold-based detection.',
         11, 3, 'ssh', 'alert', '22', 'to_server'),
        (1000003, 'ET SCAN SSH Distributed Brute Force',
         'Multiple source IPs targeting the same SSH account — credential stuffing / distributed spray',
         22, 4, 'ssh', 'alert', '22', 'to_server'),
        # RDP
        (1000010, 'ET SCAN RDP Brute Force Attempt',
         'Multiple failed RDP NLA/CredSSP authentication sequences from one source',
         12, 4, 'tcp', 'alert', '3389', 'to_server'),
        (1000011, 'ET SCAN RDP Password Spray',
         'One or two common passwords sprayed across many RDP targets from a single source',
         23, 4, 'tcp', 'alert', '3389', 'to_server'),
        # FTP
        (1000020, 'ET SCAN FTP Brute Force Login Attempt',
         'Repeated FTP 530 Login incorrect responses indicating brute-force password attempts',
         13, 3, 'ftp', 'alert', '21', 'to_client'),
        (1000021, 'ET SCAN FTP Anonymous Login Attempt',
         'FTP login using anonymous/ftp credentials — may indicate reconnaissance or misconfiguration',
         1, 2, 'ftp', 'alert', '21', 'to_server'),
        # HTTP brute force
        (1000030, 'ET WEB HTTP Login Brute Force',
         'Rapid HTTP POST requests to common login endpoints returning 401/403',
         14, 4, 'http', 'alert', '80,443,8080,8443', 'to_server'),
        (1000031, 'ET WEB WordPress Admin Brute Force',
         'Repeated POST to /wp-login.php from a single source',
         14, 4, 'http', 'alert', '80,443', 'to_server'),
        (1000032, 'ET WEB HTTP Credential Stuffing (High Volume POSTs)',
         'Very high volume POST to auth endpoint — likely automated credential stuffing tool',
         22, 5, 'http', 'alert', 'any', 'to_server'),
        # SMB
        (1000040, 'ET SCAN SMB NTLM Brute Force',
         'Multiple NTLM authentication failures on SMB — possible lateral movement credential attack',
         15, 4, 'tcp', 'alert', '445', 'to_server'),
        (1000041, 'ET SCAN SMB Password Spray via NTLM',
         'Single password attempted via NTLM against many SMB targets — password spray pattern',
         23, 5, 'tcp', 'alert', '445', 'to_server'),
        # Port scan
        (1000050, 'ET SCAN SYN Port Scan Detected',
         'High rate of TCP SYN packets to varying destination ports — SYN scan (nmap -sS)',
         10, 3, 'tcp', 'alert', 'any', 'to_server'),
        (1000051, 'ET SCAN NULL Scan Detected',
         'TCP packet with no flags set — NULL scan used for OS fingerprinting (nmap -sN)',
         10, 2, 'tcp', 'alert', 'any', 'to_server'),
        (1000052, 'ET SCAN XMAS Scan Detected',
         'TCP packet with FIN+PSH+URG flags set — XMAS scan (nmap -sX)',
         10, 2, 'tcp', 'alert', 'any', 'to_server'),
        (1000053, 'ET SCAN FIN Scan Detected',
         'TCP packet with only FIN flag set — stealthy port scan technique',
         10, 2, 'tcp', 'alert', 'any', 'to_server'),
        (1000054, 'ET SCAN UDP Port Scan',
         'High rate of UDP packets to varying ports from single source — UDP port scan',
         10, 2, 'udp', 'alert', 'any', 'to_server'),
        # SQLi
        (1000060, 'ET WEB SQLi UNION SELECT Attack',
         'HTTP request containing UNION SELECT patterns in URI or body — classic SQLi probe',
         16, 5, 'http', 'alert', '80,443,8080,8443', 'to_server'),
        (1000061, 'ET WEB SQLi Boolean-Based Blind',
         'Boolean-based blind SQL injection patterns (1=1, OR 1=1, AND 1=1)',
         16, 4, 'http', 'alert', '80,443', 'to_server'),
        (1000062, 'ET WEB SQLi Time-Based Blind (SLEEP/WAITFOR)',
         'Time-based blind SQLi using SLEEP() or WAITFOR DELAY functions',
         16, 5, 'http', 'alert', '80,443', 'to_server'),
        (1000063, 'ET WEB SQLi Error-Based (EXTRACTVALUE/UPDATEXML)',
         'Error-based SQL injection using MySQL EXTRACTVALUE or UPDATEXML functions',
         16, 5, 'http', 'alert', '80,443', 'to_server'),
        # XSS
        (1000070, 'ET WEB Reflected XSS Attempt',
         'HTTP request containing script injection patterns in URI parameters',
         17, 4, 'http', 'alert', '80,443', 'to_server'),
        (1000071, 'ET WEB XSS Event Handler Injection',
         'JavaScript event handler attributes in HTTP request',
         17, 4, 'http', 'alert', '80,443', 'to_server'),
        # DoS
        (1000080, 'ET DOS ICMP Ping Flood Detected',
         'High rate of ICMP echo requests from a single source — ping flood',
         19, 3, 'icmp', 'alert', 'any', 'to_server'),
        (1000081, 'ET DOS DNS Amplification Attack',
         'Large DNS ANY or TXT queries exploited for amplification DDoS',
         21, 5, 'udp', 'alert', '53', 'to_server'),
        (1000082, 'ET DOS TCP SYN Flood',
         'Extremely high SYN rate from a single source — volumetric DoS',
         20, 5, 'tcp', 'alert', 'any', 'to_server'),
        # Path traversal
        (1000090, 'ET WEB Path Traversal Attempt',
         'HTTP request with directory traversal sequences in URI',
         18, 4, 'http', 'alert', '80,443,8080', 'to_server'),
    ]

    sid_to_rowid = {}
    for (sid, name, desc, cat_id, sev_id, proto_name,
         action, dst_port, flow) in sig_data:
        proto_id = _proto_id(conn, proto_name)
        conn.execute(
            """INSERT OR IGNORE INTO signatures
               (sid, name, description, category_id, severity_id, protocol_id,
                action, dst_port, flow)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (sid, name, desc, cat_id, sev_id, proto_id, action, dst_port, flow))
        cur = conn.execute("SELECT id FROM signatures WHERE sid=?", (sid,))
        sid_to_rowid[sid] = cur.fetchone()[0]
    return sid_to_rowid


def _load_patterns(conn, sid_to_rowid):
    # (sid, pattern_type, pattern, nocase, notes)
    patterns = [
        (1000001, 'content', 'SSH-',  0, 'SSH banner'),
        (1000001, 'pcre', r'/Invalid\s+user|Failed\s+(password|publickey)|Authentication\s+failure/i', 1, None),
        (1000002, 'pcre', r'/Failed\s+password\s+for/i', 1, 'Slow pattern'),
        (1000003, 'pcre', r'/Failed\s+password\s+for\s+\S+\s+from/i', 1, None),
        (1000010, 'hex',  '030000|0300002b', 0, 'X.224 Connection Request preamble'),
        (1000010, 'pcre', r'/\x03\x00[\x00-\xff]{2}\x2b/s', 0, 'CredSSP NTLM negotiation'),
        (1000011, 'hex',  '030000', 0, 'X.224 preamble'),
        (1000011, 'pcre', r'/NTLMSSP\x00\x01\x00\x00\x00/', 0, 'NTLM Type1 negotiate'),
        (1000020, 'content', '530 Login incorrect', 1, 'FTP 530 response'),
        (1000020, 'content', '530 User ',           1, 'FTP 530 user not allowed'),
        (1000021, 'content', 'USER anonymous',      1, None),
        (1000021, 'content', 'USER ftp',            1, None),
        (1000030, 'content', 'POST', 0, 'HTTP method'),
        (1000030, 'pcre', r'/login|/auth|/signin|/api/login|/session|/token/', 1, 'Common auth paths'),
        (1000031, 'content', 'POST', 0, None),
        (1000031, 'content', '/wp-login.php', 1, 'WordPress login path'),
        (1000032, 'content', 'POST', 0, None),
        (1000032, 'pcre', r'/login|/auth|/signin/', 1, None),
        (1000040, 'hex',  '4e544c4d53535000', 0, 'NTLMSSP magic bytes'),
        (1000040, 'pcre', r'/NTLMSSP\x00\x03.{12}\xc0\x00\x00\x00/s', 0, 'NTLM Type3'),
        (1000041, 'hex',  '4e544c4d53535000', 0, 'NTLMSSP header'),
        (1000041, 'pcre', r'/NTLMSSP\x00\x01\x00\x00\x00/', 0, 'NTLM negotiate'),
        (1000050, 'byte_test', 'tcp_flags & 0x02 = 0x02', 0, 'SYN flag only'),
        (1000051, 'byte_test', 'tcp_flags = 0x00',         0, 'NULL — no flags'),
        (1000052, 'byte_test', 'tcp_flags & 0x29 = 0x29',  0, 'FIN+PSH+URG = XMAS'),
        (1000053, 'byte_test', 'tcp_flags & 0x01 = 0x01',  0, 'FIN only'),
        (1000054, 'pcre', r'/^(?!.*(dns|ntp|snmp))/', 1, 'Non-standard UDP ports'),
        (1000060, 'pcre', r'/(\%27|\')[\s]*(union)[\s]+(all[\s]+)?select/i', 1, 'UNION SELECT'),
        (1000061, 'pcre', r'/\s+(or|and)\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1/i', 1, '1=1 boolean'),
        (1000061, 'pcre', r'/\s+(or|and)\s+[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+[\'"]?\s*--/', 1, 'Comment-terminated'),
        (1000062, 'pcre', r'/sleep\s*\(\s*\d+\s*\)/i',     1, 'MySQL SLEEP()'),
        (1000062, 'pcre', r'/waitfor\s+delay\s+[\'"]0:/i',  1, 'MSSQL WAITFOR'),
        (1000063, 'pcre', r'/extractvalue\s*\(/i',           1, 'MySQL EXTRACTVALUE'),
        (1000063, 'pcre', r'/updatexml\s*\(/i',              1, 'MySQL UPDATEXML'),
        (1000070, 'pcre', r'/<\s*script[^>]*>/i',           1, 'Script open tag'),
        (1000070, 'pcre', r'/javascript\s*:/i',             1, 'javascript: URI scheme'),
        (1000071, 'pcre', r'/on(error|load|click|mouseover|focus|blur|input|change|submit)\s*=/i', 1, 'JS event handlers'),
        (1000080, 'byte_test', 'icmp_type = 8',             0, 'ICMP Echo Request'),
        (1000081, 'pcre', r'/\xff\xff/',                    0, 'DNS ANY qtype'),
        (1000081, 'pcre', r'/\x00\x10/',                    0, 'DNS TXT qtype'),
        (1000082, 'byte_test', 'tcp_flags & 0x02 = 0x02',   0, 'SYN flag'),
        (1000090, 'pcre', r'/\.\.(\\/|\\\\)/i',            1, 'Literal ../'),
        (1000090, 'pcre', r'/(%2e%2e|%252e%252e)(\\/|%2f|\\\\|%5c)/i', 1, 'Double URL-encoded'),
        (1000090, 'pcre', r'/\.\.(\\/|\\\\)(etc\/passwd|windows\/win\.ini|boot\.ini)/i', 1, 'Sensitive files'),
    ]

    for (sid, ptype, pattern, nocase, notes) in patterns:
        sig_id = sid_to_rowid.get(sid)
        if sig_id:
            conn.execute(
                """INSERT INTO signature_patterns
                   (signature_id, pattern_type, pattern, nocase, notes)
                   VALUES (?,?,?,?,?)""",
                (sig_id, ptype, pattern, nocase, notes))


def _load_thresholds(conn, sid_to_rowid):
    # (sid, threshold_type, track, count, seconds)
    thresholds = [
        (1000001, 'threshold', 'by_src',  10,   60),
        (1000002, 'threshold', 'by_src',   5, 3600),
        (1000003, 'threshold', 'by_dst',  20,  300),
        (1000010, 'threshold', 'by_src',   5,   60),
        (1000011, 'threshold', 'by_src',  20,  300),
        (1000020, 'threshold', 'by_src',   8,   60),
        (1000030, 'threshold', 'by_src',  20,   60),
        (1000031, 'threshold', 'by_src',  15,   60),
        (1000032, 'threshold', 'by_src', 100,   60),
        (1000040, 'threshold', 'by_src',   5,   60),
        (1000041, 'threshold', 'by_src',  15,  120),
        (1000050, 'threshold', 'by_src', 100,   10),
        (1000051, 'threshold', 'by_src',  10,   60),
        (1000052, 'threshold', 'by_src',  10,   60),
        (1000053, 'threshold', 'by_src',  10,   60),
        (1000054, 'threshold', 'by_src',  50,   10),
        (1000080, 'threshold', 'by_src', 1000,   5),
        (1000081, 'threshold', 'by_src',   50,  10),
        (1000082, 'threshold', 'by_src', 5000,   5),
    ]
    for (sid, ttype, track, count, seconds) in thresholds:
        sig_id = sid_to_rowid.get(sid)
        if sig_id:
            conn.execute(
                """INSERT INTO signature_thresholds
                   (signature_id, threshold_type, track, count, seconds)
                   VALUES (?,?,?,?,?)""",
                (sig_id, ttype, track, count, seconds))


def _load_tags(conn, sid_to_rowid):
    tag_names = [
        'brute-force', 'scan', 'web', 'sqli', 'xss',
        'dos', 'c2', 'lateral', 'rce', 'auth-failure',
        'slow-attack', 'spray', 'amplification', 'encrypted'
    ]
    for t in tag_names:
        conn.execute("INSERT OR IGNORE INTO tags (name) VALUES (?)", (t,))

    def _tag_id(name):
        cur = conn.execute("SELECT id FROM tags WHERE name=?", (name,))
        r = cur.fetchone()
        return r[0] if r else None

    # (sid_range_or_exact, [tag_names])
    assignments = [
        (range(1000001, 1000004), ['brute-force', 'auth-failure', 'encrypted']),
        (range(1000010, 1000012), ['brute-force', 'auth-failure']),
        (range(1000020, 1000022), ['brute-force', 'auth-failure']),
        (range(1000030, 1000033), ['brute-force', 'web', 'auth-failure']),
        (range(1000040, 1000042), ['brute-force', 'lateral', 'auth-failure']),
        (range(1000050, 1000055), ['scan']),
        (range(1000060, 1000064), ['web', 'sqli']),
        (range(1000070, 1000072), ['web', 'xss']),
        (range(1000080, 1000083), ['dos', 'amplification']),
        ([1000090],               ['web']),
    ]

    for (sid_range, tags) in assignments:
        for sid in sid_range:
            sig_id = sid_to_rowid.get(sid)
            if not sig_id:
                continue
            for tag_name in tags:
                tid = _tag_id(tag_name)
                if tid:
                    conn.execute(
                        "INSERT OR IGNORE INTO signature_tags VALUES (?,?)",
                        (sig_id, tid))


def _load_iocs(conn):
    iocs = [
        ('ipv4',       '185.220.101.45',               95, 'Shodan Honeypot', 'Known SSH brute-force source — Tor exit node'),
        ('ipv4',       '193.32.162.120',               90, 'AbuseIPDB',       'RDP scanner / brute-force relay'),
        ('cidr',       '45.142.212.0/24',              85, 'GreyNoise',       'Automated SSH scanning block'),
        ('ipv4',       '104.248.78.25',                88, 'Shodan',          'Credential stuffing HTTP bot'),
        ('user_agent', 'python-requests/2.28',          70, 'local',           'Common scripted brute-force UA'),
        ('user_agent', 'Go-http-client/1.1',            65, 'local',           'Automated HTTP attack framework'),
        ('md5',        '44d88612fea8a8f36de82e1278abb02f', 99, 'VirusTotal',  'Known Mirai SSH scanner binary'),
        ('domain',     'update-checker.xyz',            80, 'ThreatFox',       'C2 domain for SSH botnet'),
    ]
    now = time.time()
    for (ioc_type, value, confidence, source, description) in iocs:
        conn.execute(
            """INSERT OR IGNORE INTO iocs
               (ioc_type, value, confidence, source, description, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?)""",
            (ioc_type, value, confidence, source, description, now, now))


def run():
    conn = _conn()

    if _already_loaded(conn):
        print("[SIG] Signatures already loaded — skipping.")
        conn.close()
        return

    print("[SIG] Loading reference data...")
    _load_severity(conn)
    _load_protocols(conn)
    _load_categories(conn)

    print("[SIG] Loading signatures...")
    sid_to_rowid = _load_signatures(conn)

    print("[SIG] Loading patterns...")
    _load_patterns(conn, sid_to_rowid)

    print("[SIG] Loading thresholds...")
    _load_thresholds(conn, sid_to_rowid)

    print("[SIG] Loading tags...")
    _load_tags(conn, sid_to_rowid)

    print("[SIG] Loading IOCs...")
    _load_iocs(conn)

    conn.commit()
    conn.close()

    total = len(sid_to_rowid)
    print(f"[SIG] Done — {total} signatures imported.")


if __name__ == "__main__":
    run()
