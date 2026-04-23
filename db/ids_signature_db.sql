-- ============================================================
--  HYBRID IDS — SIGNATURE DATABASE SCHEMA
--  Engine: PostgreSQL 14+
--  Author: Hybrid NIDS Project
-- ============================================================

-- ────────────────────────────────────────
--  ENUMERATIONS
-- ────────────────────────────────────────

CREATE TYPE rule_action      AS ENUM ('alert', 'drop', 'reject', 'log', 'pass');
CREATE TYPE pattern_type     AS ENUM ('pcre', 'content', 'hex', 'regex', 'byte_test');
CREATE TYPE flow_direction   AS ENUM ('to_server', 'to_client', 'both');
CREATE TYPE ioc_type         AS ENUM ('ipv4', 'ipv6', 'cidr', 'domain', 'url', 'user_agent', 'md5', 'sha256');
CREATE TYPE threshold_track  AS ENUM ('by_src', 'by_dst', 'by_both');
CREATE TYPE threshold_type   AS ENUM ('threshold', 'limit', 'both');
CREATE TYPE alert_disposition AS ENUM ('new', 'confirmed', 'false_positive', 'suppressed', 'resolved');

-- ────────────────────────────────────────
--  REFERENCE TABLES
-- ────────────────────────────────────────

CREATE TABLE severity_levels (
    id          SMALLINT PRIMARY KEY,
    name        VARCHAR(20)  NOT NULL UNIQUE,   -- Critical / High / Medium / Low / Info
    score       SMALLINT     NOT NULL,           -- 1 (info) – 5 (critical)
    color_hex   CHAR(7)      NOT NULL,           -- UI hint
    response_sla_minutes INT NOT NULL DEFAULT 60
);

INSERT INTO severity_levels VALUES
(1, 'Info',     1, '#6B7280', 1440),
(2, 'Low',      2, '#3B82F6', 480),
(3, 'Medium',   3, '#F59E0B', 120),
(4, 'High',     4, '#EF4444',  30),
(5, 'Critical', 5, '#7C3AED',   5);


CREATE TABLE protocols (
    id          SMALLSERIAL PRIMARY KEY,
    name        VARCHAR(20) NOT NULL UNIQUE,  -- tcp, udp, icmp, http, ssh, …
    layer       SMALLINT,                     -- OSI layer
    default_port SMALLINT
);

INSERT INTO protocols (name, layer, default_port) VALUES
('any',   NULL, NULL),
('tcp',      4, NULL),
('udp',      4, NULL),
('icmp',     3, NULL),
('http',     7, 80),
('https',    7, 443),
('ssh',      7, 22),
('ftp',      7, 21),
('smtp',     7, 25),
('smb',      7, 445),
('rdp',      7, 3389),
('dns',      7, 53),
('mysql',    7, 3306),
('mssql',    7, 1433),
('postgres', 7, 5432),
('telnet',   7, 23),
('ldap',     7, 389),
('snmp',     7, 161);


CREATE TABLE attack_categories (
    id          SMALLSERIAL PRIMARY KEY,
    name        VARCHAR(60)  NOT NULL UNIQUE,
    description TEXT,
    parent_id   SMALLINT REFERENCES attack_categories(id)
);

INSERT INTO attack_categories (id, name, description, parent_id) VALUES
(1,  'Reconnaissance',         'Scanning and footprinting activities',              NULL),
(2,  'Brute Force',            'Repeated authentication attempts',                  NULL),
(3,  'Exploitation',           'Active vulnerability exploitation',                 NULL),
(4,  'Denial of Service',      'Service availability attacks',                      NULL),
(5,  'Lateral Movement',       'Internal network pivoting',                         NULL),
(6,  'Exfiltration',           'Data leaving the network',                          NULL),
(7,  'Command & Control',      'C2 communication channels',                         NULL),
(8,  'Web Attack',             'HTTP/HTTPS application attacks',                    NULL),
(9,  'Malware',                'Known malicious software patterns',                 NULL),
(10, 'Port Scan',              'Port/service discovery',                            1),
(11, 'SSH Brute Force',        'Repeated SSH login attempts',                       2),
(12, 'RDP Brute Force',        'Repeated RDP login attempts',                       2),
(13, 'FTP Brute Force',        'Repeated FTP login attempts',                       2),
(14, 'HTTP Brute Force',       'Repeated HTTP form/API login attempts',             2),
(15, 'SMB Brute Force',        'Repeated SMB/NTLM login attempts',                 2),
(16, 'SQL Injection',          'SQL code injected into queries',                    8),
(17, 'XSS',                    'Cross-site scripting',                              8),
(18, 'Path Traversal',         'Directory traversal attacks',                       8),
(19, 'ICMP Flood',             'ICMP-based denial of service',                      4),
(20, 'SYN Flood',              'TCP SYN flood DoS',                                 4),
(21, 'DNS Amplification',      'DNS-based DDoS amplification',                      4),
(22, 'Credential Stuffing',    'Automated use of leaked credentials',               2),
(23, 'Password Spray',         'Single password against many accounts',             2);


-- ────────────────────────────────────────
--  CORE SIGNATURES TABLE
-- ────────────────────────────────────────

CREATE TABLE signatures (
    id              SERIAL PRIMARY KEY,
    sid             INT          NOT NULL UNIQUE,   -- Suricata-compatible rule SID
    rev             SMALLINT     NOT NULL DEFAULT 1,
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    category_id     SMALLINT     NOT NULL REFERENCES attack_categories(id),
    severity_id     SMALLINT     NOT NULL REFERENCES severity_levels(id),
    protocol_id     SMALLINT     NOT NULL REFERENCES protocols(id),
    action          rule_action  NOT NULL DEFAULT 'alert',
    src_ip          VARCHAR(50)  DEFAULT 'any',   -- CIDR or 'any'
    src_port        VARCHAR(50)  DEFAULT 'any',
    dst_ip          VARCHAR(50)  DEFAULT 'any',
    dst_port        VARCHAR(50)  DEFAULT 'any',
    flow            flow_direction DEFAULT 'to_server',
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    false_positive_rate NUMERIC(5,2) DEFAULT 0.0, -- tracked from alerts
    true_positive_rate  NUMERIC(5,2) DEFAULT 0.0,
    author          VARCHAR(100),
    source          VARCHAR(100) DEFAULT 'local',  -- local | ET | snort-community | custom
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);


-- ────────────────────────────────────────
--  SIGNATURE PATTERNS (multi-pattern per rule)
-- ────────────────────────────────────────

CREATE TABLE signature_patterns (
    id              SERIAL PRIMARY KEY,
    signature_id    INT          NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    pattern_type    pattern_type NOT NULL,
    pattern         TEXT         NOT NULL,   -- PCRE string, hex bytes, or plaintext content
    offset          INT          DEFAULT 0,
    depth           INT          DEFAULT 0,  -- 0 = unlimited
    distance        INT,
    within          INT,
    negated         BOOLEAN      NOT NULL DEFAULT FALSE,
    nocase          BOOLEAN      NOT NULL DEFAULT TRUE,
    order_num       SMALLINT     NOT NULL DEFAULT 0,  -- match order within rule
    notes           TEXT
);


-- ────────────────────────────────────────
--  THRESHOLDS  (suppress noisy rules)
-- ────────────────────────────────────────

CREATE TABLE signature_thresholds (
    id              SERIAL PRIMARY KEY,
    signature_id    INT          NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    threshold_type  threshold_type NOT NULL DEFAULT 'threshold',
    track           threshold_track NOT NULL DEFAULT 'by_src',
    count           SMALLINT     NOT NULL DEFAULT 5,   -- N events …
    seconds         INT          NOT NULL DEFAULT 60   -- … within T seconds
);


-- ────────────────────────────────────────
--  CVE / REFERENCE LINKS
-- ────────────────────────────────────────

CREATE TABLE references (
    id              SERIAL PRIMARY KEY,
    signature_id    INT          NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    ref_type        VARCHAR(20)  NOT NULL DEFAULT 'url',   -- cve | url | bugtraq | osvdb
    ref_value       VARCHAR(200) NOT NULL,                 -- e.g. CVE-2023-1234
    url             TEXT
);


-- ────────────────────────────────────────
--  TAGS
-- ────────────────────────────────────────

CREATE TABLE tags (
    id      SMALLSERIAL PRIMARY KEY,
    name    VARCHAR(60) NOT NULL UNIQUE
);

CREATE TABLE signature_tags (
    signature_id INT      NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    tag_id       SMALLINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (signature_id, tag_id)
);


-- ────────────────────────────────────────
--  INDICATORS OF COMPROMISE
-- ────────────────────────────────────────

CREATE TABLE iocs (
    id              SERIAL PRIMARY KEY,
    ioc_type        ioc_type     NOT NULL,
    value           VARCHAR(500) NOT NULL,
    confidence      SMALLINT     NOT NULL DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
    source          VARCHAR(100),          -- threat feed name
    description     TEXT,
    first_seen      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    active          BOOLEAN      NOT NULL DEFAULT TRUE,
    UNIQUE (ioc_type, value)
);

CREATE TABLE ioc_signature_links (
    ioc_id          INT NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    signature_id    INT NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    PRIMARY KEY (ioc_id, signature_id)
);


-- ────────────────────────────────────────
--  WHITELIST / SUPPRESSION LIST
-- ────────────────────────────────────────

CREATE TABLE whitelist (
    id              SERIAL PRIMARY KEY,
    entry_type      ioc_type     NOT NULL,
    value           VARCHAR(200) NOT NULL,
    reason          TEXT         NOT NULL,
    signature_id    INT REFERENCES signatures(id),  -- NULL = suppress for all rules
    created_by      VARCHAR(100),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);


-- ────────────────────────────────────────
--  ALERT LOG
-- ────────────────────────────────────────

CREATE TABLE alerts (
    id              BIGSERIAL PRIMARY KEY,
    signature_id    INT          NOT NULL REFERENCES signatures(id),
    src_ip          INET         NOT NULL,
    dst_ip          INET         NOT NULL,
    src_port        SMALLINT,
    dst_port        SMALLINT,
    protocol        VARCHAR(10),
    flow_id         BIGINT,                   -- Suricata flow_id
    packet_summary  TEXT,                     -- first 256 bytes of payload (base64)
    raw_log         JSONB,                    -- full eve.json entry
    sensor_id       VARCHAR(60),              -- which probe fired
    timestamp       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    disposition     alert_disposition NOT NULL DEFAULT 'new',
    analyst_note    TEXT,
    resolved_at     TIMESTAMPTZ,
    resolved_by     VARCHAR(100)
);

CREATE INDEX idx_alerts_sig    ON alerts(signature_id);
CREATE INDEX idx_alerts_src    ON alerts(src_ip);
CREATE INDEX idx_alerts_dst    ON alerts(dst_ip);
CREATE INDEX idx_alerts_ts     ON alerts(timestamp DESC);
CREATE INDEX idx_alerts_disp   ON alerts(disposition);


-- ────────────────────────────────────────
--  HELPER VIEW — FLAT RULE EXPORT
--  (Suricata-compatible rule text generator)
-- ────────────────────────────────────────

CREATE OR REPLACE VIEW v_suricata_rules AS
SELECT
    s.id,
    s.sid,
    s.rev,
    s.action || ' ' ||
    p.name   || ' ' ||
    s.src_ip || ' ' || s.src_port || ' -> ' ||
    s.dst_ip || ' ' || s.dst_port ||
    ' (msg:"' || s.name || '"; ' ||
    'sid:' || s.sid || '; ' ||
    'rev:' || s.rev || ';)'
        AS rule_text,
    s.enabled,
    ac.name AS category,
    sl.name AS severity
FROM signatures s
JOIN protocols       p  ON p.id = s.protocol_id
JOIN attack_categories ac ON ac.id = s.category_id
JOIN severity_levels sl  ON sl.id = s.severity_id;


-- ────────────────────────────────────────
--  SEED DATA — SIGNATURES
-- ────────────────────────────────────────

INSERT INTO tags (name) VALUES
('brute-force'), ('scan'), ('web'), ('sqli'), ('xss'),
('dos'), ('c2'), ('lateral'), ('rce'), ('auth-failure'),
('slow-attack'), ('spray'), ('amplification'), ('encrypted');


-- ── SSH BRUTE FORCE ─────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000001, 'ET SCAN SSH Brute Force Attempt',
 'Multiple SSH authentication failures from a single source IP within a short window',
 11, 4, 7, 'alert', '22', 'to_server'),

(1000002, 'ET SCAN SSH Slow Brute Force (Low-Rate)',
 'Low-rate SSH auth failures designed to evade threshold-based detection. Requires longer observation window.',
 11, 3, 7, 'alert', '22', 'to_server'),

(1000003, 'ET SCAN SSH Distributed Brute Force',
 'Multiple source IPs targeting the same SSH account — credential stuffing / distributed spray',
 22, 4, 7, 'alert', '22', 'to_server');


INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(1, 'content',  'SSH-', FALSE, 'SSH banner in payload'),
(1, 'pcre',    '/Invalid\s+user|Failed\s+(password|publickey)|Authentication\s+failure/i', TRUE, NULL),
(2, 'pcre',    '/Failed\s+password\s+for/i', TRUE, 'Slow pattern — combined with threshold'),
(3, 'pcre',    '/Failed\s+password\s+for\s+\S+\s+from/i', TRUE, NULL);

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(1, 'threshold', 'by_src',  10,   60),   -- 10 failures / 60 s from same IP
(2, 'threshold', 'by_src',   5, 3600),   -- 5 failures / 1 hr (slow attack)
(3, 'threshold', 'by_dst',  20,  300);   -- 20 failures toward same target from distinct IPs


-- ── RDP BRUTE FORCE ─────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000010, 'ET SCAN RDP Brute Force Attempt',
 'Multiple failed RDP NLA/CredSSP authentication sequences from one source',
 12, 4, 2, 'alert', '3389', 'to_server'),

(1000011, 'ET SCAN RDP Password Spray',
 'One or two common passwords sprayed across many RDP targets from a single source',
 23, 4, 2, 'alert', '3389', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(4, 'hex',  '030000|0300002b', FALSE, 'X.224 Connection Request (RDP) preamble'),
(4, 'pcre', '/\x03\x00[\x00-\xff]{2}\x2b/s', FALSE, 'CredSSP NTLM negotiation byte pattern'),
(5, 'hex',  '030000', FALSE, 'X.224 preamble repeated'),
(5, 'pcre', '/NTLMSSP\x00\x01\x00\x00\x00/', FALSE, 'NTLM Type1 negotiate message');

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(4, 'threshold', 'by_src',  5,  60),
(5, 'threshold', 'by_src', 20, 300);


-- ── FTP BRUTE FORCE ─────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000020, 'ET SCAN FTP Brute Force Login Attempt',
 'Repeated FTP 530 "Login incorrect" responses indicating brute-force password attempts',
 13, 3, 8, 'alert', '21', 'to_client'),

(1000021, 'ET SCAN FTP Anonymous Login Attempt',
 'FTP login using anonymous/ftp credentials — may indicate reconnaissance or misconfiguration',
 1, 2, 8, 'alert', '21', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(6, 'content', '530 Login incorrect', TRUE,  'FTP 530 response'),
(6, 'content', '530 User ',           TRUE,  'FTP 530 user not allowed'),
(7, 'content', 'USER anonymous',      TRUE,  NULL),
(7, 'content', 'USER ftp',            TRUE,  NULL);

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(6, 'threshold', 'by_src', 8, 60);


-- ── HTTP BRUTE FORCE ────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000030, 'ET WEB HTTP Login Brute Force',
 'Rapid HTTP POST requests to common login endpoints returning 401/403',
 14, 4, 5, 'alert', '80,443,8080,8443', 'to_server'),

(1000031, 'ET WEB WordPress Admin Brute Force',
 'Repeated POST to /wp-login.php from a single source',
 14, 4, 5, 'alert', '80,443', 'to_server'),

(1000032, 'ET WEB HTTP Credential Stuffing (High Volume POSTs)',
 'Very high volume POST to auth endpoint — likely automated credential stuffing tool',
 22, 5, 5, 'alert', 'any', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(8,  'content', 'POST', FALSE, 'HTTP method'),
(8,  'pcre',    '|/login|/auth|/signin|/api/login|/session|/token|', TRUE, 'Common auth paths'),
(9,  'content', 'POST', FALSE, NULL),
(9,  'content', '/wp-login.php', TRUE, 'WordPress login path'),
(10, 'content', 'POST', FALSE, NULL),
(10, 'pcre',    '/login|/auth|/signin/', TRUE, NULL);

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(8,  'threshold', 'by_src',  20,  60),
(9,  'threshold', 'by_src',  15,  60),
(10, 'threshold', 'by_src', 100,  60);


-- ── SMB / NTLM BRUTE FORCE ──────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000040, 'ET SCAN SMB NTLM Brute Force',
 'Multiple NTLM authentication failures on SMB — possible lateral movement credential attack',
 15, 4, 2, 'alert', '445', 'to_server'),

(1000041, 'ET SCAN SMB Password Spray via NTLM',
 'Single password attempted via NTLM against many SMB targets — password spray pattern',
 23, 5, 2, 'alert', '445', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(11, 'hex',  '4e544c4d53535000', FALSE, 'NTLMSSP magic bytes'),
(11, 'pcre', '/NTLMSSP\x00\x03.{12}\xc0\x00\x00\x00/s', FALSE, 'NTLM Type3 with status bits'),
(12, 'hex',  '4e544c4d53535000', FALSE, 'NTLMSSP header'),
(12, 'pcre', '/NTLMSSP\x00\x01\x00\x00\x00/', FALSE, 'NTLM negotiate');

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(11, 'threshold', 'by_src',  5,  60),
(12, 'threshold', 'by_src', 15, 120);


-- ── PORT SCAN ───────────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000050, 'ET SCAN SYN Port Scan Detected',
 'High rate of TCP SYN packets to varying destination ports — SYN scan (nmap -sS)',
 10, 3, 2, 'alert', 'any', 'to_server'),

(1000051, 'ET SCAN NULL Scan Detected',
 'TCP packet with no flags set — NULL scan used for OS fingerprinting (nmap -sN)',
 10, 2, 2, 'alert', 'any', 'to_server'),

(1000052, 'ET SCAN XMAS Scan Detected',
 'TCP packet with FIN+PSH+URG flags set — XMAS scan (nmap -sX)',
 10, 2, 2, 'alert', 'any', 'to_server'),

(1000053, 'ET SCAN FIN Scan Detected',
 'TCP packet with only FIN flag set — stealthy port scan technique',
 10, 2, 2, 'alert', 'any', 'to_server'),

(1000054, 'ET SCAN UDP Port Scan',
 'High rate of UDP packets to varying ports from single source — UDP port scan',
 10, 2, 3, 'alert', 'any', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(13, 'byte_test', 'tcp_flags & 0x02 = 0x02', FALSE, 'SYN flag only'),
(14, 'byte_test', 'tcp_flags = 0x00',          FALSE, 'NULL — no flags'),
(15, 'byte_test', 'tcp_flags & 0x29 = 0x29',   FALSE, 'FIN+PSH+URG = XMAS'),
(16, 'byte_test', 'tcp_flags & 0x01 = 0x01',   FALSE, 'FIN only'),
(17, 'pcre',      '/^(?!.*(dns|ntp|snmp))/', TRUE, 'Non-standard UDP ports');

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(13, 'threshold', 'by_src', 100,  10),
(14, 'threshold', 'by_src',  10,  60),
(15, 'threshold', 'by_src',  10,  60),
(16, 'threshold', 'by_src',  10,  60),
(17, 'threshold', 'by_src',  50,  10);


-- ── SQL INJECTION ───────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000060, 'ET WEB SQLi UNION SELECT Attack',
 'HTTP request containing UNION SELECT patterns in URI or body — classic SQLi probe',
 16, 5, 5, 'alert', '80,443,8080,8443', 'to_server'),

(1000061, 'ET WEB SQLi Boolean-Based Blind',
 'Boolean-based blind SQL injection patterns (1=1, OR 1=1, AND 1=1)',
 16, 4, 5, 'alert', '80,443', 'to_server'),

(1000062, 'ET WEB SQLi Time-Based Blind (SLEEP/WAITFOR)',
 'Time-based blind SQLi using SLEEP() or WAITFOR DELAY functions',
 16, 5, 5, 'alert', '80,443', 'to_server'),

(1000063, 'ET WEB SQLi Error-Based (EXTRACTVALUE/UPDATEXML)',
 'Error-based SQL injection using MySQL EXTRACTVALUE or UPDATEXML functions',
 16, 5, 5, 'alert', '80,443', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(18, 'pcre', '/(\%27|\')\s*(union)\s+(all\s+)?select/i',   TRUE, 'URL encoded and raw UNION SELECT'),
(19, 'pcre', '/\s+(or|and)\s+[\'\"]?1[\'\"]?\s*=\s*[\'\"]?1/i', TRUE, '1=1 boolean'),
(19, 'pcre', '/\s+(or|and)\s+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+[\'\"]?\s*--/', TRUE, 'Comment-terminated'),
(20, 'pcre', '/sleep\s*\(\s*\d+\s*\)/i',       TRUE, 'MySQL SLEEP()'),
(20, 'pcre', '/waitfor\s+delay\s+[\'\"]0:/i',   TRUE, 'MSSQL WAITFOR'),
(21, 'pcre', '/extractvalue\s*\(/i',            TRUE, 'MySQL EXTRACTVALUE'),
(21, 'pcre', '/updatexml\s*\(/i',               TRUE, 'MySQL UPDATEXML');


-- ── XSS ─────────────────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000070, 'ET WEB Reflected XSS Attempt',
 'HTTP request containing script injection patterns in URI parameters',
 17, 4, 5, 'alert', '80,443', 'to_server'),

(1000071, 'ET WEB XSS Event Handler Injection',
 'JavaScript event handler attributes in HTTP request (onerror, onload, onclick, etc.)',
 17, 4, 5, 'alert', '80,443', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(22, 'pcre', '/<\s*script[^>]*>/i',            TRUE, 'Script open tag'),
(22, 'pcre', '/javascript\s*:/i',              TRUE, 'javascript: URI scheme'),
(22, 'pcre', '/\%3Cscript[\%20>]/i',           TRUE, 'URL-encoded script tag'),
(23, 'pcre', '/on(error|load|click|mouseover|focus|blur|input|change|submit)\s*=/i', TRUE, 'JS event handlers');


-- ── DoS / FLOOD ──────────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000080, 'ET DOS ICMP Ping Flood Detected',
 'High rate of ICMP echo requests from a single source — ping flood',
 19, 3, 4, 'alert', 'any', 'to_server'),

(1000081, 'ET DOS DNS Amplification Attack',
 'Large DNS ANY or TXT queries exploited for amplification DDoS',
 21, 5, 3, 'alert', '53', 'to_server'),

(1000082, 'ET DOS TCP SYN Flood',
 'Extremely high SYN rate from a single source — volumetric DoS',
 20, 5, 2, 'alert', 'any', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(25, 'byte_test', 'icmp_type = 8', FALSE, 'ICMP Echo Request'),
(26, 'pcre',      '/\xff\xff/', FALSE, 'DNS ANY qtype (0xFFFF)'),
(26, 'pcre',      '/\x00\x10/', FALSE, 'DNS TXT qtype (0x0010)'),
(27, 'byte_test', 'tcp_flags & 0x02 = 0x02', FALSE, 'SYN flag');

INSERT INTO signature_thresholds (signature_id, threshold_type, track, count, seconds) VALUES
(25, 'threshold', 'by_src', 1000,  5),
(26, 'threshold', 'by_src',   50, 10),
(27, 'threshold', 'by_src', 5000,  5);


-- ── PATH TRAVERSAL ───────────────────────

INSERT INTO signatures
  (sid, name, description, category_id, severity_id, protocol_id, action, dst_port, flow)
VALUES
(1000090, 'ET WEB Path Traversal Attempt',
 'HTTP request with directory traversal sequences (../, ..\\ , %2e%2e) in URI',
 18, 4, 5, 'alert', '80,443,8080', 'to_server');

INSERT INTO signature_patterns (signature_id, pattern_type, pattern, nocase, notes) VALUES
(28, 'pcre', '/\.\.(\/|\\\\)/i', TRUE, 'Literal ../'),
(28, 'pcre', '/(%2e%2e|%252e%252e)(\/|%2f|\\\\|%5c)/i', TRUE, 'Double URL-encoded'),
(28, 'pcre', '/\.\.(\/|\\\\)(etc\/passwd|windows\/win\.ini|boot\.ini)/i', TRUE, 'Targeting sensitive files');


-- ── REFERENCES / CVE ─────────────────────

INSERT INTO "references" (signature_id, ref_type, ref_value, url) VALUES
(1, 'url', 'Emerging Threats SSH Rules', 'https://rules.emergingthreats.net/'),
(4, 'url', 'MS-RDPBCGR Protocol Spec',  'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr'),
(18,'cve', 'CVE-2023-24844', 'https://nvd.nist.gov/vuln/detail/CVE-2023-24844'),
(22,'cve', 'CVE-2020-1938',  'https://nvd.nist.gov/vuln/detail/CVE-2020-1938'),
(27,'url', 'OWASP XSS Prevention', 'https://owasp.org/www-community/attacks/xss/');


-- ── IOC SEED DATA ────────────────────────

INSERT INTO iocs (ioc_type, value, confidence, source, description) VALUES
('ipv4',    '185.220.101.45',  95, 'Shodan Honeypot', 'Known SSH brute-force source — Tor exit node'),
('ipv4',    '193.32.162.120',  90, 'AbuseIPDB',       'RDP scanner / brute-force relay'),
('cidr',    '45.142.212.0/24', 85, 'GreyNoise',       'Automated SSH scanning block'),
('ipv4',    '104.248.78.25',   88, 'Shodan',          'Credential stuffing HTTP bot'),
('user_agent', 'python-requests/2.28', 70, 'local', 'Common scripted brute-force UA'),
('user_agent', 'Go-http-client/1.1',   65, 'local', 'Automated HTTP attack framework'),
('md5',     '44d88612fea8a8f36de82e1278abb02f', 99, 'VirusTotal', 'Known Mirai SSH scanner binary'),
('domain',  'update-checker.xyz', 80, 'ThreatFox', 'C2 domain for SSH botnet');


-- ── TAG ASSIGNMENTS ──────────────────────

INSERT INTO signature_tags (signature_id, tag_id)
SELECT s.id, t.id FROM signatures s, tags t WHERE
  (s.sid BETWEEN 1000001 AND 1000003 AND t.name IN ('brute-force','auth-failure','encrypted')) OR
  (s.sid BETWEEN 1000010 AND 1000011 AND t.name IN ('brute-force','auth-failure')) OR
  (s.sid BETWEEN 1000020 AND 1000021 AND t.name IN ('brute-force','auth-failure')) OR
  (s.sid BETWEEN 1000030 AND 1000032 AND t.name IN ('brute-force','web','auth-failure')) OR
  (s.sid BETWEEN 1000040 AND 1000041 AND t.name IN ('brute-force','lateral','auth-failure')) OR
  (s.sid BETWEEN 1000050 AND 1000054 AND t.name IN ('scan')) OR
  (s.sid BETWEEN 1000060 AND 1000063 AND t.name IN ('web','sqli')) OR
  (s.sid BETWEEN 1000070 AND 1000071 AND t.name IN ('web','xss')) OR
  (s.sid BETWEEN 1000080 AND 1000082 AND t.name IN ('dos','amplification')) OR
  (s.sid = 1000090                    AND t.name IN ('web'));


-- ────────────────────────────────────────
--  USEFUL QUERIES (reference comments)
-- ────────────────────────────────────────

-- Active rules by severity:
-- SELECT sl.name, COUNT(*) FROM signatures s JOIN severity_levels sl ON sl.id=s.severity_id WHERE s.enabled GROUP BY sl.name;

-- All brute-force rules:
-- SELECT s.sid, s.name, ac.name AS category FROM signatures s JOIN attack_categories ac ON ac.id=s.category_id WHERE ac.parent_id=2 OR ac.id=2;

-- Top alerted signatures (last 24h):
-- SELECT s.name, COUNT(*) AS hits FROM alerts a JOIN signatures s ON s.id=a.signature_id WHERE a.timestamp > NOW()-INTERVAL'24h' GROUP BY s.name ORDER BY hits DESC LIMIT 10;

-- Export Suricata rule text:
-- SELECT rule_text FROM v_suricata_rules WHERE enabled=TRUE ORDER BY sid;
