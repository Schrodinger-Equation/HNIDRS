-- ============================================================
--  HNIDRS — SQLite Schema
-- ============================================================

CREATE TABLE IF NOT EXISTS severity_levels (
    id      INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE,
    score   INTEGER NOT NULL,
    color_hex TEXT NOT NULL,
    response_sla_minutes INTEGER NOT NULL DEFAULT 60
);

CREATE TABLE IF NOT EXISTS protocols (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    layer        INTEGER,
    default_port INTEGER
);

CREATE TABLE IF NOT EXISTS attack_categories (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    parent_id   INTEGER REFERENCES attack_categories(id)
);

CREATE TABLE IF NOT EXISTS signatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sid             INTEGER NOT NULL UNIQUE,
    rev             INTEGER NOT NULL DEFAULT 1,
    name            TEXT NOT NULL,
    description     TEXT,
    category_id     INTEGER NOT NULL REFERENCES attack_categories(id),
    severity_id     INTEGER NOT NULL REFERENCES severity_levels(id),
    protocol_id     INTEGER NOT NULL REFERENCES protocols(id),
    action          TEXT NOT NULL DEFAULT 'alert',
    src_ip          TEXT DEFAULT 'any',
    src_port        TEXT DEFAULT 'any',
    dst_ip          TEXT DEFAULT 'any',
    dst_port        TEXT DEFAULT 'any',
    flow            TEXT DEFAULT 'to_server',
    enabled         INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS signature_patterns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    pattern_type TEXT NOT NULL,
    pattern      TEXT NOT NULL,
    negated      INTEGER NOT NULL DEFAULT 0,
    nocase       INTEGER NOT NULL DEFAULT 1,
    order_num    INTEGER NOT NULL DEFAULT 0,
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS signature_thresholds (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_id    INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    threshold_type  TEXT NOT NULL DEFAULT 'threshold',
    track           TEXT NOT NULL DEFAULT 'by_src',
    count           INTEGER NOT NULL DEFAULT 5,
    seconds         INTEGER NOT NULL DEFAULT 60
);

CREATE TABLE IF NOT EXISTS tags (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS signature_tags (
    signature_id INTEGER NOT NULL REFERENCES signatures(id) ON DELETE CASCADE,
    tag_id       INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (signature_id, tag_id)
);

CREATE TABLE IF NOT EXISTS iocs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type    TEXT NOT NULL,
    value       TEXT NOT NULL,
    confidence  INTEGER NOT NULL DEFAULT 80,
    source      TEXT,
    description TEXT,
    first_seen  REAL NOT NULL DEFAULT (strftime('%s','now')),
    last_seen   REAL NOT NULL DEFAULT (strftime('%s','now')),
    expires_at  REAL,
    active      INTEGER NOT NULL DEFAULT 1,
    UNIQUE (ioc_type, value)
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    REAL    NOT NULL DEFAULT (strftime('%s','now')),
    alert_type   TEXT    NOT NULL,
    severity     TEXT    NOT NULL DEFAULT 'medium',
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT,
    detail       TEXT,
    signature_id INTEGER REFERENCES signatures(id),
    notified     INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src  ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);

CREATE TABLE IF NOT EXISTS packet_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL DEFAULT (strftime('%s','now')),
    src_mac   TEXT,
    src_ip    TEXT,
    dst_ip    TEXT,
    src_port  INTEGER,
    dst_port  INTEGER,
    protocol  TEXT,
    length    INTEGER,
    flags     TEXT,
    payload   TEXT
);

CREATE INDEX IF NOT EXISTS idx_pkt_ts  ON packet_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pkt_src ON packet_log(src_ip);

CREATE TABLE IF NOT EXISTS ip_mac_map (
    ip         TEXT PRIMARY KEY,
    mac        TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen  REAL NOT NULL
);

-- Append-only history of every MAC seen for each IP.
-- Never updated, only inserted — used for rollback / oscillation detection.
CREATE TABLE IF NOT EXISTS ip_mac_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip        TEXT    NOT NULL,
    mac       TEXT    NOT NULL,
    seen_at   REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_mac_hist_ip ON ip_mac_history(ip, seen_at DESC);

CREATE TABLE IF NOT EXISTS traffic_avg (
    ip           TEXT PRIMARY KEY,
    avg_pps      REAL    DEFAULT 0,
    avg_bps      REAL    DEFAULT 0,
    sample_count INTEGER DEFAULT 0,
    last_updated REAL
);

CREATE TABLE IF NOT EXISTS whitelist (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ip       TEXT UNIQUE NOT NULL,
    note     TEXT,
    added_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS blacklist (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ip       TEXT UNIQUE NOT NULL,
    reason   TEXT,
    added_at REAL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS discovered_devices (
    ip         TEXT PRIMARY KEY,
    mac        TEXT,
    hostname   TEXT,
    vendor     TEXT,
    first_seen REAL,
    last_seen  REAL
);
