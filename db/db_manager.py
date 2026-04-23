"""
db_manager.py — Thread-safe SQLite access for HNIDRS.
One connection per thread via threading.local().
"""

import sqlite3
import threading
import time
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

_local = threading.local()


def _get_conn():
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """Create schema tables. Safe to call multiple times."""
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    conn = _get_conn()
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path) as f:
        conn.executescript(f.read())
    conn.commit()
    print("[DB] Schema ready.")


# ── Whitelist / Blacklist ─────────────────────────────────────────────────────

_wl_cache: dict = {}   # {ip: (result_bool, expires_at)}
_bl_cache: dict = {}
_LIST_CACHE_TTL = 5    # seconds — new whitelist entries take effect within 5s

def _fresh_read(query, params=()):
    """Execute a single read on a throw-away connection — always sees latest committed data."""
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    try:
        return conn.execute(query, params).fetchone()
    finally:
        conn.close()

def is_whitelisted(ip):
    now = time.time()
    entry = _wl_cache.get(ip)
    if entry and now < entry[1]:
        return entry[0]
    result = _fresh_read("SELECT 1 FROM whitelist WHERE ip=?", (ip,)) is not None
    _wl_cache[ip] = (result, now + _LIST_CACHE_TTL)
    return result

def is_blacklisted(ip):
    now = time.time()
    entry = _bl_cache.get(ip)
    if entry and now < entry[1]:
        return entry[0]
    result = _fresh_read("SELECT 1 FROM blacklist WHERE ip=?", (ip,)) is not None
    _bl_cache[ip] = (result, now + _LIST_CACHE_TTL)
    return result

def add_whitelist(ip, note=""):
    conn = _get_conn()
    conn.execute("INSERT OR IGNORE INTO whitelist (ip, note) VALUES (?,?)", (ip, note))
    conn.commit()
    _wl_cache.pop(ip, None)  # invalidate immediately

def remove_whitelist(ip):
    conn = _get_conn()
    conn.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
    conn.commit()
    _wl_cache.pop(ip, None)

def add_blacklist(ip, reason=""):
    conn = _get_conn()
    conn.execute("INSERT OR IGNORE INTO blacklist (ip, reason) VALUES (?,?)", (ip, reason))
    conn.commit()
    _bl_cache.pop(ip, None)

def remove_blacklist(ip):
    conn = _get_conn()
    conn.execute("DELETE FROM blacklist WHERE ip=?", (ip,))
    conn.commit()
    _bl_cache.pop(ip, None)

def get_whitelist():
    cur = _get_conn().execute("SELECT * FROM whitelist ORDER BY added_at DESC")
    return [dict(r) for r in cur.fetchall()]

def get_blacklist():
    cur = _get_conn().execute("SELECT * FROM blacklist ORDER BY added_at DESC")
    return [dict(r) for r in cur.fetchall()]


# ── Alerts ────────────────────────────────────────────────────────────────────

def insert_alert(alert_type, severity, src_ip=None, dst_ip=None,
                 src_port=None, dst_port=None, protocol=None,
                 detail=None, signature_id=None):
    conn = _get_conn()
    conn.execute(
        """INSERT INTO alerts
           (alert_type, severity, src_ip, dst_ip,
            src_port, dst_port, protocol, detail, signature_id)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (alert_type, severity, src_ip, dst_ip,
         src_port, dst_port, protocol, detail, signature_id)
    )
    conn.commit()
    # Return the new row id
    cur = conn.execute("SELECT last_insert_rowid()")
    return cur.fetchone()[0]

def get_alerts(limit=200, alert_type=None, src_ip=None, since=None):
    q = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if alert_type:
        q += " AND alert_type=?"; params.append(alert_type)
    if src_ip:
        q += " AND src_ip=?"; params.append(src_ip)
    if since:
        q += " AND timestamp>?"; params.append(since)  # exclusive — skip already-seen alerts
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    cur = _get_conn().execute(q, params)
    return [dict(r) for r in cur.fetchall()]

def clear_alerts():
    conn = _get_conn()
    conn.execute("DELETE FROM alerts")
    conn.commit()

def mark_alerted(alert_id):
    conn = _get_conn()
    conn.execute("UPDATE alerts SET notified=1 WHERE id=?", (alert_id,))
    conn.commit()

def get_pending_notifications():
    cur = _get_conn().execute(
        "SELECT * FROM alerts WHERE notified=0 ORDER BY timestamp ASC LIMIT 50")
    return [dict(r) for r in cur.fetchall()]


# ── Packet log ────────────────────────────────────────────────────────────────

def log_packet(src_mac,src_ip, dst_ip, src_port, dst_port,
               protocol, length, flags="", payload=""):
    conn = _get_conn()
    conn.execute(
        """INSERT INTO packet_log
           (src_mac, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (src_mac,src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload)
    )
    conn.commit()

def get_packets(limit=500, src_ip=None, protocol=None, since=None, http_only=False):
    q = "SELECT * FROM packet_log WHERE 1=1"
    params = []
    if src_ip:
        q += " AND src_ip=?"; params.append(src_ip)
    if protocol:
        q += " AND protocol=?"; params.append(protocol)
    if since:
        q += " AND timestamp>=?"; params.append(since)
    if http_only:
        q += " AND (dst_port IN (80,8080,8443) OR src_port IN (80,8080,8443))"
    q += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    cur = _get_conn().execute(q, params)
    return [dict(r) for r in cur.fetchall()]


# ── ARP / IP-MAC map ─────────────────────────────────────────────────────────

def get_ip_mac(ip):
    cur = _get_conn().execute("SELECT * FROM ip_mac_map WHERE ip=?", (ip,))
    r = cur.fetchone()
    return dict(r) if r else None

def upsert_ip_mac(ip, mac):
    conn = _get_conn()
    now = time.time()
    existing = get_ip_mac(ip)
    if existing is None:
        conn.execute(
            "INSERT INTO ip_mac_map (ip, mac, first_seen, last_seen) VALUES (?,?,?,?)",
            (ip, mac, now, now))
        conn.execute(
            "INSERT INTO ip_mac_history (ip, mac, seen_at) VALUES (?,?,?)",
            (ip, mac, now))
        conn.commit()
        return None   # new entry — no old MAC to compare
    else:
        old_mac = existing["mac"]
        conn.execute(
            "UPDATE ip_mac_map SET mac=?, last_seen=? WHERE ip=?",
            (mac, now, ip))
        if old_mac != mac:
            conn.execute(
                "INSERT INTO ip_mac_history (ip, mac, seen_at) VALUES (?,?,?)",
                (ip, mac, now))
        conn.commit()
        return old_mac if old_mac != mac else None

def get_mac_history(ip, limit=20):
    """Return the last `limit` MAC entries for an IP, newest first."""
    cur = _get_conn().execute(
        "SELECT mac, seen_at FROM ip_mac_history WHERE ip=? ORDER BY seen_at DESC LIMIT ?",
        (ip, limit))
    return [dict(r) for r in cur.fetchall()]

def get_all_ip_mac():
    cur = _get_conn().execute("SELECT * FROM ip_mac_map ORDER BY last_seen DESC")
    return [dict(r) for r in cur.fetchall()]


# ── Traffic averages ──────────────────────────────────────────────────────────

def update_traffic_avg(ip, pps, bps):
    conn = _get_conn()
    existing = conn.execute(
        "SELECT * FROM traffic_avg WHERE ip=?", (ip,)).fetchone()
    now = time.time()
    if existing is None:
        conn.execute(
            """INSERT INTO traffic_avg (ip, avg_pps, avg_bps, sample_count, last_updated)
               VALUES (?,?,?,1,?)""", (ip, pps, bps, now))
    else:
        n = existing["sample_count"]
        new_pps = (existing["avg_pps"] * n + pps) / (n + 1)
        new_bps = (existing["avg_bps"] * n + bps) / (n + 1)
        conn.execute(
            """UPDATE traffic_avg
               SET avg_pps=?, avg_bps=?, sample_count=?, last_updated=?
               WHERE ip=?""",
            (new_pps, new_bps, n + 1, now, ip))
    conn.commit()

def get_traffic_avg(ip):
    cur = _get_conn().execute("SELECT * FROM traffic_avg WHERE ip=?", (ip,))
    r = cur.fetchone()
    return dict(r) if r else None

def get_all_traffic_avgs(limit=100):
    cur = _get_conn().execute(
        "SELECT * FROM traffic_avg ORDER BY avg_pps DESC LIMIT ?", (limit,))
    return [dict(r) for r in cur.fetchall()]


# ── Discovered devices ────────────────────────────────────────────────────────

def upsert_device(ip, mac=None, hostname=None, vendor=None):
    conn = _get_conn()
    now = time.time()
    existing = conn.execute(
        "SELECT 1 FROM discovered_devices WHERE ip=?", (ip,)).fetchone()
    if existing is None:
        conn.execute(
            """INSERT INTO discovered_devices
               (ip, mac, hostname, vendor, first_seen, last_seen)
               VALUES (?,?,?,?,?,?)""",
            (ip, mac, hostname, vendor, now, now))
    else:
        conn.execute(
            """UPDATE discovered_devices
               SET mac=COALESCE(?,mac), hostname=COALESCE(?,hostname),
                   vendor=COALESCE(?,vendor), last_seen=?
               WHERE ip=?""",
            (mac, hostname, vendor, now, ip))
    conn.commit()

def get_devices():
    cur = _get_conn().execute(
        "SELECT * FROM discovered_devices ORDER BY last_seen DESC")
    return [dict(r) for r in cur.fetchall()]


# ── Signatures ────────────────────────────────────────────────────────────────

def get_all_signatures(enabled_only=True):
    # JOIN protocols so signature engine can filter by protocol name
    q = """SELECT s.*, p.name AS protocol_name
           FROM signatures s
           JOIN protocols p ON p.id = s.protocol_id"""
    if enabled_only:
        q += " WHERE s.enabled=1"
    cur = _get_conn().execute(q)
    return [dict(r) for r in cur.fetchall()]

def get_patterns_for_sig(sig_id):
    cur = _get_conn().execute(
        "SELECT * FROM signature_patterns WHERE signature_id=? ORDER BY order_num",
        (sig_id,))
    return [dict(r) for r in cur.fetchall()]

def get_threshold_for_sig(sig_id):
    cur = _get_conn().execute(
        "SELECT * FROM signature_thresholds WHERE signature_id=? LIMIT 1",
        (sig_id,))
    r = cur.fetchone()
    return dict(r) if r else None

def get_iocs(ioc_type=None, active_only=True):
    q = "SELECT * FROM iocs WHERE 1=1"
    params = []
    if active_only:
        q += " AND active=1"
    if ioc_type:
        q += " AND ioc_type=?"; params.append(ioc_type)
    cur = _get_conn().execute(q, params)
    return [dict(r) for r in cur.fetchall()]


# ── Logs by IP (webapp helper) ────────────────────────────────────────────────

def get_logs_by_ip(ip, limit=200):
    packets = get_packets(limit=limit // 2, src_ip=ip)
    alerts  = get_alerts(limit=limit // 2, src_ip=ip)
    return {"packets": packets, "alerts": alerts}
