"""
anomaly.py — Detects sudden traffic spikes per IP by comparing
current packet rate against a rolling 1-hour average stored in DB.

Uses a lightweight in-memory bucket (1-second resolution).
Every 60 s it flushes the bucket → updates the DB average →
checks spike condition.
"""

import time
import threading
from collections import defaultdict
import logging

log = logging.getLogger("detection.anomaly")

# In-memory counters: {ip: {"pkts": int, "bytes": int, "window_start": float}}
_counters: dict = defaultdict(lambda: {"pkts": 0, "bytes": 0, "window_start": time.time()})
_lock = threading.Lock()

FLUSH_INTERVAL = 60   # seconds — flush counters to DB and check

_last_flush = time.time()
_am  = None
_db  = None
_cfg = None
_init_lock = threading.Lock()

def _load():
    global _am, _db, _cfg
    if _am is not None and _db is not None and _cfg is not None:
        return
    with _init_lock:
        if _am is None or _db is None or _cfg is None:
            from core import alert_manager
            from db   import db_manager
            import config
            _am  = alert_manager
            _db  = db_manager
            _cfg = config


def _flush():
    global _last_flush
    _load()
    now = time.time()
    snapshot = {}

    with _lock:
        for ip, c in _counters.items():
            elapsed = max(now - c["window_start"], 1)
            snapshot[ip] = {
                "pps": c["pkts"] / elapsed,
                "bps": c["bytes"] / elapsed,
                "pkts": c["pkts"],
            }
        _counters.clear()

    _last_flush = now

    for ip, stats in snapshot.items():
        pps = stats["pps"]
        bps = stats["bps"]

        # Update rolling average in DB
        _db.update_traffic_avg(ip, pps, bps)

        # Check spike
        avg = _db.get_traffic_avg(ip)
        if avg and avg["sample_count"] >= 3:     # need at least 3 samples for a baseline
            threshold_pps = avg["avg_pps"] * _cfg.ANOMALY_MULTIPLIER
            if pps > threshold_pps and pps > 10:  # ignore tiny rates
                detail = (f"Traffic anomaly: {ip} current={pps:.1f} pps "
                          f"vs avg={avg['avg_pps']:.1f} pps "
                          f"(×{_cfg.ANOMALY_MULTIPLIER})")
                _am.fire(
                    alert_type = "anomaly",
                    severity   = "high",
                    src_ip     = ip,
                    detail     = detail,
                    protocol   = "ANY",
                )
                log.warning(f"[Anomaly] {detail}")


def process(pkt: dict):
    _load()
    global _last_flush

    src_ip = pkt.get("src_ip")
    if not src_ip:
        return

    length = pkt.get("length", 0)

    with _lock:
        c = _counters[src_ip]
        c["pkts"]  += 1
        c["bytes"] += length

    now = time.time()
    if now - _last_flush >= FLUSH_INTERVAL:
        _flush()
