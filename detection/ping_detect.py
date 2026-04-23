"""
ping_detect.py — Detects two ICMP-based attacks:

  1. Ping Sweep  — one source sends ICMP echo-requests to many distinct
                   destination IPs within a short window.
                   Indicates network reconnaissance / host discovery.

  2. Ping Flood  — one source sends a large volume of ICMP packets to
                   a single destination within a short window.
                   Indicates DoS / stress testing.
"""

import time
import threading
import logging
from collections import defaultdict

import config

log = logging.getLogger("detection.ping_detect")

_lock         = threading.Lock()
_init_lock    = threading.Lock()
_am           = None
_db           = None

# ── In-memory state (all guarded by _lock) ────────────────────────────────────

# Ping sweep: {src_ip: {dst_ip: last_seen_ts}}
_sweep_targets: dict = defaultdict(dict)

# Ping flood + sustained: {(src_ip, dst_ip): [timestamps]}
_flood_times: dict = defaultdict(list)

# Dedup: {key: last_alert_ts}
_dedup: dict = {}
DEDUP_WINDOW = 30  # seconds


def _load():
    """Lazy-load shared modules. Uses a separate lock so _lock is never held during import."""
    global _am, _db
    if _am is not None and _db is not None:
        return
    with _init_lock:
        if _am is None or _db is None:
            from core import alert_manager
            from db   import db_manager
            _am = alert_manager
            _db = db_manager


def _is_dedup(key) -> bool:
    """Must be called with _lock already held."""
    now = time.time()
    last = _dedup.get(key)
    if last and (now - last) < DEDUP_WINDOW:
        return True
    _dedup[key] = now
    return False


def process(pkt: dict):
    if pkt.get("type") != "ICMP":
        return

    _load()  # outside _lock — import can be slow

    icmp_type = pkt.get("icmp_type")
    src_ip    = pkt.get("src_ip")
    dst_ip    = pkt.get("dst_ip")
    now       = time.time()

    if not src_ip or not dst_ip:
        return

    if src_ip == dst_ip:
        return

    # Skip self-generated traffic (this device's own IPs)
    if dst_ip in ("127.0.0.1", "::1"):
        return

    with _lock:
        # ── Ping Sweep (icmp_type=8 = echo request only) ──────────────────────
        if icmp_type == 8:
            sweep_cutoff = now - config.PING_SWEEP_WINDOW
            targets = _sweep_targets[src_ip]
            targets[dst_ip] = now
            # Prune stale entries
            _sweep_targets[src_ip] = {ip: ts for ip, ts in targets.items()
                                       if ts >= sweep_cutoff}
            unique_targets = len(_sweep_targets[src_ip])

            if unique_targets >= config.PING_SWEEP_THRESHOLD:
                # Always reset counter so it doesn't stay pinned above threshold
                _sweep_targets[src_ip] = {}
                if not _is_dedup(f"sweep:{src_ip}"):
                    detail = (f"Ping sweep from {src_ip}: "
                              f"{unique_targets} hosts probed in "
                              f"{config.PING_SWEEP_WINDOW}s — possible reconnaissance")
                    _am.fire(
                        alert_type = "ping_sweep",
                        severity   = "high",
                        src_ip     = src_ip,
                        detail     = detail,
                        protocol   = "ICMP",
                    )
                    log.warning("[PingDetect] %s", detail)

        # ── Ping Flood + Sustained ping (echo-requests only, icmp_type=8) ───────
        # Counting only type=8 prevents the PC's own echo-replies (type=0)
        # from appearing as a flood in the opposite direction.
        if icmp_type != 8:
            return
        flood_key = (src_ip, dst_ip)
        times = _flood_times[flood_key]
        times.append(now)

        # Use the larger window so one list covers both checks
        max_window   = max(config.PING_FLOOD_WINDOW, config.PING_SUSTAINED_WINDOW)
        pruned       = [t for t in times if t >= now - max_window]
        _flood_times[flood_key] = pruned

        flood_count     = sum(1 for t in pruned if t >= now - config.PING_FLOOD_WINDOW)
        sustained_count = sum(1 for t in pruned if t >= now - config.PING_SUSTAINED_WINDOW)

        if flood_count >= config.PING_FLOOD_THRESHOLD:
            _flood_times[flood_key] = []
            if not _is_dedup(f"flood:{src_ip}:{dst_ip}"):
                detail = (f"Ping flood: {src_ip} → {dst_ip}: "
                          f"{flood_count} ICMP packets in {config.PING_FLOOD_WINDOW}s"
                          f" — possible DoS")
                _am.fire(
                    alert_type = "ping_flood",
                    severity   = "critical",
                    src_ip     = src_ip,
                    dst_ip     = dst_ip,
                    detail     = detail,
                    protocol   = "ICMP",
                )
                log.warning("[PingDetect] %s", detail)

        elif sustained_count >= config.PING_SUSTAINED_THRESHOLD:
            _flood_times[flood_key] = []
            if not _is_dedup(f"sustained:{src_ip}:{dst_ip}"):
                detail = (f"Sustained ping: {src_ip} → {dst_ip}: "
                          f"{sustained_count} ICMP packets in {config.PING_SUSTAINED_WINDOW}s"
                          f" — continuous ping detected")
                _am.fire(
                    alert_type = "ping_flood",
                    severity   = "medium",
                    src_ip     = src_ip,
                    dst_ip     = dst_ip,
                    detail     = detail,
                    protocol   = "ICMP",
                )
                log.warning("[PingDetect] %s", detail)
