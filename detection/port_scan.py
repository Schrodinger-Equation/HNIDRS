"""
port_scan.py — Detects SYN scans, NULL scans, XMAS scans, FIN scans.
Uses a sliding window per source IP.
"""

import time
import threading
from collections import defaultdict
import logging

log = logging.getLogger("detection.port_scan")

# {src_ip: [(timestamp, dst_port, flags), ...]}
_windows: dict = defaultdict(list)
_lock = threading.Lock()
_init_lock = threading.Lock()

# Dedup: {src_ip: last_alert_ts}
_dedup: dict = {}
DEDUP_WINDOW = 30  # seconds

# Local IPs — forwarded scan packets carry laptop's IP as src
_LOCAL_IPS: set = set()

def _get_local_ips() -> set:
    ips = {"127.0.0.1", "0.0.0.0"}
    try:
        import subprocess, re
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL)
        ips.update(re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', out))
    except Exception:
        pass
    return ips

_LOCAL_IPS = _get_local_ips()

# Lazy imports
_am = None
_cfg = None

def _load():
    global _am, _cfg
    if _am is not None and _cfg is not None:
        return
    with _init_lock:
        if _am is None or _cfg is None:
            from core import alert_manager
            import config
            _am  = alert_manager
            _cfg = config


def _classify_flags(flags: str) -> str | None:
    """Return scan type from TCP flags string, or None if normal."""
    if flags == "S":       return "SYN"
    if flags == "":        return "NULL"
    if "F" in flags and "P" in flags and "U" in flags: return "XMAS"
    if flags == "F":       return "FIN"
    return None


def process(pkt: dict):
    _load()

    flags    = pkt.get("flags", "")
    scan_type = _classify_flags(flags)
    if scan_type is None:
        return

    src_ip   = pkt.get("src_ip")
    dst_port = pkt.get("dst_port", 0)
    now      = pkt.get("timestamp") or time.time()

    if not src_ip:
        return

    cfg_window    = _cfg.PORT_SCAN_WINDOW
    cfg_threshold = _cfg.PORT_SCAN_THRESHOLD

    fired = False
    unique_count = 0
    fired_scan_type = scan_type
    is_local = src_ip in _LOCAL_IPS

    with _lock:
        events = _windows[src_ip]
        cutoff = now - cfg_window
        events = [(ts, dp, ft) for ts, dp, ft in events if ts >= cutoff]
        events.append((now, dst_port, scan_type))
        _windows[src_ip] = events

        unique_ports = {dp for _, dp, _ in events}

        if len(unique_ports) >= cfg_threshold:
            unique_count = len(unique_ports)
            fired_scan_type = scan_type
            _windows[src_ip] = []

            last = _dedup.get(src_ip)
            if not last or (now - last) >= DEDUP_WINDOW:
                _dedup[src_ip] = now
                fired = True

    if fired:
        note = (" [NOTE: src is this device — may be forwarded from a routed scan]"
                if is_local else "")
        detail = (f"{fired_scan_type} scan: {unique_count} unique ports "
                  f"in {cfg_window}s{note}")
        _am.fire(
            alert_type = "port_scan",
            severity   = "high" if fired_scan_type == "SYN" else "medium",
            src_ip     = src_ip,
            dst_ip     = pkt.get("dst_ip"),
            protocol   = "TCP",
            detail     = detail,
        )
        log.warning("[PortScan] %s from %s", detail, src_ip)
