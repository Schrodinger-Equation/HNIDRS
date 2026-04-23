"""
brute_force.py — Detects repeated SYN attempts to auth-heavy ports
(SSH, RDP, FTP, Telnet, SMB, MySQL, etc.) from a single source IP.
"""

import time
import threading
from collections import defaultdict
import logging

log = logging.getLogger("detection.brute_force")

# Ports considered brute-force targets
BRUTE_PORTS = {
    22:   ("SSH",      "high"),
    21:   ("FTP",      "medium"),
    23:   ("Telnet",   "medium"),
    3389: ("RDP",      "high"),
    445:  ("SMB",      "high"),
    3306: ("MySQL",    "medium"),
    5432: ("Postgres", "medium"),
    1433: ("MSSQL",    "medium"),
    6379: ("Redis",    "high"),
    27017:("MongoDB",  "high"),
    5900: ("VNC",      "medium"),
    25:   ("SMTP",     "low"),
    110:  ("POP3",     "low"),
    143:  ("IMAP",     "low"),
}

# {(src_ip, dst_port): [timestamps]}
_windows: dict = defaultdict(list)
_lock = threading.Lock()

_am  = None
_cfg = None
_init_lock = threading.Lock()

# Dedup: {(src_ip, dst_port): last_alert_ts}
_dedup: dict = {}
DEDUP_WINDOW = 30  # seconds

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


def process(pkt: dict):
    _load()

    dst_port = pkt.get("dst_port")
    if dst_port not in BRUTE_PORTS:
        return

    flags = pkt.get("flags", "")
    if "S" not in flags:      # Only count SYN packets
        return

    src_ip   = pkt.get("src_ip")
    now      = pkt.get("timestamp") or time.time()

    if not src_ip:
        return

    key      = (src_ip, dst_port)
    svc_name, severity = BRUTE_PORTS[dst_port]

    cfg_window    = _cfg.BRUTE_FORCE_WINDOW
    cfg_threshold = _cfg.BRUTE_FORCE_THRESHOLD

    fired = False
    count = 0
    with _lock:
        cutoff = now - cfg_window
        ts_list = _windows[key]
        ts_list = [t for t in ts_list if t >= cutoff]
        ts_list.append(now)
        _windows[key] = ts_list
        count = len(ts_list)

        if count >= cfg_threshold:
            _windows[key] = []
            last = _dedup.get(key)
            if not last or (now - last) >= DEDUP_WINDOW:
                _dedup[key] = now
                fired = True

    if fired:
        detail = (f"Brute-force on {svc_name} (port {dst_port}): "
                  f"{count} SYNs in {cfg_window}s")
        _am.fire(
            alert_type = "brute_force",
            severity   = severity,
            src_ip     = src_ip,
            dst_ip     = pkt.get("dst_ip"),
            src_port   = pkt.get("src_port"),
            dst_port   = dst_port,
            protocol   = "TCP",
            detail     = detail,
        )
        log.warning("[BruteForce] %s from %s", detail, src_ip)
