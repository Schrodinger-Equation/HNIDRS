"""
arp_spoof.py — Detects ARP spoofing / impersonation by tracking
IP → MAC mappings and alerting on changes.

Improvements over naive single-record approach:
  - MAC change history stored in ip_mac_history (append-only) for rollback detection
  - Oscillation detection: A→B→A pattern within a configurable window
  - Alert deduplication: same (ip, old_mac, new_mac) suppressed within DEDUP_WINDOW seconds
  - Flood guard: rapid MAC changes within FLOOD_WINDOW seconds treated as a flood attack
  - Gratuitous ARP: known-legitimate sources (GARP_WHITELIST) are not alerted
"""

import time
import threading
import logging

log = logging.getLogger("detection.arp_spoof")

_lock      = threading.Lock()
_init_lock = threading.Lock()
_am        = None
_db        = None

# --- Tuneable constants ------------------------------------------------------

# Suppress duplicate (ip, old_mac→new_mac) alerts within this many seconds
DEDUP_WINDOW = 60

# If the same IP changes MAC more than FLOOD_THRESHOLD times within
# FLOOD_WINDOW seconds, fire a single flood-level alert instead of per-change alerts
FLOOD_WINDOW    = 10   # seconds
FLOOD_THRESHOLD = 5    # changes

# How far back (seconds) to look in history when checking for A→B→A rollback
OSCILLATION_WINDOW = 120

# MACs that are known to send legitimate gratuitous ARPs (e.g. gateway, HSRP/VRRP)
# Populate from config or admin UI as needed
GARP_WHITELIST: set = set()

# --- In-memory state (guarded by _lock) --------------------------------------

# {ip: {(old_mac, new_mac): last_alert_ts}}
_dedup: dict = {}

# {ip: [change_ts, ...]}  — rolling window for flood detection
_change_times: dict = {}


def _load():
    global _am, _db
    if _am is not None and _db is not None:
        return
    with _init_lock:
        if _am is None or _db is None:
            from core import alert_manager
            from db   import db_manager
            _am = alert_manager
            _db = db_manager


def _fire(alert_type, severity, src_ip, detail):
    _am.fire(
        alert_type = alert_type,
        severity   = severity,
        src_ip     = src_ip,
        detail     = detail,
        protocol   = "ARP",
    )
    log.warning("[ARPSpoof] %s", detail)


def _is_dedup(ip, old_mac, new_mac) -> tuple[bool, int]:
    """
    Return (is_duplicate, hit_count).
    is_duplicate=True means this pair was already alerted within DEDUP_WINDOW.
    hit_count is how many times it was suppressed since the last real alert;
    non-zero only when the window just expired (i.e. is_duplicate=False and hits>0).
    """
    now = time.time()
    key = (old_mac, new_mac)
    bucket = _dedup.setdefault(ip, {})
    entry = bucket.get(key)
    if entry and (now - entry["ts"]) < DEDUP_WINDOW:
        entry["hits"] += 1
        return True, 0
    # window expired or first time — read accumulated hits before resetting
    hits = entry["hits"] if entry else 0
    bucket[key] = {"ts": now, "hits": 0}
    return False, hits



def _record_change(ip) -> bool:
    """
    Record a MAC change timestamp for `ip`.
    Returns True if the change count within FLOOD_WINDOW exceeds FLOOD_THRESHOLD.
    """
    now = time.time()
    times = _change_times.setdefault(ip, [])
    times.append(now)
    # prune old entries
    cutoff = now - FLOOD_WINDOW
    _change_times[ip] = [t for t in times if t >= cutoff]
    return len(_change_times[ip]) > FLOOD_THRESHOLD


def _check_oscillation(ip, current_mac) -> tuple[bool, str | None]:
    """
    Return (is_oscillating, intruder_mac).
    intruder_mac is the B MAC in the A→B→A pattern — the attacker's MAC.
    """
    history = _db.get_mac_history(ip, limit=20)
    if len(history) < 2:
        return False, None
    cutoff = time.time() - OSCILLATION_WINDOW
    recent = [h["mac"] for h in history if h["seen_at"] >= cutoff]
    if recent.count(current_mac) <= 1:
        return False, None
    # Find the B MAC: any MAC between two occurrences of current_mac
    # recent is newest-first; find the MACs sandwiched between the two current_mac hits
    first = recent.index(current_mac)           # newest occurrence (index 0 = most recent)
    second = recent.index(current_mac, first+1) # earlier occurrence
    intruders = list(dict.fromkeys(recent[first+1:second]))  # unique MACs between them
    intruder_mac = intruders[0] if intruders else None
    return True, intruder_mac



def process(pkt: dict):
    _load()

    op      = pkt.get("op")      # 1=who-has (request), 2=is-at (reply)
    src_ip  = pkt.get("src_ip")
    src_mac = pkt.get("src_mac")

    if not src_ip or not src_mac:
        return

    if src_ip in ("0.0.0.0", "255.255.255.255"):
        return

    with _lock:
        old_mac = _db.upsert_ip_mac(src_ip, src_mac)
        if old_mac is not None:
            # --- Flood guard -------------------------------------------------
            if _record_change(src_ip):
                is_dup, hits = _is_dedup(src_ip, "__flood__", "__flood__")
                if not is_dup:
                    repeat_info = f", repeated {hits}x while suppressed" if hits else ""
                    _fire(
                        "arp_spoof", "critical", src_ip,
                        f"ARP MAC-change flood on {src_ip}: "
                        f">{FLOOD_THRESHOLD} changes in {FLOOD_WINDOW}s"
                        f"{repeat_info} — baseline may be poisoned",
                    )
                return  # suppress per-change noise during flood

            # --- Deduplication -----------------------------------------------
            is_dup, hits = _is_dedup(src_ip, old_mac, src_mac)
            if is_dup:
                return

            # --- Oscillation / rollback detection ----------------------------
            oscillating, intruder_mac = _check_oscillation(src_ip, src_mac)
            if oscillating:
                repeat_info   = f" (pair repeated {hits}x before this alert)" if hits else ""
                intruder_info = f", attacker MAC={intruder_mac}" if intruder_mac else ""
                _fire(
                    "arp_spoof", "critical", src_ip,
                    f"ARP rollback spoofing: {src_ip} oscillating MACs "
                    f"(legitimate={src_mac}{intruder_info}, op={op}){repeat_info}",
                )
                return

            # --- Standard MAC change -----------------------------------------
            repeat_info = f" (pair repeated {hits}x before this alert)" if hits else ""
            _fire(
                "arp_spoof", "critical", src_ip,
                f"ARP spoofing: {src_ip} changed MAC {old_mac} → {src_mac} "
                f"(op={op}){repeat_info}",
            )
            return

    # --- Gratuitous ARP (op=2, dst_ip == src_ip) -----------------------------
    # This block is intentionally outside the MAC-change block above.
    # It only runs when MAC did NOT change (old_mac == src_mac or new IP),
    # because all MAC-change paths return early.
    # Scenario: attacker already poisoned the baseline (MAC updated to theirs),
    # then keeps broadcasting GARPs with that same MAC — no MAC change is seen,
    # but the unsolicited is-at still indicates impersonation.
    if op == 2:
        dst_ip = pkt.get("dst_ip", "")
        if dst_ip in (src_ip, "0.0.0.0", "255.255.255.255"):
            if src_mac in GARP_WHITELIST:
                return  # known-legitimate GARP sender (gateway, HSRP/VRRP)
            is_dup, hits = _is_dedup(src_ip, "__garp__", "__garp__")
            if not is_dup:
                repeat_info = f" (repeated {hits}x while suppressed)" if hits else ""
                _fire(
                    "arp_spoof", "high", src_ip,
                    f"Gratuitous ARP from {src_ip} ({src_mac})"
                    f"{repeat_info} — possible impersonation",
                )
