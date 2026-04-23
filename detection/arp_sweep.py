"""
arp_sweep.py — Detects ARP-based host discovery (ARP sweep).

Two detection methods:
  1. Packet-based — inspects live ARP who-has (op=1) packets from the wire.
     Catches sweeps FROM OTHER devices. Direction: attacker → network.

  2. ARP-cache poll — reads /proc/net/arp every 2s and detects when many
     new entries appear rapidly. Catches sweeps FROM THIS DEVICE (e.g.
     local nmap -sn) which Scapy cannot capture because locally-generated
     packets bypass the wire capture layer on Linux.
"""

import time
import socket
import threading
import logging
from collections import defaultdict

import config


def _get_local_ips() -> set:
    """Return all IPs assigned to this machine's interfaces."""
    ips = {"127.0.0.1", "0.0.0.0"}
    try:
        import subprocess
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show"], text=True, stderr=subprocess.DEVNULL)
        import re
        ips.update(re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', out))
    except Exception:
        pass
    return ips


_LOCAL_IPS: set = _get_local_ips()

log = logging.getLogger("detection.arp_sweep")

_lock      = threading.Lock()
_init_lock = threading.Lock()
_am        = None

# Packet-based state: {src_mac: {dst_ip: last_seen_ts}}
_sweep_targets: dict = defaultdict(dict)

# Dedup: {key: last_alert_ts}
_dedup: dict = {}
DEDUP_WINDOW = 60  # seconds

# ARP cache poll state
_arp_cache_prev: set   = set()
_arp_cache_window: list = []   # [(ts, ip), ...]
_poll_thread = None
_last_wire_sweep_ts: float = 0  # set when packet-based fires; suppresses cache-poll


def _load():
    global _am
    if _am is not None:
        return
    with _init_lock:
        if _am is None:
            from core import alert_manager
            _am = alert_manager


def _local_ip() -> str:
    """Return this machine's primary non-loopback IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _is_dedup(key) -> bool:
    """Must be called with _lock already held."""
    now = time.time()
    last = _dedup.get(key)
    if last and (now - last) < DEDUP_WINDOW:
        return True
    _dedup[key] = now
    return False


def _read_arp_cache() -> set:
    """Return set of all IPs in /proc/net/arp (any state — 0x0=incomplete counts during sweep)."""
    ips = set()
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ips.add(parts[0])
    except Exception:
        pass
    return ips


def _poll_arp_cache():
    """Background thread: poll /proc/net/arp to detect local sweeps."""
    global _arp_cache_prev
    _load()
    _arp_cache_prev = _read_arp_cache()

    while True:
        time.sleep(2)
        current  = _read_arp_cache()
        new_ips  = current - _arp_cache_prev
        _arp_cache_prev = current  # update after diff so no IPs are lost

        if not new_ips:
            continue

        now = time.time()
        with _lock:
            for ip in new_ips:
                _arp_cache_window.append((now, ip))

            # Prune entries outside window
            cutoff = now - config.ARP_SWEEP_WINDOW
            while _arp_cache_window and _arp_cache_window[0][0] < cutoff:
                _arp_cache_window.pop(0)

            unique = {ip for _, ip in _arp_cache_window}
            if len(unique) < config.ARP_SWEEP_THRESHOLD:
                continue

            # Snapshot count before clearing
            unique_count = len(unique)
            _arp_cache_window.clear()

            # Suppress if a wire-based sweep fired recently —
            # cache growth was caused by the remote attacker, not this device
            if (now - _last_wire_sweep_ts) < DEDUP_WINDOW:
                continue

            if not _is_dedup("local_sweep"):
                src = _local_ip()
                detail = (f"ARP sweep from this device ({src}): "
                          f"{unique_count} new hosts resolved in "
                          f"{config.ARP_SWEEP_WINDOW}s — possible local nmap/scan")
                _am.fire(
                    alert_type = "arp_sweep",
                    severity   = "high",
                    src_ip     = src,
                    detail     = detail,
                    protocol   = "ARP",
                )
                log.warning("[ARPSweep] %s", detail)


def start_poll():
    """Start the ARP cache polling thread. Must be called after app init."""
    global _poll_thread
    if _poll_thread and _poll_thread.is_alive():
        return
    _poll_thread = threading.Thread(target=_poll_arp_cache,
                                    name="arp_cache_poll", daemon=True)
    _poll_thread.start()
    log.info("[ARPSweep] ARP cache poll started.")


def process(pkt: dict):
    if pkt.get("type") != "ARP":
        return

    # Only who-has requests (op=1) — direction: attacker → target IPs
    if pkt.get("op") != 1:
        return

    _load()

    src_mac = pkt.get("src_mac")
    src_ip  = pkt.get("src_ip")
    dst_ip  = pkt.get("dst_ip")
    now     = time.time()

    if not src_mac or not src_ip or not dst_ip:
        return

    if src_ip in ("0.0.0.0", "255.255.255.255"):
        return
    if dst_ip in ("0.0.0.0", "255.255.255.255"):
        return

    is_local = src_ip in _LOCAL_IPS

    global _last_wire_sweep_ts

    with _lock:
        cutoff = now - config.ARP_SWEEP_WINDOW
        _sweep_targets[src_mac][dst_ip] = now
        _sweep_targets[src_mac] = {
            ip: ts for ip, ts in _sweep_targets[src_mac].items()
            if ts >= cutoff
        }
        unique_targets = len(_sweep_targets[src_mac])

        if unique_targets < config.ARP_SWEEP_THRESHOLD:
            return

        unique_count = unique_targets
        _sweep_targets[src_mac] = {}
        _last_wire_sweep_ts = now

        if not _is_dedup(src_mac):
            note = (" [NOTE: src is this device — may be forwarded from a routed scan]"
                    if is_local else "")
            detail = (f"ARP sweep: {src_ip} ({src_mac}) probed "
                      f"{unique_count} hosts in {config.ARP_SWEEP_WINDOW}s"
                      f" — possible subnet reconnaissance{note}")
            _am.fire(
                alert_type = "arp_sweep",
                severity   = "high",
                src_ip     = src_ip,
                detail     = detail,
                protocol   = "ARP",
            )
            log.warning("[ARPSweep] %s", detail)
