"""
discovery.py — Network discovery using both ARP and ICMP ping.

Scans the full /24 subnet of the chosen interface.
Progress is tracked in a shared state dict polled by /api/discovery/status.
Results are written to discovered_devices table as they arrive.
"""

import re
import threading
import time
import socket
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("offensive.discovery")

# ── Tunables ──────────────────────────────────────────────────────────────────
ARP_TIMEOUT  = 7     # seconds per ARP round
ARP_ROUNDS   = 2     # number of ARP broadcast rounds
PING_TIMEOUT = 3     # seconds per ping
MAX_PARALLEL = 48    # max concurrent ping threads

# Worst-case stop budget: ARP + all pings serialised + MAC lookups + pause
_STOP_TIMEOUT = ARP_ROUNDS * ARP_TIMEOUT + PING_TIMEOUT + 2 + 15

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Shared scan state ─────────────────────────────────────────────────────────
_state = {
    "running":     False,
    "method":      "",
    "iface":       "",
    "subnet":      "",
    "total":       0,
    "scanned":     0,
    "found":       0,
    "current_ip":  "",
    "devices":     [],
    "started_at":  None,
    "finished_at": None,
    "error":       "",
}
_state_lock  = threading.Lock()
_stop_event  = threading.Event()
_scan_thread = None

_db        = None
_init_lock = threading.Lock()


# ── State helpers ─────────────────────────────────────────────────────────────

def get_status() -> dict:
    with _state_lock:
        s = dict(_state)
        s["devices"] = [dict(d) for d in _state["devices"]]
        s["pct"] = round(s["scanned"] / s["total"] * 100) if s["total"] > 0 else 0
        return s


def _load_db():
    global _db
    if _db is not None:
        return
    with _init_lock:
        if _db is None:
            from db import db_manager
            _db = db_manager


# ── Network helpers ───────────────────────────────────────────────────────────

def _get_iface_ip(iface: str) -> str:
    try:
        from scapy.arch import get_if_addr
        ip = get_if_addr(iface)
        if ip and ip != "0.0.0.0":
            return ip
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface], text=True, stderr=subprocess.DEVNULL)
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return ""


def _get_subnet(iface: str) -> str:
    ip = _get_iface_ip(iface)
    if ip:
        return ip.rsplit(".", 1)[0] + ".0/24"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip.rsplit(".", 1)[0] + ".0/24"
    except Exception:
        return "192.168.1.0/24"


def _subnet_ips(subnet: str) -> list:
    base = subnet.split("/")[0].rsplit(".", 1)[0]
    return [f"{base}.{i}" for i in range(1, 255)]


_hostname_cache: dict = {}

def _resolve_hostname(ip: str) -> str:
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    result = [""]
    def _lookup():
        try:
            result[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout=1.0)
    _hostname_cache[ip] = result[0]
    return result[0]


def _read_arp_cache() -> dict:
    """Return {ip: mac} for complete entries in the kernel ARP table."""
    cache = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header line
            for line in f:
                parts = line.split()
                # columns: IP  HW-type  Flags  MAC  Mask  Device
                # Flags 0x2 = complete (resolved) entry
                if len(parts) >= 4 and parts[2] == "0x2":
                    mac = parts[3]
                    if re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac, re.I):
                        cache[parts[0]] = mac
    except Exception:
        pass
    return cache


def _mac_for_ip(ip: str, iface: str) -> str:
    """Try kernel ARP cache first; fall back to a targeted ARP request."""
    mac = _read_arp_cache().get(ip, "")
    if mac:
        return mac
    if not SCAPY_OK:
        return ""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(pkt, iface=iface, timeout=2, verbose=False)
        if answered:
            return answered[0][1][ARP].hwsrc
    except Exception:
        pass
    return ""


def _ping_one(ip: str) -> bool:
    """Return True if host replies to ICMP echo via kernel ping."""
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(PING_TIMEOUT),
             "-w", str(PING_TIMEOUT + 1), "-n", "-q", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=PING_TIMEOUT + 2,
        )
        return proc.returncode == 0
    except Exception:
        return False


# ── ARP scan ──────────────────────────────────────────────────────────────────

def _arp_round(subnet: str, iface: str) -> dict:
    """One ARP broadcast round. Returns {ip: mac} for all respondents."""
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        answered, _ = srp(pkt, iface=iface, timeout=ARP_TIMEOUT, verbose=False)
        return {rcv[ARP].psrc: rcv[ARP].hwsrc for _, rcv in answered}
    except Exception as e:
        log.error("[Discovery] ARP round error: %s", e)
        return {}


# ── Combined scan loop ────────────────────────────────────────────────────────

def _run_scan(iface: str, subnet: str = None):
    _load_db()

    if _db is None:
        with _state_lock:
            _state["error"]   = "Database not available"
            _state["running"] = False
        log.error("[Discovery] Cannot start — DB not loaded.")
        return

    if not subnet:
        subnet = _get_subnet(iface)
    elif "/" not in subnet:
        subnet = subnet.rsplit(".", 1)[0] + ".0/24"

    all_ips = _subnet_ips(subnet)
    total   = len(all_ips)  # 254

    with _state_lock:
        _state.update({
            "running":     True,
            "iface":       iface,
            "subnet":      subnet,
            "total":       total,
            "scanned":     0,
            "found":       0,
            "current_ip":  "",
            "devices":     [],
            "started_at":  time.time(),
            "finished_at": None,
            "error":       "",
            "method":      "ARP + ICMP ping",
        })

    log.info("[Discovery] Scanning %s on %s (%d hosts)", subnet, iface, total)

    def _add_device(ip, mac, hostname, method):
        """Add or update a device in shared state and DB under lock."""
        try:
            _db.upsert_device(ip, mac=mac, hostname=hostname)
        except Exception as e:
            log.error("[Discovery] upsert_device failed for %s: %s", ip, e)
        with _state_lock:
            for d in _state["devices"]:
                if d["ip"] == ip:
                    d["mac"]      = mac or d["mac"]
                    d["hostname"] = hostname or d["hostname"]
                    return
            _state["devices"].append({
                "ip": ip, "mac": mac, "hostname": hostname, "method": method
            })
            _state["found"] += 1

    sweep = 0
    while not _stop_event.is_set():
        sweep += 1
        try:
            # ── Phase 1: ARP broadcast ────────────────────────────────────────
            with _state_lock:
                _state["method"]  = f"Sweep #{sweep} · Phase 1/2: ARP broadcast"
                _state["scanned"] = 0
                _state["total"]   = total

            arp_half = total // 2          # ARP fills 0% → 50%
            ping_half = total - arp_half   # ICMP fills 50% → 100%

            arp_results = {}
            for attempt in range(ARP_ROUNDS):
                if _stop_event.is_set():
                    break

                round_found = _arp_round(subnet, iface)
                new_ips = {ip: mac for ip, mac in round_found.items()
                           if ip not in arp_results}
                arp_results.update(round_found)

                with _state_lock:
                    _state["scanned"] = arp_half * (attempt + 1) // ARP_ROUNDS

                if not new_ips or _stop_event.is_set():
                    continue

                def _res_arp(item, _ni=new_ips):
                    ip, mac = item
                    return ip, mac, _resolve_hostname(ip)

                with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
                    for ip, mac, hostname in pool.map(_res_arp, list(new_ips.items())):
                        if _stop_event.is_set():
                            break
                        _add_device(ip, mac, hostname, "ARP")

            # ── Phase 2: ICMP ping ────────────────────────────────────────────
            # total/scanned stay at 254/254 — bar remains full.
            # Only the method label updates to show ICMP is in progress.
            arp_found    = set(arp_results.keys())
            ping_targets = [ip for ip in all_ips if ip not in arp_found]
            n_ping       = len(ping_targets)

            with _state_lock:
                _state["method"]  = f"Sweep #{sweep} · Phase 2/2: ICMP ping ({n_ping} hosts)"
                _state["scanned"] = arp_half   # start at 50%

            if not _stop_event.is_set() and ping_targets:
                alive = []
                ping_done = 0
                with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
                    futures = {pool.submit(_ping_one, ip): ip for ip in ping_targets}
                    for future in as_completed(futures):
                        if _stop_event.is_set():
                            for f in futures:
                                f.cancel()
                            break
                        ip = futures[future]
                        ping_done += 1
                        with _state_lock:
                            _state["current_ip"] = ip
                            _state["scanned"] = arp_half + ping_done * ping_half // n_ping
                        try:
                            if future.result():
                                alive.append(ip)
                        except Exception:
                            pass

                if alive and not _stop_event.is_set():
                    def _res_icmp(ip, _iface=iface):
                        return ip, _mac_for_ip(ip, _iface), _resolve_hostname(ip)

                    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
                        for ip, mac, hostname in pool.map(_res_icmp, alive):
                            if _stop_event.is_set():
                                break
                            _add_device(ip, mac, hostname, "ICMP")

        except Exception as e:
            log.error("[Discovery] Sweep %d error (continuing): %s", sweep, e)

        # Brief pause between sweeps
        for _ in range(30):
            if _stop_event.is_set():
                break
            time.sleep(0.1)

    with _state_lock:
        _state["running"]     = False
        _state["finished_at"] = time.time()
        _state["current_ip"]  = ""
        _state["method"]      = "Stopped"
        found = _state["found"]

    log.info("[Discovery] Stopped after %d sweep(s) — %d devices on %s", sweep, found, subnet)


# ── Public API ────────────────────────────────────────────────────────────────

def start(iface: str = "eth0", subnet: str = None) -> dict:
    global _scan_thread
    if not SCAPY_OK:
        msg = "Scapy not installed"
        log.error("[Discovery] %s", msg)
        with _state_lock:
            _state["error"] = msg
        return {"error": msg}

    if _scan_thread and _scan_thread.is_alive():
        log.info("[Discovery] Stopping previous scan before restart.")
        _stop_event.set()
        _scan_thread.join(timeout=_STOP_TIMEOUT)
        if _scan_thread.is_alive():
            log.warning("[Discovery] Previous scan did not stop in time; starting anyway.")

    _stop_event.clear()
    with _state_lock:
        _state["error"] = ""
    _scan_thread = threading.Thread(
        target=_run_scan, args=(iface, subnet), name="discovery", daemon=True)
    _scan_thread.start()
    return {"status": "started"}


def stop():
    _stop_event.set()
    log.info("[Discovery] Stop signal sent.")


def is_running() -> bool:
    return bool(_scan_thread and _scan_thread.is_alive()
                and not _stop_event.is_set())