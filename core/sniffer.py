"""
sniffer.py — Raw packet capture via Scapy.
Runs in its own thread; pushes parsed packet dicts onto a Queue
that analyzer.py consumes.
"""

import threading
import queue
import time
import logging
from collections import deque
log = logging.getLogger("sniffer")

# Lazy import — Scapy not needed at import time for tests
try:
    from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, Raw
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    log.warning("Scapy not installed — sniffer disabled.")

_stop_event = threading.Event()
_sniffer_thread = None
packet_queue= deque(maxlen=10_000)


def _parse_packet(pkt) -> dict | None:
    
    """Convert a Scapy packet to a plain dict for the analyzer."""
    if not pkt.haslayer(IP):
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            return {
                "type":    "ARP",
                "src_ip":  arp.psrc,
                "dst_ip":  arp.pdst,
                "src_mac": arp.hwsrc,
                "dst_mac": arp.hwdst,
                "op":      arp.op,        # 1=who-has(pooch rha), 2=is-at(bata rha)
                "timestamp": time.time(),
            }
        return None

    ip  = pkt[IP]
    ts  = time.time()
    base = {
        "src_mac": pkt[Ether].src,
        "src_ip":  ip.src,
        "dst_ip":  ip.dst,
        "length":  len(pkt),
        "timestamp": ts,
    }

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = _tcp_flags(tcp.flags)
        payload = ""
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load[:1024].hex()

        # 2. Extract HTTP (if present)
        http_info = {}  # Start as None
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            try:
                http_info = {
                    "method": req.Method.decode(errors="replace") if req.Method else "",
                    "host":   req.Host.decode(errors="replace")   if req.Host   else "",
                    "path":   req.Path.decode(errors="replace")   if req.Path   else "",
                }
            except Exception:
                pass # Or log the error

        return {
            **base,
            "type":     "TCP",
            "protocol": "TCP",
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "flags":    flags,
            "payload":  payload,
            "http":     http_info  # Now this is either a dict OR None
        }

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        payload = ""
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load[:256].hex();
            except Exception:
                payload = ""
        return {**base,
                "type":     "UDP",
                "protocol": "UDP",
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "flags":    "",
                "payload":  payload,
                "http":     {}}

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        return {**base,
                "type":     "ICMP",
                "protocol": "ICMP",
                "src_port": None,
                "dst_port": None,
                "flags":    "",
                "icmp_type": icmp.type,
                "payload":  "",
                "http":     {}}

    return {**base,
            "type":     "OTHER",
            "protocol": str(ip.proto),
            "src_port": None,
            "dst_port": None,
            "flags":    "",
            "payload":  "",
            "http":     {}}


def _tcp_flags(flags_int) -> str:
    names = {0x01: "F", 0x02: "S", 0x04: "R",
             0x08: "P", 0x10: "A", 0x20: "U"}
    return "".join(v for k, v in names.items() if flags_int & k)


_packets_captured = 0

def get_packet_count():
    return _packets_captured

def _packet_callback(pkt):
    global _packets_captured
    if _stop_event.is_set():
        return
    parsed = _parse_packet(pkt)
    #print(parsed)
    if parsed is None:
        return
    packet_queue.append(parsed)
    _packets_captured += 1
    # drop if analyzer is behind — never block the capture thread


def _run_sniff(iface, bpf_filter):
    log.info(f"[Sniffer] Starting on {iface!r} filter={bpf_filter!r}")
    try:
        sniff(
            iface=None,
            filter=bpf_filter or None,
            prn=_packet_callback,
            store=False,
            stop_filter=lambda _: _stop_event.is_set(),
        )
    except PermissionError:
        log.error("[Sniffer] Permission denied — run with sudo/root.")
    except OSError as e:
        log.error(f"[Sniffer] OS error (bad interface?): {e}")
    except Exception as e:
        log.error(f"[Sniffer] Unexpected error: {e}", exc_info=True)
    log.info("[Sniffer] Stopped.")


def start(iface: str, bpf_filter: str = ""):
    global _sniffer_thread
    if not SCAPY_OK:
        log.error("Cannot start sniffer — Scapy not installed.")
        return
    if _sniffer_thread and _sniffer_thread.is_alive():
        log.warning("Sniffer already running.")
        return
    _stop_event.clear()
    _sniffer_thread = threading.Thread(
        target=_run_sniff, args=(iface, bpf_filter),
        name="sniffer", daemon=True)
    _sniffer_thread.start()


def stop():
    _stop_event.set()
    log.info("[Sniffer] Stop signal sent.")


def is_running() -> bool:
    return bool(_sniffer_thread and _sniffer_thread.is_alive()
                and not _stop_event.is_set())


def get_interfaces() -> list[str]:
    """Return available network interfaces, excluding loopback."""
    if not SCAPY_OK:
        return []
    try:
        from scapy.arch import get_if_list
        return get_if_list()
    except Exception:
        return []
