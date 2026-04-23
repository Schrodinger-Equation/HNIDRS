"""
attack_sim.py — Simulated attack generator for demonstration.
Fires all or individual offensive techniques at a target.
Each attack runs in its own thread with a short burst, then stops.
"""

import threading
import time
import logging

log = logging.getLogger("offensive.attack_sim")

try:
    from scapy.all import (IP, TCP, UDP, ICMP, ARP, Ether,
                           send, sendp, RandShort, RandMAC)
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

ATTACKS = ["port_scan", "syn_flood", "brute_force", "arp_spoof",
           "dns_spoof", "icmp_flood", "xmas_scan", "null_scan"]


def _sim_port_scan(target_ip, iface, results):
    log.info(f"[Sim] Port scan on {target_ip}")
    try:
        pkts = [IP(dst=target_ip)/TCP(dport=p, flags="S")
                for p in [22, 23, 80, 443, 3389, 445, 3306, 8080]]
        send(pkts, iface=iface, verbose=False)
        results.append({"attack": "port_scan", "status": "sent",
                        "detail": "SYN to 8 common ports"})
    except Exception as e:
        results.append({"attack": "port_scan", "status": "error", "detail": str(e)})


def _sim_syn_flood(target_ip, iface, results, count=50):
    log.info(f"[Sim] SYN flood on {target_ip}")
    try:
        pkts = [IP(dst=target_ip)/TCP(sport=RandShort(), dport=80, flags="S")
                for _ in range(count)]
        send(pkts, iface=iface, verbose=False)
        results.append({"attack": "syn_flood", "status": "sent",
                        "detail": f"{count} SYN packets to port 80"})
    except Exception as e:
        results.append({"attack": "syn_flood", "status": "error", "detail": str(e)})


def _sim_brute_force(target_ip, iface, results, count=25):
    log.info(f"[Sim] Brute-force simulation on {target_ip}")
    try:
        pkts = [IP(dst=target_ip)/TCP(sport=RandShort(), dport=22, flags="S")
                for _ in range(count)]
        send(pkts, iface=iface, verbose=False)
        results.append({"attack": "brute_force", "status": "sent",
                        "detail": f"{count} SYN packets to SSH port 22"})
    except Exception as e:
        results.append({"attack": "brute_force", "status": "error", "detail": str(e)})


def _sim_icmp_flood(target_ip, iface, results, count=100):
    log.info(f"[Sim] ICMP flood on {target_ip}")
    try:
        pkts = [IP(dst=target_ip)/ICMP() for _ in range(count)]
        send(pkts, iface=iface, verbose=False)
        results.append({"attack": "icmp_flood", "status": "sent",
                        "detail": f"{count} ICMP echo requests"})
    except Exception as e:
        results.append({"attack": "icmp_flood", "status": "error", "detail": str(e)})


def _sim_xmas_scan(target_ip, iface, results):
    log.info(f"[Sim] XMAS scan on {target_ip}")
    try:
        pkts = [IP(dst=target_ip)/TCP(dport=p, flags="FPU")
                for p in [22, 80, 443, 3389]]
        send(pkts, iface=iface, verbose=False)
        results.append({"attack": "xmas_scan", "status": "sent",
                        "detail": "FIN+PSH+URG to 4 ports"})
    except Exception as e:
        results.append({"attack": "xmas_scan", "status": "error", "detail": str(e)})


def _sim_null_scan(target_ip, iface, results):
    log.info(f"[Sim] NULL scan on {target_ip}")
    try:
        pkts = [IP(dst=target_ip)/TCP(dport=p, flags="")
                for p in [22, 80, 443, 3389]]
        send(pkts, iface=iface, verbose=False)
        results.append({"attack": "null_scan", "status": "sent",
                        "detail": "No-flag TCP to 4 ports"})
    except Exception as e:
        results.append({"attack": "null_scan", "status": "error", "detail": str(e)})


def _sim_arp_spoof(target_ip, iface, results):
    log.info(f"[Sim] ARP spoof simulation on {target_ip}")
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=2, pdst=target_ip, psrc="192.168.1.1",
            hwsrc=str(RandMAC()))
        sendp(pkt, iface=iface, count=5, verbose=False)
        results.append({"attack": "arp_spoof", "status": "sent",
                        "detail": "5 gratuitous ARP packets"})
    except Exception as e:
        results.append({"attack": "arp_spoof", "status": "error", "detail": str(e)})


def _sim_dns_spoof(target_ip, iface, results):
    """Simulate a DNS query that would be spoofed."""
    log.info(f"[Sim] DNS spoof simulation toward {target_ip}")
    try:
        from scapy.all import DNS, DNSQR
        pkt = (IP(dst=target_ip) /
               UDP(dport=53, sport=RandShort()) /
               DNS(rd=1, qd=DNSQR(qname="example.com")))
        send(pkt, iface=iface, count=3, verbose=False)
        results.append({"attack": "dns_spoof", "status": "sent",
                        "detail": "3 DNS queries (would be intercepted if DNS spoof active)"})
    except Exception as e:
        results.append({"attack": "dns_spoof", "status": "error", "detail": str(e)})


_ATTACK_MAP = {
    "port_scan":   _sim_port_scan,
    "syn_flood":   _sim_syn_flood,
    "brute_force": _sim_brute_force,
    "icmp_flood":  _sim_icmp_flood,
    "xmas_scan":   _sim_xmas_scan,
    "null_scan":   _sim_null_scan,
    "arp_spoof":   _sim_arp_spoof,
    "dns_spoof":   _sim_dns_spoof,
}


def run(target_ip: str, attack_type: str = "all",
        iface: str = "eth0") -> dict:
    if not SCAPY_OK:
        return {"error": "Scapy not installed"}

    results = []
    threads = []

    attacks = list(_ATTACK_MAP.keys()) if attack_type == "all" \
              else [attack_type]

    for name in attacks:
        fn = _ATTACK_MAP.get(name)
        if fn:
            t = threading.Thread(target=fn,
                                 args=(target_ip, iface, results),
                                 daemon=True)
            threads.append(t)
            t.start()

    for t in threads:
        t.join(timeout=15)

    return {
        "target":  target_ip,
        "attacks": attacks,
        "results": results,
    }
