"""
analyzer.py — Consumes packets from sniffer.packet_queue
and dispatches to every detection module.
Runs in its own daemon thread.
"""

import threading
import queue
import time
import logging

log = logging.getLogger("analyzer")

_stop_event   = threading.Event()
_analyzer_thread = None

# Broadcast queue — webapp drains this to push live packets to WebSocket
# clients. Kept separate from sniffer.packet_queue so the webapp cannot
# starve detectors of packets.
broadcast_queue: queue.Queue = queue.Queue(maxsize=5_000)

# Detection modules (imported lazily to avoid circular imports at startup)
_modules_loaded = False
_port_scan   = None
_brute_force = None
_arp_spoof   = None
_anomaly     = None
_signature   = None
_ping_detect = None
_arp_sweep   = None

# DB / sniffer
_db  = None
_snf = None


def _load_modules():
    global _modules_loaded, _port_scan, _brute_force, _arp_spoof, _anomaly, _signature, _ping_detect, _arp_sweep
    global _db, _snf
    if _modules_loaded:
        return
    from detection import port_scan, brute_force, arp_spoof, anomaly, signature, ping_detect, arp_sweep
    from db       import db_manager
    from core     import sniffer

    _port_scan   = port_scan
    _brute_force = brute_force
    _arp_spoof   = arp_spoof
    _anomaly     = anomaly
    _signature   = signature
    _ping_detect = ping_detect
    _arp_sweep   = arp_sweep
    _db          = db_manager
    _snf         = sniffer
    _modules_loaded = True
    arp_sweep.start_poll()  # start after full app init, not at import time


def _process(pkt: dict):
    """Route one parsed packet dict to all detectors."""
    src_ip = pkt.get("src_ip")
    src_mac = pkt.get("src_mac")

    if not src_ip:
        return

    # Skip whitelisted IPs entirely
    if _db.is_whitelisted(src_ip):
        #print("ip : ",src_ip, "is whitlisted")

        return

    ptype = pkt.get("type", "")

    # ── Push to broadcast queue first — must happen regardless of DB errors ───
    if ptype != "ARP":
        try:
            broadcast_queue.put_nowait(pkt)
        except queue.Full:
            pass

    # ── Always log to packet_log (non-ARP) ───────────────────────────────────
    if ptype != "ARP":
        try:
            _db.log_packet(
                src_mac     = src_mac,
                src_ip      = src_ip,
                dst_ip      = pkt.get("dst_ip"),
                src_port    = pkt.get("src_port"),
                dst_port    = pkt.get("dst_port"),
                protocol    = pkt.get("protocol", ptype),
                length      = pkt.get("length", 0),
                flags       = pkt.get("flags", ""),
                payload     = pkt.get("payload", "")[:1024],
            )
        except Exception as e:
            log.error(f"[Analyzer] log_packet failed: {e}")

    # ── ARP → spoof + sweep detectors ────────────────────────────────────────
    if ptype == "ARP":
        _arp_spoof.process(pkt)
        _arp_sweep.process(pkt)
        return

    # ── Traffic anomaly (every IP packet) ────────────────────────────────────
    _anomaly.process(pkt)

    # ── Protocol-specific detectors ──────────────────────────────────────────
    if ptype == "TCP":
        _port_scan.process(pkt)
        _brute_force.process(pkt)

    if ptype == "ICMP":
        _ping_detect.process(pkt)

    # ── Signature engine (TCP + UDP with payload) ─────────────────────────────
    if ptype in ("TCP", "UDP"):
       _signature.process(pkt)


_packets_processed = 0

def get_packet_count():
    return _packets_processed

def _run():
    global _packets_processed
    _load_modules()
    log.info("[Analyzer] Started.")
    
    q = _snf.packet_queue # This is your deque

    while not _stop_event.is_set():
        try:
            # 1. Attempt to pop from the left (FIFO)
            pkt = q.popleft() 
            
            # 2. Try to process the data
            try:
                _process(pkt)
                _packets_processed += 1
            except Exception as e:
                log.error(f"[Analyzer] Error processing packet: {e}", exc_info=True)
                
        except IndexError:
            # This happens when the deque is empty.
            # We sleep for a bit to prevent the CPU from hitting 100%
            time.sleep(0.1)
            continue
        except Exception as e:
            log.error(f"[Analyzer] Unexpected error: {e}")

    log.info("[Analyzer] Stopped.")

def start():
    global _analyzer_thread
    if _analyzer_thread and _analyzer_thread.is_alive():
        log.warning("Analyzer already running.")
        return
    _stop_event.clear()
    _analyzer_thread = threading.Thread(
        target=_run, name="analyzer", daemon=True)
    _analyzer_thread.start()


def stop():
    _stop_event.set()


def is_running() -> bool:
    return bool(_analyzer_thread and _analyzer_thread.is_alive()
                and not _stop_event.is_set())
