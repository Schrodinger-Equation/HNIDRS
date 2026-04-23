"""api.py — FastAPI REST endpoints (all sync def = thread pool, isolated DB connections)."""

import time
from fastapi import APIRouter, Request

router = APIRouter()


def _db():
    from db import db_manager
    return db_manager

def _sniffer():
    from core import sniffer
    return sniffer

def _analyzer():
    from core import analyzer
    return analyzer


@router.get("/status")
def status():
    s = _sniffer()
    a = _analyzer()
    return {
        "sniffer_running":    s.is_running(),
        "analyzer_running":   a.is_running(),
        "queue_size":         len(s.packet_queue),
        "packets_captured":   s.get_packet_count(),
        "packets_processed":  a.get_packet_count(),
        "interfaces":         s.get_interfaces(),
        "server_time":        time.time(),
    }


@router.get("/alerts")
def alerts(limit: int = 200, since: float = 0, src_ip: str = None):
    return _db().get_alerts(limit=limit, since=since if since > 0 else None, src_ip=src_ip)

@router.delete("/alerts")
def clear_alerts():
    _db().clear_alerts()
    return {"status": "cleared"}


@router.get("/packets")
def packets(limit: int = 300, http_only: int = 0, src_ip: str = None, since: float = 0):
    return _db().get_packets(limit=limit, http_only=bool(http_only), src_ip=src_ip, since=since if since > 0 else None)


@router.get("/traffic_avgs")
def traffic_avgs():
    return _db().get_all_traffic_avgs()


@router.get("/devices")
def devices():
    return _db().get_devices()


@router.get("/ip_mac")
def ip_mac():
    return _db().get_all_ip_mac()


@router.post("/sniffer/start")
async def sniffer_start(request: Request):
    data  = await request.json()
    iface = data.get("interface", "eth0")
    bpf   = data.get("filter", "")
    _sniffer().start(iface, bpf)
    _analyzer().start()
    return {"status": "started", "interface": iface}


@router.post("/sniffer/stop")
def sniffer_stop():
    _sniffer().stop()
    _analyzer().stop()
    return {"status": "stopped"}


@router.get("/discovery/status")
def discovery_status():
    from offensive.discovery import get_status
    return get_status()
