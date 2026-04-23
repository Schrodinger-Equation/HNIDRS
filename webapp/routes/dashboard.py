"""dashboard.py — Single-page tabbed dashboard."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

templates = Jinja2Templates(directory=os.path.join(ROOT, "webapp", "templates"))
router    = APIRouter()


def _interfaces():
    try:
        from core.sniffer import get_interfaces
        ifaces = get_interfaces()
        return ifaces if ifaces else ["eth0", "wlan0"]
    except Exception:
        return ["eth0", "wlan0"]


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    from db import db_manager as db
    capture_iface = getattr(request.app.state, "capture_iface", "eth0")
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "devices":        db.get_devices(),
            "traffic_avgs":   db.get_all_traffic_avgs(limit=50),
            "whitelist":      db.get_whitelist(),
            "blacklist":      db.get_blacklist(),
            "ip_mac":         db.get_all_ip_mac(),
            "interfaces":     _interfaces(),
            "capture_iface":  capture_iface,
        }
    )
