"""
webapp/app.py — FastAPI + native WebSocket.

Broadcaster (asyncio task, 100ms tick):
  1. Drains sniffer.packet_queue  → WS push {"type":"packet",...}
  2. Polls DB for new alerts       → WS push {"type":"alert",...}
  3. Every 2s: status frame        → WS push {"type":"status",...}
"""

import asyncio, time, queue as _qmod, logging, os, sys
from contextlib import asynccontextmanager
from typing import Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

log = logging.getLogger("webapp")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    task = asyncio.create_task(_broadcaster())
    log.info("[App] WebSocket broadcaster started.")
    try:
        yield
    finally:
        task.cancel()


app = FastAPI(title="HNIDRS", lifespan=_lifespan)


# ── WebSocket connection manager ──────────────────────────────────────────────
class _Manager:
    def __init__(self):
        self._ws: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._ws.add(ws)

    def disconnect(self, ws: WebSocket):
        self._ws.discard(ws)

    async def broadcast(self, data: dict):
        dead = set()
        for ws in list(self._ws):
            try:
                await ws.send_json(data)
            except Exception:
                dead.add(ws)
        self._ws -= dead

    @property
    def count(self):
        return len(self._ws)


manager = _Manager()


# ── Broadcaster asyncio task ──────────────────────────────────────────────────
async def _broadcaster():
    from core import sniffer, analyzer
    from db   import db_manager as db

    last_alert_ts = time.time()
    last_status   = time.time()

    while True:
        await asyncio.sleep(0.1)

        # 1. Drain analyzer broadcast queue (up to 50 packets per tick).
        # Only the analyzer writes here; the sniffer queue is fed to the
        # detectors exclusively.
        if manager.count > 0:
            for _ in range(50):
                try:
                    pkt = analyzer.broadcast_queue.get_nowait()
                    msg = {"type": "packet"}
                    msg.update(pkt)
                    await manager.broadcast(msg)
                except _qmod.Empty:
                    break
                except Exception as e:
                    log.debug(f"Packet broadcast err: {e}")
                    break
        else:
            # No clients — still drain the broadcast queue so it can't back up
            try:
                while True:
                    analyzer.broadcast_queue.get_nowait()
            except _qmod.Empty:
                pass
            continue

        # 2. New alerts from DB — only strictly newer than last seen timestamp
        try:
            new_alerts = db.get_alerts(limit=20, since=last_alert_ts)
            for a in reversed(new_alerts):
                if a["timestamp"] <= last_alert_ts:
                    continue
                last_alert_ts = a["timestamp"]
                await manager.broadcast({"type": "alert", **a})
        except Exception as e:
            log.debug(f"Alert poll err: {e}")

        # 3. Status frame every 2s
        now = time.time()
        if now - last_status >= 2:
            last_status = now
            try:
                await manager.broadcast({
                    "type":              "status",
                    "sniffer_running":   sniffer.is_running(),
                    "analyzer_running":  analyzer.is_running(),
                    "queue_size":        len(sniffer.packet_queue),
                    "packets_captured":  sniffer.get_packet_count(),
                    "packets_processed": analyzer.get_packet_count(),
                    "ws_clients":        manager.count,
                })
            except Exception as e:
                log.debug(f"Status broadcast err: {e}")


# ── WebSocket endpoint ────────────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Send immediate status on connect
        from core import sniffer, analyzer
        await ws.send_json({
            "type":              "status",
            "sniffer_running":   sniffer.is_running(),
            "analyzer_running":  analyzer.is_running(),
            "queue_size":        len(sniffer.packet_queue),
            "packets_captured":  sniffer.get_packet_count(),
            "packets_processed": analyzer.get_packet_count(),
            "ws_clients":        manager.count,
        })
        # Keep connection alive — browser sends "ping" text frames
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception as e:
        log.exception(f"[WS] connection error: {e}")
        manager.disconnect(ws)


# ── Routers ───────────────────────────────────────────────────────────────────
from webapp.routes.dashboard import router as dashboard_router
from webapp.routes.api       import router as api_router
from webapp.routes.lists     import router as lists_router
from webapp.routes.offensive import router as offensive_router

app.include_router(dashboard_router)
app.include_router(api_router,       prefix="/api")
app.include_router(lists_router,     prefix="/lists")
app.include_router(offensive_router, prefix="/offensive")
