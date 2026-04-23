"""
alert_manager.py — Central alert dispatcher.
All detectors call fire() which:
  1. Writes to the DB
  2. Queues the notification (handled by a background thread
     that calls smtp + telegram notifiers)
"""

import threading
import queue
import time
import logging

log = logging.getLogger("alert_manager")

_notify_queue: queue.Queue = queue.Queue(maxsize=500)
_notifier_thread = None
_stop_event = threading.Event()

# Lazy imports
_db        = None
_smtp      = None
_tg        = None
_init_lock = threading.Lock()


def _load():
    global _db, _smtp, _tg
    if _db is not None and _smtp is not None:
        return
    with _init_lock:
        if _db is None:
            from db import db_manager
            _db = db_manager
        if _smtp is None:
            from notifications import smtp_notifier, telegram_notifier
            _smtp = smtp_notifier
            _tg   = telegram_notifier


def fire(alert_type: str,
         severity: str,
         src_ip:   str = None,
         dst_ip:   str = None,
         src_port: int = None,
         dst_port: int = None,
         protocol: str = None,
         detail:   str = None,
         signature_id: int = None):
    """Called by any detector to raise an alert."""
    _load()

    # Suppress if whitelisted
    if src_ip and _db.is_whitelisted(src_ip):
        return

    # Escalate blacklisted IPs to critical and tag the detail line
    if src_ip and _db.is_blacklisted(src_ip):
        severity = "critical"
        detail = f"[BLACKLISTED] {detail or ''}".strip()

    alert_id = _db.insert_alert(
        alert_type   = alert_type,
        severity     = severity,
        src_ip       = src_ip,
        dst_ip       = dst_ip,
        src_port     = src_port,
        dst_port     = dst_port,
        protocol     = protocol,
        detail       = detail,
        signature_id = signature_id,
    )

    # Push to notification queue (non-blocking)
    payload = {
        "id":          alert_id,
        "alert_type":  alert_type,
        "severity":    severity,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "protocol":    protocol,
        "detail":      detail,
        "timestamp":   time.time(),
    }
    try:
        _notify_queue.put_nowait(payload)
    except queue.Full:
        pass

    log.info(f"[ALERT] {severity.upper()} {alert_type} src={src_ip} — {detail}")
    return alert_id


def _notifier_loop():
    """Background thread: drain notify_queue → SMTP + Telegram."""
    _load()
    while not _stop_event.is_set():
        try:
            alert = _notify_queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            _smtp.send(alert)
        except Exception as e:
            log.debug(f"SMTP error: {e}")
        try:
            _tg.send(alert)
        except Exception as e:
            log.debug(f"Telegram error: {e}")
        try:
            _db.mark_alerted(alert["id"])
        except Exception:
            pass


def start():
    global _notifier_thread
    if _notifier_thread and _notifier_thread.is_alive():
        return
    _stop_event.clear()
    _notifier_thread = threading.Thread(
        target=_notifier_loop, name="notifier", daemon=True)
    _notifier_thread.start()


def stop():
    _stop_event.set()
