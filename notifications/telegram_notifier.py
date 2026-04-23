"""telegram_notifier.py — Sends alert messages via Telegram Bot API."""

import urllib.request
import urllib.parse
import json
import logging
from datetime import datetime

log = logging.getLogger("notifications.telegram")

_cfg = None

def _load():
    global _cfg
    if _cfg is None:
        import config
        _cfg = config

SEVERITY_EMOJI = {
    "info":     "ℹ️",
    "low":      "🔵",
    "medium":   "🟡",
    "high":     "🔴",
    "critical": "🚨",
}

def send(alert: dict):
    _load()
    if not _cfg.TELEGRAM_ENABLED:
        return

    ts  = datetime.fromtimestamp(alert.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
    sev = alert.get("severity", "medium").lower()
    typ = alert.get("alert_type", "unknown")
    src = alert.get("src_ip", "N/A")
    emoji = SEVERITY_EMOJI.get(sev, "⚠️")

    text = (
        f"{emoji} *HNIDRS ALERT*\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"*Type:* `{typ}`\n"
        f"*Severity:* `{sev.upper()}`\n"
        f"*Source IP:* `{src}`\n"
        f"*Dest IP:* `{alert.get('dst_ip', 'N/A')}`\n"
        f"*Port:* `{alert.get('dst_port', 'N/A')}`\n"
        f"*Protocol:* `{alert.get('protocol', 'N/A')}`\n"
        f"*Time:* `{ts}`\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"_{alert.get('detail', '')}_"
    )

    url  = f"https://api.telegram.org/bot{_cfg.TELEGRAM_BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id":    _cfg.TELEGRAM_CHAT_ID,
        "text":       text,
        "parse_mode": "Markdown",
    }).encode()

    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if not result.get("ok"):
                log.error(f"[Telegram] API error: {result}")
            else:
                log.info(f"[Telegram] Alert sent for id={alert.get('id')}")
    except Exception as e:
        log.error(f"[Telegram] Failed: {e}")
