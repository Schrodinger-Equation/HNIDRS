"""smtp_notifier.py — Sends alert emails via SMTP."""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

log = logging.getLogger("notifications.smtp")

_cfg = None

def _load():
    global _cfg
    if _cfg is None:
        import config
        _cfg = config


def send(alert: dict):
    _load()
    if not _cfg.SMTP_ENABLED:
        return

    ts  = datetime.fromtimestamp(alert.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S")
    sev = alert.get("severity", "").upper()
    typ = alert.get("alert_type", "")

    subject = f"[HNIDRS] {sev} — {typ} from {alert.get('src_ip', 'unknown')}"

    body = f"""HNIDRS Security Alert
{'='*50}
Time      : {ts}
Type      : {typ}
Severity  : {sev}
Source IP : {alert.get('src_ip', 'N/A')}
Dest IP   : {alert.get('dst_ip', 'N/A')}
Src Port  : {alert.get('src_port', 'N/A')}
Dst Port  : {alert.get('dst_port', 'N/A')}
Protocol  : {alert.get('protocol', 'N/A')}

Detail:
{alert.get('detail', 'No detail.')}
{'='*50}
"""

    msg = MIMEMultipart()
    msg["From"]    = _cfg.SMTP_USER
    msg["To"]      = _cfg.SMTP_TO
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(_cfg.SMTP_HOST, _cfg.SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(_cfg.SMTP_USER, _cfg.SMTP_PASS)
            server.sendmail(_cfg.SMTP_USER, _cfg.SMTP_TO, msg.as_string())
        log.info(f"[SMTP] Alert email sent for alert id={alert.get('id')}")
    except Exception as e:
        log.error(f"[SMTP] Failed to send email: {e}")
