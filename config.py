import os

# ── Network ──────────────────────────────────────────────────────────────────
DEFAULT_INTERFACE   = "wlo1"          # override at runtime via UI
CAPTURE_FILTER      = ""              # BPF filter string (empty = all traffic)

# ── Database ─────────────────────────────────────────────────────────────────
BASE_DIR            = os.path.dirname(os.path.abspath(__file__))
DB_PATH             = os.path.join(BASE_DIR, "db", "hnidrs.sqlite")
SIGNATURE_SQL       = os.path.join(BASE_DIR, "db", "ids_signature_db.sql")

# ── Detection thresholds ─────────────────────────────────────────────────────
PORT_SCAN_WINDOW    = 10      # seconds
PORT_SCAN_THRESHOLD = 15      # unique ports in window → alert

BRUTE_FORCE_WINDOW  = 30      # seconds
BRUTE_FORCE_THRESHOLD = 20    # failed connections in window → alert

ANOMALY_WINDOW      = 3600    # 1 hour rolling baseline (seconds)
ANOMALY_MULTIPLIER  = 3.0     # spike = current_rate > avg * multiplier

ARP_CHECK_INTERVAL  = 5       # seconds between ARP table scans

# ARP sweep: one src sending who-has to many distinct IPs on the subnet
ARP_SWEEP_WINDOW    = 10      # seconds
ARP_SWEEP_THRESHOLD = 8       # unique dst IPs in window → alert

# Ping sweep: one src hitting many distinct dst IPs with ICMP echo
PING_SWEEP_WINDOW    = 10     # seconds
PING_SWEEP_THRESHOLD = 5      # unique dst IPs in window → alert

# Ping flood: one src sending many ICMP packets to one dst
# Phone default ping = 1 pkt/sec — 15 pkts in 20s is a realistic flood signal
PING_FLOOD_WINDOW    = 20     # seconds
PING_FLOOD_THRESHOLD = 15     # ICMP packets in window → alert (high rate)

# Sustained ping: low rate but continuous — catches default phone/tool ping
PING_SUSTAINED_WINDOW    = 60  # seconds
PING_SUSTAINED_THRESHOLD = 20  # ICMP packets in window → alert (low rate, long duration)

# ── Notifications ─────────────────────────────────────────────────────────────
# SMTP
SMTP_ENABLED        = False
SMTP_HOST           = "smtp.gmail.com"
SMTP_PORT           = 587
SMTP_USER           = "your@email.com"
SMTP_PASS           = "yourpassword"
SMTP_TO             = "alert@email.com"

# Telegram
TELEGRAM_ENABLED    = False
TELEGRAM_BOT_TOKEN  = "your-bot-token"
TELEGRAM_CHAT_ID    = "your-chat-id"

# ── Flask ─────────────────────────────────────────────────────────────────────
FLASK_HOST          = "0.0.0.0"
FLASK_PORT          = 5000
FLASK_DEBUG         = False
SECRET_KEY          = "change-me-in-production"
