#!/usr/bin/env python3
"""main.py — HNIDRS entry point."""

import argparse, logging, sys, os

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("main")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Silence Scapy's noisy "MAC address to reach destination not found. Using
# broadcast." warnings — these fire constantly during discovery /24 sweeps
# and attack simulations against unreachable hosts. They're expected and
# drown out real log output.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


def _local_ips(iface):
    """Return all IPs on this interface (IPv4 + loopback)."""
    ips = ["127.0.0.1"]
    try:
        from scapy.arch import get_if_addr
        ip = get_if_addr(iface)
        if ip and ip != "0.0.0.0":
            ips.append(ip)
    except Exception:
        pass
    try:
        import socket
        hostname = socket.gethostname()
        ips.append(socket.gethostbyname(hostname))
    except Exception:
        pass
    return list(set(ips))


def main():
    parser = argparse.ArgumentParser(description="HNIDRS")
    parser.add_argument("--interface", default=None)
    parser.add_argument("--port",      type=int, default=None)
    parser.add_argument("--no-sniffer", action="store_true")
    parser.add_argument("--debug",     action="store_true")
    args = parser.parse_args()

    import config
    iface = args.interface or config.DEFAULT_INTERFACE
    port  = args.port      or config.FLASK_PORT

    # 1. DB
    log.info("Initialising database…")
    from db import db_manager
    db_manager.init_db()

    # 2. Auto-whitelist own IPs so we don't alert on our own traffic
    own_ips = _local_ips(iface)
    for ip in own_ips:
        db_manager.add_whitelist(ip, note=f"Auto: local machine ({iface})")
    log.info(f"Auto-whitelisted own IPs: {own_ips}")

    # 3. Signatures
    
    log.info("Loading IDS signatures…")
    from db import sig_importer
    sig_importer.run()
    
    # 4. Alert manager
    log.info("Starting alert manager…")
    from core import alert_manager
    alert_manager.start()

    # 5. Sniffer + analyzer
    if not args.no_sniffer:
        log.info(f"Starting sniffer on {iface}")
        from core import sniffer, analyzer
        sniffer.start(iface, config.CAPTURE_FILTER)
        analyzer.start()
    else:
        log.info("Sniffer skipped (--no-sniffer)")

    # 6. FastAPI — pass active interface so UI can use it as default for offensive tools
    import uvicorn
    from webapp.app import app
    app.state.capture_iface = iface      # available to all routes via request.app.state

    log.info(f"Dashboard → http://0.0.0.0:{port}")
    uvicorn.run(app, host=config.FLASK_HOST, port=port,
                log_level="debug" if args.debug else "warning")


if __name__ == "__main__":
    main()
