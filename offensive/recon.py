"""
recon.py — Nmap-based full port + vulnerability scan for a target IP.
Returns a structured dict parsed from nmap XML output.
"""

import subprocess
import xml.etree.ElementTree as ET
import logging
import shutil

log = logging.getLogger("offensive.recon")


def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def run(target_ip: str) -> dict:
    if not _nmap_available():
        return {"error": "nmap not installed. Run: sudo apt install nmap"}

    log.info(f"[Recon] Scanning {target_ip}")
    cmd = [
        "nmap",
        "-A",                        # aggressive: OS detect + version + scripts + traceroute
        "-T4",                       # aggressive timing
        "-p-",                       # all 65535 ports
        "--open",                    # only show open ports
        "-sV", "--version-intensity", "9",   # max version detection intensity
        "-sC",                       # default scripts
        "--script", "vuln,exploit,auth,discovery,default",
        "--osscan-guess",            # aggressive OS guessing
        "--max-retries", "3",
        "--min-rate", "1000",        # min 1000 packets/sec on LAN
        "-oX", "-",                  # XML to stdout
        target_ip,
    ]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0 and not proc.stdout:
            return {"error": proc.stderr.strip()}
        return _parse_xml(proc.stdout, target_ip)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out (600s)"}
    except Exception as e:
        return {"error": str(e)}


def _parse_xml(xml_str: str, target_ip: str) -> dict:
    result = {
        "target":     target_ip,
        "status":     "unknown",
        "hostname":   "",
        "ports":      [],
        "vulns":      [],
        "os":         "",
        "os_accuracy": "",
        "mac":        "",
        "traceroute": [],
        "host_scripts": [],
    }
    try:
        root = ET.fromstring(xml_str)
        host = root.find("host")
        if host is None:
            return result

        status = host.find("status")
        if status is not None:
            result["status"] = status.get("state", "unknown")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                result["hostname"] = hn.get("name", "")

        os_el = host.find("os/osmatch")
        if os_el is not None:
            result["os"]          = os_el.get("name", "")
            result["os_accuracy"] = os_el.get("accuracy", "") + "%"

        # MAC address (present when target is on the same LAN)
        for addr in host.findall("address"):
            if addr.get("addrtype") == "mac":
                vendor = addr.get("vendor", "")
                result["mac"] = addr.get("addr", "") + (f" ({vendor})" if vendor else "")

        # Traceroute hops
        trace = host.find("trace")
        if trace is not None:
            for hop in trace.findall("hop"):
                result["traceroute"].append({
                    "ttl":  hop.get("ttl"),
                    "ip":   hop.get("ipaddr", ""),
                    "host": hop.get("host", ""),
                    "rtt":  hop.get("rtt", ""),
                })

        # Host-level scripts (e.g. smb-security-mode, ssh-hostkey)
        hostscript = host.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                sid    = script.get("id", "")
                output = script.get("output", "")
                result["host_scripts"].append({"id": sid, "output": output[:500]})
                if "VULNERABLE" in output.upper():
                    result["vulns"].append({
                        "port":   "host",
                        "script": sid,
                        "detail": output[:300],
                    })

        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                port_id  = port.get("portid")
                protocol = port.get("protocol")
                state_el = port.find("state")
                state    = state_el.get("state") if state_el is not None else "unknown"
                svc_el   = port.find("service")
                service  = svc_el.get("name", "") if svc_el is not None else ""
                product  = svc_el.get("product", "") if svc_el is not None else ""
                version  = svc_el.get("version", "") if svc_el is not None else ""

                port_entry = {
                    "port":     port_id,
                    "protocol": protocol,
                    "state":    state,
                    "service":  service,
                    "product":  product,
                    "version":  version,
                    "scripts":  [],
                }

                # Collect script outputs (vuln results)
                for script in port.findall("script"):
                    sid    = script.get("id", "")
                    output = script.get("output", "")
                    port_entry["scripts"].append({"id": sid, "output": output[:500]})
                    if "VULNERABLE" in output.upper():
                        result["vulns"].append({
                            "port":   port_id,
                            "script": sid,
                            "detail": output[:300],
                        })

                result["ports"].append(port_entry)

    except ET.ParseError as e:
        result["parse_error"] = str(e)

    return result
