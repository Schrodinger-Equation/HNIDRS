"""
signature.py — Matches live packets against rules loaded from the
ids_signatures table (populated by sig_importer.py).

Supports:
  - content  : plain substring match in payload (offset/depth honoured)
  - pcre     : Python re match in payload
  - hex      : hex byte pattern in raw payload
  - byte_test: tcp_flags / icmp_type symbolic checks
"""

import re
import ipaddress
import time
import threading
from collections import defaultdict
import logging

log = logging.getLogger("detection.signature")

# Map application-layer protocol names → transport layer
# Sniffer only produces tcp/udp/icmp; all app-layer rules must be normalised
_PROTO_MAP = {
    "ssh": "tcp", "ftp": "tcp", "http": "tcp", "https": "tcp",
    "smtp": "tcp", "smb": "tcp", "rdp": "tcp", "mysql": "tcp",
    "mssql": "tcp", "postgres": "tcp", "telnet": "tcp", "ldap": "tcp",
    "snmp": "udp", "dns": "udp",
}

# Sliding window for threshold tracking: {(sig_id, track_key): [timestamps]}
_windows: dict = defaultdict(list)
_win_lock = threading.Lock()

_rules_loaded = False
_rules_failed = False
_rules: list  = []
_load_lock    = threading.Lock()

_am        = None
_db        = None
_init_lock = threading.Lock()


def _load():
    global _am, _db
    if _am is not None and _db is not None:
        return
    with _init_lock:
        if _am is None or _db is None:
            from core import alert_manager
            from db   import db_manager
            _am = alert_manager
            _db = db_manager


def _load_rules():
    global _rules_loaded, _rules_failed, _rules
    with _load_lock:
        if _rules_loaded or _rules_failed:
            return
        _load()
        if _db is None:
            _rules_failed = True
            return
        try:
            sigs = _db.get_all_signatures(enabled_only=True)
        except Exception as e:
            log.error("[Signature] Failed to load signatures: %s", e)
            _rules_failed = True
            return

        rules = []
        for sig in sigs:
            # Skip non-alert actions — 'pass' means explicitly allowed traffic
            action = (sig.get("action") or "alert").lower()
            if action not in ("alert", "log"):
                continue

            try:
                patterns  = _db.get_patterns_for_sig(sig["id"])
                threshold = _db.get_threshold_for_sig(sig["id"])
            except Exception as e:
                log.warning("[Signature] Skipping sig %s — DB error: %s", sig["id"], e)
                continue

            compiled = []
            for p in patterns:
                entry = dict(p)
                if p["pattern_type"] == "pcre":
                    try:
                        base_flags = re.IGNORECASE if p.get("nocase", 1) else 0
                        pat = p["pattern"].strip()
                        if pat.startswith("/"):
                            pat = pat[1:]
                            if pat.endswith("/i"):
                                pat = pat[:-2]
                                base_flags = re.IGNORECASE
                            elif pat.endswith("/"):
                                pat = pat[:-1]
                        if not pat:
                            entry["_compiled"] = None
                        else:
                            entry["_compiled"] = re.compile(pat, base_flags)
                    except re.error as e:
                        log.warning("[Signature] PCRE compile failed for sig %s: %s", sig["id"], e)
                        entry["_compiled"] = None
                compiled.append(entry)

            rules.append({
                "sig":       sig,
                "patterns":  compiled,
                "threshold": threshold,
            })

        _rules = rules
        _rules_loaded = True
        log.info("[Signature] Loaded %d rules.", len(_rules))


def _decode_payload(payload: str) -> tuple:
    """
    Payload from sniffer is a hex string (e.g. "474554202f...").
    Returns (decoded_str, raw_bytes) for content/pcre and hex matching.
    """
    try:
        raw = bytes.fromhex(payload)
        decoded = raw.decode("utf-8", errors="replace")
    except ValueError:
        raw     = payload.encode("latin-1", errors="replace")
        decoded = payload
    return decoded, raw


def _match_pattern(p: dict, pkt: dict) -> bool:
    ptype   = p.get("pattern_type", "")
    pattern = p.get("pattern", "") or ""
    payload = pkt.get("payload", "") or ""
    flags   = pkt.get("flags",   "") or ""
    negated = bool(p.get("negated", 0))

    decoded_payload, raw_payload = _decode_payload(payload)

    if ptype == "content":
        # offset/depth apply to decoded string bytes
        offset = p.get("offset") or 0
        depth  = p.get("depth")  or 0
        search_payload = decoded_payload[offset:offset + depth] if depth else decoded_payload[offset:]
        if p.get("nocase", 1):
            result = pattern.lower() in search_payload.lower()
        else:
            result = pattern in search_payload
        return not result if negated else result

    if ptype == "pcre":
        compiled = p.get("_compiled")
        if compiled is None:
            return False
        result = bool(compiled.search(decoded_payload))
        return not result if negated else result

    if ptype == "hex":
        for hex_part in pattern.split("|"):
            hex_part = hex_part.strip()
            if not hex_part:
                continue
            try:
                needle = bytes.fromhex(hex_part.replace(" ", ""))
                if needle in raw_payload:
                    return not negated
            except ValueError:
                pass
        return negated

    if ptype == "byte_test":
        p_lower = pattern.lower()
        if "tcp_flags" in p_lower:
            try:
                parts = re.split(r"[&=\s]+", p_lower)
                parts = [x for x in parts if x not in ("tcp_flags", "")]
                flag_byte = _flags_to_byte(flags)
                if len(parts) == 2:
                    mask  = int(parts[0], 16)
                    value = int(parts[1], 16)
                    result = (flag_byte & mask) == value
                elif len(parts) == 1:
                    value = int(parts[0], 16)
                    result = flag_byte == value
                else:
                    result = False
                return not result if negated else result
            except Exception:
                return False
        elif "icmp_type" in p_lower:
            try:
                value  = int(p_lower.split("=")[-1].strip())
                result = pkt.get("icmp_type") == value
                return not result if negated else result
            except Exception:
                pass
        return False

    return False


def _flags_to_byte(flags: str) -> int:
    mapping = {"F": 0x01, "S": 0x02, "R": 0x04,
               "P": 0x08, "A": 0x10, "U": 0x20}
    result = 0
    for ch in flags.upper():
        result |= mapping.get(ch, 0)
    return result


def _check_threshold(sig_id: int, threshold: dict, track_key: str, now: float) -> bool:
    """
    Return True when the rule should fire based on threshold_type:
      threshold — fire every time count events occur within seconds
      limit     — fire only once per window (suppress after first alert)
      both      — fire once, then suppress until count is reached again
    """
    if threshold is None:
        return True

    count          = threshold.get("count", 5)
    seconds        = threshold.get("seconds", 60)
    ttype          = (threshold.get("threshold_type") or "threshold").lower()
    key            = (sig_id, track_key)

    with _win_lock:
        cutoff  = now - seconds
        ts_list = [t for t in _windows[key] if t >= cutoff]
        ts_list.append(now)
        _windows[key] = ts_list
        current = len(ts_list)

        if ttype == "limit":
            # Fire only on the first event per window; suppress the rest
            if current == 1:
                return True
            return False

        # threshold / both: fire every time count is reached
        if current >= count:
            _windows[key] = []
            return True

    return False


def _ip_match(sig_ip, pkt_ip: str) -> bool:
    """Match packet IP against 'any', exact IP, or CIDR."""
    if not sig_ip:
        return True
    sig_ip_str = str(sig_ip).strip()
    if sig_ip_str.lower() in ("any", ""):
        return True
    if not pkt_ip:
        return False
    if "/" in sig_ip_str:
        try:
            return ipaddress.ip_address(pkt_ip) in ipaddress.ip_network(sig_ip_str, strict=False)
        except ValueError:
            return False
    return sig_ip_str == pkt_ip.strip()


def _port_match(sig_port, pkt_port) -> bool:
    """Match packet port against 'any', single port, or CSV list."""
    if not sig_port:
        return True
    sig_port_str = str(sig_port).strip().lower()
    if sig_port_str in ("any", ""):
        return True
    if pkt_port is None:
        return False
    ports = [p.strip() for p in sig_port_str.split(",")]
    return str(pkt_port) in ports


def _flow_match(sig_flow: str, pkt: dict) -> bool:
    """
    to_server  — pure SYN or PSH+ACK (client → server)
    to_client  — ACK without SYN (server → client)
    established — ACK set (connection is up, either direction)
    both / any  — always match
    """
    if not sig_flow:
        return True
    flow = sig_flow.strip().lower()
    if flow in ("any", "both", ""):
        return True
    flags = set(pkt.get("flags", "") or "")
    syn = "S" in flags
    ack = "A" in flags
    psh = "P" in flags
    if flow == "to_server":
        return (syn and not ack) or (psh and ack)
    if flow == "to_client":
        return ack and not syn
    if flow == "established":
        return ack
    return True  # unknown value — don't block


def _severity_name(severity_id) -> str:
    mapping = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
    try:
        return mapping.get(int(severity_id), "medium")
    except (TypeError, ValueError):
        return "medium"


def process(pkt: dict):
    if not _rules_loaded and not _rules_failed:
        _load_rules()

    rules_snapshot = _rules
    if not rules_snapshot or _db is None or _am is None:
        return

    src_ip    = pkt.get("src_ip") or ""
    dst_ip    = pkt.get("dst_ip") or ""
    dst_port  = pkt.get("dst_port")
    src_port  = pkt.get("src_port")
    pkt_proto = (pkt.get("protocol") or "").lower()
    now       = pkt.get("timestamp") or time.time()

    if src_ip and _db.is_whitelisted(src_ip):
        return

    for rule in rules_snapshot:
        sig      = rule["sig"]
        patterns = rule["patterns"]

        # Protocol filter — map app-layer names to transport
        sig_proto = _PROTO_MAP.get(
            (sig.get("protocol_name") or "any").lower().strip(),
            (sig.get("protocol_name") or "any").lower().strip()
        )
        if sig_proto not in ("any", ""):
            if not pkt_proto or sig_proto != pkt_proto:
                continue

        # IP filters
        if not _ip_match(sig.get("src_ip"), src_ip):
            continue
        if not _ip_match(sig.get("dst_ip"), dst_ip):
            continue

        # Port filters
        if not _port_match(sig.get("src_port"), src_port):
            continue
        if not _port_match(sig.get("dst_port"), dst_port):
            continue

        # Flow direction filter
        if not _flow_match(sig.get("flow"), pkt):
            continue

        # All patterns must match (AND logic)
        if patterns and not all(_match_pattern(p, pkt) for p in patterns):
            continue

        # Threshold check
        threshold = rule["threshold"]
        track = "by_src"
        if threshold:
            track = threshold.get("track") or "by_src"
        track_key = src_ip if track in ("by_src", "by_both") else dst_ip

        if not _check_threshold(sig["id"], threshold, track_key, now):
            continue

        severity = _severity_name(sig.get("severity_id"))
        detail   = f"Signature match: {sig['name']}"
        if sig.get("description"):
            detail += f" — {sig['description']}"

        _am.fire(
            alert_type   = "signature",
            severity     = severity,
            src_ip       = src_ip or None,
            dst_ip       = dst_ip or None,
            src_port     = src_port,
            dst_port     = dst_port,
            protocol     = pkt_proto.upper() or None,
            detail       = detail,
            signature_id = sig["id"],
        )
        log.warning("[Signature] Rule %s matched: %s from %s",
                    sig.get("sid"), sig["name"], src_ip)


def reload_rules():
    """Force reload of rules from DB (called after rule edits)."""
    global _rules_loaded, _rules_failed, _rules
    # Do NOT hold _load_lock here — _load_rules() acquires it; holding it here
    # then calling _load_rules() would deadlock.
    _rules_loaded = False
    _rules_failed = False
    _rules = []
    # Clear stale threshold windows so old sig IDs don't leak memory
    with _win_lock:
        _windows.clear()
    _load_rules()
