from typing import Dict, Any, Optional, Tuple, Set
from datetime import datetime, timezone
import socket
import time
from .logging_utils import action as log_action, result as log_result, error as log_error, event as log_event


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _get_local_ips_for_iface(iface: Optional[str]) -> Set[str]:
    """Collect local IPv4/IPv6 addresses for direction determination.
    Works on Linux and Windows using Scapy helpers.
    """
    ips: Set[str] = set()
    try:
        from scapy.all import get_if_addr, get_if_list
        try:
            # IPv6 helper (may be missing on some builds)
            from scapy.layers.inet6 import in6_getifaddr  # type: ignore
        except Exception:  # pragma: no cover
            in6_getifaddr = None  # type: ignore

        if iface:
            try:
                ip4 = get_if_addr(iface)
                if ip4 and ip4 != '0.0.0.0':
                    ips.add(ip4)
            except Exception:
                pass
            if in6_getifaddr:
                try:
                    for rec in in6_getifaddr():
                        # rec is tuple-like: (addr, scope, prefixlen, iface)
                        try:
                            addr, _scope, _plen, ifn = rec
                        except Exception:
                            # Fallback to object attrs
                            addr = getattr(rec, 'addr', None)
                            ifn = getattr(rec, 'iface', None)
                        if ifn == iface and addr:
                            ips.add(addr)
                except Exception:
                    pass
        else:
            # All interfaces
            try:
                for ifn in get_if_list():
                    try:
                        ip4 = get_if_addr(ifn)
                        if ip4 and ip4 != '0.0.0.0':
                            ips.add(ip4)
                    except Exception:
                        continue
                if in6_getifaddr:
                    try:
                        for rec in in6_getifaddr():
                            try:
                                addr, _scope, _plen, _ifn = rec
                            except Exception:
                                addr = getattr(rec, 'addr', None)
                            if addr:
                                ips.add(addr)
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    # Always include localhost
    ips.update({"127.0.0.1", "::1"})
    return ips


def _canon_session_key(src: str, sport: int, dst: str, dport: int, proto: str) -> Tuple[str, int, str, int, str]:
    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        return (a[0], a[1], b[0], b[1], proto)
    else:
        return (b[0], b[1], a[0], a[1], proto)


def _session_id_from_key(key: Tuple[str, int, str, int, str]) -> str:
    s1, p1, s2, p2, proto = key
    return f"{s1}:{p1}-{s2}:{p2}-{proto}"


def capture_to_jsonl(
    output_path: str,
    iface: Optional[str] = None,
    duration: int = 10,
    bpf_filter: Optional[str] = None,
    bin_seconds: int = 1,
) -> int:
    """Sniff network traffic and write per-session, per-bin feature events.

    Produces JSONL events with fields: timestamp, session_id, bytes_in, bytes_out, src_ip, dst_ip, dst_port, proto.
    bytes_in/out are relative to local host IPs.
    Returns number of events written.
    """
    log_action(f"capture_to_jsonl:start iface={iface} duration={duration} bpf={bpf_filter} bin={bin_seconds} -> {output_path}")
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP
    except Exception as e:
        msg = "Scapy missing or capture backend not available"
        log_error(f"capture_to_jsonl:error {msg}: {e}")
        raise RuntimeError("Scapy is required. Install 'scapy' and ensure Npcap/WinPcap is installed on Windows.") from e

    local_ips = _get_local_ips_for_iface(iface)
    t0 = time.time()
    end_time = t0 + max(1, int(duration))
    bin_s = max(1, int(bin_seconds))

    # Accumulate per (session_key, bin_index)
    buckets: Dict[Tuple[Tuple[str, int, str, int, str], int], Dict[str, Any]] = {}

    def on_pkt(pkt):
        try:
            ts = float(pkt.time)
        except Exception:
            ts = time.time()
        # Extract 5-tuple
        src = dst = None
        sport = dport = 0
        proto = "IP"

        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            # Detect protocol: TCP/UDP/ICMP or numeric
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif getattr(ip, 'proto', None) == 1:
                proto = "ICMP"
            else:
                proto = str(ip.proto)
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            src = ip6.src
            dst = ip6.dst
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif getattr(ip6, 'nh', None) == 58:
                proto = "ICMPv6"
            else:
                proto = str(ip6.nh)
        else:
            return

        if TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        elif UDP in pkt:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)

        if not src or not dst:
            return

        key = _canon_session_key(src, sport, dst, dport, proto)
        # Direction relative to local IPs
        try:
            size = int(len(bytes(pkt)))
        except Exception:
            size = int(getattr(pkt, 'len', 0) or 0)

        incoming = dst in local_ips
        outgoing = src in local_ips

        bin_index = int((ts - t0) // bin_s)
        bucket_key = (key, bin_index)
        if bucket_key not in buckets:
            buckets[bucket_key] = {
                "timestamp": t0 + bin_index * bin_s,
                "session_key": key,
                "bytes_in": 0,
                "bytes_out": 0,
                "src_ip": key[0],
                "dst_ip": key[2],
                "dst_port": key[3],
                "proto": key[4],
            }
        if incoming:
            buckets[bucket_key]["bytes_in"] += size
        if outgoing:
            buckets[bucket_key]["bytes_out"] += size

    # Run sniff until end_time
    timeout = max(1, int(duration))
    sniff_kwargs: Dict[str, Any] = {
        "prn": on_pkt,
        "store": False,
        "timeout": timeout,
    }
    if iface:
        sniff_kwargs["iface"] = iface
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    try:
        sniff(**sniff_kwargs)
    except Exception as e:
        log_error(f"capture_to_jsonl:sniff_error {e}")
        raise

    # Write JSONL
    import json, os
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    count = 0
    with open(output_path, "w", encoding="utf-8") as f:
        for ((_, _), rec) in sorted(buckets.items(), key=lambda x: (x[0][0], x[0][1])):
            ts = float(rec["timestamp"])
            session_id = _session_id_from_key(rec["session_key"])
            out = {
                "timestamp": _iso_utc(ts),
                "session_id": session_id,
                "bytes_in": rec["bytes_in"],
                "bytes_out": rec["bytes_out"],
                "src_ip": rec["src_ip"],
                "dst_ip": rec["dst_ip"],
                "dst_port": rec["dst_port"],
                "proto": rec["proto"],
            }
            line = json.dumps(out, ensure_ascii=False)
            f.write(line + "\n")
            log_result(line)
            # Also mirror each captured event into logs/captured_events.jsonl via event logger
            log_event(line)
            count += 1
    log_action(f"capture_to_jsonl:done count={count} -> {output_path}")
    return count
