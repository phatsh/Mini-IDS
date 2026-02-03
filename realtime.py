from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from datetime import datetime, timezone
import time
import json
import os
from .logging_utils import action as log_action, result as log_result, error as log_error, event as log_event, formatted as log_formatted, ml as log_ml
from .packet_features import compute_packet_features


def _iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


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


@dataclass
class _BinRec:
    ts: float
    bytes_in: int = 0
    bytes_out: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    proto: str = ""


def realtime_monitor(
    rules_matcher,
    detector,
    feature_names: List[str],
    alerts_output: str,
    iface: Optional[str] = None,
    duration: Optional[int] = None,
    bpf_filter: Optional[str] = None,
    bin_seconds: int = 1,
) -> None:
    """Capture packets and perform realtime detection. Sigma is evaluated first; if no hit, run ML.

    Appends JSONL alerts to alerts_output as they occur.
    """
    log_action(f"realtime_monitor:start iface={iface} duration={duration} bpf={bpf_filter} bin={bin_seconds}")
    try:
        from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, get_if_addr, get_if_list
        try:
            from scapy.layers.inet6 import in6_getifaddr  # type: ignore
        except Exception:  # pragma: no cover
            in6_getifaddr = None  # type: ignore
    except Exception as e:
        log_error(f"realtime_monitor:scapy_missing {e}")
        raise RuntimeError("Scapy is required. Install 'scapy' and ensure Npcap/WinPcap is installed on Windows.") from e

    local_ips: List[str] = []
    try:
        if iface:
            try:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0':
                    local_ips.append(ip)
            except Exception:
                pass
            if in6_getifaddr:
                try:
                    for rec in in6_getifaddr():
                        try:
                            addr, _scope, _plen, ifn = rec
                        except Exception:
                            addr = getattr(rec, 'addr', None)
                            ifn = getattr(rec, 'iface', None)
                        if ifn == iface and addr:
                            local_ips.append(addr)
                except Exception:
                    pass
        else:
            for ifn in get_if_list():
                try:
                    ip = get_if_addr(ifn)
                    if ip and ip != '0.0.0.0':
                        local_ips.append(ip)
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
                            local_ips.append(addr)
                except Exception:
                    pass
    except Exception:
        pass
    local_ips += ["127.0.0.1", "::1"]

    t0 = time.time()
    bin_s = max(1, int(bin_seconds))

    # Aggregation per session and bin index (for flow-level stats & Sigma)
    bins: Dict[Tuple[str, int, str, int, str], Dict[int, _BinRec]] = {}
    # Sliding feature windows per session for ML (packet-level features)
    session_feats: Dict[Tuple[str, int, str, int, str], List[List[float]]] = {}
    # Derived stats history per session for heuristic enrichment
    session_stats: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}

    os.makedirs(os.path.dirname(alerts_output) or ".", exist_ok=True)
    alert_f = open(alerts_output, "a", encoding="utf-8")

    def write_alert(event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False)
        alert_f.write(line + "\n")
        alert_f.flush()
        log_result(line)

    def on_packet(pkt) -> None:
        try:
            ts = float(pkt.time)
        except Exception:
            ts = time.time()

        src = dst = None
        sport = dport = 0
        proto = "IP"

        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
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

        try:
            size = int(len(bytes(pkt)))
        except Exception:
            size = int(getattr(pkt, 'len', 0) or 0)

        key = _canon_session_key(src, sport, dst, dport, proto)
        incoming = dst in local_ips
        outgoing = src in local_ips

        # Immediately emit formatted per-packet features log and feed ML feature buffer
        try:
            # Feature names come from detector.feature_names
            # Determine forward/backward based on canonical session key
            # In our canonical key, (src,sport) is lexicographically <= (dst,dport)
            # Treat packets matching the first tuple as forward
            fwd = (src == key[0] and sport == key[1])
            feat_values = compute_packet_features(
                pkt,
                getattr(detector, 'feature_names', []),
                local_ips,
                is_forward=fwd,
            )
            formatted_entry = {
                "timestamp": _iso_utc(ts),
                "src_ip": src,
                "dst_ip": dst,
                "src_port": sport,
                "dst_port": dport,
                "proto": proto,
                "length": size,
                "features": feat_values,
            }
            log_formatted(json.dumps(formatted_entry, ensure_ascii=False))

            # Build ML feature row based on model's expected feature_names
            try:
                feat_row: List[float] = []
                for name in feature_names:
                    v = feat_values.get(name)
                    feat_row.append(float(v) if v is not None else 0.0)
                buf = session_feats.setdefault(key, [])
                buf.append(feat_row)
                # Keep only recent window; detector.L exists
                L = getattr(detector, 'L', 10)
                if len(buf) > L + 50:
                    # keep small cushion to avoid frequent reallocs
                    buf[:] = buf[-(L + 20) :]
            except Exception:
                pass
        except Exception:
            pass

        bin_index = int((ts - t0) // bin_s)
        recs = bins.setdefault(key, {})
        if bin_index not in recs:
            recs[bin_index] = _BinRec(
                ts=t0 + bin_index * bin_s,
                bytes_in=0,
                bytes_out=0,
                src_ip=key[0],
                dst_ip=key[2],
                dst_port=key[3],
                proto=key[4],
            )
        if incoming:
            recs[bin_index].bytes_in += size
        if outgoing:
            recs[bin_index].bytes_out += size

    # Start async sniffer
    sniffer = AsyncSniffer(prn=on_packet, store=False, iface=iface, filter=bpf_filter) if bpf_filter else AsyncSniffer(prn=on_packet, store=False, iface=iface)
    sniffer.start()
    log_action("realtime_monitor:sniffer_started")

    # Main loop: flush completed bins periodically
    try:
        end_time = None if duration is None else (time.time() + max(1, int(duration)))
        while True:
            now = time.time()
            now_bin = int((now - t0) // bin_s)
            # For each session, flush all bins older than current bin
            for key, recs in list(bins.items()):
                ready_bins = [b for b in recs.keys() if b < now_bin]
                ready_bins.sort()
                for b in ready_bins:
                    rec = recs.pop(b)
                    stats = session_stats.setdefault(key, {
                        "out_rates": [],
                        "in_rates": [],
                        "bytes_out_hist": [],
                        "bytes_in_hist": [],
                    })

                    out_rate = rec.bytes_out / float(bin_s)
                    in_rate = rec.bytes_in / float(bin_s)
                    stats["out_rates"].append(out_rate)
                    stats["in_rates"].append(in_rate)
                    stats["bytes_out_hist"].append(rec.bytes_out)
                    stats["bytes_in_hist"].append(rec.bytes_in)

                    # Rolling mean/std for out_rate (last 20 bins)
                    import math
                    recent_out = stats["out_rates"][-20:]
                    if recent_out:
                        mean_out = sum(recent_out) / len(recent_out)
                        var_out = sum((x - mean_out) ** 2 for x in recent_out) / len(recent_out)
                        std_out = math.sqrt(var_out)
                    else:
                        mean_out = 0.0
                        std_out = 0.0
                    out_rate_z = (out_rate - mean_out) / (std_out if std_out > 0 else 1.0)
                    asymmetry = rec.bytes_out / float(rec.bytes_in + 1)

                    event_obj = {
                        "timestamp": _iso_utc(rec.ts),
                        "session_id": _session_id_from_key(key),
                        "bytes_in": rec.bytes_in,
                        "bytes_out": rec.bytes_out,
                        "src_ip": rec.src_ip,
                        "dst_ip": rec.dst_ip,
                        "dst_port": rec.dst_port,
                        "proto": rec.proto,
                        # Enriched derived metrics
                        "out_rate": out_rate,
                        "in_rate": in_rate,
                        "out_rate_mean": mean_out,
                        "out_rate_std": std_out,
                        "out_rate_z": out_rate_z,
                        "asymmetry": asymmetry,
                    }
                    # Log raw captured event to events log
                    try:
                        log_event(json.dumps(event_obj, ensure_ascii=False))
                    except Exception:
                        pass
                    # 1) Sigma first
                    sigma_hits = rules_matcher.match_event(event_obj)

                    # Use packet-level ML feature buffer for this session
                    buf = session_feats.get(key, [])
                    flags = detector.predict_flags(buf) if buf else []
                    scores = detector.predict_scores(buf) if buf else []
                    try:
                        log_ml(json.dumps({
                            "ts": _iso_utc(rec.ts),
                            "session_id": _session_id_from_key(key),
                            "phase": "bin_window_eval",
                            "score": float(scores[-1] or 0.0) if scores else 0.0,
                            "flag": bool(flags[-1]) if flags else False,
                            "threshold": float(getattr(detector, 'threshold', 0.5)),
                            "window_len": len(buf),
                        }, ensure_ascii=False))
                    except Exception:
                        pass

                    # New workflow: If Sigma matched, use ML bin score + heuristics to decide severity and action
                    if sigma_hits:
                        last_score = float(scores[-1] or 0.0) if scores else 0.0
                        last_flag = bool(flags[-1]) if flags else False

                        # Heuristic override: elevate if out_rate_z high or asymmetry extreme
                        heuristic_hit = False
                        try:
                            if out_rate_z >= 3.0 and rec.bytes_out >= 10000:
                                heuristic_hit = True
                            if asymmetry >= 50 and rec.bytes_out >= 5000:
                                heuristic_hit = True
                        except Exception:
                            pass

                        final_flag = last_flag or heuristic_hit
                        severity = "Medium" if not final_flag else "High"
                        action = "allow" if not final_flag else "drop"

                        try:
                            log_ml(json.dumps({
                                "ts": _iso_utc(rec.ts),
                                "session_id": _session_id_from_key(key),
                                "phase": "sigma_bin_eval",
                                "score": last_score,
                                "flag": final_flag,
                                "threshold": float(getattr(detector, 'threshold', 0.5)),
                                "heuristic": heuristic_hit,
                                "rule_ids": [h.get("rule_id") for h in sigma_hits] if isinstance(sigma_hits, list) else [],
                            }, ensure_ascii=False))
                        except Exception:
                            pass

                        alert = {
                            "timestamp": event_obj["timestamp"],
                            "session_id": event_obj["session_id"],
                            "src_ip": event_obj["src_ip"],
                            "dst_ip": event_obj["dst_ip"],
                            "dst_port": event_obj["dst_port"],
                            "proto": event_obj["proto"],
                            "bytes_in": event_obj["bytes_in"],
                            "bytes_out": event_obj["bytes_out"],
                            "_alert_kind": "sigma+ml",
                            "_alert_details": {
                                "sigma": sigma_hits,
                                "ml": {
                                    "hit": final_flag,
                                    "score": last_score,
                                    "threshold": float(getattr(detector, 'threshold', 0.5)),
                                    "heuristic": heuristic_hit,
                                },
                            },
                            # CIM-like fields
                            "event_category": "network",
                            "event_type": "ids",
                            "severity": severity,
                            "action": action,
                            "rule": sigma_hits[0].get("title") if isinstance(sigma_hits, list) and sigma_hits else None,
                        }
                        # Log IDS-style event and any action
                        if action == "drop":
                            try:
                                log_action(
                                    "ids_action:drop "
                                    f"session={alert['session_id']} proto={alert['proto']} "
                                    f"src={alert['src_ip']} dst={alert['dst_ip']} port={alert['dst_port']} "
                                    f"score={last_score} out_rate_z={out_rate_z:.2f} asym={asymmetry:.2f}"
                                )
                            except Exception:
                                pass
                        write_alert(alert)
                        continue

                    # 2) ML if Sigma didn't hit: raise ML alerts only on anomaly
                    if flags and flags[-1]:
                        alert = dict(event_obj)
                        alert["_alert_kind"] = "ml"
                        alert["_alert_details"] = {"ml": {"hit": True, "score": float(scores[-1] or 0.0), "threshold": float(getattr(detector, 'threshold', 0.5))}}
                        # CIM-like fields
                        alert["event_category"] = "network"
                        alert["event_type"] = "ids"
                        alert["severity"] = "High"
                        alert["action"] = "drop"
                        try:
                            log_action(f"ids_action:drop session={alert['session_id']} proto={alert['proto']} src={alert['src_ip']} dst={alert['dst_ip']} port={alert['dst_port']} score={float(scores[-1] or 0.0)}")
                        except Exception:
                            pass
                        write_alert(alert)

                if not recs:
                    bins.pop(key, None)

            if end_time is not None and now >= end_time:
                break
            time.sleep(max(0.1, bin_s * 0.2))
    finally:
        try:
            sniffer.stop()
            log_action("realtime_monitor:sniffer_stopped")
        except Exception as e:
            # Some platforms/interfaces may emit 'Unsupported (offline or unsupported socket)' on stop; degrade to info
            log_action(f"realtime_monitor:sniffer_stop_noncritical {e}")
        alert_f.close()
        log_action("realtime_monitor:closed")
