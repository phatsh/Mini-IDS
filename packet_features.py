from typing import Dict, Any, List, Optional, Tuple


def _tcp_flag_bits(tcp) -> Dict[str, int]:
    flags = int(getattr(tcp, 'flags', 0))
    return {
        'tcp_flag_fin': 1 if (flags & 0x01) else 0,
        'tcp_flag_syn': 1 if (flags & 0x02) else 0,
        'tcp_flag_rst': 1 if (flags & 0x04) else 0,
        'tcp_flag_psh': 1 if (flags & 0x08) else 0,
        'tcp_flag_ack': 1 if (flags & 0x10) else 0,
        'tcp_flag_urg': 1 if (flags & 0x20) else 0,
        'tcp_flag_ece': 1 if (flags & 0x40) else 0,
        'tcp_flag_cwr': 1 if (flags & 0x80) else 0,
    }


def compute_packet_features(
    pkt,
    feature_names: List[str],
    local_ips: List[str],
    *,
    is_forward: Optional[bool] = None,
) -> Dict[str, float]:
    """Compute a numeric feature dict for a single Scapy packet.
    Unknown feature names are filled with 0.0.
    """
    # Lazy imports to avoid mandatory scapy when unused
    from scapy.all import IP, IPv6, TCP, UDP, Raw, ICMP  # type: ignore
    try:  # ICMPv6 classes vary; we’ll detect generically via payload chain
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply  # type: ignore
    except Exception:  # pragma: no cover
        ICMPv6EchoRequest = None  # type: ignore
        ICMPv6EchoReply = None  # type: ignore

    out: Dict[str, float] = {name: 0.0 for name in feature_names}
    length = float(len(bytes(pkt))) if pkt is not None else 0.0

    src = dst = None
    sport = dport = 0
    proto = None
    ip_len = None
    ttl = None
    hlim = None
    payload_len = 0.0

    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        ip_len = int(getattr(ip, 'len', 0) or 0)
        ttl = int(getattr(ip, 'ttl', 0) or 0)
        if TCP in pkt:
            proto = 'TCP'
        elif UDP in pkt:
            proto = 'UDP'
        elif getattr(ip, 'proto', None) == 1:
            proto = 'ICMP'
        else:
            proto = str(getattr(ip, 'proto', '0'))
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        src = ip6.src
        dst = ip6.dst
        hlim = int(getattr(ip6, 'hlim', 0) or 0)
        if TCP in pkt:
            proto = 'TCP'
        elif UDP in pkt:
            proto = 'UDP'
        elif getattr(ip6, 'nh', None) == 58:
            proto = 'ICMPv6'
        else:
            proto = str(getattr(ip6, 'nh', '0'))

    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        flags = _tcp_flag_bits(pkt[TCP])
    else:
        flags = {k: 0 for k in [
            'tcp_flag_fin','tcp_flag_syn','tcp_flag_rst','tcp_flag_psh','tcp_flag_ack','tcp_flag_urg','tcp_flag_ece','tcp_flag_cwr']}

    if UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

    if Raw in pkt:
        try:
            payload_len = float(len(bytes(pkt[Raw].load)))
        except Exception:
            payload_len = 0.0

    # Direction: prioritize local IP membership; use is_forward only as fallback
    out_local = 1.0 if (src in local_ips) else 0.0
    in_local = 1.0 if (dst in local_ips) else 0.0
    if out_local or in_local:
        outgoing = out_local
        incoming = in_local
    elif is_forward is not None:
        outgoing = 1.0 if is_forward else 0.0
        incoming = 1.0 if (not is_forward) else 0.0
    else:
        # If neither matches local IPs (e.g., passive monitoring on gateway), default forward=True
        outgoing = 1.0
        incoming = 0.0

    # Feature value resolver helpers
    def set_if(name: str, val: float):
        if name in out:
            out[name] = float(val)

    # Common names mapping (generic features)
    set_if('bytes_in', length if incoming else 0.0)
    set_if('bytes_out', length if outgoing else 0.0)
    for alias in ('packet_len', 'pkt_len', 'length'):
        set_if(alias, length)
    if ip_len is not None:
        set_if('ip_len', float(ip_len))
    if ttl is not None:
        set_if('ttl', float(ttl))
    if hlim is not None:
        set_if('hop_limit', float(hlim))
    set_if('payload_len', payload_len)
    set_if('src_port', float(sport))
    set_if('sport', float(sport))
    set_if('dst_port', float(dport))
    set_if('dport', float(dport))

    # Protocol one-hot-ish hints
    set_if('proto_tcp', 1.0 if proto == 'TCP' else 0.0)
    set_if('proto_udp', 1.0 if proto == 'UDP' else 0.0)
    set_if('proto_icmp', 1.0 if proto == 'ICMP' else 0.0)
    set_if('proto_icmpv6', 1.0 if proto == 'ICMPv6' else 0.0)

    # ICMP/ICMPv6 specifics where available
    try:
        icmp_type = icmp_code = icmp_id = icmp_seq = icmp_chksum = None
        if 'ICMP' in proto and ICMP in pkt:
            ic = pkt[ICMP]
            icmp_type = getattr(ic, 'type', None)
            icmp_code = getattr(ic, 'code', None)
            icmp_id = getattr(ic, 'id', None)
            icmp_seq = getattr(ic, 'seq', None)
            icmp_chksum = getattr(ic, 'chksum', None)
        elif proto == 'ICMPv6':
            # Traverse payload chain to find first ICMPv6 layer and its common fields
            layer = pkt
            seen = 0
            while hasattr(layer, 'payload') and getattr(layer, 'payload') and seen < 8:
                layer = layer.payload
                seen += 1
                name = getattr(layer.__class__, '__name__', '')
                if name.startswith('ICMPv6'):
                    icmp_type = getattr(layer, 'type', None)
                    icmp_code = getattr(layer, 'code', None)
                    icmp_id = getattr(layer, 'id', None)
                    icmp_seq = getattr(layer, 'seq', None)
                    icmp_chksum = getattr(layer, 'cksum', None) or getattr(layer, 'chksum', None)
                    break
        # Map if present and requested
        if icmp_type is not None:
            set_if('icmp_type', float(icmp_type))
        if icmp_code is not None:
            set_if('icmp_code', float(icmp_code))
        if icmp_id is not None:
            set_if('icmp_id', float(icmp_id))
        if icmp_seq is not None:
            set_if('icmp_seq', float(icmp_seq))
        if icmp_chksum is not None:
            set_if('icmp_checksum', float(icmp_chksum))
            set_if('icmp_chksum', float(icmp_chksum))  # alias
    except Exception:
        pass

    # TCP fields
    if TCP in pkt:
        set_if('tcp_window', float(getattr(pkt[TCP], 'window', 0) or 0))
        set_if('tcp_seq', float(getattr(pkt[TCP], 'seq', 0) or 0))
        set_if('tcp_ack', float(getattr(pkt[TCP], 'ack', 0) or 0))
        for k, v in flags.items():
            set_if(k, float(v))
        # Also common synonyms
        set_if('syn', float(flags['tcp_flag_syn']))
        set_if('ack', float(flags['tcp_flag_ack']))
        set_if('fin', float(flags['tcp_flag_fin']))
        set_if('rst', float(flags['tcp_flag_rst']))

    # Flow counters per-packet
    set_if('flow_packets_in', 1.0 if incoming else 0.0)
    set_if('flow_packets_out', 1.0 if outgoing else 0.0)

    # CICIDS-style feature name approximations (single-packet estimations)
    # Many pretrained feature sets use CICIDS2017/2018 names. We approximate
    # per-packet values so logs are informative even without multi-packet flow context.
    # Ports
    set_if('Destination Port', float(dport))

    # Forward (outgoing) packet length stats
    fwd_len = length if outgoing else 0.0
    set_if('Total Length of Fwd Packets', fwd_len)
    set_if('Fwd Packet Length Max', fwd_len)
    set_if('Fwd Packet Length Min', fwd_len)
    set_if('Fwd Packet Length Mean', fwd_len)
    set_if('Fwd Packet Length Std', 0.0)

    # Backward (incoming) packet length stats
    bwd_len = length if incoming else 0.0
    set_if('Bwd Packet Length Max', bwd_len)
    set_if('Bwd Packet Length Min', bwd_len)
    set_if('Bwd Packet Length Mean', bwd_len)
    set_if('Bwd Packet Length Std', 0.0)

    # Flow rate (approximate per single packet): 1 pkt/s
    set_if('Flow Packets/s', 1.0)

    # Backward IAT metrics unavailable per-single packet; keep 0.0 defaults
    # set_if('Bwd IAT Total', 0.0)
    # set_if('Bwd IAT Mean', 0.0)
    # set_if('Bwd IAT Std', 0.0)
    # set_if('Bwd IAT Max', 0.0)

    # Packet size related
    set_if('Min Packet Length', length)
    set_if('Max Packet Length', length)
    set_if('Packet Length Mean', length)
    set_if('Packet Length Std', 0.0)
    set_if('Packet Length Variance', 0.0)
    set_if('Average Packet Size', length)

    # TCP flag counts (count within this packet)
    syn_cnt = float(flags.get('tcp_flag_syn', 0))
    psh_cnt = float(flags.get('tcp_flag_psh', 0))
    urg_cnt = float(flags.get('tcp_flag_urg', 0))
    set_if('SYN Flag Count', syn_cnt)
    set_if('PSH Flag Count', psh_cnt)
    set_if('URG Flag Count', urg_cnt)
    # Directional PSH
    set_if('Fwd PSH Flags', psh_cnt if outgoing else 0.0)

    # Directional averages
    set_if('Avg Fwd Segment Size', fwd_len)
    set_if('Avg Bwd Segment Size', bwd_len)

    # Subflow bytes approximations
    set_if('Subflow Fwd Bytes', fwd_len)
    set_if('Subflow Bwd Bytes', bwd_len)

    # Min segment size forward (use payload length if available; else total length)
    set_if('min_seg_size_forward', payload_len if outgoing else 0.0)

    # Ratio metrics: Down/Up Ratio (avoid divide-by-zero). If only outgoing, set 0; if only incoming and no outgoing, treat as large value but cap to length.
    dur = 0.0
    try:
        down = bwd_len
        up = fwd_len
        ratio = (down / up) if up > 0 else (down if down > 0 else 0.0)
        set_if('Down/Up Ratio', ratio)
    except Exception:
        pass

    return out
