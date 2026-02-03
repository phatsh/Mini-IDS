"""Extract CICFlowMeter-style features from pcap or realtime capture."""

from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timezone
import json
import time
import os

from .cicflow.flow import Flow
from .cicflow.context import PacketDirection, get_packet_flow_key
from .logging_utils import action as log_action, error as log_error


def _iso_utc(ts: float) -> str:
    """Convert timestamp to ISO UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _determine_direction(
    packet, local_ips: Set[str], flow_key: tuple
) -> PacketDirection:
    """Determine packet direction based on local IPs and flow key.
    
    Args:
        packet: Scapy packet
        local_ips: Set of local IP addresses
        flow_key: (src_ip, dest_ip, src_port, dest_port) tuple
        
    Returns:
        PacketDirection.FORWARD if packet matches first endpoint, else REVERSE
    """
    from scapy.all import IP, IPv6
    
    src_ip = None
    if IP in packet:
        src_ip = packet[IP].src
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
    
    # If src_ip matches the first endpoint in canonicalized flow key, it's FORWARD
    if src_ip == flow_key[0]:
        return PacketDirection.FORWARD
    return PacketDirection.REVERSE


def extract_flows_from_pcap(
    pcap_path: str,
    local_ips: Optional[List[str]] = None,
    flow_timeout: float = 120.0,
    output_jsonl: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Extract flows from a pcap file and return as list of feature dicts.
    
    Args:
        pcap_path: Path to pcap file
        local_ips: List of local IP addresses (for direction determination)
        flow_timeout: Timeout for flow expiration (seconds)
        output_jsonl: Optional path to write JSONL output
        
    Returns:
        List of flow feature dictionaries
    """
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP
    
    log_action(f"extract_flows_from_pcap:start pcap={pcap_path} timeout={flow_timeout}")
    
    if local_ips is None:
        local_ips = []
    local_ips_set = set(local_ips) | {"127.0.0.1", "::1"}
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        log_error(f"extract_flows_from_pcap:error reading pcap {e}")
        raise
    
    flows: Dict[tuple, Flow] = {}
    flows_data: List[Dict[str, Any]] = []
    
    for packet in packets:
        try:
            # Skip non-IP packets
            if IP not in packet and IPv6 not in packet:
                continue
            
            # Skip non-TCP/UDP packets (for now)
            if TCP not in packet and UDP not in packet:
                continue
            
            # Determine flow key
            src_ip = dest_ip = None
            src_port = dest_port = 0
            
            if IP in packet:
                src_ip = packet[IP].src
                dest_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dest_ip = packet[IPv6].dst
            
            if TCP in packet:
                src_port = int(packet[TCP].sport)
                dest_port = int(packet[TCP].dport)
            elif UDP in packet:
                src_port = int(packet[UDP].sport)
                dest_port = int(packet[UDP].dport)
            
            if not src_ip or not dest_ip:
                continue
            
            # Canonicalize flow key
            flow_key = get_packet_flow_key(packet, PacketDirection.FORWARD)
            key_tuple = (flow_key[0], flow_key[1], flow_key[2], flow_key[3])
            
            # Determine direction
            direction = _determine_direction(packet, local_ips_set, flow_key)
            
            # Get or create flow
            if key_tuple not in flows:
                flows[key_tuple] = Flow(packet, direction)
            else:
                flow = flows[key_tuple]
                # Check if flow expired
                if packet.time - flow.latest_timestamp > flow_timeout:
                    # Flush expired flow
                    flow_data = flow.get_data()
                    flow_data["timestamp"] = _iso_utc(flow.start_timestamp)
                    flows_data.append(flow_data)
                    # Create new flow
                    flows[key_tuple] = Flow(packet, direction)
                else:
                    flow.add_packet(packet, direction)
        
        except Exception as e:
            log_error(f"extract_flows_from_pcap:error processing packet {e}")
            continue
    
    # Flush remaining flows
    for flow in flows.values():
        try:
            flow_data = flow.get_data()
            flow_data["timestamp"] = _iso_utc(flow.start_timestamp)
            flows_data.append(flow_data)
        except Exception as e:
            log_error(f"extract_flows_from_pcap:error flushing flow {e}")
            continue
    
    log_action(f"extract_flows_from_pcap:done extracted {len(flows_data)} flows")
    
    # Write to JSONL if requested
    if output_jsonl:
        os.makedirs(os.path.dirname(output_jsonl) or ".", exist_ok=True)
        with open(output_jsonl, "w", encoding="utf-8") as f:
            for flow_data in flows_data:
                f.write(json.dumps(flow_data, ensure_ascii=False) + "\n")
        log_action(f"extract_flows_from_pcap:wrote {len(flows_data)} flows to {output_jsonl}")
    
    return flows_data


def capture_and_extract_flows(
    iface: Optional[str] = None,
    duration: Optional[int] = None,
    bpf_filter: Optional[str] = None,
    local_ips: Optional[List[str]] = None,
    flow_timeout: float = 120.0,
    output_jsonl: str = "flows.jsonl",
) -> List[Dict[str, Any]]:
    """Capture packets and extract flows in realtime.
    
    Args:
        iface: Network interface name
        duration: Capture duration in seconds (None = until Ctrl+C)
        bpf_filter: BPF filter string
        local_ips: List of local IP addresses
        flow_timeout: Flow expiration timeout (seconds)
        output_jsonl: Output JSONL file path
        
    Returns:
        List of flow feature dictionaries
    """
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, get_if_addr, get_if_list
    try:
        from scapy.layers.inet6 import in6_getifaddr
    except Exception:
        in6_getifaddr = None
    
    log_action(f"capture_and_extract_flows:start iface={iface} duration={duration} bpf={bpf_filter}")
    
    # Build local IP set
    if local_ips is None:
        local_ips = []
    local_ips_set = set(local_ips)
    
    try:
        if iface:
            try:
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0':
                    local_ips_set.add(ip)
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
                            local_ips_set.add(addr)
                except Exception:
                    pass
        else:
            for ifn in get_if_list():
                try:
                    ip = get_if_addr(ifn)
                    if ip and ip != '0.0.0.0':
                        local_ips_set.add(ip)
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
                            local_ips_set.add(addr)
                except Exception:
                    pass
    except Exception:
        pass
    
    local_ips_set.update({"127.0.0.1", "::1"})
    
    flows: Dict[tuple, Flow] = {}
    flows_data: List[Dict[str, Any]] = []
    t0 = time.time()
    
    def on_packet(pkt):
        try:
            # Skip non-IP packets
            if IP not in pkt and IPv6 not in pkt:
                return
            
            # Skip non-TCP/UDP packets
            if TCP not in pkt and UDP not in pkt:
                return
            
            # Extract flow key
            src_ip = dest_ip = None
            src_port = dest_port = 0
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dest_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dest_ip = pkt[IPv6].dst
            
            if TCP in pkt:
                src_port = int(pkt[TCP].sport)
                dest_port = int(pkt[TCP].dport)
            elif UDP in pkt:
                src_port = int(pkt[UDP].sport)
                dest_port = int(pkt[UDP].dport)
            
            if not src_ip or not dest_ip:
                return
            
            # Canonicalize flow key
            flow_key = get_packet_flow_key(pkt, PacketDirection.FORWARD)
            key_tuple = (flow_key[0], flow_key[1], flow_key[2], flow_key[3])
            
            # Determine direction
            direction = _determine_direction(pkt, local_ips_set, flow_key)
            
            # Get or create flow
            if key_tuple not in flows:
                flows[key_tuple] = Flow(pkt, direction)
            else:
                flow = flows[key_tuple]
                # Check expiration
                if pkt.time - flow.latest_timestamp > flow_timeout:
                    # Flush expired flow
                    try:
                        flow_data = flow.get_data()
                        flow_data["timestamp"] = _iso_utc(flow.start_timestamp)
                        flows_data.append(flow_data)
                        # Write immediately
                        os.makedirs(os.path.dirname(output_jsonl) or ".", exist_ok=True)
                        with open(output_jsonl, "a", encoding="utf-8") as f:
                            f.write(json.dumps(flow_data, ensure_ascii=False) + "\n")
                    except Exception as e:
                        log_error(f"capture_and_extract_flows:error flushing flow {e}")
                    # Create new flow
                    flows[key_tuple] = Flow(pkt, direction)
                else:
                    flow.add_packet(pkt, direction)
        
        except Exception as e:
            log_error(f"capture_and_extract_flows:error processing packet {e}")
    
    # Start sniffer
    sniffer_kwargs = {"prn": on_packet, "store": False}
    if iface:
        sniffer_kwargs["iface"] = iface
    if bpf_filter:
        sniffer_kwargs["filter"] = bpf_filter
    
    sniffer = AsyncSniffer(**sniffer_kwargs)
    sniffer.start()
    log_action("capture_and_extract_flows:sniffer_started")
    
    try:
        end_time = None if duration is None else (time.time() + max(1, int(duration)))
        while True:
            now = time.time()
            if end_time is not None and now >= end_time:
                break
            
            # Periodically flush expired flows
            expired_keys = []
            for key_tuple, flow in flows.items():
                if now - flow.latest_timestamp > flow_timeout:
                    expired_keys.append(key_tuple)
            
            for key_tuple in expired_keys:
                flow = flows.pop(key_tuple)
                try:
                    flow_data = flow.get_data()
                    flow_data["timestamp"] = _iso_utc(flow.start_timestamp)
                    flows_data.append(flow_data)
                    # Write immediately
                    os.makedirs(os.path.dirname(output_jsonl) or ".", exist_ok=True)
                    with open(output_jsonl, "a", encoding="utf-8") as f:
                        f.write(json.dumps(flow_data, ensure_ascii=False) + "\n")
                except Exception as e:
                    log_error(f"capture_and_extract_flows:error flushing expired flow {e}")
            
            time.sleep(1.0)
    
    finally:
        try:
            sniffer.stop()
            log_action("capture_and_extract_flows:sniffer_stopped")
        except Exception as e:
            log_action(f"capture_and_extract_flows:sniffer_stop_noncritical {e}")
        
        # Flush all remaining flows
        os.makedirs(os.path.dirname(output_jsonl) or ".", exist_ok=True)
        with open(output_jsonl, "a", encoding="utf-8") as f:
            for flow in flows.values():
                try:
                    flow_data = flow.get_data()
                    flow_data["timestamp"] = _iso_utc(flow.start_timestamp)
                    flows_data.append(flow_data)
                    f.write(json.dumps(flow_data, ensure_ascii=False) + "\n")
                except Exception as e:
                    log_error(f"capture_and_extract_flows:error flushing final flow {e}")
        
        log_action(f"capture_and_extract_flows:done extracted {len(flows_data)} flows")
    
    return flows_data

