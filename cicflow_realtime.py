"""Realtime flow extraction with immediate Sigma + ML detection."""

from typing import Dict, Any, Optional, List, Set, Callable
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
    """Determine packet direction based on local IPs and flow key."""
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


def capture_and_detect_realtime(
    iface: Optional[str] = None,
    duration: Optional[int] = None,
    bpf_filter: Optional[str] = None,
    local_ips: Optional[List[str]] = None,
    flow_timeout: float = 120.0,
    flows_output: str = "flows.jsonl",
    on_flow_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
    packet_dropper: Optional[Any] = None,
) -> None:
    """Capture packets and extract flows in realtime, calling callback immediately when flow completes.
    
    Args:
        iface: Network interface name
        duration: Capture duration in seconds (None = until Ctrl+C)
        bpf_filter: BPF filter string
        local_ips: List of local IP addresses
        flow_timeout: Flow expiration timeout (seconds)
        flows_output: Output JSONL file path (for logging)
        on_flow_complete: Callback function called immediately when a flow is completed.
                         Receives flow_data dict as argument.
        packet_dropper: Optional PacketDropper instance for dropping malicious packets.
    """
    from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, get_if_addr, get_if_list
    try:
        from scapy.layers.inet6 import in6_getifaddr
    except Exception:
        in6_getifaddr = None
    
    log_action(f"capture_and_detect_realtime:start iface={iface} duration={duration} bpf={bpf_filter}")
    
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
    os.makedirs(os.path.dirname(flows_output) or ".", exist_ok=True)
    flows_file = open(flows_output, "a", encoding="utf-8")
    
    def _flush_flow(flow: Flow) -> None:
        """Flush a completed flow and trigger detection."""
        try:
            flow_data = flow.get_data()
            flow_data["timestamp"] = _iso_utc(flow.start_timestamp)
            
            # Write to flows file
            flows_file.write(json.dumps(flow_data, ensure_ascii=False) + "\n")
            flows_file.flush()
            
            # Immediately call callback for realtime detection
            if on_flow_complete:
                on_flow_complete(flow_data)
        except Exception as e:
            log_error(f"capture_and_detect_realtime:error flushing flow {e}")
    
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
            protocol = "TCP"
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dest_ip = pkt[IP].dst
                packet_size = len(pkt[IP])
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dest_ip = pkt[IPv6].dst
                packet_size = len(pkt[IPv6])
            else:
                packet_size = 0
            
            if TCP in pkt:
                src_port = int(pkt[TCP].sport)
                dest_port = int(pkt[TCP].dport)
                protocol = "TCP"
            elif UDP in pkt:
                src_port = int(pkt[UDP].sport)
                dest_port = int(pkt[UDP].dport)
                protocol = "UDP"
            
            if not src_ip or not dest_ip:
                return
            
            # Canonicalize flow key FIRST (needed for flow tracking)
            flow_key = get_packet_flow_key(pkt, PacketDirection.FORWARD)
            key_tuple = (flow_key[0], flow_key[1], flow_key[2], flow_key[3])
            
            # Determine direction (needed before checking flow existence)
            direction = _determine_direction(pkt, local_ips_set, flow_key)
            
            # Check if flow exists BEFORE processing
            flow_exists = key_tuple in flows
            
            # If flow doesn't exist, check if it should be dropped BEFORE creating it
            # This ensures current flow is processed fully before being marked malicious
            # Only NEW flows (not existing ones) can be dropped
            # IMPORTANT: Use canonicalized flow key (key_tuple) to check drop status
            if packet_dropper and not flow_exists:
                # Use canonicalized flow key for consistency
                canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port = key_tuple
                should_drop, _ = packet_dropper.should_drop_packet(
                    canon_src_ip, canon_src_port, canon_dst_ip, canon_dst_port
                )
                if should_drop:
                    # This is a new flow from a previously detected malicious endpoint
                    # Drop the packet (don't create the flow)
                    packet_dropper.drop_packet(
                        canon_src_ip, canon_src_port, canon_dst_ip, canon_dst_port, packet_size
                    )
                    return
            
            # Get or create flow (flow doesn't exist or we've determined it shouldn't be dropped)
            if not flow_exists:
                flows[key_tuple] = Flow(pkt, direction)
            else:
                flow = flows[key_tuple]
                # Check expiration
                if pkt.time - flow.latest_timestamp > flow_timeout:
                    # Flush expired flow immediately
                    _flush_flow(flow)
                    # Check if the new flow (with same key_tuple) should be dropped
                    # Use canonicalized flow key for consistency
                    if packet_dropper:
                        canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port = key_tuple
                        should_drop, _ = packet_dropper.should_drop_packet(
                            canon_src_ip, canon_src_port, canon_dst_ip, canon_dst_port
                        )
                        if should_drop:
                            # Don't create new flow, drop the packet
                            packet_dropper.drop_packet(
                                canon_src_ip, canon_src_port, canon_dst_ip, canon_dst_port, packet_size
                            )
                            return
                    # Create new flow (after checking it shouldn't be dropped)
                    flows[key_tuple] = Flow(pkt, direction)
                else:
                    # Add packet to existing flow (flow is being processed, don't drop)
                    flow.add_packet(pkt, direction)
        
        except Exception as e:
            log_error(f"capture_and_detect_realtime:error processing packet {e}")
    
    # Start sniffer
    sniffer_kwargs = {"prn": on_packet, "store": False}
    if iface:
        sniffer_kwargs["iface"] = iface
    if bpf_filter:
        sniffer_kwargs["filter"] = bpf_filter
    
    sniffer = AsyncSniffer(**sniffer_kwargs)
    sniffer.start()
    log_action("capture_and_detect_realtime:sniffer_started")
    
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
                _flush_flow(flow)
            
            time.sleep(1.0)  # Check every second
    
    finally:
        try:
            sniffer.stop()
            log_action("capture_and_detect_realtime:sniffer_stopped")
        except Exception as e:
            log_action(f"capture_and_detect_realtime:sniffer_stop_noncritical {e}")
        
        # Flush all remaining flows
        for flow in flows.values():
            _flush_flow(flow)
        
        flows_file.close()
        log_action("capture_and_detect_realtime:done")

