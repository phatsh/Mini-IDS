"""Packet direction and flow key extraction."""

from enum import Enum
from typing import Tuple
from scapy.packet import Packet


class PacketDirection(Enum):
    """Direction of packet in flow."""
    FORWARD = 1
    REVERSE = 2


def get_packet_flow_key(packet: Packet, direction: PacketDirection) -> Tuple[str, str, int, int]:
    """Extract flow key (src_ip, dest_ip, src_port, dest_port) from packet.
    
    Args:
        packet: Scapy packet
        direction: Packet direction (used to determine canonical flow endpoints)
        
    Returns:
        Tuple of (src_ip, dest_ip, src_port, dest_port)
    """
    from scapy.all import IP, IPv6, TCP, UDP
    
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
    
    # Canonicalize: always use lexicographically smaller IP:port as "src"
    # This ensures consistent flow direction regardless of capture point
    # Compare tuples: (IP, port)
    a_tuple = (src_ip or "", src_port)
    b_tuple = (dest_ip or "", dest_port)
    if a_tuple > b_tuple:
        src_ip, dest_ip = dest_ip, src_ip
        src_port, dest_port = dest_port, src_port
    
    return (src_ip or "", dest_ip or "", src_port, dest_port)

