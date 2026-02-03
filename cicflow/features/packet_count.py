"""Packet counting for flows."""

from typing import Optional
from scapy.packet import Packet
from ..context import PacketDirection


class PacketCount:
    """Count packets and calculate rates."""
    
    def __init__(self, flow):
        """Initialize with a Flow object."""
        self.flow = flow
    
    @staticmethod
    def get_payload(packet: Packet) -> bytes:
        """Extract payload from packet."""
        from scapy.all import Raw
        if Raw in packet:
            return bytes(packet[Raw].load)
        return b""
    
    def get_rate(self, direction: Optional[PacketDirection] = None) -> float:
        """Get packets per second."""
        duration = self.flow.duration
        if duration <= 0:
            return 0.0
        
        count = self.get_total(direction)
        return count / duration
    
    def get_total(self, direction: Optional[PacketDirection] = None) -> int:
        """Get total packet count."""
        if direction is None:
            return len(self.flow.packets)
        return sum(1 for _, d in self.flow.packets if d == direction)
    
    def has_payload(self, direction: PacketDirection) -> int:
        """Count packets with payload in given direction."""
        count = 0
        for packet, pkt_dir in self.flow.packets:
            if pkt_dir != direction:
                continue
            if len(self.get_payload(packet)) > 0:
                count += 1
        return count
    
    def get_down_up_ratio(self) -> float:
        """Get ratio of reverse to forward packets."""
        forward = self.get_total(PacketDirection.FORWARD)
        reverse = self.get_total(PacketDirection.REVERSE)
        if forward == 0:
            return float(reverse) if reverse > 0 else 0.0
        return reverse / forward

