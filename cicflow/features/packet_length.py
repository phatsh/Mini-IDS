"""Packet length statistics for flows."""

from typing import Optional
from scapy.packet import Packet
from ..context import PacketDirection
from ..utils import get_statistics


class PacketLength:
    """Calculate packet length statistics."""
    
    def __init__(self, flow):
        """Initialize with a Flow object."""
        self.flow = flow
    
    def get_total(self, direction: Optional[PacketDirection] = None) -> int:
        """Get total bytes in packets."""
        total = 0
        for packet, pkt_dir in self.flow.packets:
            if direction is None or pkt_dir == direction:
                total += len(bytes(packet))
        return total
    
    def get_max(self, direction: Optional[PacketDirection] = None) -> float:
        """Get maximum packet length."""
        lengths = [len(bytes(pkt)) for pkt, d in self.flow.packets 
                   if direction is None or d == direction]
        return float(max(lengths)) if lengths else 0.0
    
    def get_min(self, direction: Optional[PacketDirection] = None) -> float:
        """Get minimum packet length."""
        lengths = [len(bytes(pkt)) for pkt, d in self.flow.packets 
                   if direction is None or d == direction]
        return float(min(lengths)) if lengths else 0.0
    
    def get_mean(self, direction: Optional[PacketDirection] = None) -> float:
        """Get mean packet length."""
        lengths = [len(bytes(pkt)) for pkt, d in self.flow.packets 
                   if direction is None or d == direction]
        if not lengths:
            return 0.0
        return sum(lengths) / len(lengths)
    
    def get_std(self, direction: Optional[PacketDirection] = None) -> float:
        """Get standard deviation of packet lengths."""
        lengths = [float(len(bytes(pkt))) for pkt, d in self.flow.packets 
                   if direction is None or d == direction]
        stats = get_statistics(lengths)
        return stats["std"]
    
    def get_var(self, direction: Optional[PacketDirection] = None) -> float:
        """Get variance of packet lengths."""
        std = self.get_std(direction)
        return std * std
    
    def get_avg(self) -> float:
        """Get average packet size (alias for get_mean)."""
        return self.get_mean()

