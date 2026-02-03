"""Packet timing statistics for flows."""

from ..context import PacketDirection
from ..utils import get_statistics


class PacketTime:
    """Calculate timing-related statistics."""
    
    def __init__(self, flow):
        """Initialize with a Flow object."""
        self.flow = flow
    
    def get_timestamp(self) -> float:
        """Get flow start timestamp."""
        return self.flow.start_timestamp
    
    def get_duration(self) -> float:
        """Get flow duration."""
        return self.flow.duration
    
    def get_packet_iat(self, direction: PacketDirection) -> list:
        """Get inter-arrival times for packets in given direction."""
        iats = []
        last_time = None
        
        for packet, pkt_dir in self.flow.packets:
            if pkt_dir != direction:
                continue
            
            if last_time is not None:
                iats.append(packet.time - last_time)
            last_time = packet.time
        
        return iats

