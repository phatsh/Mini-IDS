"""TCP flag counting for flows."""

from typing import Optional
from scapy.packet import Packet
from ..context import PacketDirection


class FlagCount:
    """Count TCP flags in a flow."""
    
    def __init__(self, flow):
        """Initialize with a Flow object."""
        self.flow = flow
    
    def count(self, flag: str, direction: Optional[PacketDirection] = None) -> int:
        """Count occurrences of a TCP flag.
        
        Args:
            flag: Flag name (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
            direction: If provided, only count flags in that direction
            
        Returns:
            Count of flag occurrences
        """
        from scapy.all import TCP
        
        count = 0
        for packet, pkt_dir in self.flow.packets:
            if TCP not in packet:
                continue
            
            if direction is not None and pkt_dir != direction:
                continue
            
            flags = int(packet[TCP].flags)
            flag_bit = {
                "SYN": 0x02,
                "ACK": 0x10,
                "FIN": 0x01,
                "RST": 0x04,
                "PSH": 0x08,
                "URG": 0x20,
                "ECE": 0x40,
                "CWR": 0x80,
            }.get(flag.upper(), 0)
            
            if flags & flag_bit:
                count += 1
        
        return count

