"""Flow byte statistics."""

from ..context import PacketDirection


class FlowBytes:
    """Calculate byte-related statistics for a flow."""
    
    def __init__(self, flow):
        """Initialize with a Flow object."""
        self.flow = flow
    
    def get_rate(self) -> float:
        """Get flow bytes per second."""
        duration = self.flow.duration
        if duration <= 0:
            return 0.0
        
        total_bytes = sum(len(bytes(pkt)) for pkt, _ in self.flow.packets)
        return total_bytes / duration
    
    def get_forward_header_bytes(self) -> int:
        """Get total forward header bytes."""
        from scapy.all import IP, IPv6
        
        total = 0
        for packet, direction in self.flow.packets:
            if direction != PacketDirection.FORWARD:
                continue
            
            if IP in packet:
                total += 20  # IPv4 header
            elif IPv6 in packet:
                total += 40  # IPv6 header
            
            from scapy.all import TCP, UDP
            if TCP in packet:
                total += 20  # TCP header
            elif UDP in packet:
                total += 8  # UDP header
        
        return total
    
    def get_reverse_header_bytes(self) -> int:
        """Get total reverse header bytes."""
        from scapy.all import IP, IPv6
        
        total = 0
        for packet, direction in self.flow.packets:
            if direction != PacketDirection.REVERSE:
                continue
            
            if IP in packet:
                total += 20
            elif IPv6 in packet:
                total += 40
            
            from scapy.all import TCP, UDP
            if TCP in packet:
                total += 20
            elif UDP in packet:
                total += 8
        
        return total
    
    def get_min_forward_header_bytes(self) -> int:
        """Get minimum forward header bytes (approximation)."""
        return min(self.get_forward_header_bytes(), 20)
    
    def get_bytes_per_bulk(self, direction: PacketDirection) -> float:
        """Get average bytes per bulk transfer."""
        if direction == PacketDirection.FORWARD:
            bulk_count = self.flow.forward_bulk_count
            bulk_size = self.flow.forward_bulk_size
        else:
            bulk_count = self.flow.backward_bulk_count
            bulk_size = self.flow.backward_bulk_size
        
        if bulk_count == 0:
            return 0.0
        return bulk_size / bulk_count
    
    def get_packets_per_bulk(self, direction: PacketDirection) -> float:
        """Get average packets per bulk transfer."""
        if direction == PacketDirection.FORWARD:
            bulk_count = self.flow.forward_bulk_count
            bulk_packets = self.flow.forward_bulk_packet_count
        else:
            bulk_count = self.flow.backward_bulk_count
            bulk_packets = self.flow.backward_bulk_packet_count
        
        if bulk_count == 0:
            return 0.0
        return bulk_packets / bulk_count
    
    def get_bulk_rate(self, direction: PacketDirection) -> float:
        """Get bulk transfer rate."""
        duration = self.flow.duration
        if duration <= 0:
            return 0.0
        
        if direction == PacketDirection.FORWARD:
            bulk_duration = self.flow.forward_bulk_duration
        else:
            bulk_duration = self.flow.backward_bulk_duration
        
        return bulk_duration / duration if duration > 0 else 0.0

