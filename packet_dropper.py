"""Module for dropping malicious packets/flows."""

import time
from typing import Dict, Set, Tuple, Optional, Any
from collections import defaultdict
from .logging_utils import result as log_result, action as log_action, error as log_error


def _canonicalize_flow_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, str, int, int]:
    """
    Canonicalize flow key by ensuring smaller (IP, port) tuple is always "src".
    This matches the canonicalization logic in cicflow.context.get_packet_flow_key.
    """
    a_tuple = (src_ip or "", src_port)
    b_tuple = (dst_ip or "", dst_port)
    if a_tuple > b_tuple:
        src_ip, dst_ip = dst_ip, src_ip
        src_port, dst_port = dst_port, src_port
    return (src_ip or "", dst_ip or "", src_port, dst_port)


class PacketDropper:
    """
    Manages dropping of malicious packets/flows.
    
    Tracks flows that have been identified as malicious and drops subsequent
    packets from those flows. Logs drop status to results.log.
    """
    
    def __init__(self, enable_firewall_block: bool = False):
        """
        Initialize the packet dropper.
        
        Args:
            enable_firewall_block: If True, attempt to block via Windows Firewall
                                   (requires admin privileges). Default: False
        """
        # Track flows that should be dropped
        # Key: (src_ip, src_port, dst_ip, dst_port) tuple
        # Value: dict with alert info and timestamp
        self._dropped_flows: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
        
        # Track packets dropped per flow (for statistics)
        self._drop_stats: Dict[Tuple[str, int, str, int], int] = defaultdict(int)
        
        # Track if we've logged the first drop for each flow (to avoid excessive logging)
        self._logged_first_drop: Set[Tuple[str, int, str, int]] = set()
        
        # Enable Windows Firewall blocking (requires admin)
        self._enable_firewall_block = enable_firewall_block
        
        # Track firewall rules added (for cleanup)
        self._firewall_rules: Set[str] = set()
    
    def add_malicious_flow(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        alert_info: Dict[str, Any],
        protocol: str = "TCP"
    ) -> bool:
        """
        Mark a flow as malicious and start dropping its packets.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            alert_info: Alert information dict (for logging)
            protocol: Protocol (TCP/UDP/ICMP)
            
        Returns:
            True if flow was successfully marked for dropping, False otherwise
        """
        # Canonicalize flow key (same logic as get_packet_flow_key)
        canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port = _canonicalize_flow_key(
            src_ip, src_port, dst_ip, dst_port
        )
        flow_key = (canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port)
        # Also store reverse direction for bidirectional matching
        flow_key_reverse = (canon_dst_ip, canon_src_ip, canon_dst_port, canon_src_port)
        
        try:
            # Check if already dropped
            if flow_key in self._dropped_flows or flow_key_reverse in self._dropped_flows:
                # Already dropped, just update timestamp
                existing_key = flow_key if flow_key in self._dropped_flows else flow_key_reverse
                self._dropped_flows[existing_key]["last_seen"] = time.time()
                return True
            
            # Mark flow for dropping (using canonicalized key)
            drop_info = {
                "src_ip": canon_src_ip,
                "src_port": canon_src_port,
                "dst_ip": canon_dst_ip,
                "dst_port": canon_dst_port,
                "protocol": protocol,
                "alert_kind": alert_info.get("_alert_kind", "unknown"),
                "severity": alert_info.get("severity", "Unknown"),
                "rule": alert_info.get("rule"),
                "timestamp": time.time(),
                "last_seen": time.time(),
            }
            
            # Add both directions (canonicalized and reverse)
            self._dropped_flows[flow_key] = drop_info
            self._dropped_flows[flow_key_reverse] = drop_info
            
            # Log drop action
            drop_status = {
                "type": "packet_drop",
                "action": "flow_marked_for_drop",
                "status": "success",
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "alert_kind": drop_info["alert_kind"],
                "severity": drop_info["severity"],
                "rule": drop_info["rule"],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()),
            }
            
            log_result(drop_status)
            log_action(
                f"packet_dropper:flow_marked_for_drop "
                f"src={canon_src_ip}:{canon_src_port} dst={canon_dst_ip}:{canon_dst_port} "
                f"protocol={protocol} severity={drop_info['severity']}"
            )
            
            # Optionally add Windows Firewall rule
            if self._enable_firewall_block:
                self._add_firewall_rule(src_ip, dst_ip, protocol)
            
            return True
            
        except Exception as e:
            log_error(f"packet_dropper:error marking flow for drop {e}")
            drop_status = {
                "type": "packet_drop",
                "action": "flow_marked_for_drop",
                "status": "failed",
                "error": str(e),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
            }
            log_result(drop_status)
            return False
    
    def should_drop_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if a packet should be dropped.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            
        Returns:
            Tuple of (should_drop: bool, drop_info: Optional[Dict])
        """
        # Canonicalize flow key (same logic as get_packet_flow_key)
        canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port = _canonicalize_flow_key(
            src_ip, src_port, dst_ip, dst_port
        )
        flow_key = (canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port)
        flow_key_reverse = (canon_dst_ip, canon_src_ip, canon_dst_port, canon_src_port)
        
        # Check both directions (canonicalized and reverse)
        if flow_key in self._dropped_flows:
            drop_info = self._dropped_flows[flow_key]
            drop_info["last_seen"] = time.time()
            self._drop_stats[flow_key] += 1
            return True, drop_info
        elif flow_key_reverse in self._dropped_flows:
            drop_info = self._dropped_flows[flow_key_reverse]
            drop_info["last_seen"] = time.time()
            self._drop_stats[flow_key_reverse] += 1
            return True, drop_info
        
        return False, None
    
    def drop_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        packet_size: int = 0
    ) -> bool:
        """
        Drop a packet and log the action.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            packet_size: Size of the packet in bytes
            
        Returns:
            True if packet was dropped, False otherwise
        """
        should_drop, drop_info = self.should_drop_packet(src_ip, src_port, dst_ip, dst_port)
        
        if should_drop and drop_info:
            # Canonicalize flow key for consistent stats tracking
            canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port = _canonicalize_flow_key(
                src_ip, src_port, dst_ip, dst_port
            )
            flow_key = (canon_src_ip, canon_dst_ip, canon_src_port, canon_dst_port)
            
            # Get drop count (should_drop_packet already incremented it)
            drop_count = self._drop_stats.get(flow_key, 0)
            
            # Log first packet drop for this flow, then log periodically (every 100 packets)
            is_first_drop = flow_key not in self._logged_first_drop
            should_log = is_first_drop or (drop_count > 0 and drop_count % 100 == 0)
            
            if is_first_drop:
                self._logged_first_drop.add(flow_key)
            
            try:
                if should_log:
                    # Log packet drop status
                    drop_status = {
                        "type": "packet_drop",
                        "action": "packet_dropped",
                        "status": "success",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "protocol": drop_info.get("protocol", "UNKNOWN"),
                        "packet_size": packet_size,
                        "drop_count": drop_count,
                        "alert_kind": drop_info.get("alert_kind"),
                        "severity": drop_info.get("severity"),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%fZ", time.gmtime()),
                    }
                    log_result(drop_status)
                return True
            except Exception as e:
                log_error(f"packet_dropper:error logging packet drop {e}")
                drop_status = {
                    "type": "packet_drop",
                    "action": "packet_dropped",
                    "status": "failed",
                    "error": str(e),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                }
                log_result(drop_status)
                return False
        
        return False
    
    def _add_firewall_rule(self, src_ip: str, dst_ip: str, protocol: str) -> None:
        """
        Add Windows Firewall rule to block the malicious flow.
        
        Note: This requires administrator privileges and may not work on all Windows versions.
        """
        if not self._enable_firewall_block:
            return
        
        try:
            import subprocess
            import platform
            
            if platform.system() != "Windows":
                return
            
            # Create rule name
            rule_name = f"CLI_IDS_Block_{src_ip}_{dst_ip}_{int(time.time())}"
            
            # Create firewall rule using netsh
            # Block outbound packets from src_ip to dst_ip
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"protocol={protocol.lower()}",
                f"remoteip={dst_ip}",
                f"localip={src_ip}",
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode == 0:
                self._firewall_rules.add(rule_name)
                log_action(f"packet_dropper:firewall_rule_added rule={rule_name}")
            else:
                log_error(f"packet_dropper:firewall_rule_failed {result.stderr}")
                
        except Exception as e:
            log_error(f"packet_dropper:error adding firewall rule {e}")
    
    def cleanup_firewall_rules(self) -> None:
        """Remove all firewall rules created by this dropper."""
        if not self._firewall_rules:
            return
        
        try:
            import subprocess
            import platform
            
            if platform.system() != "Windows":
                return
            
            for rule_name in self._firewall_rules.copy():
                try:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_name}",
                    ]
                    subprocess.run(cmd, capture_output=True, timeout=5)
                    self._firewall_rules.discard(rule_name)
                    log_action(f"packet_dropper:firewall_rule_removed rule={rule_name}")
                except Exception as e:
                    log_error(f"packet_dropper:error removing firewall rule {rule_name}: {e}")
        except Exception as e:
            log_error(f"packet_dropper:error cleaning up firewall rules {e}")
    
    def get_drop_stats(self) -> Dict[str, Any]:
        """Get statistics about dropped packets."""
        return {
            "dropped_flows_count": len(self._dropped_flows) // 2,  # Divide by 2 because we store both directions
            "total_packets_dropped": sum(self._drop_stats.values()),
            "flows_dropped": list(self._drop_stats.keys()),
        }
    
    def clear_expired_flows(self, max_age_seconds: float = 3600.0) -> int:
        """
        Remove flows that haven't been seen for a while.
        
        Args:
            max_age_seconds: Maximum age in seconds before removing a flow
            
        Returns:
            Number of flows removed
        """
        current_time = time.time()
        expired_keys = []
        
        for flow_key, drop_info in self._dropped_flows.items():
            last_seen = drop_info.get("last_seen", drop_info.get("timestamp", 0))
            if current_time - last_seen > max_age_seconds:
                expired_keys.append(flow_key)
        
        for key in expired_keys:
            self._dropped_flows.pop(key, None)
            self._drop_stats.pop(key, None)
        
        return len(expired_keys) // 2  # Divide by 2 because we store both directions
