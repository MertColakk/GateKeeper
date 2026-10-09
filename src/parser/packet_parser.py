from dataclasses import dataclass
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

@dataclass
class ParsedPacket:
    timestamp: float
    
    src_ip: Optional[str]
    dst_ip: Optional[str]
    
    src_port: Optional[int]
    dst_port: Optional[int]

    protocol: Optional[str]
    
    packet_size: int

    tcp_flags: Optional[str]
    
class PacketParser:
    @staticmethod
    def parse(packet: Packet) -> Optional[ParsedPacket]:
        
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        protocol: Optional[str] = None
        tcp_flags: Optional[str] = None

        # TCP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = "TCP"
            tcp_flags = str(tcp_layer.flags)

        # UDP
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]

            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol = "UDP"

        else:
            protocol = str(ip_layer.proto)

        return ParsedPacket(
            timestamp=float(packet.time),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=len(packet),
            tcp_flags=tcp_flags,
        )