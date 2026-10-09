from scapy.all import Packet
from parser.packet_parser import PacketParser, ParsedPacket
from flow.flow_manager import FlowManager

_fm = FlowManager(idle_timeout=3)

def packet_details(packet: Packet) -> None:
    _pp = PacketParser.parse(packet)

    if _pp is None:
        return
    
    _fpp = _fm.process_packet(_pp)
    
    """print(f"[FLOW]\n\nFlow ID: {_fpp.id}\n"
          + f"Source: {_fpp.src_ip}:{_fpp.src_port}\n"
          + f"Destination: {_fpp.dst_ip}:{_fpp.dst_port}\n"
          + f"Protocol   : {_fpp.protocol}\n\n"
          + f"Packets    : {_fpp.packet_count}\n"
          + f"Bytes      : {_fpp.byte_count}\n\n"
          + f"Forward packets : {_fpp.forward_packet_count}\n"
          + f"Backward packets: {_fpp.backward_packet_count}\n\n"
          + f"Duration   : {_fpp.duration:.6f}s\n\n"
          + f"SYN : {_fpp.syn_count}\n"
          + f"ACK : {_fpp.ack_count}\n"
          + f"PSH : {_fpp.psh_count}\n"
          + f"FIN : {_fpp.fin_count}\n"
          + f"RST : {_fpp.rst_count}"
        )"""

def create_flow_key(packet: ParsedPacket) -> tuple:
    endpoint_a = (packet.src_ip, packet.src_port)
    endpoint_b = (packet.dst_ip, packet.dst_port)

    if endpoint_a <= endpoint_b:
        first = endpoint_a
        second = endpoint_b
    else:
        first = endpoint_b
        second = endpoint_a

    return (first[0], first[1], second[0], second[1], packet.protocol)