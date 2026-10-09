from dataclasses import dataclass, field
from typing import List
from uuid import uuid4
from parser.packet_parser import ParsedPacket

@dataclass
class Flow:
    id: str = field(default_factory=lambda: uuid4().hex)

    src_ip: str = ""
    dst_ip: str = ""

    src_port: int | None = None
    dst_port: int | None = None

    protocol: str = ""

    # Time infos
    start_time: float = 0.0
    last_seen: float = 0.0

    # General packet infos
    packet_count: int = 0
    byte_count: int = 0

    # Direction base stats
    forward_packet_count: int = 0
    backward_packet_count: int = 0

    forward_byte_count: int = 0
    backward_byte_count: int = 0

    # For mL
    packet_sizes: List[int] = field(default_factory=list)
    timestamps: List[float] = field(default_factory=list)

    # TCP flags
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0

    def __post_init__(self) -> None:

        if self.start_time < 0:
            raise ValueError("start_time cannot be negative.")

        if self.last_seen < 0:
            raise ValueError("last_seen cannot be negative.")

    def add_packet(self, packet: ParsedPacket) -> None:
        if self.packet_count == 0:

            self.src_ip = packet.src_ip or ""
            self.dst_ip = packet.dst_ip or ""

            self.src_port = packet.src_port
            self.dst_port = packet.dst_port

            self.protocol = packet.protocol or ""

            self.start_time = packet.timestamp
            self.last_seen = packet.timestamp

        # Update stats
        self.packet_count += 1
        self.byte_count += packet.packet_size

        self.packet_sizes.append(packet.packet_size)
        self.timestamps.append(packet.timestamp)

        self.last_seen = packet.timestamp

        # Direction determination
        is_forward = (
            packet.src_ip == self.src_ip
            and packet.dst_ip == self.dst_ip
            and packet.src_port == self.src_port
            and packet.dst_port == self.dst_port
        )

        if is_forward:
            self.forward_packet_count += 1
            self.forward_byte_count += packet.packet_size
        else:
            self.backward_packet_count += 1
            self.backward_byte_count += packet.packet_size

        if packet.tcp_flags:
            self._update_tcp_flags(packet.tcp_flags)

    def _update_tcp_flags(self, flags: str) -> None:
        if "S" in flags:
            self.syn_count += 1

        if "A" in flags:
            self.ack_count += 1

        if "F" in flags:
            self.fin_count += 1

        if "R" in flags:
            self.rst_count += 1

        if "P" in flags:
            self.psh_count += 1

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.start_time, 0.0)

    def contains_packet(self, packet: ParsedPacket,) -> bool:
        forward_match = (
            packet.src_ip == self.src_ip
            and packet.dst_ip == self.dst_ip
            and packet.src_port == self.src_port
            and packet.dst_port == self.dst_port
        )

        reverse_match = (
            packet.src_ip == self.dst_ip
            and packet.dst_ip == self.src_ip
            and packet.src_port == self.dst_port
            and packet.dst_port == self.src_port
        )

        protocol_match = packet.protocol == self.protocol

        return (protocol_match and (forward_match or reverse_match))