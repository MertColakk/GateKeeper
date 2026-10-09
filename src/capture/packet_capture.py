from typing import Callable, Optional

from scapy.all import Packet, sniff

class PacketCapturer:
    def __init__(self,interface: Optional[str] = None, packet_callback: Optional[Callable[[Packet], None]] = None, packet_filter: Optional[str] = None,) -> None:
        self.interface = interface
        self.packet_callback = packet_callback
        self.packet_filter = packet_filter
    
    def _handle(self, packet: Packet) -> None:
        if self.packet_callback:
            self.packet_callback(packet)
            
    def start(self) -> None:
        print("[*] Network capture started!")
        
        if self.interface:
            print(f"[*] Interface: {self.interface}")
        else:
            print("[*] Interface: Default")
            
        if self.packet_filter:
            print(f"[*] Filter: {self.packet_filter}")
            
        print("[*] Packets are listenning...\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._handle,
                store=False,
            )
        except PermissionError:
            print(
                "[!] Permission denied. Packet capture require elevated privileges."
            )
        except OSError as exc:
            print(f"[!] Network capture error: {exc}")
        except KeyboardInterrupt:
            print("\n[*] Packet capture stopped with user request.")