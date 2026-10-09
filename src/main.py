from utils.packet_helper import packet_details
from capture.packet_capture import PacketCapturer

def main():
    _c = PacketCapturer(interface=None, packet_callback=packet_details)
        
    _c.start()

if __name__ == "__main__":
    main()