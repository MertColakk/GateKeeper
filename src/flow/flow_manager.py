from typing import Dict, Optional
from parser.packet_parser import ParsedPacket

from flow.flow import Flow
from flow.flow_timer import FlowTimer

from storage.csv_writer import CSVWriter
from features.data_extractor import FeatureExtractor

class FlowManager:
    def __init__(self, idle_timeout: float = 10.0) -> None:
        self.flows: Dict[tuple, Flow] = {}
        self.timer = FlowTimer(idle_timeout = idle_timeout)
        
        self.extractor = FeatureExtractor()
        self.csv_writer = CSVWriter( "../data/flows/flows.csv")
        
    def process_packet(self, packet: ParsedPacket) -> Flow:
        from utils.packet_helper import create_flow_key
        
        current_time = packet.timestamp

        for key, flow in list(self.flows.items()):
            if self.timer.is_expired(flow, current_time):
                features = self.extractor.extract(flow)
                 
                self.csv_writer.write(features)
                
                print("[+] Flow saved to CSV\n")
                
                del self.flows[key]
        
        flow_key = create_flow_key(packet)

        if flow_key in self.flows:

            flow = self.flows[flow_key]
            flow.add_packet(packet)

            return flow

        flow = Flow()
        flow.add_packet(packet)

        self.flows[flow_key] = flow

        return flow

    def get_flow(self, packet: ParsedPacket) -> Optional[Flow]:
        from utils.packet_helper import create_flow_key
        flow_key = create_flow_key(packet)

        return self.flows.get(flow_key)

    def get_active_flows(self) -> list[Flow]:
        return list(self.flows.values())

    def get_flow_count(self) -> int:
        return len(self.flows)