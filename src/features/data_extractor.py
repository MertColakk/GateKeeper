import statistics

from flow.flow import Flow


class FeatureExtractor:
    """
    Flow nesnesinden makine öğrenmesi için kullanılabilecek
    feature'ları çıkarır.
    """

    @staticmethod
    def extract(flow: Flow) -> dict:
        """
        Verilen flow için feature dictionary oluşturur.
        """

        duration = flow.duration

        if duration > 0:
            packet_rate = flow.packet_count / duration
            byte_rate = flow.byte_count / duration
        else:
            packet_rate = 0.0
            byte_rate = 0.0

        # Packet size istatistikleri
        if flow.packet_sizes:
            packet_size_mean = statistics.mean(
                flow.packet_sizes
            )

            packet_size_std = (
                statistics.stdev(flow.packet_sizes)
                if len(flow.packet_sizes) > 1
                else 0.0
            )

            packet_size_min = min(flow.packet_sizes)
            packet_size_max = max(flow.packet_sizes)

        else:
            packet_size_mean = 0.0
            packet_size_std = 0.0
            packet_size_min = 0
            packet_size_max = 0

        # Inter-Arrival Time (IAT)
        if len(flow.timestamps) > 1:

            iat_values = [
                current - previous
                for previous, current
                in zip(
                    flow.timestamps,
                    flow.timestamps[1:],
                )
            ]

            iat_mean = statistics.mean(iat_values)

            iat_std = (
                statistics.stdev(iat_values)
                if len(iat_values) > 1
                else 0.0
            )

            iat_min = min(iat_values)
            iat_max = max(iat_values)

        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_min = 0.0
            iat_max = 0.0

        return {
            "flow_id": flow.id,

            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,

            "src_port": flow.src_port,
            "dst_port": flow.dst_port,

            "protocol": flow.protocol,

            "duration": duration,

            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,

            "forward_packet_count": flow.forward_packet_count,
            "backward_packet_count": flow.backward_packet_count,

            "forward_byte_count": flow.forward_byte_count,
            "backward_byte_count": flow.backward_byte_count,

            "packet_rate": packet_rate,
            "byte_rate": byte_rate,

            "packet_size_mean": packet_size_mean,
            "packet_size_std": packet_size_std,
            "packet_size_min": packet_size_min,
            "packet_size_max": packet_size_max,

            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_min": iat_min,
            "iat_max": iat_max,

            "syn_count": flow.syn_count,
            "ack_count": flow.ack_count,
            "psh_count": flow.psh_count,
            "fin_count": flow.fin_count,
            "rst_count": flow.rst_count,
        }