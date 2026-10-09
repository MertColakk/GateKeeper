import csv
from pathlib import Path

class CSVWriter:
    """
    Feature verilerini CSV dosyasına yazar.
    """

    def __init__(
        self,
        file_path: str = "data/flows/flows.csv",
    ) -> None:

        self.file_path = Path(file_path)

        self.file_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.fieldnames = [
            "flow_id",

            "src_ip",
            "dst_ip",

            "src_port",
            "dst_port",

            "protocol",

            "duration",

            "packet_count",
            "byte_count",

            "forward_packet_count",
            "backward_packet_count",

            "forward_byte_count",
            "backward_byte_count",

            "packet_rate",
            "byte_rate",

            "packet_size_mean",
            "packet_size_std",
            "packet_size_min",
            "packet_size_max",

            "iat_mean",
            "iat_std",
            "iat_min",
            "iat_max",

            "syn_count",
            "ack_count",
            "psh_count",
            "fin_count",
            "rst_count",
        ]

    def write(self, features: dict) -> None:
        """
        Tek bir feature satırını CSV'ye ekler.
        """

        file_exists = self.file_path.exists()

        with self.file_path.open(
            mode="a",
            newline="",
            encoding="utf-8",
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=self.fieldnames,
                extrasaction="ignore",
            )

            if not file_exists:
                writer.writeheader()

            writer.writerow(features)