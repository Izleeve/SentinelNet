from __future__ import annotations

from scapy.all import sniff

from config import IDSConfig
from core.detector import DetectionEngine
from core.logger import IDSLogger
from utils.helpers import extract_packet_metadata


class PacketSniffer:
    """Scapy-based packet capture loop wired to detection and logging."""

    def __init__(self, config: IDSConfig, detector: DetectionEngine, logger: IDSLogger) -> None:
        self.config = config
        self.detector = detector
        self.logger = logger

    def start(self) -> None:
        self.logger.log_info("SentinelNet packet sniffer started")

        sniff(
            prn=self._on_packet,
            store=self.config.CAPTURE_STORE_PACKETS,
            iface=self.config.INTERFACE,
            filter=self.config.BPF_FILTER or None,
        )

    def _on_packet(self, packet) -> None:
        metadata = extract_packet_metadata(packet)
        if not metadata:
            return

        src_ip = metadata["src_ip"]
        dst_ip = metadata["dst_ip"]
        protocol = metadata["protocol"]
        src_port = metadata.get("src_port")
        dst_port = metadata.get("dst_port")

        if self.config.VERBOSE_PACKET_INFO:
            port_fragment = ""
            if src_port is not None or dst_port is not None:
                port_fragment = f" (sport={src_port}, dport={dst_port})"
            print(f"[INFO] Packet from {src_ip} -> {dst_ip} [{protocol}]{port_fragment}")

        alerts = self.detector.process_packet(metadata)
        for alert in alerts:
            print(f"[ALERT] {alert.message}")
            self.logger.log_alert(
                message=alert.message,
                source_ip=alert.source_ip,
                attack_type=alert.attack_type,
            )
