from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Tuple

from config import IDSConfig
from core.logger import IDSLogger
from utils.helpers import safe_block_ip


@dataclass
class DetectionAlert:
    attack_type: str
    source_ip: str
    message: str


class DetectionEngine:
    """Stateful detector for simple real-time network intrusion patterns."""

    def __init__(self, config: IDSConfig, logger: IDSLogger) -> None:
        self.config = config
        self.logger = logger

        self._port_activity: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._traffic_activity: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_alert_time: Dict[Tuple[str, str], float] = {}

    def process_packet(self, metadata: dict) -> List[DetectionAlert]:
        """Evaluate a parsed packet against enabled detection rules."""
        src_ip = metadata.get("src_ip")
        dst_port = metadata.get("dst_port")

        if not src_ip:
            return []

        now = metadata.get("timestamp", time.time())
        alerts: List[DetectionAlert] = []

        port_scan_alert = self._detect_port_scan(src_ip, dst_port, now)
        if port_scan_alert:
            alerts.append(port_scan_alert)

        flood_alert = self._detect_flood(src_ip, now)
        if flood_alert:
            alerts.append(flood_alert)

        suspicious_port_alert = self._detect_sensitive_port(src_ip, dst_port, now)
        if suspicious_port_alert:
            alerts.append(suspicious_port_alert)

        for alert in alerts:
            if self.config.ENABLE_IP_BLOCKING:
                safe_block_ip(alert.source_ip, self.config, self.logger)

        return alerts

    def _detect_port_scan(self, src_ip: str, dst_port: int | None, now: float) -> DetectionAlert | None:
        if dst_port is None:
            return None

        history = self._port_activity[src_ip]
        history.append((now, dst_port))

        while history and now - history[0][0] > self.config.PORT_SCAN_WINDOW_SECONDS:
            history.popleft()

        unique_ports = {port for _, port in history}
        if len(unique_ports) >= self.config.PORT_SCAN_PORT_THRESHOLD and self._should_alert(src_ip, "port_scan", now):
            return DetectionAlert(
                attack_type="port_scan",
                source_ip=src_ip,
                message=(
                    f"Port scan detected from {src_ip} "
                    f"({len(unique_ports)} ports in {self.config.PORT_SCAN_WINDOW_SECONDS}s)"
                ),
            )
        return None

    def _detect_flood(self, src_ip: str, now: float) -> DetectionAlert | None:
        history = self._traffic_activity[src_ip]
        history.append(now)

        while history and now - history[0] > self.config.FLOOD_WINDOW_SECONDS:
            history.popleft()

        if len(history) >= self.config.FLOOD_PACKET_THRESHOLD and self._should_alert(src_ip, "traffic_flood", now):
            return DetectionAlert(
                attack_type="traffic_flood",
                source_ip=src_ip,
                message=(
                    f"Traffic flood detected from {src_ip} "
                    f"({len(history)} packets in {self.config.FLOOD_WINDOW_SECONDS}s)"
                ),
            )
        return None

    def _detect_sensitive_port(self, src_ip: str, dst_port: int | None, now: float) -> DetectionAlert | None:
        if dst_port is None or dst_port not in self.config.SENSITIVE_PORTS:
            return None

        key = f"suspicious_port_{dst_port}"
        if not self._should_alert(src_ip, key, now):
            return None

        return DetectionAlert(
            attack_type="suspicious_port_access",
            source_ip=src_ip,
            message=f"Suspicious access to sensitive port {dst_port} from {src_ip}",
        )

    def _should_alert(self, src_ip: str, attack_key: str, now: float) -> bool:
        """Prevent alert storms by enforcing a short cooldown per source and rule."""
        cache_key = (src_ip, attack_key)
        last = self._last_alert_time.get(cache_key)

        if last is None or now - last >= self.config.ALERT_COOLDOWN_SECONDS:
            self._last_alert_time[cache_key] = now
            return True
        return False
