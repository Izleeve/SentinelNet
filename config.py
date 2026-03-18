from dataclasses import dataclass, field
from pathlib import Path
from typing import Set


@dataclass(frozen=True)
class IDSConfig:
    """Central runtime configuration for SentinelNet IDS."""

    # Network capture settings
    INTERFACE: str | None = None
    BPF_FILTER: str = ""
    CAPTURE_STORE_PACKETS: bool = False
    VERBOSE_PACKET_INFO: bool = True

    # Detection thresholds
    PORT_SCAN_WINDOW_SECONDS: int = 10
    PORT_SCAN_PORT_THRESHOLD: int = 12
    FLOOD_WINDOW_SECONDS: int = 5
    FLOOD_PACKET_THRESHOLD: int = 120
    ALERT_COOLDOWN_SECONDS: int = 15

    # Detection scope
    SENSITIVE_PORTS: Set[int] = field(default_factory=lambda: {22, 23, 3389})

    # Logging
    LOG_FILE_PATH: Path = Path("logs/alerts.log")

    # Optional active response (Linux iptables)
    ENABLE_IP_BLOCKING: bool = False
    IP_BLOCK_RULE_COMMENT: str = "SentinelNet automatic block"
    BLOCK_EXEMPT_IPS: Set[str] = field(default_factory=lambda: {"127.0.0.1", "::1"})


CONFIG = IDSConfig()
