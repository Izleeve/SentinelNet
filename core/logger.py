from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path


class IDSLogger:
    """File-backed logger for IDS alerts and operational events."""

    def __init__(self, log_file_path: Path) -> None:
        self.log_file_path = log_file_path
        self.log_file_path.parent.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("sentinelnet")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        if not self._logger.handlers:
            file_handler = logging.FileHandler(self.log_file_path, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(file_handler)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def log_alert(self, message: str, source_ip: str | None = None, attack_type: str | None = None) -> None:
        """Write a standardized alert line to alert log file."""
        details = []
        if source_ip:
            details.append(f"src={source_ip}")
        if attack_type:
            details.append(f"type={attack_type}")
        suffix = f" ({', '.join(details)})" if details else ""
        line = f"[{self._timestamp()}] ALERT: {message}{suffix}"
        self._logger.info(line)

    def log_info(self, message: str) -> None:
        """Write informational operational entries to alert log for traceability."""
        line = f"[{self._timestamp()}] INFO: {message}"
        self._logger.info(line)
