from __future__ import annotations

from dataclasses import replace

import core.detector as detector_module
from config import CONFIG
from core.detector import DetectionEngine
from core.logger import IDSLogger


def _packet(ts: float, src_ip: str = "10.0.0.5", dst_port: int = 80) -> dict:
    return {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": "10.0.0.10",
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": dst_port,
    }


def _build_engine(tmp_path, **overrides):
    default_overrides = {
        "LOG_FILE_PATH": tmp_path / "alerts.log",
        "PORT_SCAN_WINDOW_SECONDS": 10,
        "PORT_SCAN_PORT_THRESHOLD": 5,
        "FLOOD_WINDOW_SECONDS": 2,
        "FLOOD_PACKET_THRESHOLD": 6,
        "ALERT_COOLDOWN_SECONDS": 10,
        "ENABLE_IP_BLOCKING": False,
        "SENSITIVE_PORTS": {22, 23, 3389},
    }
    default_overrides.update(overrides)

    config = replace(CONFIG, **default_overrides)
    logger = IDSLogger(config.LOG_FILE_PATH)
    return DetectionEngine(config, logger), config


def test_port_scan_detection(tmp_path):
    engine, _ = _build_engine(tmp_path)
    base = 1000.0

    alerts = []
    for index, port in enumerate([1000, 1001, 1002, 1003, 1004]):
        alerts.extend(engine.process_packet(_packet(base + (index * 0.4), dst_port=port)))

    assert any(a.attack_type == "port_scan" for a in alerts)


def test_traffic_flood_detection(tmp_path):
    engine, _ = _build_engine(tmp_path)
    base = 2000.0

    alerts = []
    for index in range(6):
        alerts.extend(engine.process_packet(_packet(base + (index * 0.2), dst_port=8080)))

    assert any(a.attack_type == "traffic_flood" for a in alerts)


def test_sensitive_port_detection(tmp_path):
    engine, _ = _build_engine(tmp_path)

    alerts = engine.process_packet(_packet(3000.0, dst_port=22))

    assert any(a.attack_type == "suspicious_port_access" for a in alerts)


def test_alert_cooldown_suppresses_duplicates(tmp_path):
    engine, config = _build_engine(tmp_path)
    src = "10.10.10.10"

    first_alerts = engine.process_packet(_packet(4000.0, src_ip=src, dst_port=22))
    second_alerts = engine.process_packet(_packet(4001.0, src_ip=src, dst_port=22))
    third_alerts = engine.process_packet(
        _packet(4000.0 + config.ALERT_COOLDOWN_SECONDS + 1, src_ip=src, dst_port=22)
    )

    assert any(a.attack_type == "suspicious_port_access" for a in first_alerts)
    assert all(a.attack_type != "suspicious_port_access" for a in second_alerts)
    assert any(a.attack_type == "suspicious_port_access" for a in third_alerts)


def test_normal_low_volume_traffic_no_alert(tmp_path):
    engine, _ = _build_engine(tmp_path)

    alerts_a = engine.process_packet(_packet(5000.0, src_ip="10.1.1.2", dst_port=80))
    alerts_b = engine.process_packet(_packet(5003.0, src_ip="10.1.1.2", dst_port=443))

    assert alerts_a == []
    assert alerts_b == []


def test_ip_block_called_when_enabled(tmp_path, monkeypatch):
    blocked_ips = []

    def fake_block(ip_address, config, logger):
        blocked_ips.append(ip_address)

    monkeypatch.setattr(detector_module, "safe_block_ip", fake_block)

    engine, _ = _build_engine(tmp_path, ENABLE_IP_BLOCKING=True)
    engine.process_packet(_packet(6000.0, src_ip="192.168.56.20", dst_port=22))

    assert blocked_ips == ["192.168.56.20"]
