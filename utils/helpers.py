from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import time

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from config import IDSConfig
from core.logger import IDSLogger


def is_root_user() -> bool:
    """Return True when running with effective root privileges."""
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def extract_packet_metadata(packet) -> dict | None:
    """Normalize relevant packet fields for downstream detection logic."""
    src_ip = None
    dst_ip = None

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    if not src_ip or not dst_ip:
        return None

    protocol = "OTHER"
    src_port = None
    dst_port = None

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif ICMP in packet:
        protocol = "ICMP"

    return {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
    }


def safe_block_ip(ip_address: str, config: IDSConfig, logger: IDSLogger) -> None:
    """Attempt to block an attacker IP with iptables, idempotently and safely."""
    if ip_address in config.BLOCK_EXEMPT_IPS:
        return

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logger.log_info(f"Skipping block for invalid IP: {ip_address}")
        return

    if not shutil.which("iptables"):
        logger.log_info("iptables not available; IP blocking skipped")
        return

    check_cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
    add_cmd = [
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip_address,
        "-j",
        "DROP",
        "-m",
        "comment",
        "--comment",
        config.IP_BLOCK_RULE_COMMENT,
    ]

    check_result = subprocess.run(check_cmd, capture_output=True, text=True)
    if check_result.returncode == 0:
        return

    add_result = subprocess.run(add_cmd, capture_output=True, text=True)
    if add_result.returncode == 0:
        logger.log_alert(
            message=f"Blocked attacker IP via iptables: {ip_address}",
            source_ip=ip_address,
            attack_type="active_response",
        )
    else:
        logger.log_info(
            f"Failed to block IP {ip_address}: {add_result.stderr.strip() or 'unknown error'}"
        )
