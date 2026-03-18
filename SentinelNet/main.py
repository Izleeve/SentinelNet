from __future__ import annotations

import argparse
import platform
import sys
from dataclasses import replace

from scapy.error import Scapy_Exception

from config import CONFIG
from core.detector import DetectionEngine
from core.logger import IDSLogger
from core.sniffer import PacketSniffer
from utils.helpers import is_root_user


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="SentinelNet",
        description="SentinelNet: Real-time Network Intrusion Detection System for Kali Linux",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to monitor (example: eth0, wlan0). Defaults to Scapy auto-detect.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Disable per-packet info output and show alerts only.",
    )
    parser.add_argument(
        "--block",
        action="store_true",
        help="Enable active response: block attacker IPs with iptables.",
    )
    parser.add_argument(
        "--bpf",
        default=None,
        help="Optional BPF capture filter (example: tcp or udp or icmp).",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    runtime_config = replace(
        CONFIG,
        INTERFACE=args.interface,
        VERBOSE_PACKET_INFO=not args.quiet,
        ENABLE_IP_BLOCKING=args.block,
        BPF_FILTER=(args.bpf if args.bpf is not None else CONFIG.BPF_FILTER),
    )

    print("--- SentinelNet IDS ---")
    print("Monitoring traffic...")

    if platform.system().lower() != "linux":
        print("[WARN] SentinelNet is optimized for Kali Linux and Linux-based systems.")

    if not is_root_user():
        print("[ERROR] Root privileges are required to capture live packets.")
        print("[HINT] Run with: sudo python3 main.py")
        return 1

    logger = IDSLogger(runtime_config.LOG_FILE_PATH)
    detector = DetectionEngine(runtime_config, logger)
    sniffer = PacketSniffer(runtime_config, detector, logger)

    logger.log_info("SentinelNet initialized successfully")
    logger.log_info(
        f"Capture settings: interface={runtime_config.INTERFACE or 'auto'}, "
        f"bpf_filter={runtime_config.BPF_FILTER or 'none'}, "
        f"ip_blocking={runtime_config.ENABLE_IP_BLOCKING}"
    )

    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\n[INFO] Stopping SentinelNet...")
        logger.log_info("SentinelNet stopped by user")
    except Scapy_Exception as error:
        print(f"[ERROR] Scapy runtime failure: {error}")
        logger.log_info(f"Scapy failure: {error}")
        return 2
    except PermissionError as error:
        print(f"[ERROR] Permission denied: {error}")
        logger.log_info(f"Permission error: {error}")
        return 3
    except Exception as error:  # defensive catch for production resilience
        print(f"[ERROR] Unexpected failure: {error}")
        logger.log_info(f"Unexpected failure: {error}")
        return 99

    return 0


if __name__ == "__main__":
    sys.exit(main())
