# SentinelNet IDS

SentinelNet is a modular, real-time Network Intrusion Detection System (IDS) engineered for Kali Linux. It captures live packets using Scapy, applies multiple detection rules, logs actionable alerts, and provides a clean command-line monitoring experience.

## Project Goals

- Capture and inspect live traffic in real time
- Detect suspicious network behavior with configurable thresholds
- Log security alerts with timestamps and attack metadata
- Offer a clean and practical CLI dashboard
- Maintain extensible, production-style architecture

## Features

- Live packet sniffing with Scapy
- Port scan detection
- Traffic flood detection
- Sensitive port access detection (default: 22, 23, 3389)
- Alert cooldown controls to avoid duplicate alert storms
- Structured alert logging to logs/alerts.log
- Optional active response: attacker IP blocking via iptables
- Configurable runtime via centralized config.py and CLI flags

## Architecture

SentinelNet follows separation of concerns:

- main.py: bootstrap, argument parsing, runtime wiring, startup validation
- config.py: centralized thresholds and security settings
- core/sniffer.py: packet capture loop and packet-to-detector pipeline
- core/detector.py: stateful detection engine and alert generation
- core/logger.py: standardized logging for operational and alert events
- utils/helpers.py: packet parsing, privilege check, optional iptables helper
- logs/alerts.log: persisted alert stream
- tests/test_detector.py: automated unit tests for IDS detection behavior

## Project Structure

SentinelNet/
|-- main.py
|-- config.py
|-- requirements.txt
|-- README.md
|-- core/
|   |-- __init__.py
|   |-- sniffer.py
|   |-- detector.py
|   |-- logger.py
|-- utils/
|   |-- __init__.py
|   |-- helpers.py
|-- logs/
|   |-- alerts.log
|-- tests/
|   |-- test_detector.py

## Kali Linux Installation

1. Update package index:

   sudo apt update

2. Install Python tooling if needed:

   sudo apt install -y python3 python3-pip python3-venv

3. Create and activate a virtual environment:

   python3 -m venv .venv
   source .venv/bin/activate

4. Install project dependencies:

   pip install -r requirements.txt

### Troubleshooting: externally-managed-environment (PEP 668)

If Kali shows externally-managed-environment when running pip install, install dependencies inside a virtual environment:

1. Ensure venv support is installed:

   sudo apt update
   sudo apt install -y python3-full python3-venv

2. Create and activate a virtual environment:

   python3 -m venv .venv
   source .venv/bin/activate

3. Upgrade pip and install requirements:

   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt

4. Run SentinelNet from the same activated shell:

   sudo -E python main.py --interface eth0

Avoid using --break-system-packages unless you explicitly accept system Python risk.

## Running SentinelNet

Basic run (auto interface):

sudo python3 main.py

Run on specific interface:

sudo python3 main.py --interface eth0

Alert-only mode:

sudo python3 main.py --quiet

Enable active response with iptables:

sudo python3 main.py --block

Run with BPF filter:

sudo python3 main.py --bpf "tcp or udp or icmp"

## Configuration

Tune behavior in config.py:

- PORT_SCAN_WINDOW_SECONDS
- PORT_SCAN_PORT_THRESHOLD
- FLOOD_WINDOW_SECONDS
- FLOOD_PACKET_THRESHOLD
- ALERT_COOLDOWN_SECONDS
- SENSITIVE_PORTS
- LOG_FILE_PATH
- ENABLE_IP_BLOCKING
- BLOCK_EXEMPT_IPS

## Example CLI Output

--- SentinelNet IDS ---
Monitoring traffic...
[INFO] Packet from 192.168.1.2 -> 192.168.1.1 [TCP] (sport=50314, dport=80)
[ALERT] Port scan detected from 192.168.1.5 (18 ports in 10s)
[ALERT] Suspicious access to sensitive port 22 from 192.168.1.5

## Example Alert Log Entry

[2026-03-18 10:32:11] ALERT: Port scan detected from 192.168.1.5 (18 ports in 10s) (src=192.168.1.5, type=port_scan)

## Testing Instructions (Mandatory)

### Automated Unit Tests (pytest)

Run all unit tests:

python -m pytest -q

Current automated coverage includes:

- Port scan detection logic
- Traffic flood detection logic
- Sensitive port access detection
- Alert cooldown behavior
- Normal traffic no-alert baseline
- Active response hook invocation (mocked)

### Live Network Validation

Use two machines or network namespaces when possible:

- Defender host: Kali system running SentinelNet
- Attacker/test host: separate host or container in same subnet

### 1) Port Scan Simulation (nmap)

From attacker host:

nmap -sS -Pn <KALI_TARGET_IP>

Expected SentinelNet behavior:

- Multiple destination ports from one source in short window
- Port scan alert appears in CLI and logs/alerts.log

### 2) Traffic Flood Simulation (ping)

From attacker host (requires elevated privileges on many systems):

sudo ping -f <KALI_TARGET_IP>

Expected SentinelNet behavior:

- Packet-per-window threshold exceeded
- Traffic flood alert appears in CLI and logs/alerts.log

### 3) Suspicious Port Access Simulation

From attacker host:

nc -vz <KALI_TARGET_IP> 22
nc -vz <KALI_TARGET_IP> 23
nc -vz <KALI_TARGET_IP> 3389

Expected SentinelNet behavior:

- Suspicious port access alerts for monitored sensitive ports

### 4) Normal Traffic Baseline

From benign host:

ping -c 5 <KALI_TARGET_IP>
curl http://<KALI_TARGET_IP>

Expected SentinelNet behavior:

- Packet info lines without high-severity alerts (unless thresholds are intentionally low)

## Operational Notes

- Live sniffing needs root privileges.
- Ensure the selected interface carries target traffic.
- If running in a VM, verify network mode (bridged is generally best for realistic monitoring).
- For active response mode, verify iptables rules with:

  sudo iptables -L INPUT -n --line-numbers

## Disclaimer

SentinelNet is for authorized defensive security use only. Test only in environments where you have explicit permission.
