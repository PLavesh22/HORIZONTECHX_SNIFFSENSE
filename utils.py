"""
utils.py - Formatting, Statistics, Alerting, and Raw Socket Reference.

This module provides helper utilities for the beginner-friendly packet sniffer:
  1. Terminal color utilities (ANSI colors with cross-platform support via colorama).
  2. Hex + printable ASCII payload dump (similar to Wireshark / tcpdump).
  3. Statistics tracking (packet totals, protocol counts, top talkers).
  4. Lightweight security alerts (SYN port scan detection, cleartext credentials).
  5. Raw socket comparison code and explanation for educational purposes.
"""

from __future__ import annotations

import collections
import html
import re
import socket
import struct
import sys
import time
from typing import Any, Counter, Dict, List, Optional, Set, Tuple

# Try initializing colorama for Windows ANSI color support
try:
    import colorama
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


# ANSI Color Codes for terminal highlighting
class Colors:
    """ANSI color codes for clean visual distinction between protocols."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Protocols
    BLUE = "\033[94m"     # Ethernet / Layer 2
    CYAN = "\033[96m"     # IP (v4 / v6)
    GREEN = "\033[92m"    # TCP
    YELLOW = "\033[93m"   # UDP
    MAGENTA = "\033[95m"  # ICMP / Diagnostics
    ORANGE = "\033[33m"   # DNS
    WHITE = "\033[97m"    # HTTP / Application
    RED = "\033[91m"      # Suspicious / Alerts
    GRAY = "\033[90m"     # Hexdump / Dim text


def colorize(text: str, color: str) -> str:
    """Wraps text in ANSI color codes if stdout is an interactive terminal."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def format_hexdump(data: bytes, max_bytes: Optional[int] = 64) -> str:
    """
    Format raw payload bytes into a classic Wireshark/tcpdump style hexdump.

    Each line displays 16 bytes:
      Offset:   Hex representation (with spacing)            Printable ASCII
      0000      47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a    GET / HTTP/1.1..

    Args:
        data: Raw payload in bytes.
        max_bytes: Maximum number of bytes to format. None means dump all bytes.

    Returns:
        A formatted multi-line string representing the hexdump.
    """
    if not data:
        return "    (empty payload)"

    total_len = len(data)
    truncated = False
    if max_bytes is not None and total_len > max_bytes:
        data = data[:max_bytes]
        truncated = True

    lines: List[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]

        # Hex values formatted as 2-character hex strings
        hex_bytes_left = [f"{b:02x}" for b in chunk[:8]]
        hex_bytes_right = [f"{b:02x}" for b in chunk[8:]]

        hex_str_left = " ".join(hex_bytes_left).ljust(23)
        hex_str_right = " ".join(hex_bytes_right).ljust(23)
        hex_combined = f"{hex_str_left}  {hex_str_right}".strip()

        # Printable ASCII: print char if printable (32 to 126), else print a dot '.'
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)

        lines.append(f"    {offset:04x}   {hex_combined:<48}   |{ascii_str}|")

    if truncated:
        lines.append(f"    ... [truncated: showing first {max_bytes} of {total_len} bytes; use -v for full dump]")

    return "\n".join(lines)


class PacketStats:
    """
    Maintains network capture statistics to display upon exit.

    Tracks:
      - Total packet count and total bytes transferred
      - Breakdown by protocol (IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS, HTTP, etc.)
      - Top 5 source IP addresses (Top Talkers)
      - Top 5 destination IP addresses (Top Listeners)
    """

    def __init__(self) -> None:
        self.start_time: float = time.time()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter[str] = collections.Counter()
        self.src_ip_counts: Counter[str] = collections.Counter()
        self.dst_ip_counts: Counter[str] = collections.Counter()

    def update(self, packet_info: Dict[str, Any]) -> None:
        """Update metrics with metadata extracted from a parsed packet."""
        self.total_packets += 1
        self.total_bytes += packet_info.get("length", 0)

        # Count protocols observed
        for proto in packet_info.get("protocols", []):
            self.protocol_counts[proto] += 1

        # Track IP endpoints
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        if src_ip:
            self.src_ip_counts[src_ip] += 1
        if dst_ip:
            self.dst_ip_counts[dst_ip] += 1

    def print_summary(self) -> None:
        """Print a formatted summary table of capture statistics."""
        elapsed = time.time() - self.start_time
        rate = (self.total_packets / elapsed) if elapsed > 0 else 0.0

        header = "=" * 68
        print(f"\n{colorize(header, Colors.CYAN)}")
        print(f"{colorize('CAPTURE SESSION STATISTICS', Colors.BOLD)}")
        print(f"{colorize(header, Colors.CYAN)}")
        print(f" Duration:         {elapsed:.2f} seconds")
        print(f" Total Packets:    {self.total_packets:,}")
        print(f" Total Data:       {self.total_bytes:,} bytes")
        print(f" Average Rate:     {rate:.2f} packets/second")

        print(f"\n{colorize('--- Protocol Distribution ---', Colors.BOLD)}")
        if self.protocol_counts:
            max_proto_len = max(len(p) for p in self.protocol_counts.keys())
            for proto, count in self.protocol_counts.most_common():
                pct = (count / self.total_packets * 100) if self.total_packets else 0
                bar = "#" * int(pct / 5)
                print(f"  {proto.ljust(max_proto_len + 2)} : {count:6d} ({pct:5.1f}%)  {colorize(bar, Colors.GREEN)}")
        else:
            print("  No protocol packets recorded.")

        print(f"\n{colorize('--- Top 5 Source IP Addresses (Top Talkers) ---', Colors.BOLD)}")
        if self.src_ip_counts:
            for ip, count in self.src_ip_counts.most_common(5):
                pct = (count / self.total_packets * 100) if self.total_packets else 0
                print(f"  {ip.ljust(20)} : {count:6d} packets ({pct:5.1f}%)")
        else:
            print("  No IP sources observed.")

        print(f"\n{colorize('--- Top 5 Destination IP Addresses (Top Listeners) ---', Colors.BOLD)}")
        if self.dst_ip_counts:
            for ip, count in self.dst_ip_counts.most_common(5):
                pct = (count / self.total_packets * 100) if self.total_packets else 0
                print(f"  {ip.ljust(20)} : {count:6d} packets ({pct:5.1f}%)")
        else:
            print("  No IP destinations observed.")

        print(f"{colorize(header, Colors.CYAN)}\n")


class AlertEngine:
    """
    Lightweight rule-based alert engine for suspicious network activity.

    Detection Rules:
      1. TCP Port Scan:
         A single source IP address sending TCP SYN flags (connection attempts)
         to multiple distinct destination ports within a short sliding time window.
      2. Cleartext Credentials in HTTP:
         Detects keywords like 'password=', 'passwd=', 'token=', 'api_key=' in plain
         HTTP requests (POST/GET bodies and query strings).
    """

    def __init__(self, time_window_seconds: float = 10.0, port_scan_threshold: int = 10) -> None:
        self.time_window = time_window_seconds
        self.port_scan_threshold = port_scan_threshold

        # Maps src_ip -> deque of (timestamp, dst_port)
        self.syn_history: Dict[str, collections.deque[Tuple[float, int]]] = collections.defaultdict(
            collections.deque
        )
        # Keeps track of IPs already alerted for port scan to avoid flooding the console
        self.alerted_scanners: Set[str] = set()

        # Regex patterns for sensitive credentials in HTTP text
        self.cred_patterns = [
            re.compile(r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key)=([^&\s]+)", re.IGNORECASE),
            re.compile(r"(?:username|user|uname|login|email)=([^&\s]+)", re.IGNORECASE),
        ]

    def inspect(self, packet_info: Dict[str, Any]) -> List[str]:
        """
        Inspect a parsed packet and return a list of triggered security warnings.

        Args:
            packet_info: Dictionary containing parsed packet fields.

        Returns:
            List of human-readable alert strings (empty if benign).
        """
        alerts: List[str] = []
        now = packet_info.get("timestamp_epoch", time.time())
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")

        # --- Rule 1: Port Scan Detection (TCP SYN flood across ports) ---
        protocols = packet_info.get("protocols", [])
        if "TCP" in protocols and src_ip and dst_ip:
            flags = packet_info.get("tcp_flags", set())
            dst_port = packet_info.get("dst_port")

            # A classic port scan sends SYN packets without ACK
            if "SYN" in flags and "ACK" not in flags and dst_port:
                history = self.syn_history[src_ip]
                history.append((now, dst_port))

                # Prune events older than our sliding time window
                while history and (now - history[0][0]) > self.time_window:
                    history.popleft()

                # Count unique destination ports targeted in this window
                unique_ports = {port for _, port in history}
                if len(unique_ports) >= self.port_scan_threshold and src_ip not in self.alerted_scanners:
                    self.alerted_scanners.add(src_ip)
                    sample_ports = sorted(list(unique_ports))[:8]
                    ports_str = ", ".join(str(p) for p in sample_ports)
                    alerts.append(
                        f"[ALERT: POSSIBLE PORT SCAN] Host {src_ip} sent SYN packets to {len(unique_ports)} "
                        f"different ports on {dst_ip} within {self.time_window:.0f}s (Ports: {ports_str}...)"
                    )

        # --- Rule 2: Cleartext Credentials in HTTP ---
        if "HTTP" in protocols:
            payload_str = packet_info.get("payload_text", "")
            if payload_str:
                found_creds: List[str] = []
                for pattern in self.cred_patterns:
                    matches = pattern.findall(payload_str)
                    for match in matches:
                        # Mask the sensitive value for safety while proving detection
                        masked = match[0] + "*" * max(1, len(match) - 2) + match[-1] if len(match) > 2 else "***"
                        found_creds.append(f"field matched, value={masked}")

                if found_creds:
                    method = packet_info.get("http_method", "HTTP")
                    host = packet_info.get("http_host", dst_ip)
                    path = packet_info.get("http_path", "/")
                    alerts.append(
                        f"[ALERT: CLEARTEXT CREDENTIAL EXPOSURE] Unencrypted credential transmitted via {method} "
                        f"to {host}{path} from {src_ip} -> {dst_ip} ({len(found_creds)} matched token(s))"
                    )

        return alerts


# ============================================================================
# EDUCATIONAL SECTION: MINIMAL SNIFFER USING RAW PYTHON `socket` MODULE
# ============================================================================
# Below is a minimal example explaining how packet sniffing can be done at a
# lower level using Python's standard `socket` module without external libraries.
#
# WHY DO WE USE SCAPY INSTEAD OF RAW SOCKETS?
# 1. Portability: On Windows, `socket.AF_INET` raw sockets only capture incoming
#    IPv4 traffic (and require promiscuous mode IOCTL calls: `SIO_RCVALL`). On
#    Linux, you use `socket.AF_PACKET`, which is completely absent on Windows.
# 2. Layer 2 Access: Raw sockets on Windows cannot capture Ethernet frame headers
#    or ARP packets without third-party drivers (like Npcap).
# 3. Protocol Parsing: With raw sockets, you must manually parse every protocol
#    header using `struct.unpack('!BBHHHBBH4s4s', raw_bytes)` and bitmask operations.
#    Scapy encapsulates this complexity into reliable, well-tested protocol objects.
# ============================================================================

def raw_socket_sniffer_example() -> None:
    """
    Demonstration function showing how raw sockets work in Python.
    (Educational reference - not called in the main sniffer loop).
    """
    # Note: On Windows, running raw sockets requires Administrator privileges:
    #   s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    #   s.bind((HOST_IP, 0))
    #   s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable Promiscuous mode
    #
    # On Linux, raw sockets can capture all Layer 2 frames using AF_PACKET:
    #   s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("""
    # --- Python Raw Socket Example (Linux Layer 2) ---
    import socket, struct

    # 1. Open raw packet socket (ETH_P_ALL = 0x0003 captures all ethernet protocols)
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        # 2. Receive raw byte stream from the network interface card
        raw_data, addr = raw_socket.recvfrom(65535)

        # 3. Unpack 14-byte Ethernet header: Destination MAC (6s), Source MAC (6s), Type (H)
        eth_header = struct.unpack('!6s6sH', raw_data[:14])
        dst_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = socket.ntohs(eth_header[2])

        # 4. If IPv4 (EtherType 0x0800), unpack 20-byte IP header
        if eth_type == 0x0800:
            ip_header = struct.unpack('!BBHHHBBH4s4s', raw_data[14:34])
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            protocol = ip_header[6]
            print(f"Ethernet {src_mac} -> {dst_mac} | IPv4 {src_ip} -> {dst_ip} (Proto: {protocol})")
    """)

