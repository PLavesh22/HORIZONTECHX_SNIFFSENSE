"""
raw_socket_example.py - Educational Comparison: Raw Sockets vs. Scapy.

This script demonstrates how a low-level packet sniffer is constructed using
only Python's standard `socket` and `struct` modules, without third-party libraries.

INTERNSHIP INTERVIEW NOTES:
---------------------------
Q: What is a raw socket?
A: Standard stream (TCP) or datagram (UDP) sockets operate at Layer 4 (Transport),
   leaving the operating system kernel to handle IP and Ethernet headers.
   A Raw Socket (SOCK_RAW) bypasses the transport layer, giving the user-space
   program direct access to the raw header bytes (Layer 3 or Layer 2).

Q: Why do we use Scapy for our main project instead of raw sockets?
A: 1. Cross-Platform Consistency:
      - Linux uses `socket.AF_PACKET`, which can capture all Layer 2 Ethernet frames.
      - Windows does NOT support `AF_PACKET`. On Windows, Python's raw sockets only
        support `AF_INET` (Layer 3 IPv4 only), cannot see Ethernet frames, and require
        setting Windows-specific IOCTL flags (SIO_RCVALL) on a specific local IP.
   2. Manual Binary Parsing:
      - Raw sockets return an opaque stream of `bytes`. You must manually compute
        offsets, handle big-endian byte order (`!`), and use `struct.unpack()`.
      - Scapy provides high-level objects for hundreds of protocols with built-in
        validation, checksum calculation, and dissection.
   3. Kernel BPF Filtering:
      - Scapy leverages libpcap/Npcap to compile BPF filters directly into kernel
        bytecode, discarding unwanted packets before they reach Python user-space.
"""

from __future__ import annotations

import os
import socket
import struct
import sys


def parse_ipv4_header(raw_data: bytes) -> dict:
    """
    Parse an IPv4 header from raw packet bytes using Python's `struct` module.

    IPv4 Header Layout (RFC 791 - 20 bytes minimum):
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Version|  IHL  |Type of Service|          Total Length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Identification        |Flags|      Fragment Offset    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Time to Live |    Protocol   |        Header Checksum        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Source Address                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Destination Address                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    # Struct format string '!BBHHHBBH4s4s':
    #   !  : Network byte order (Big-Endian)
    #   B  : 1 byte (Version + IHL combined)
    #   B  : 1 byte (Type of Service / DSCP)
    #   H  : 2 bytes (Total Length)
    #   H  : 2 bytes (Identification)
    #   H  : 2 bytes (Flags + Fragment Offset)
    #   B  : 1 byte (Time to Live - TTL)
    #   B  : 1 byte (Protocol: 1=ICMP, 6=TCP, 17=UDP)
    #   H  : 2 bytes (Header Checksum)
    #   4s : 4 bytes (Source IP raw bytes)
    #   4s : 4 bytes (Destination IP raw bytes)
    header_fields = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])

    version_and_ihl = header_fields[0]
    version = version_and_ihl >> 4       # First 4 bits
    ihl = (version_and_ihl & 0x0F) * 4   # Next 4 bits, multiplied by 4 bytes

    ttl = header_fields[5]
    protocol_num = header_fields[6]
    src_ip = socket.inet_ntoa(header_fields[8])
    dst_ip = socket.inet_ntoa(header_fields[9])

    proto_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    proto_name = proto_names.get(protocol_num, f"Proto-{protocol_num}")

    return {
        "version": version,
        "header_length": ihl,
        "ttl": ttl,
        "protocol": proto_name,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }


def run_raw_sniffer(interface_ip: str = "0.0.0.0", max_packets: int = 5) -> None:
    """
    Runs a minimal raw socket sniffer.
    Requires Administrator / root privileges.
    """
    print("=" * 70)
    print("      MINIMAL RAW SOCKET SNIFFER (EDUCATIONAL DEMO)")
    print("=" * 70)

    is_windows = (os.name == "nt")
    raw_socket = None

    try:
        if is_windows:
            print("[*] Detected OS: Windows")
            print("[*] Creating AF_INET SOCK_RAW socket (IPv4 only)...")
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

            # On Windows, you must bind to a specific host IP and enable promiscuous mode
            if interface_ip == "0.0.0.0":
                # Fallback to local machine hostname IP
                interface_ip = socket.gethostbyname(socket.gethostname())

            print(f"[*] Binding raw socket to {interface_ip}...")
            raw_socket.bind((interface_ip, 0))

            # Include IP headers in received packets
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable Promiscuous mode via Windows IOCTL (SIO_RCVALL)
            print("[*] Enabling promiscuous mode via SIO_RCVALL IOCTL...")
            raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            print("[*] Detected OS: Linux / Unix")
            print("[*] Creating AF_PACKET SOCK_RAW socket (Full Layer 2 Ethernet capture)...")
            # ETH_P_ALL = 0x0003 in network byte order captures all Layer 2 protocols
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        print(f"[*] Listening for {max_packets} packets (Press Ctrl+C to abort)...\n")
        count = 0

        while count < max_packets:
            packet_bytes, addr = raw_socket.recvfrom(65535)
            count += 1

            # On Linux AF_PACKET, the first 14 bytes are the Ethernet header
            # On Windows AF_INET RAW, the data starts directly with the IPv4 header
            ip_data = packet_bytes[14:] if not is_windows else packet_bytes

            if len(ip_data) >= 20:
                parsed = parse_ipv4_header(ip_data)
                print(f"[{count:02d}] {parsed['protocol']:<6} {parsed['src_ip']:<15} -> {parsed['dst_ip']:<15} (TTL={parsed['ttl']}, IHL={parsed['header_length']}B)")
            else:
                print(f"[{count:02d}] Short packet received: {len(packet_bytes)} bytes")

    except PermissionError:
        print("\n[!] PERMISSION DENIED: Raw sockets require Administrator/root privileges.")
        print("    On Windows: Run Command Prompt / PowerShell as Administrator.")
        print("    On Linux: Run with 'sudo python3 raw_socket_example.py'.")
    except Exception as e:
        print(f"\n[!] Socket error: {e}")
    finally:
        if raw_socket and is_windows:
            try:
                # Disable promiscuous mode before closing
                raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        if raw_socket:
            raw_socket.close()
        print("\n[*] Raw socket closed.")


if __name__ == "__main__":
    # If arguments are provided, use them; otherwise run a safe 5-packet demonstration
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    run_raw_sniffer(interface_ip=target_ip, max_packets=5)

