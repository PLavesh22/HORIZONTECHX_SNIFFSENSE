"""
sniffer.py - Beginner-Friendly Network Packet Sniffer.

Entry point for capturing, parsing, inspecting, and saving network packets.
Designed for educational purposes and internship project presentations.

Usage Examples:
  # 1. List network interfaces
  python sniffer.py --list

  # 2. Live capture on interface 'Wi-Fi' with BPF filter
  python sniffer.py -i Wi-Fi -c 20 -f "tcp port 80"

  # 3. Save capture to a pcap file
  python sniffer.py -i Ethernet -c 50 -o capture.pcap

  # 4. Analyze an existing pcap without admin privileges (Verbose + Alerts)
  python sniffer.py -r sample.pcap -v --alerts
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
from typing import Any, List, Optional

# --- Pre-flight Dependency Check ---
try:
    from scapy.all import (
        conf,
        get_if_list,
        PcapReader,
        PcapWriter,
        sniff,
    )
    from scapy.error import Scapy_Exception
except ImportError:
    print("\n[ERROR] Scapy is not installed!")
    print("Please install required dependencies with:")
    print("    pip install -r requirements.txt\n")
    sys.exit(1)

from parser import format_verbose, parse_packet
from utils import (
    AlertEngine,
    Colors,
    PacketStats,
    colorize,
    format_hexdump,
    raw_socket_sniffer_example,
)


ETHICS_BANNER = """
================================================================================
                    ETHICAL USE & AUTHORIZATION NOTICE
  This packet sniffer is created strictly for authorized educational research,
  internship study, and defensive network troubleshooting.
  Capturing network traffic without explicit authorization from the network owner
  may violate privacy laws, organizational policies, and computer fraud statutes.
  Always ensure you have written permission before monitoring non-local networks.
================================================================================
"""


def is_admin() -> bool:
    """
    Check if the current script is running with elevated privileges (Admin/root).
    Works on both Windows (ctypes.windll) and Unix-like systems (os.geteuid).
    """
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def list_interfaces() -> None:
    """List available network interfaces on the system in a readable table."""
    print(colorize("\n--- Available Network Interfaces ---", Colors.BOLD))
    try:
        ifaces = conf.ifaces
        # Format table header
        header = f"{'Index':<6} {'Name':<28} {'IP Address':<18} {'MAC Address':<20} {'Description'}"
        print(colorize(header, Colors.CYAN))
        print("-" * 95)

        for iface_key, iface in ifaces.items():
            name = str(getattr(iface, "name", iface_key))
            ip = str(getattr(iface, "ip", "None") or "None")
            mac = str(getattr(iface, "mac", "None") or "None")
            desc = str(getattr(iface, "description", "") or "")
            # Truncate long names for alignment
            short_name = (name[:25] + "..") if len(name) > 27 else name
            index_str = str(getattr(iface, "index", "-"))
            print(f"{index_str:<6} {short_name:<28} {ip:<18} {mac:<20} {desc}")
        print("\nTip: Use the Name (or Index) with the -i flag, e.g.: python sniffer.py -i Wi-Fi\n")
    except Exception as e:
        print(f"[!] Could not list interfaces: {e}")
        print("Fallback raw interface list:", get_if_list())


def build_arg_parser() -> argparse.ArgumentParser:
    """Configure command line arguments using standard argparse."""
    parser = argparse.ArgumentParser(
        description="Sniffsense - A Beginner-Friendly Network Packet Sniffer (Python 3.10+ & Scapy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py --list
  python sniffer.py -i Wi-Fi -c 10
  python sniffer.py -i 0 -f "tcp port 443" -v
  python sniffer.py -r sample.pcap --alerts
  python sniffer.py --raw-demo
        """,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i", "--interface",
        type=str,
        help="Network interface to capture on (e.g. 'Wi-Fi', 'Ethernet', or interface index).",
    )
    group.add_argument(
        "-r", "--read",
        type=str,
        metavar="PCAP_FILE",
        help="Read and analyze packets from a saved .pcap file (works without admin rights).",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all available network interfaces on this machine and exit.",
    )
    group.add_argument(
        "--raw-demo",
        action="store_true",
        help="Display the minimal Python raw socket comparison code & tutorial.",
    )
    group.add_argument(
        "--web",
        action="store_true",
        help="Launch the interactive Web Dashboard at http://localhost:5000.",
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0 = continuous until Ctrl+C).",
    )
    parser.add_argument(
        "-f", "--filter",
        type=str,
        default="",
        help="BPF (Berkeley Packet Filter) syntax string (e.g. 'tcp port 80', 'icmp', 'udp').",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        metavar="OUT_PCAP",
        help="File path to save captured packets in .pcap format.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose mode: print detailed multi-line breakdown of every layer and full payload.",
    )
    parser.add_argument(
        "--alerts",
        action="store_true",
        help="Enable detection of suspicious patterns (TCP SYN port scans and plain HTTP credentials).",
    )

    return parser


class SnifferEngine:
    """Coordinates packet capture, parsing, display, stats, and file writing."""

    def __init__(
        self,
        verbose: bool = False,
        enable_alerts: bool = False,
        pcap_writer: Optional[PcapWriter] = None,
    ) -> None:
        self.verbose = verbose
        self.enable_alerts = enable_alerts
        self.pcap_writer = pcap_writer
        self.stats = PacketStats()
        self.alert_engine = AlertEngine() if enable_alerts else None
        self.packet_index = 0

    def process_packet(self, packet: Any) -> None:
        """Callback invoked by Scapy for every captured or read packet."""
        self.packet_index += 1

        # 1. Save to PCAP file if requested
        if self.pcap_writer:
            try:
                self.pcap_writer.write(packet)
            except Exception as e:
                print(f"[!] Failed to write packet to file: {e}", file=sys.stderr)

        # 2. Parse packet layers
        info = parse_packet(packet)
        info["index"] = self.packet_index

        # 3. Update capture session statistics
        self.stats.update(info)

        # 4. Run suspicious activity checks if alerts are enabled
        if self.alert_engine:
            alerts = self.alert_engine.inspect(info)
            for alert_msg in alerts:
                print(f"\n{colorize(alert_msg, Colors.RED)}")

        # 5. Output packet to console
        if self.verbose:
            # Full layer-by-layer breakdown
            print(format_verbose(info))
        else:
            # Clean single summary line
            print(info["summary"])
            # In standard mode, show first 64 bytes of payload if present
            payload = info.get("payload_bytes", b"")
            if payload:
                print(colorize(f"  Payload ({len(payload)} bytes, first 64 shown):", Colors.GRAY))
                print(colorize(format_hexdump(payload, max_bytes=64), Colors.GRAY))


def main() -> None:
    """Main execution flow and CLI driver."""
    parser = build_arg_parser()
    args = parser.parse_args()

    # Display Ethics Notice
    print(colorize(ETHICS_BANNER, Colors.CYAN))

    # --- Mode 1: List Interfaces ---
    if args.list:
        list_interfaces()
        return

    # --- Mode 2: Educational Raw Socket Demonstration ---
    if args.raw_demo:
        raw_socket_sniffer_example()
        return

    # --- Mode 2.5: Interactive Web Dashboard ---
    if args.web:
        try:
            from web_dashboard import run_dashboard
            run_dashboard(host="0.0.0.0", port=5000)
        except Exception as e:
            print(colorize(f"[ERROR] Failed to start Web Dashboard: {e}", Colors.RED))
        return

    # Prepare PCAP Writer if output file specified
    pcap_writer: Optional[PcapWriter] = None
    if args.output:
        try:
            pcap_writer = PcapWriter(args.output, append=False, sync=True)
            print(colorize(f"[*] Live capture will be saved to: {args.output}", Colors.GREEN))
        except Exception as e:
            print(colorize(f"[!] Cannot open '{args.output}' for writing: {e}", Colors.RED))
            sys.exit(1)

    sniffer_engine = SnifferEngine(
        verbose=args.verbose,
        enable_alerts=args.alerts,
        pcap_writer=pcap_writer,
    )

    # Clean signal handling for Ctrl+C
    def sigint_handler(sig: Any, frame: Any) -> None:
        print(colorize("\n[!] Capture stopped by user (Ctrl+C).", Colors.YELLOW))
        if pcap_writer:
            pcap_writer.close()
        sniffer_engine.stats.print_summary()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    # --- Mode 3: Offline PCAP File Analysis ---
    if args.read:
        pcap_path = args.read
        if not os.path.exists(pcap_path):
            print(colorize(f"[ERROR] PCAP file '{pcap_path}' not found!", Colors.RED))
            print("Please verify the file path. You can create a test capture with generate_sample_pcap.py.")
            sys.exit(1)

        print(colorize(f"[*] Reading and analyzing packets from '{pcap_path}'...", Colors.CYAN))
        if args.filter:
            print(colorize(f"[*] Applying filter: \"{args.filter}\"", Colors.CYAN))

        try:
            sniff(
                offline=pcap_path,
                prn=sniffer_engine.process_packet,
                filter=args.filter if args.filter else None,
                count=args.count if args.count > 0 else 0,
                store=False,
            )
        except Scapy_Exception as se:
            err_str = str(se).lower()
            if "tcpdump is not available" in err_str or "libpcap" in err_str:
                print(colorize(f"\n[NOTICE] BPF filtering with '-f \"{args.filter}\"' requires Npcap / libpcap or tcpdump.", Colors.YELLOW))
                print("BPF filters are compiled into kernel bytecode using the libpcap BPF compiler.")
                print("On Windows without Npcap installed, please install Npcap (https://npcap.com) or run without '-f'.")
            else:
                print(colorize(f"\n[ERROR] Failed to read PCAP: {se}", Colors.RED))
                print("The file might be corrupted or in an unsupported format.")
            sys.exit(1)
        except Exception as e:
            print(colorize(f"\n[ERROR] An error occurred while parsing PCAP: {e}", Colors.RED))
            sys.exit(1)

        # Print capture summary
        sniffer_engine.stats.print_summary()
        return

    # --- Mode 4: Live Packet Capture ---
    # Check for elevated privileges when sniffing live interfaces
    if not is_admin():
        print(colorize("[WARNING] Sniffer is running WITHOUT administrator / root privileges!", Colors.YELLOW))
        if os.name == "nt":
            print("On Windows, live capture requires Administrator permissions and Npcap driver.")
            print("To run as Administrator: Right-click PowerShell/CMD -> 'Run as Administrator'.")
            print("Alternatively, analyze an existing capture without admin using: python sniffer.py -r file.pcap\n")
        else:
            print("On Linux/macOS, live capture requires root privileges.")
            print("Try running with: sudo python3 sniffer.py ...\n")

    chosen_iface = args.interface
    if chosen_iface:
        # Validate interface
        valid_ifaces = [str(getattr(i, "name", k)) for k, i in conf.ifaces.items()]
        # Also allow index
        valid_indices = [str(getattr(i, "index", "")) for i in conf.ifaces.values()]

        if chosen_iface not in valid_ifaces and chosen_iface not in valid_indices and chosen_iface not in conf.ifaces:
            print(colorize(f"[ERROR] Interface '{chosen_iface}' was not recognized!", Colors.RED))
            print("Run 'python sniffer.py --list' to view available interfaces on this machine.")
            sys.exit(1)

    print(colorize("[*] Starting live packet sniffer...", Colors.GREEN))
    if chosen_iface:
        print(f"[*] Bound to interface: {chosen_iface}")
    else:
        print("[*] Bound to default interface (use -i to specify)")

    if args.filter:
        print(f"[*] BPF Filter:         \"{args.filter}\"")
    if args.count > 0:
        print(f"[*] Packet Target:      {args.count} packets")
    else:
        print("[*] Packet Target:      Continuous (Press Ctrl+C to stop)")
    if args.alerts:
        print(colorize("[*] Suspicious Activity Alerts: ENABLED (Port scan, Cleartext creds)", Colors.YELLOW))
    print(colorize("-" * 72, Colors.DIM))

    try:
        sniff(
            iface=chosen_iface if chosen_iface else None,
            prn=sniffer_engine.process_packet,
            filter=args.filter if args.filter else None,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print(colorize("\n[ERROR] Permission denied while opening network interface!", Colors.RED))
        print("Please rerun this command from an elevated shell (Administrator on Windows, sudo on Linux).")
        sys.exit(1)
    except Scapy_Exception as se:
        print(colorize(f"\n[ERROR] Scapy capture error: {se}", Colors.RED))
        if "libpcap" in str(se).lower() or "npcap" in str(se).lower() or "pcap" in str(se).lower():
            print("\nNpcap / libpcap driver appears to be missing or not functioning.")
            print("On Windows: Download and install Npcap from https://npcap.com (ensure 'WinPcap API-compatible Mode' is checked).")
            print("On Debian/Ubuntu: sudo apt install libpcap-dev")
        sys.exit(1)
    except Exception as e:
        print(colorize(f"\n[ERROR] Capture failed: {e}", Colors.RED))
        sys.exit(1)
    finally:
        if pcap_writer:
            pcap_writer.close()

    # Print summary when count target is met
    sniffer_engine.stats.print_summary()


if __name__ == "__main__":
    main()
