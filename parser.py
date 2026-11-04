"""
parser.py - Packet Layer Parsing and Representation.

This module provides modular parsing for network packets captured by Scapy.
It breaks down packets layer by layer:
  - Layer 2 (Data Link): Ethernet, ARP
  - Layer 3 (Network): IPv4, IPv6
  - Layer 4 (Transport): TCP, UDP, ICMP, ICMPv6
  - Layer 7 (Application): DNS, HTTP
  - Payload: Raw application data / hexdump
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Set

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoReply, ICMPv6EchoRequest
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from utils import Colors, colorize, format_hexdump


# Human-readable dictionary of ICMP Type -> Meaning
ICMP_TYPE_MEANINGS: Dict[int, str] = {
    0: "Echo Reply (Ping response)",
    3: "Destination Unreachable",
    4: "Source Quench (Congestion control)",
    5: "Redirect (Route change)",
    8: "Echo Request (Ping inquiry)",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded (TTL expired in transit - traceroute)",
    12: "Parameter Problem (Bad IP header)",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# TCP Flag abbreviations to full human-readable names
TCP_FLAG_MAP: Dict[str, str] = {
    "F": "FIN",   # Finish: sender is done transmitting
    "S": "SYN",   # Synchronize: initiate 3-way connection handshake
    "R": "RST",   # Reset: abruptly abort / reject connection
    "P": "PSH",   # Push: tell receiver to immediately pass data to app
    "A": "ACK",   # Acknowledgment: confirms receipt of packets
    "U": "URG",   # Urgent: high priority data
    "E": "ECE",   # ECN-Echo: explicit congestion notification
    "C": "CWR",   # Congestion Window Reduced
}

# Standard DNS Query Types
DNS_TYPE_MAP: Dict[int, str] = {
    1: "A (IPv4)",
    28: "AAAA (IPv6)",
    5: "CNAME (Alias)",
    15: "MX (Mail)",
    16: "TXT (Text)",
    12: "PTR (Reverse)",
    2: "NS (Name Server)",
    6: "SOA (Authority)",
}


def parse_tcp_flags(flag_value: Any) -> Tuple[Set[str], str]:
    """
    Convert Scapy's TCP flag representation into both a set and a formatted string.

    Args:
        flag_value: Scapy Flag object or integer flag representation.

    Returns:
        Tuple of (set_of_flag_names, formatted_string_like_[SYN, ACK])
    """
    flag_str = str(flag_value)
    flags_present: Set[str] = set()

    for char, name in TCP_FLAG_MAP.items():
        if char in flag_str:
            flags_present.add(name)

    if not flags_present:
        return set(), "[None]"

    # Order flags logically: SYN, ACK, FIN, RST, PSH, URG
    ordered = [f for f in ["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"] if f in flags_present]
    return flags_present, "[" + ", ".join(ordered) + "]"


def parse_http_payload(payload_bytes: bytes) -> Dict[str, str]:
    """
    Attempt to extract basic HTTP request/response headers from raw payload.

    Args:
        payload_bytes: Raw bytes from the transport payload.

    Returns:
        Dictionary with extracted HTTP details (method, path, host, status, etc.).
    """
    info: Dict[str, str] = {}
    try:
        # Decode as ASCII / Latin-1 so it doesn't fail on binary POST bodies
        text = payload_bytes.decode("latin-1", errors="replace")
    except Exception:
        return info

    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return info

    first_line = lines[0].strip()
    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")

    # Check for HTTP Request (e.g., 'GET /index.html HTTP/1.1')
    if any(first_line.startswith(m + " ") for m in http_methods):
        parts = first_line.split(" ")
        if len(parts) >= 2:
            info["method"] = parts[0]
            info["path"] = parts[1]
        info["first_line"] = first_line

        # Parse headers like Host, User-Agent, Content-Type
        for line in lines[1:]:
            if not line:
                break  # Blank line signals end of HTTP headers
            if ":" in line:
                k, v = line.split(":", 1)
                k_lower = k.strip().lower()
                if k_lower == "host":
                    info["host"] = v.strip()
                elif k_lower == "user-agent":
                    info["user_agent"] = v.strip()
                elif k_lower == "content-type":
                    info["content_type"] = v.strip()

    # Check for HTTP Response (e.g., 'HTTP/1.1 200 OK')
    elif first_line.startswith("HTTP/1."):
        info["status_line"] = first_line
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            info["status_code"] = parts[1]
        if len(parts) >= 3:
            info["status_phrase"] = parts[2]

    return info


def parse_packet(packet: Packet) -> Dict[str, Any]:
    """
    Parse a Scapy packet into a structured dictionary containing all decoded layers.

    Extracts:
      - Timestamp, length, packet count index
      - Ethernet source/destination MAC addresses
      - IPv4 / IPv6 source/destination IP addresses, TTL / Hop Limit, Protocol
      - ARP source/destination hardware and IP addresses
      - TCP / UDP source/destination ports, TCP flags, sequence/ack numbers
      - ICMP Type / Code and human-readable explanation
      - DNS queries and answers
      - HTTP method, path, host, or status
      - Raw payload bytes

    Args:
        packet: The Scapy Packet instance.

    Returns:
        Structured dictionary of parsed fields.
    """
    data: Dict[str, Any] = {
        "timestamp_epoch": float(packet.time),
        "timestamp_str": datetime.datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3],
        "length": len(packet),
        "protocols": [],
        "layers": {},
        "summary": "",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "payload_bytes": b"",
        "payload_text": "",
    }

    # -------------------------------------------------------------------------
    # Layer 2: Ethernet / Data Link Layer
    # -------------------------------------------------------------------------
    if packet.haslayer(Ether):
        eth = packet[Ether]
        data["protocols"].append("Ethernet")
        data["layers"]["Ethernet"] = {
            "src_mac": eth.src,
            "dst_mac": eth.dst,
            "type_hex": f"0x{eth.type:04x}",
        }

    # -------------------------------------------------------------------------
    # Layer 2/3: ARP (Address Resolution Protocol)
    # -------------------------------------------------------------------------
    if packet.haslayer(ARP):
        arp = packet[ARP]
        data["protocols"].append("ARP")
        op_name = "Who-has (Request)" if arp.op == 1 else "Is-at (Reply)" if arp.op == 2 else f"Op={arp.op}"
        data["layers"]["ARP"] = {
            "operation": op_name,
            "hw_src": arp.hwsrc,
            "hw_dst": arp.hwdst,
            "ip_src": arp.psrc,
            "ip_dst": arp.pdst,
        }
        data["src_ip"] = arp.psrc
        data["dst_ip"] = arp.pdst

    # -------------------------------------------------------------------------
    # Layer 3: IPv4
    # -------------------------------------------------------------------------
    if packet.haslayer(IP):
        ip = packet[IP]
        data["protocols"].append("IPv4")
        data["src_ip"] = ip.src
        data["dst_ip"] = ip.dst
        header_len = (ip.ihl * 4) if (ip.ihl is not None) else 20
        total_len = ip.len if (ip.len is not None) else len(ip)
        data["layers"]["IPv4"] = {
            "version": ip.version,
            "header_len": header_len,  # IHL is in 32-bit words (x4 bytes)
            "tos": ip.tos,
            "total_len": total_len,
            "id": ip.id,
            "ttl": ip.ttl,
            "protocol_num": ip.proto,
            "src_ip": ip.src,
            "dst_ip": ip.dst,
        }

    # -------------------------------------------------------------------------
    # Layer 3: IPv6
    # -------------------------------------------------------------------------
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        data["protocols"].append("IPv6")
        data["src_ip"] = ip6.src
        data["dst_ip"] = ip6.dst
        data["layers"]["IPv6"] = {
            "version": ip6.version,
            "traffic_class": ip6.tc,
            "flow_label": ip6.fl,
            "payload_len": ip6.plen,
            "next_header": ip6.nh,
            "hop_limit": ip6.hlim,
            "src_ip": ip6.src,
            "dst_ip": ip6.dst,
        }

    # -------------------------------------------------------------------------
    # Layer 4: TCP (Transmission Control Protocol)
    # -------------------------------------------------------------------------
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        data["protocols"].append("TCP")
        flags_set, flags_str = parse_tcp_flags(tcp.flags)
        data["src_port"] = tcp.sport
        data["dst_port"] = tcp.dport
        data["tcp_flags"] = flags_set
        tcp_chksum = f"0x{tcp.chksum:04x}" if (tcp.chksum is not None) else "0x0000"
        data["layers"]["TCP"] = {
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "flags_raw": str(tcp.flags),
            "flags_formatted": flags_str,
            "window": tcp.window,
            "checksum": tcp_chksum,
        }

    # -------------------------------------------------------------------------
    # Layer 4: UDP (User Datagram Protocol)
    # -------------------------------------------------------------------------
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        data["protocols"].append("UDP")
        data["src_port"] = udp.sport
        data["dst_port"] = udp.dport
        udp_chksum = f"0x{udp.chksum:04x}" if (udp.chksum is not None) else "0x0000"
        udp_len = udp.len if (udp.len is not None) else len(udp)
        data["layers"]["UDP"] = {
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "length": udp_len,
            "checksum": udp_chksum,
        }

    # -------------------------------------------------------------------------
    # Layer 4 / Control: ICMP (Internet Control Message Protocol)
    # -------------------------------------------------------------------------
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        data["protocols"].append("ICMP")
        meaning = ICMP_TYPE_MEANINGS.get(icmp.type, "Informational / Unassigned")
        icmp_chksum = f"0x{icmp.chksum:04x}" if (icmp.chksum is not None) else "0x0000"
        data["layers"]["ICMP"] = {
            "type": icmp.type,
            "code": icmp.code,
            "meaning": meaning,
            "checksum": icmp_chksum,
        }

    # ICMPv6
    if packet.haslayer(ICMPv6EchoRequest):
        data["protocols"].append("ICMPv6")
        data["layers"]["ICMPv6"] = {"type": 128, "meaning": "Echo Request (Ping inquiry)"}
    elif packet.haslayer(ICMPv6EchoReply):
        data["protocols"].append("ICMPv6")
        data["layers"]["ICMPv6"] = {"type": 129, "meaning": "Echo Reply (Ping response)"}

    # -------------------------------------------------------------------------
    # Layer 7: DNS (Domain Name System)
    # -------------------------------------------------------------------------
    if packet.haslayer(DNS):
        dns = packet[DNS]
        data["protocols"].append("DNS")
        is_response = (dns.qr == 1)
        dns_info: Dict[str, Any] = {
            "id": dns.id,
            "qr": "Response" if is_response else "Query",
            "opcode": dns.opcode,
            "rcode": dns.rcode,
            "queries": [],
            "answers": [],
        }

        # Extract DNS Queries
        qdcount = dns.qdcount if dns.qdcount is not None else 1
        if packet.haslayer(DNSQR) and qdcount > 0:
            q = packet[DNSQR]
            qname = q.qname.decode("utf-8", errors="replace").rstrip(".") if isinstance(q.qname, bytes) else str(q.qname).rstrip(".")
            qtype_name = DNS_TYPE_MAP.get(q.qtype, f"Type {q.qtype}")
            dns_info["queries"].append({"name": qname, "type": qtype_name})

        # Extract DNS Answers (if response)
        ancount = dns.ancount if dns.ancount is not None else (1 if packet.haslayer(DNSRR) else 0)
        if packet.haslayer(DNSRR) and ancount > 0:
            curr = packet[DNSRR]
            for _ in range(min(5, ancount)):
                if not curr:
                    break
                rdata = str(curr.rdata)
                dns_info["answers"].append(rdata)
                curr = curr.payload if isinstance(curr.payload, DNSRR) else None

        data["layers"]["DNS"] = dns_info

    # -------------------------------------------------------------------------
    # Raw Payload & Application Level Inspection (HTTP)
    # -------------------------------------------------------------------------
    if packet.haslayer(Raw):
        raw_load = bytes(packet[Raw].load)
        data["payload_bytes"] = raw_load
        data["payload_text"] = raw_load.decode("latin-1", errors="replace")

        # Check for plain HTTP (typically port 80 / 8080 or signature in text)
        is_http_port = (data.get("src_port") in (80, 8080) or data.get("dst_port") in (80, 8080))
        http_data = parse_http_payload(raw_load)
        if http_data or is_http_port:
            if http_data:
                data["protocols"].append("HTTP")
                data["layers"]["HTTP"] = http_data
                data["http_method"] = http_data.get("method")
                data["http_path"] = http_data.get("path")
                data["http_host"] = http_data.get("host")

    # Generate one-line summary
    data["summary"] = build_summary_line(data)
    return data


def build_summary_line(info: Dict[str, Any]) -> str:
    """
    Construct a clean, single-line color-coded summary for a parsed packet.

    Format:
      [HH:MM:SS.mmm] PROTO   Src -> Dst   Details (ports, flags, DNS, HTTP, ICMP)
    """
    ts = colorize(f"[{info['timestamp_str']}]", Colors.GRAY)
    protocols = info["protocols"]

    # Determine highest-level / most descriptive protocol tag
    if "HTTP" in protocols:
        proto_tag = colorize("HTTP  ", Colors.WHITE)
    elif "DNS" in protocols:
        proto_tag = colorize("DNS   ", Colors.ORANGE)
    elif "ICMP" in protocols or "ICMPv6" in protocols:
        proto_tag = colorize("ICMP  ", Colors.MAGENTA)
    elif "TCP" in protocols:
        proto_tag = colorize("TCP   ", Colors.GREEN)
    elif "UDP" in protocols:
        proto_tag = colorize("UDP   ", Colors.YELLOW)
    elif "ARP" in protocols:
        proto_tag = colorize("ARP   ", Colors.CYAN)
    elif "IPv6" in protocols:
        proto_tag = colorize("IPv6  ", Colors.CYAN)
    elif "IPv4" in protocols:
        proto_tag = colorize("IPv4  ", Colors.CYAN)
    else:
        proto_tag = colorize("ETH   ", Colors.BLUE)

    src = info.get("src_ip") or (info["layers"].get("Ethernet", {}).get("src_mac", "Unknown"))
    dst = info.get("dst_ip") or (info["layers"].get("Ethernet", {}).get("dst_mac", "Unknown"))

    src_port = info.get("src_port")
    dst_port = info.get("dst_port")
    if src_port and dst_port:
        endpoints = f"{src}:{src_port} -> {dst}:{dst_port}"
    else:
        endpoints = f"{src} -> {dst}"

    # Build contextual details
    details: List[str] = []

    # TCP specific details: Flags, Seq, Ack, Window
    if "TCP" in info["layers"]:
        tcp_info = info["layers"]["TCP"]
        details.append(tcp_info["flags_formatted"])
        details.append(f"Seq={tcp_info['seq']}")
        if "ACK" in info.get("tcp_flags", set()):
            details.append(f"Ack={tcp_info['ack']}")
        details.append(f"Win={tcp_info['window']}")

    # ICMP specific details: Type and meaning
    elif "ICMP" in info["layers"]:
        icmp_info = info["layers"]["ICMP"]
        details.append(f"{icmp_info['meaning']} (Type={icmp_info['type']}, Code={icmp_info['code']})")

    # ARP specific details
    elif "ARP" in info["layers"]:
        arp_info = info["layers"]["ARP"]
        details.append(f"{arp_info['operation']} for {arp_info['ip_dst']}")

    # DNS specific details: Query or Response
    if "DNS" in info["layers"]:
        dns_info = info["layers"]["DNS"]
        if dns_info["queries"]:
            q = dns_info["queries"][0]
            details.append(f"Q: {q['name']} ({q['type']})")
        if dns_info["answers"]:
            details.append(f"Ans: {', '.join(dns_info['answers'][:2])}")

    # HTTP specific details
    if "HTTP" in info["layers"]:
        http_info = info["layers"]["HTTP"]
        if "first_line" in http_info:
            details.append(f"'{http_info['first_line']}'")
        elif "status_line" in http_info:
            details.append(f"'{http_info['status_line']}'")

    details_str = " | ".join(details)
    length_str = f"Len={info['length']}"

    return f"{ts} {proto_tag} {endpoints:<42} | {length_str:<8} | {details_str}"


def format_verbose(info: Dict[str, Any]) -> str:
    """
    Produce a comprehensive, multi-line, layer-by-layer breakdown of a packet.

    Suitable for debugging, learning protocol headers, and in-depth inspection.
    """
    lines: List[str] = []
    separator = "-" * 72
    lines.append(colorize(f"\nPacket #{info.get('index', 1)}: {info['length']} bytes captured at {info['timestamp_str']}", Colors.BOLD))
    lines.append(colorize(separator, Colors.DIM))

    # --- Ethernet Layer ---
    if "Ethernet" in info["layers"]:
        eth = info["layers"]["Ethernet"]
        lines.append(colorize("[Layer 2: Ethernet Frame]", Colors.BLUE))
        lines.append(f"  Source MAC:        {eth['src_mac']}")
        lines.append(f"  Destination MAC:   {eth['dst_mac']}")
        lines.append(f"  EtherType:         {eth['type_hex']}")

    # --- ARP Layer ---
    if "ARP" in info["layers"]:
        arp = info["layers"]["ARP"]
        lines.append(colorize("[Layer 2/3: ARP - Address Resolution Protocol]", Colors.CYAN))
        lines.append(f"  Operation:         {arp['operation']}")
        lines.append(f"  Sender MAC / IP:   {arp['hw_src']} / {arp['ip_src']}")
        lines.append(f"  Target MAC / IP:   {arp['hw_dst']} / {arp['ip_dst']}")

    # --- IPv4 Layer ---
    if "IPv4" in info["layers"]:
        ip = info["layers"]["IPv4"]
        lines.append(colorize("[Layer 3: IPv4 - Internet Protocol version 4]", Colors.CYAN))
        lines.append(f"  Source IP:         {ip['src_ip']}")
        lines.append(f"  Destination IP:    {ip['dst_ip']}")
        lines.append(f"  Header Length:     {ip['header_len']} bytes (IHL={ip['header_len'] // 4})")
        lines.append(f"  Total Length:      {ip['total_len']} bytes")
        lines.append(f"  Identification:    {ip['id']} (0x{ip['id']:04x})")
        lines.append(f"  Time To Live (TTL): {ip['ttl']} (decremented at each router hop)")
        lines.append(f"  Protocol Number:   {ip['protocol_num']}")

    # --- IPv6 Layer ---
    elif "IPv6" in info["layers"]:
        ip6 = info["layers"]["IPv6"]
        lines.append(colorize("[Layer 3: IPv6 - Internet Protocol version 6]", Colors.CYAN))
        lines.append(f"  Source IP:         {ip6['src_ip']}")
        lines.append(f"  Destination IP:    {ip6['dst_ip']}")
        lines.append(f"  Traffic Class:     {ip6['traffic_class']}")
        lines.append(f"  Flow Label:        {ip6['flow_label']}")
        lines.append(f"  Payload Length:    {ip6['payload_len']} bytes")
        lines.append(f"  Next Header:       {ip6['next_header']}")
        lines.append(f"  Hop Limit:         {ip6['hop_limit']}")

    # --- TCP Layer ---
    if "TCP" in info["layers"]:
        tcp = info["layers"]["TCP"]
        lines.append(colorize("[Layer 4: TCP - Transmission Control Protocol]", Colors.GREEN))
        lines.append(f"  Source Port:       {tcp['src_port']}")
        lines.append(f"  Destination Port:  {tcp['dst_port']}")
        lines.append(f"  Sequence Number:   {tcp['seq']}")
        lines.append(f"  Acknowledgment:    {tcp['ack']}")
        lines.append(f"  Flags:             {tcp['flags_formatted']} (Raw: {tcp['flags_raw']})")
        lines.append(f"  Window Size:       {tcp['window']} (Flow control buffer)")
        lines.append(f"  Checksum:          {tcp['checksum']}")

    # --- UDP Layer ---
    elif "UDP" in info["layers"]:
        udp = info["layers"]["UDP"]
        lines.append(colorize("[Layer 4: UDP - User Datagram Protocol]", Colors.YELLOW))
        lines.append(f"  Source Port:       {udp['src_port']}")
        lines.append(f"  Destination Port:  {udp['dst_port']}")
        lines.append(f"  Length:            {udp['length']} bytes")
        lines.append(f"  Checksum:          {udp['checksum']}")

    # --- ICMP Layer ---
    if "ICMP" in info["layers"]:
        icmp = info["layers"]["ICMP"]
        lines.append(colorize("[Layer 4: ICMP - Internet Control Message Protocol]", Colors.MAGENTA))
        lines.append(f"  Type:              {icmp['type']} ({icmp['meaning']})")
        lines.append(f"  Code:              {icmp['code']}")
        lines.append(f"  Checksum:          {icmp['checksum']}")

    # --- DNS Layer ---
    if "DNS" in info["layers"]:
        dns = info["layers"]["DNS"]
        lines.append(colorize("[Layer 7: DNS - Domain Name System]", Colors.ORANGE))
        lines.append(f"  Transaction ID:    0x{dns['id']:04x}")
        lines.append(f"  Message Type:      {dns['qr']}")
        for q in dns["queries"]:
            lines.append(f"  Query:             {q['name']} [{q['type']}]")
        for ans in dns["answers"]:
            lines.append(f"  Answer:            {ans}")

    # --- HTTP Layer ---
    if "HTTP" in info["layers"]:
        http = info["layers"]["HTTP"]
        lines.append(colorize("[Layer 7: HTTP - Hypertext Transfer Protocol (Plaintext)]", Colors.WHITE))
        for k, v in http.items():
            lines.append(f"  {k.capitalize():<18}: {v}")

    # --- Payload / Hexdump ---
    payload = info.get("payload_bytes", b"")
    if payload:
        lines.append(colorize(f"[Application Data / Payload: {len(payload)} bytes]", Colors.GRAY))
        # In verbose mode, we dump the entire payload
        lines.append(format_hexdump(payload, max_bytes=None))

    return "\n".join(lines)

