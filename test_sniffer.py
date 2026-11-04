"""
test_sniffer.py - Automated PyTest Suite for Sniffsense.

Covers layer-by-layer parsing and security alert rules:
  1. ARP layer (Who-has request, Is-at reply)
  2. ICMP layer (Echo request/reply with payload)
  3. DNS layer (Queries and A-record answers)
  4. TCP 3-way handshake (SYN, SYN-ACK, ACK, flags)
  5. HTTP layer (GET request, HTTP 200 OK response, POST with payload)
  6. Security alert: Cleartext credential exposure
  7. Security alert: SYN port scan detection
  8. PacketStats accumulator validation
"""

import pytest
import time
from scapy.all import (
    Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw
)

from parser import parse_packet
from utils import AlertEngine, PacketStats, format_hexdump


# ============================================================================
# 1. ARP PACKET PARSER TESTS
# ============================================================================
def test_arp_request_parsing():
    """Verify ARP 'who-has' request decoding."""
    pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="aa:bb:cc:dd:ee:01",
        psrc="192.168.1.100",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1"
    )
    info = parse_packet(pkt)

    assert "Ethernet" in info["protocols"]
    assert "ARP" in info["protocols"]
    assert info["src_ip"] == "192.168.1.100"
    assert info["dst_ip"] == "192.168.1.1"
    assert "ARP" in info["layers"]
    assert info["layers"]["ARP"]["operation"] == "Who-has (Request)"
    assert info["layers"]["ARP"]["ip_src"] == "192.168.1.100"
    assert info["layers"]["ARP"]["ip_dst"] == "192.168.1.1"


def test_arp_reply_parsing():
    """Verify ARP 'is-at' reply decoding."""
    pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:01") / ARP(
        op=2,
        hwsrc="00:11:22:33:44:55",
        psrc="192.168.1.1",
        hwdst="aa:bb:cc:dd:ee:01",
        pdst="192.168.1.100"
    )
    info = parse_packet(pkt)

    assert "ARP" in info["protocols"]
    assert info["layers"]["ARP"]["operation"] == "Is-at (Reply)"
    assert info["layers"]["ARP"]["hw_src"] == "00:11:22:33:44:55"


# ============================================================================
# 2. ICMP PACKET PARSER TESTS
# ============================================================================
def test_icmp_echo_request_parsing():
    """Verify ICMP ping request (Type 8, Code 0) parsing."""
    payload_data = b"abcdefghijklmnopqrstuvwabcdefghi"
    pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8", ttl=64) / ICMP(type=8, code=0) / Raw(load=payload_data)
    info = parse_packet(pkt)

    assert "IPv4" in info["protocols"]
    assert "ICMP" in info["protocols"]
    assert info["src_ip"] == "192.168.1.50"
    assert info["dst_ip"] == "8.8.8.8"
    assert info["layers"]["ICMP"]["type"] == 8
    assert info["layers"]["ICMP"]["code"] == 0
    assert "Echo Request" in info["layers"]["ICMP"]["meaning"]
    assert info["payload_bytes"] == payload_data


def test_icmp_echo_reply_parsing():
    """Verify ICMP ping reply (Type 0, Code 0) parsing."""
    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.50", ttl=56) / ICMP(type=0, code=0)
    info = parse_packet(pkt)

    assert info["layers"]["ICMP"]["type"] == 0
    assert "Echo Reply" in info["layers"]["ICMP"]["meaning"]


# ============================================================================
# 3. DNS PACKET PARSER TESTS
# ============================================================================
def test_dns_query_parsing():
    """Verify DNS standard query decoding."""
    dns_query = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=54321, dport=53) / DNS(
        id=0x1234,
        qr=0,
        qd=DNSQR(qname="example.com", qtype="A")
    )
    info = parse_packet(dns_query)

    assert "UDP" in info["protocols"]
    assert "DNS" in info["protocols"]
    assert info["src_port"] == 54321
    assert info["dst_port"] == 53
    assert info["layers"]["DNS"]["qr"] == "Query"
    assert len(info["layers"]["DNS"]["queries"]) == 1
    assert info["layers"]["DNS"]["queries"][0]["name"] == "example.com"
    assert "A" in info["layers"]["DNS"]["queries"][0]["type"]


def test_dns_response_parsing():
    """Verify DNS response containing resolved A-records."""
    dns_resp = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=54321) / DNS(
        id=0x1234,
        qr=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")
    )
    info = parse_packet(dns_resp)

    assert "DNS" in info["protocols"]
    assert info["layers"]["DNS"]["qr"] == "Response"
    assert "93.184.216.34" in info["layers"]["DNS"]["answers"]


# ============================================================================
# 4. TCP 3-WAY HANDSHAKE PARSER TESTS
# ============================================================================
def test_tcp_three_way_handshake_parsing():
    """Verify parsing of SYN, SYN-ACK, and ACK packets."""
    # Step 1: SYN
    syn_pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=44000, dport=80, flags="S", seq=1000)
    syn_info = parse_packet(syn_pkt)
    assert "TCP" in syn_info["protocols"]
    assert "SYN" in syn_info["tcp_flags"]
    assert "ACK" not in syn_info["tcp_flags"]
    assert syn_info["layers"]["TCP"]["seq"] == 1000

    # Step 2: SYN-ACK
    synack_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=44000, flags="SA", seq=5000, ack=1001)
    synack_info = parse_packet(synack_pkt)
    assert "SYN" in synack_info["tcp_flags"]
    assert "ACK" in synack_info["tcp_flags"]
    assert synack_info["layers"]["TCP"]["ack"] == 1001

    # Step 3: ACK
    ack_pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=44000, dport=80, flags="A", seq=1001, ack=5001)
    ack_info = parse_packet(ack_pkt)
    assert "ACK" in ack_info["tcp_flags"]
    assert "SYN" not in ack_info["tcp_flags"]
    assert ack_info["layers"]["TCP"]["seq"] == 1001
    assert ack_info["layers"]["TCP"]["ack"] == 5001


# ============================================================================
# 5. HTTP PROTOCOL PARSER TESTS
# ============================================================================
def test_http_get_request_parsing():
    """Verify HTTP GET request extraction."""
    http_payload = b"GET /api/v1/status HTTP/1.1\r\nHost: api.local\r\nUser-Agent: curl/7.88.1\r\n\r\n"
    pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50000, dport=80, flags="PA") / Raw(load=http_payload)
    info = parse_packet(pkt)

    assert "HTTP" in info["protocols"]
    assert "HTTP" in info["layers"]
    assert info["layers"]["HTTP"]["method"] == "GET"
    assert info["layers"]["HTTP"]["path"] == "/api/v1/status"
    assert info["layers"]["HTTP"]["host"] == "api.local"


def test_http_response_parsing():
    """Verify HTTP 200 OK response extraction."""
    http_response = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n\r\n{\"status\":\"healthy\"}"
    pkt = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=50000, flags="PA") / Raw(load=http_response)
    info = parse_packet(pkt)

    assert "HTTP" in info["protocols"]
    assert info["layers"]["HTTP"]["status_code"] == "200"
    assert info["layers"]["HTTP"]["status_phrase"] == "OK"


# ============================================================================
# 6. SECURITY ALERTS: CLEARTEXT CREDENTIAL EXPOSURE
# ============================================================================
def test_alert_cleartext_credentials():
    """Verify detection of plaintext credentials transmitted over unencrypted HTTP."""
    alert_engine = AlertEngine()
    post_body = b"POST /login HTTP/1.1\r\nHost: portal.internal\r\n\r\nusername=admin&password=SuperSecretPassword123"
    pkt = Ether() / IP(src="192.168.1.50", dst="192.168.1.200") / TCP(sport=49152, dport=80, flags="PA") / Raw(load=post_body)
    info = parse_packet(pkt)

    alerts = alert_engine.inspect(info)
    assert len(alerts) >= 1
    assert any("CLEARTEXT CREDENTIAL EXPOSURE" in a for a in alerts)
    assert any("portal.internal" in a for a in alerts)


def test_alert_no_credentials_on_benign_traffic():
    """Verify benign HTTP requests do not trigger false positive credential alerts."""
    alert_engine = AlertEngine()
    get_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="PA") / Raw(load=get_payload)
    info = parse_packet(pkt)

    alerts = alert_engine.inspect(info)
    assert len(alerts) == 0


# ============================================================================
# 7. SECURITY ALERTS: SYN PORT SCAN DETECTION
# ============================================================================
def test_alert_syn_port_scan():
    """Verify detection when a single host probes multiple ports with SYN packets."""
    alert_engine = AlertEngine(time_window_seconds=10.0, port_scan_threshold=5)
    scanner_ip = "10.0.0.99"
    target_ip = "192.168.1.1"

    ports = [21, 22, 23, 25, 53, 80, 443]
    detected_alerts = []

    for port in ports:
        pkt = Ether() / IP(src=scanner_ip, dst=target_ip) / TCP(sport=50000 + port, dport=port, flags="S")
        info = parse_packet(pkt)
        alerts = alert_engine.inspect(info)
        detected_alerts.extend(alerts)

    assert len(detected_alerts) >= 1
    assert any("POSSIBLE PORT SCAN" in a for a in detected_alerts)
    assert any("10.0.0.99" in a for a in detected_alerts)


# ============================================================================
# 8. UTILITIES & STATS VALIDATION
# ============================================================================
def test_hexdump_formatter():
    """Verify format_hexdump produces structured canonical hex+ASCII output."""
    data = b"Hello, World!\x00\x01\x02"
    dump = format_hexdump(data)
    assert "48 65 6c 6c 6f 2c 20 57" in dump.lower()
    assert "|Hello, World!|"[1:12] in dump


def test_packet_stats_aggregation():
    """Verify PacketStats tracks protocols, totals, and top talkers correctly."""
    stats = PacketStats()

    p1 = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=1234, flags="S")
    p2 = Ether() / IP(src="192.168.1.1", dst="192.168.1.3") / UDP(sport=53, dport=53)
    p3 = Ether() / ARP(psrc="192.168.1.5", pdst="192.168.1.1")

    stats.update(parse_packet(p1))
    stats.update(parse_packet(p2))
    stats.update(parse_packet(p3))

    assert stats.total_packets == 3
    assert stats.protocol_counts["Ethernet"] == 3
    assert stats.protocol_counts["IPv4"] == 2
    assert stats.protocol_counts["TCP"] == 1
    assert stats.protocol_counts["UDP"] == 1
    assert stats.protocol_counts["ARP"] == 1
    assert stats.src_ip_counts.most_common(1)[0][0] == "192.168.1.1"
    assert stats.src_ip_counts.most_common(1)[0][1] == 2
