"""
generate_sample_pcap.py - Generates an educational sample PCAP dataset.

Creates 'sample.pcap' with a variety of realistic network protocols:
  1. ARP Request and Reply (Layer 2 address resolution)
  2. ICMP Echo Request and Reply (Ping traffic)
  3. DNS Query and Response (example.com lookup)
  4. TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK)
  5. HTTP Plaintext GET request and HTTP 200 OK response
  6. HTTP POST request containing cleartext credentials (for alert testing)
  7. TCP Port Scan simulation (15 SYN packets targeting diverse ports)
  8. IPv6 ICMPv6 traffic

This allows anyone to test and demonstrate the sniffer without:
  - Administrator/root privileges
  - Npcap / libpcap kernel drivers
  - An active internet connection
"""

from __future__ import annotations

import time
from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Ether,
    ICMP,
    IP,
    IPv6,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    Raw,
    TCP,
    UDP,
    wrpcap,
)


def create_sample_pcap(filename: str = "sample.pcap") -> None:
    """Build and write realistic synthetic network packets to a PCAP file."""
    packets = []
    base_time = time.time() - 60  # Recorded 1 minute ago

    # Common MAC and IP addresses
    client_mac = "00:1a:2b:3c:4d:5e"
    gateway_mac = "00:0c:29:4f:8e:12"
    server_mac = "52:54:00:12:34:56"
    scanner_mac = "aa:bb:cc:dd:ee:ff"

    client_ip = "192.168.1.50"
    gateway_ip = "192.168.1.1"
    web_server_ip = "93.184.216.34"
    dns_server_ip = "8.8.8.8"
    scanner_ip = "10.0.0.99"

    # -------------------------------------------------------------------------
    # 1. ARP: Address Resolution Protocol (Layer 2/3)
    # -------------------------------------------------------------------------
    t = base_time + 0.1
    # ARP Request: "Who has 192.168.1.1? Tell 192.168.1.50"
    arp_req = Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=client_mac, psrc=client_ip, hwdst="00:00:00:00:00:00", pdst=gateway_ip
    )
    arp_req.time = t
    packets.append(arp_req)

    # ARP Reply: "192.168.1.1 is at 00:0c:29:4f:8e:12"
    t += 0.005
    arp_rep = Ether(src=gateway_mac, dst=client_mac) / ARP(
        op=2, hwsrc=gateway_mac, psrc=gateway_ip, hwdst=client_mac, pdst=client_ip
    )
    arp_rep.time = t
    packets.append(arp_rep)

    # -------------------------------------------------------------------------
    # 2. ICMP: Ping inquiry and response
    # -------------------------------------------------------------------------
    t += 0.1
    # Echo Request (Type 8)
    ping_req = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst="8.8.8.8", ttl=64) / ICMP(type=8, code=0) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
    ping_req.time = t
    packets.append(ping_req)

    t += 0.024
    # Echo Reply (Type 0)
    ping_rep = Ether(src=gateway_mac, dst=client_mac) / IP(src="8.8.8.8", dst=client_ip, ttl=118) / ICMP(type=0, code=0) / Raw(b"abcdefghijklmnopqrstuvwabcdefghi")
    ping_rep.time = t
    packets.append(ping_rep)

    # -------------------------------------------------------------------------
    # 3. DNS: Domain Name Resolution (example.com)
    # -------------------------------------------------------------------------
    t += 0.15
    dns_id = 0x1A2B
    dns_query = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=dns_server_ip, ttl=64)
        / UDP(sport=53530, dport=53)
        / DNS(id=dns_id, qr=0, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_query.time = t
    packets.append(dns_query)

    t += 0.035
    dns_response = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src=dns_server_ip, dst=client_ip, ttl=56)
        / UDP(sport=53, dport=53530)
        / DNS(
            id=dns_id,
            qr=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata=web_server_ip, ttl=300),
        )
    )
    dns_response.time = t
    packets.append(dns_response)

    # -------------------------------------------------------------------------
    # 4. TCP 3-Way Handshake
    # -------------------------------------------------------------------------
    client_port = 49210
    web_port = 80
    client_seq = 100000
    server_seq = 500000

    # Step 1: Client -> Server [SYN]
    t += 0.05
    tcp_syn = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=web_server_ip, ttl=64)
        / TCP(sport=client_port, dport=web_port, flags="S", seq=client_seq, window=64240)
    )
    tcp_syn.time = t
    packets.append(tcp_syn)

    # Step 2: Server -> Client [SYN, ACK]
    t += 0.04
    tcp_synack = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src=web_server_ip, dst=client_ip, ttl=52)
        / TCP(sport=web_port, dport=client_port, flags="SA", seq=server_seq, ack=client_seq + 1, window=65535)
    )
    tcp_synack.time = t
    packets.append(tcp_synack)

    # Step 3: Client -> Server [ACK] (Handshake Complete)
    t += 0.002
    tcp_ack = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=web_server_ip, ttl=64)
        / TCP(sport=client_port, dport=web_port, flags="A", seq=client_seq + 1, ack=server_seq + 1, window=64240)
    )
    tcp_ack.time = t
    packets.append(tcp_ack)

    # -------------------------------------------------------------------------
    # 5. HTTP: Plaintext GET and 200 OK Response
    # -------------------------------------------------------------------------
    t += 0.01
    http_req_text = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n"
    http_get = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst=web_server_ip, ttl=64)
        / TCP(sport=client_port, dport=web_port, flags="PA", seq=client_seq + 1, ack=server_seq + 1, window=64240)
        / Raw(http_req_text.encode("utf-8"))
    )
    http_get.time = t
    packets.append(http_get)

    t += 0.04
    http_resp_text = (
        "HTTP/1.1 200 OK\r\n"
        "Server: ECS (dcb/7F3B)\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: 48\r\n\r\n"
        "<!doctype html><html><body><h1>Example Domain</h1></body></html>"
    )
    http_resp = (
        Ether(src=gateway_mac, dst=client_mac)
        / IP(src=web_server_ip, dst=client_ip, ttl=52)
        / TCP(sport=web_port, dport=client_port, flags="PA", seq=server_seq + 1, ack=client_seq + 1 + len(http_req_text), window=65535)
        / Raw(http_resp_text.encode("utf-8"))
    )
    http_resp.time = t
    packets.append(http_resp)

    # -------------------------------------------------------------------------
    # 6. HTTP POST with Cleartext Credentials (Tests --alerts feature)
    # -------------------------------------------------------------------------
    t += 0.2
    cred_post_body = "username=intern_analyst&password=SuperSecretPassword123!&auth_action=login"
    cred_post_headers = (
        f"POST /api/v1/auth/login HTTP/1.1\r\n"
        f"Host: dev-portal.internal\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(cred_post_body)}\r\n\r\n"
        f"{cred_post_body}"
    )
    http_cred = (
        Ether(src=client_mac, dst=gateway_mac)
        / IP(src=client_ip, dst="192.168.1.200", ttl=64)
        / TCP(sport=49320, dport=80, flags="PA", seq=2000, ack=3000, window=64240)
        / Raw(cred_post_headers.encode("utf-8"))
    )
    http_cred.time = t
    packets.append(http_cred)

    # -------------------------------------------------------------------------
    # 7. TCP Port Scan Simulation (Tests --alerts port scan detection)
    # -------------------------------------------------------------------------
    # Scanner sends SYN packets across 15 different target ports in 0.5 seconds
    target_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080]
    for p in target_ports:
        t += 0.02
        scan_pkt = (
            Ether(src=scanner_mac, dst=gateway_mac)
            / IP(src=scanner_ip, dst=gateway_ip, ttl=48)
            / TCP(sport=50000 + (p % 1000), dport=p, flags="S", seq=100 + p, window=1024)
        )
        scan_pkt.time = t
        packets.append(scan_pkt)

    # -------------------------------------------------------------------------
    # 8. IPv6 ICMPv6 Echo Request / Reply
    # -------------------------------------------------------------------------
    t += 0.1
    ipv6_ping_req = (
        Ether(src=client_mac, dst=gateway_mac)
        / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64)
        / ICMPv6EchoRequest(data=b"Testing IPv6 connectivity")
    )
    ipv6_ping_req.time = t
    packets.append(ipv6_ping_req)

    t += 0.02
    ipv6_ping_rep = (
        Ether(src=gateway_mac, dst=client_mac)
        / IPv6(src="2001:db8::2", dst="2001:db8::1", hlim=58)
        / ICMPv6EchoReply(data=b"Testing IPv6 connectivity")
    )
    ipv6_ping_rep.time = t
    packets.append(ipv6_ping_rep)

    # Write all crafted packets to PCAP file
    wrpcap(filename, packets)
    print(f"[+] Successfully generated '{filename}' containing {len(packets)} realistic test packets.")


if __name__ == "__main__":
    create_sample_pcap()

