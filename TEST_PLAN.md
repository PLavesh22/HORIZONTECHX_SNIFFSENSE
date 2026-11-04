# Sniffsense - Network Packet Sniffer Test Plan

This document provides a systematic, step-by-step verification plan for testing the Sniffsense packet sniffer. It details how to generate live network traffic using standard command-line tools (`ping`, `curl`, `nslookup`), what packet patterns to expect, and how to verify offline operations without administrative privileges.

---

## Environment & Test Matrix

| Test ID | Feature Under Test | Traffic Generator | Command / Filter | Privilege Level |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | ICMP Echo Request / Reply | `ping` | BPF `icmp` | Admin (Live) or User (PCAP) |
| **TC-02** | Plaintext HTTP & Handshake | `curl http://neverssl.com` | BPF `tcp port 80` | Admin (Live) or User (PCAP) |
| **TC-03** | DNS Query & Resolution | `nslookup` | BPF `udp port 53` | Admin (Live) or User (PCAP) |
| **TC-04** | Offline PCAP Ingestion | `sample.pcap` | `-r sample.pcap` | User (No Admin) |
| **TC-05** | Suspicious Pattern Alerts | `sample.pcap` | `--alerts` | User (No Admin) |
| **TC-06** | Verbose Layer Breakdown | `sample.pcap` | `-v -c 3` | User (No Admin) |
| **TC-07** | Capture-to-File & Re-read | `sniffer.py` | `-o test.pcap` then `-r test.pcap` | User / Admin |
| **TC-08** | Raw Socket Demo & Fallback | `raw_socket_example.py` | Standalone Execution | User / Admin |

---

## Test Setup Instructions

Open two terminal windows side-by-side:
- **Terminal 1 (Sniffer)**: Runs `sniffer.py` bound to your active network interface (or reading a pcap).
- **Terminal 2 (Client / Generator)**: Executes network commands (`ping`, `curl`, `nslookup`).

To find your active network interface name:
```bash
python sniffer.py --list
```
Look for the interface showing your local IP (e.g. `Wi-Fi`, `Ethernet`, or interface index `16`).

---

## Detailed Test Procedures

### Test Case 1: ICMP Ping Verification

**Objective**: Verify Layer 3 IPv4/IPv6 and Layer 4 ICMP parsing, including Echo Request (Type 8) and Echo Reply (Type 0).

1. **Start Sniffer in Terminal 1**:
   ```bash
   python sniffer.py -i Wi-Fi -f "icmp" -c 4
   ```
   *(On Windows/Linux, run Terminal 1 as Administrator / root).*

2. **Generate Traffic in Terminal 2**:
   - **Windows**:
     ```powershell
     ping -n 2 8.8.8.8
     ```
   - **Linux / macOS**:
     ```bash
     ping -c 2 8.8.8.8
     ```

3. **Expected Sniffer Output**:
   - Two incoming/outgoing pairs of ICMP packets:
     ```
     [14:15:02.120] ICMP   192.168.1.50 -> 8.8.8.8       | Len=74   | Echo Request (Ping inquiry) (Type=8, Code=0)
       Payload (32 bytes, first 64 shown):
         0000   61 62 63 64 65 66 67 68  69 6a 6b 6c 6d 6e 6f 70   |abcdefghijklmnop|
     [14:15:02.145] ICMP   8.8.8.8 -> 192.168.1.50       | Len=74   | Echo Reply (Ping response) (Type=0, Code=0)
     ```
   - Statistics table displayed upon reaching 4 packets, showing 100% ICMP distribution.

---

### Test Case 2: Plaintext HTTP Verification

**Objective**: Verify TCP 3-way handshake (`SYN`, `SYN-ACK`, `ACK`), HTTP request parsing (`GET`), `Host` header extraction, and HTTP response status (`200 OK`).

> **Note**: We test with `http://neverssl.com` because it intentionally never upgrades to HTTPS, allowing plain HTTP inspection without TLS encryption.

1. **Start Sniffer in Terminal 1**:
   ```bash
   python sniffer.py -i Wi-Fi -f "tcp port 80" -c 10
   ```

2. **Generate Traffic in Terminal 2**:
   ```bash
   curl -i http://neverssl.com
   ```

3. **Expected Sniffer Output**:
   - Handshake sequence:
     ```
     [14:16:10.010] TCP   192.168.1.50:51234 -> 13.249.12.80:80    | Len=54   | [SYN] | Seq=... | Win=...
     [14:16:10.035] TCP   13.249.12.80:80 -> 192.168.1.50:51234    | Len=54   | [SYN, ACK] | Seq=... | Ack=...
     [14:16:10.036] TCP   192.168.1.50:51234 -> 13.249.12.80:80    | Len=54   | [ACK] | Seq=... | Ack=...
     ```
   - HTTP application payload:
     ```
     [14:16:10.040] HTTP  192.168.1.50:51234 -> 13.249.12.80:80    | Len=145  | ... | 'GET / HTTP/1.1'
       Payload (91 bytes, first 64 shown):
         0000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   |GET / HTTP/1.1..|
         0010   48 6f 73 74 3a 20 6e 65  76 65 72 73 73 6c 2e 63   |Host: neverssl.c|
         0020   6f 6d 0d 0a ...                                    |om..            |
     [14:16:10.070] HTTP  13.249.12.80:80 -> 192.168.1.50:51234    | Len=450  | ... | 'HTTP/1.1 200 OK'
     ```

---

### Test Case 3: DNS Query & Resolution Verification

**Objective**: Verify UDP transport encapsulation (port 53), DNS Query transaction, query domain name (`example.com`), and resolved IP address.

1. **Start Sniffer in Terminal 1**:
   ```bash
   python sniffer.py -i Wi-Fi -f "udp port 53" -c 4
   ```

2. **Generate Traffic in Terminal 2**:
   ```bash
   nslookup example.com 8.8.8.8
   ```

3. **Expected Sniffer Output**:
   ```
   [14:17:15.100] DNS    192.168.1.50:54321 -> 8.8.8.8:53       | Len=71   | Q: example.com (A (IPv4))
   [14:17:15.132] DNS    8.8.8.8:53 -> 192.168.1.50:54321       | Len=98   | Q: example.com (A (IPv4)) | Ans: 93.184.216.34
   ```

---

### Test Case 4: Offline PCAP Analysis (Zero Privilege Demonstration)

**Objective**: Ensure anyone reviewing or grading the project can evaluate full protocol parsing and statistics without root/admin permissions or Npcap driver installation.

1. **Command**:
   ```bash
   python sniffer.py -r sample.pcap
   ```

2. **Expected Results**:
   - Parses 29 packets spanning Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP.
   - Shows formatted hexdump for payload packets.
   - Generates summary statistics:
     * Total packets: 29
     * Protocol distribution table with graphical ASCII bars
     * Top 5 Source IPs (Top Talkers)
     * Top 5 Destination IPs (Top Listeners)

---

### Test Case 5: Suspicious Activity Alerts (`--alerts`)

**Objective**: Verify detection of:
1. TCP SYN Port Scanning across multiple ports within a sliding window.
2. Unencrypted credential exposure in HTTP POST bodies.

1. **Command**:
   ```bash
   python sniffer.py -r sample.pcap --alerts
   ```

2. **Expected Warnings Output**:
   - **Credential Alert**:
     ```
     [ALERT: CLEARTEXT CREDENTIAL EXPOSURE] Unencrypted credential transmitted via POST to dev-portal.internal/api/v1/auth/login from 192.168.1.50 -> 192.168.1.200 (2 matched token(s))
     ```
   - **Port Scan Alert**:
     ```
     [ALERT: POSSIBLE PORT SCAN] Host 10.0.0.99 sent SYN packets to 10 different ports on 192.168.1.1 within 10s (Ports: 21, 22, 23, 25, 53, 80, 110, 139...)
     ```

---

### Test Case 6: Verbose Layer Breakdown (`-v`)

**Objective**: Verify comprehensive display of every protocol header field (IHL, TTL, Identification, Flags, Sequence/Ack numbers, Window Size, EtherType).

1. **Command**:
   ```bash
   python sniffer.py -r sample.pcap -c 3 -v
   ```

2. **Expected Output**:
   - Packet 1 (ARP Request): Shows Hardware Source/Target and Protocol Source/Target.
   - Packet 2 (ARP Reply): Shows resolved MAC address.
   - Packet 3 (IPv4 ICMP Ping): Shows IHL=5 (20 bytes), TTL=64, Checksum, ICMP Type 8 (Echo Request), and complete 32-byte payload hexdump.

---

### Test Case 7: Capture-to-File and Re-read (`-o` and `-r`)

**Objective**: Verify that packets captured or filtered can be written to `.pcap` format and loaded back with 100% integrity.

1. **Commands**:
   ```bash
   # Export first 5 packets to new file
   python sniffer.py -r sample.pcap -c 5 -o verify_export.pcap

   # Re-read exported file
   python sniffer.py -r verify_export.pcap
   ```

2. **Expected Output**:
   - Exactly 5 packets read from `verify_export.pcap`.
   - Metrics match the first 5 packets of `sample.pcap`.

---

### Test Case 8: Raw Socket Demo (`raw_socket_example.py`)

**Objective**: Demonstrate low-level binary unpacking (`struct.unpack`) and verify clear error messages when running unprivileged.

1. **Execute**:
   ```bash
   python raw_socket_example.py
   ```

2. **Expected Output (Unprivileged)**:
   ```
   ======================================================================
         MINIMAL RAW SOCKET SNIFFER (EDUCATIONAL DEMO)
   ======================================================================
   [*] Detected OS: Windows
   [*] Creating AF_INET SOCK_RAW socket (IPv4 only)...

   [!] PERMISSION DENIED: Raw sockets require Administrator/root privileges.
       On Windows: Run Command Prompt / PowerShell as Administrator.
       On Linux: Run with 'sudo python3 raw_socket_example.py'.
   ```

---

## Pass / Fail Criteria Checklist

- [x] Program displays Ethical Use Notice on launch.
- [x] Lists network interfaces with `--list` without exceptions.
- [x] Friendly error message when non-existent interface is supplied.
- [x] Friendly error message when missing `.pcap` file is specified.
- [x] Graceful `Ctrl+C` interrupt with statistics summary printed.
- [x] Captures/parses Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP.
- [x] Wireshark-style Hex + ASCII payload formatting.
- [x] Both suspicious alerts trigger reliably on simulated traffic.
- [x] Works out of the box in offline mode (`sample.pcap`) without admin rights.

