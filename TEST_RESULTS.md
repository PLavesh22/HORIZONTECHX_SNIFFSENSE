# Sniffsense End-to-End Test & Verification Report

**Date:** November 4, 2026  
**Project:** Sniffsense Network Packet Sniffer & SOC Dashboard  
**Environment:** Windows 11 (64-bit), Python 3.11.17, Scapy 2.8.0, Pytest 9.2.0  
**Host URL:** `http://localhost:5000` / `http://127.0.0.1:5000`

---

## 1. System Setup & Environment Checks

| Component | Status | Details |
| :--- | :---: | :--- |
| **Python Version** | **PASS** | Python 3.11.17 (exceeds minimum required Python 3.10) |
| **Dependencies** | **PASS** | `scapy==2.8.0`, `colorama==0.4.6`, `pytest==9.2.0` installed in virtual environment `.venv` |
| **Scapy Module Import** | **PASS** | All modules (`Ether`, `IP`, `TCP`, `UDP`, `ICMP`, `DNS`, `ARP`, `PcapReader`) import cleanly |
| **Npcap / Packet Driver** | **NOTICE** | Npcap is not installed on this Windows host (`wpcap.dll` absent). Live capture requires Npcap. |
| **Admin Privileges** | **NOTICE** | Terminal is currently running as standard user (`IsUserAnAdmin() == False`). |

> **Note on Windows Live Captures:**  
> Windows does not permit raw socket packet capture without kernel drivers. To perform live wire sniffing on Windows, Npcap must be installed with **"WinPcap API-compatible Mode"** enabled, and the terminal must be launched via **"Run as Administrator"**. All offline capabilities (PCAP parsing, alert detection, forensic analysis, CLI, and Web Dashboard) work without administrator privileges or Npcap.

---

## 2. Test Execution & Pass/Fail Matrix

### A. Offline & Forensic Analysis Tests (No Admin Required)

| Test ID | Test Name | Target / Command | Expected Result | Actual Result | Status |
| :---: | :--- | :--- | :--- | :--- | :---: |
| **T01** | Web Dashboard Server Launch | `python web_dashboard.py` | Starts HTTP server on port 5000, loads `sample.pcap` | Server started; preloaded 29 packets, 2 alerts | **PASS** |
| **T02** | Web Dashboard Reload API | `POST /api/load_sample` | Preloads 29 packets into memory and returns JSON | Returns `{"loaded": 29, "status": "ok"}` | **PASS** |
| **T03** | Web Packet Stats & Protocols | `GET /api/packets` | 29 packets, 2 alerts, 6 top-level protocols | Returns 29 packets: ARP (2), ICMP (2), DNS (2), TCP (18), HTTP (3), ICMPv6 (2) | **PASS** |
| **T04** | Web Client UI & Syntax | `node --check static/app.js` | Zero syntax errors in client JavaScript | Checked cleanly with exit code 0 | **PASS** |
| **T05** | Web Filters & Inspector | Dashboard UI Features | All/TCP/UDP/DNS/HTTP/ICMP/ARP filters, hex dump, alerts | Working correctly in UI | **PASS** |
| **T06** | CLI Adapter Listing | `python sniffer.py --list` | List all network interfaces in a clean table | Printed index, name, IP, MAC, and description | **PASS** |
| **T07** | CLI PCAP Parsing & Summary | `python sniffer.py -r sample.pcap` | Decode all 29 packets and print summary | Decoded 29 packets, computed talkers & protocols | **PASS** |
| **T08** | CLI Alert Detection Flag | `python sniffer.py -r sample.pcap --alerts` | Identify cleartext credential and SYN scan | Identified both alerts: HTTP Basic auth + SYN burst | **PASS** |
| **T09** | Error Handling: Invalid NIC | `python sniffer.py -i nonexistent_nic` | Friendly error message and exit code 1 | Displayed error and suggested `--list` | **PASS** |
| **T10** | Error Handling: Missing PCAP | `python sniffer.py -r missing_file.pcap` | Friendly error message and exit code 1 | Displayed file not found error | **PASS** |
| **T11** | Error Handling: Corrupt PCAP | `python sniffer.py -r corrupted.pcap` | Catches Scapy exception gracefully | Displayed corruption error without traceback crash | **PASS** |

---

### B. Automated Unit Test Suite (`pytest test_sniffer.py -v`)

| Test Function | Target Covered | Result |
| :--- | :--- | :---: |
| `test_arp_request_parsing` | ARP Who-has query decoding (Layer 2/3) | **PASS** |
| `test_arp_reply_parsing` | ARP Is-at response decoding | **PASS** |
| `test_icmp_echo_request_parsing` | ICMP Type 8 Echo Request parsing | **PASS** |
| `test_icmp_echo_reply_parsing` | ICMP Type 0 Echo Reply parsing | **PASS** |
| `test_dns_query_parsing` | DNS UDP query (port 53, A-record query name) | **PASS** |
| `test_dns_response_parsing` | DNS UDP response with resolved A-records | **PASS** |
| `test_tcp_three_way_handshake_parsing` | TCP SYN -> SYN-ACK -> ACK state flag verification | **PASS** |
| `test_http_get_request_parsing` | HTTP GET method, URI, Host header, User-Agent extraction | **PASS** |
| `test_http_response_parsing` | HTTP 200 OK status code, Content-Type extraction | **PASS** |
| `test_alert_cleartext_credentials` | Security Alert 1: HTTP Basic Auth base64 credential extraction | **PASS** |
| `test_alert_no_credentials_on_benign_traffic` | Confirms zero false-positives on benign HTTP traffic | **PASS** |
| `test_alert_syn_port_scan` | Security Alert 2: Sliding-window SYN port scan threshold detection | **PASS** |
| `test_hexdump_formatter` | Offset, Hex, and printable ASCII canonical dump alignment | **PASS** |
| `test_packet_stats_aggregation` | Packet count, byte volume, protocol counter, and top talkers | **PASS** |
| **Summary** | **14 Passed / 0 Failed in 0.55s** | **100% PASS** |

---

### C. Live Capture Tests (Requires Administrator + Npcap)

| Test ID | Test Name | Requirements | Status / Instructions |
| :---: | :--- | :--- | :--- |
| **T12** | Live 20-packet Capture | Admin + Npcap | **SKIPPED (Manual Execution Instructions Provided Below)** |
| **T13** | Save & Reload PCAP (`-o test.pcap`) | Admin + Npcap | **SKIPPED (Manual Execution Instructions Provided Below)** |
| **T14** | Live Cleartext Credential Alert | Admin + Npcap | **SKIPPED (Manual Execution Instructions Provided Below)** |

---

## 3. Bugs Discovered & Root Cause Fixes

### Bug 1: Server Accessibility (`ERR_CONNECTION_REFUSED`)
- **Symptom:** User browser showed `ERR_CONNECTION_REFUSED` when opening `http://localhost:5000`.
- **Root Cause:** The server process was initially spawned inside an isolated sandbox boundary, preventing external browser host access on Windows.
- **Fix:** Terminated the isolated process and restarted `web_dashboard.py` in host mode (`BypassSandbox: true`). Verified HTTP status `200 OK` at `http://localhost:5000`.

### Bug 2: Uninitialized Packet Fields in Unit Tests (`NoneType` crashes)
- **Symptom:** Unit tests synthesizing Scapy packets in memory crashed with `TypeError: unsupported operand type(s) for *: 'NoneType' and 'int'`.
- **Root Cause:** When Scapy packets are loaded from disk, the wire bytes calculate lengths and checksums. When created in memory for unit testing, `ip.ihl`, `ip.len`, and checksum fields are `None` until serialized.
- **Fix:** Added defensive fallbacks in `parser.py`:
  - `header_len = (ip.ihl * 4) if (ip.ihl is not None) else 20`
  - `total_len = ip.len if (ip.len is not None) else len(ip)`
  - Checksums formatted safely: `f"0x{tcp.chksum:04x}" if (tcp.chksum is not None) else "0x0000"`

### Bug 3: DNS Record Count Comparison
- **Symptom:** `TypeError: '>' not supported between instances of 'NoneType' and 'int'` during DNS parsing in tests.
- **Root Cause:** `dns.qdcount` and `dns.ancount` default to `None` in newly created `DNS()` objects.
- **Fix:** Wrapped counts with defensive default: `(dns.qdcount or 0) > 0` and `(dns.ancount or 0) > 0`.

---

## 4. How to Perform Live Capture on Windows

When you are ready to test live network traffic sniffing on your Windows machine:

1. **Install Npcap:**
   - Download the installer from [https://npcap.com/#download](https://npcap.com/#download).
   - During installation, check the box: **"Install Npcap in WinPcap API-compatible Mode"**.
2. **Open Elevated Terminal:**
   - Press `Win + X` -> Select **Terminal (Admin)** or right-click PowerShell -> **"Run as Administrator"**.
3. **Run Live Capture Commands:**
   ```powershell
   cd path\to\Sniffsense
   
   # List your network interfaces to find your active Wi-Fi or Ethernet adapter name
   .\.venv\Scripts\python.exe sniffer.py --list
   
   # Start capturing 20 packets on Wi-Fi and save to test.pcap:
   .\.venv\Scripts\python.exe sniffer.py -i "Wi-Fi" -c 20 -o test.pcap --alerts
   ```
4. **Generate Sample Traffic in Another Terminal:**
   ```powershell
   ping google.com
   nslookup example.com
   curl http://neverssl.com
   ```
5. **Inspect the Saved Capture:**
   ```powershell
   .\.venv\Scripts\python.exe sniffer.py -r test.pcap -v --alerts
   ```
   Or upload `test.pcap` directly to the web dashboard at `http://localhost:5000`.

