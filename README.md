# Sniffsense 🛡️🔍

> **A modern, lightweight network packet sniffer, forensic analyzer, and SOC web dashboard built in Python 3.10+ and Scapy.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/scapy-2.8.0-red.svg)](https://scapy.net/)
[![Tests](https://img.shields.io/badge/tests-14%20passed-brightgreen.svg)](test_sniffer.py)

---

## 📖 Overview

A **network packet sniffer** (also called a packet analyzer or network protocol analyzer) is a tool that intercepts, decodes, and inspects raw binary data traversing a Network Interface Card (NIC). In modern operating systems, applications communicate across network boundaries through abstract sockets, which hide the complex layered encapsulation taking place underneath.

**Sniffsense** demystifies network communication by disassembling raw frames layer by layer—from Layer 2 Ethernet headers down through IP datagrams, TCP segments, and Layer 7 application payloads. Designed with both a command-line interface (CLI) and an interactive **Security Operations Center (SOC) dashboard**, Sniffsense provides educational clarity, forensic insights, and heuristic threat detection for network engineering and cybersecurity research.

---

## ✨ Features

- 🌐 **Interactive SOC Web Dashboard**: Single-page web application featuring a GitHub/Datadog-inspired dark & light theme, WCAG AA compliance, and responsive layout.
- 📡 **Dual Operation Modes**:
  - **Live Capture**: Sniffs packets from physical or wireless adapters with real-time throughput metrics.
  - **Offline Forensic Ingestion**: Analyzes `.pcap` files without requiring elevated administrator/root permissions or kernel drivers.
- 🔬 **Layer-by-Layer Packet Inspector**:
  - Collapsible cards for Ethernet (MACs, EtherType), IP (TTL, Protocol numbers), TCP/UDP (Ports, Flags, Sequence/Ack, Checksums), and Application data.
  - Clear, plain-English field descriptions explaining what each field means (e.g. TTL router decrements, TCP flow control windows).
- 🧬 **Side-by-Side Hex / ASCII Dump**:
  - Canonical Wireshark-style memory hex dump with 16-byte aligned offset addresses, hexadecimal representations, and sanitized printable ASCII characters.
  - One-click **"Copy Hex"** button to copy the raw payload for reverse engineering or debugging.
- 📊 **Visual Analytics & Protocol Telemetry**:
  - **Top-Level Protocol Donut Chart**: Proportional breakdown of L4/L7 protocols with central packet counter.
  - **Packets & Bytes Timeline Chart**: Time-bucketed throughput chart with unit labels and toggleable metrics (Packets vs. Bytes).
  - Collapsible charts panel with remembered state for maximum screen space.
- 🚨 **Heuristic Security Alert Engine**:
  - **Cleartext Credential Detection**: Flags unencrypted authentication credentials (`password=`, `username=`, `token=`, `Basic <base64>`) transmitted over plaintext HTTP.
  - **TCP SYN Port Scan Detection**: Flags hosts initiating rapid SYN connections across distinct destination ports within a sliding time window.
  - Tinted warning badges and table row indicators linked directly to suspicious packets.
- ⌨️ **Keyboard Navigation & Filters**:
  - Smooth row selection, sticky table header, and arrow-key (`↑` / `↓`) keyboard navigation.
  - Protocol filters (`All`, `TCP`, `UDP`, `DNS`, `HTTP`, `ICMP`, `ARP`) and real-time IP/port search (`/` shortcut).
- 💻 **Cross-Platform CLI**: Rich terminal output formatted with color-coded protocol tags, hexdump preview, and ANSI session summaries.

---

## 📸 Screenshots

<!-- Place your captured dashboard screenshots in the docs/ folder -->

| SOC Monitoring Dashboard | Detailed Packet Inspector |
| :---: | :---: |
| ![Dashboard](docs/dashboard.png) | ![Packet Inspector](docs/inspector.png) |

> *Note: Place your screenshot images in the `docs/` directory matching the filenames above to render previews on GitHub.*

---

## 🛠️ Tech Stack

- **Backend & Core Engine**:
  - **Python 3.10+**: Core programming language.
  - **Scapy**: Packet dissection, frame reconstruction, and PCAP serialization.
  - **Python Standard Library (`ThreadingHTTPServer`, `http.server`)**: Zero-dependency, multi-threaded REST and web server (no heavy framework overhead).
  - **Colorama**: Cross-platform ANSI terminal coloring for Windows and Unix.
- **Frontend Dashboard**:
  - **HTML5 & Vanilla JavaScript**: High-performance, lightweight SPA with zero npm build step.
  - **Tailwind CSS**: Utility-first styling with custom CSS design tokens (`--bg`, `--surface`, `--accent`).
  - **Chart.js**: Smooth Canvas-rendered donut charts and timeline telemetry.
  - **Lucide Icons**: Uniform SVG iconography.
- **Testing**:
  - **Pytest**: Automated test suite for protocol parsing and alert verification.

---

## 📂 Project Structure

```text
Sniffsense/
├── .gitignore              # Git ignore rules (virtual environments, caches, private pcaps)
├── LICENSE                 # MIT Open Source License
├── README.md               # Complete project documentation and architectural guide
├── requirements.txt        # Python package dependencies (Scapy, Colorama, Pytest)
├── run_dashboard.bat       # Windows one-click batch script to launch the web dashboard
├── sniffer.py              # CLI packet sniffer (live capture, BPF filters, PCAP analysis)
├── parser.py               # Comprehensive protocol parsing engine (Layers 2 through 7)
├── utils.py                # Hexdump formatter, AlertEngine, PacketStats, ANSI color tokens
├── web_dashboard.py        # SOC Web Dashboard server & embedded single-page application
├── generate_sample_pcap.py # Generator script for reproducible synthetic test traffic
├── sample.pcap             # Synthetic offline demo capture (29 packets, 2 alerts, 6 protocols)
├── test_sniffer.py         # Automated unit test suite (14/14 tests)
├── raw_socket_example.py   # Standalone educational demo of raw socket sniffing in Python
├── TEST_PLAN.md            # Systematic testing guide with ping, curl, and nslookup steps
├── TEST_RESULTS.md         # End-to-end verification, platform status, and audit matrix
└── docs/                   # Documentation assets and screenshots
    └── README.md           # Instructions for adding screenshots
```

---

## ⚙️ Installation & Prerequisites

### 1. Python Environment
Ensure you have **Python 3.10 or higher** installed:
```bash
python --version
```

Clone the repository and install the dependencies:
```bash
git clone https://github.com/yourusername/sniffsense.git
cd sniffsense
pip install -r requirements.txt
```

### 2. Packet Capture Driver (Required for Live Sniffing Only)
- **Windows**:
  - Download and install **Npcap** from [https://npcap.com/#download](https://npcap.com/#download).
  - **Important:** During installation, check the box: *"Install Npcap in WinPcap API-compatible Mode"*.
- **Linux**:
  - Install `libpcap`:
    ```bash
    sudo apt-get install libpcap-dev   # Debian/Ubuntu
    sudo dnf install libpcap-devel     # Fedora/RHEL
    ```
- **macOS**:
  - Built-in `libpcap` is available by default.

> 💡 **No Driver Needed for Offline Mode:** You can explore, inspect, and run all features on existing `.pcap` files (including the bundled `sample.pcap`) without installing Npcap or having administrative privileges.

---

## 🚀 Usage Guide

### 1. Starting the SOC Web Dashboard

Start the web dashboard server:
```bash
python web_dashboard.py
```
Open your browser to:
👉 **[http://localhost:5000](http://localhost:5000)**

#### Dashboard Controls:
- **Reload sample.pcap**: Restores the 29-packet demonstration dataset with pre-configured attack signatures.
- **Upload .pcap**: Upload and forensic-analyze any capture file directly from your disk.
- **Start / Stop Capture**: Begin a live background capture on your selected network adapter (requires Admin/root).
- **Clear**: Flush the active memory buffer.
- **Theme Toggle**: Switch between Dark Mode (`#0D1117`) and Light Mode (`#F6F8FA`).
- **Keyboard Shortcuts**:
  - `/` : Focus search input
  - `↑` / `↓` : Move between packets in the table
  - `Escape` : Clear filter or unfocus search

---

### 2. Command-Line Interface (CLI)

The CLI tool `sniffer.py` provides complete terminal-based capture and forensic analysis.

#### List Network Interfaces
```bash
python sniffer.py --list
```

#### Analyze a PCAP File (No Admin Needed)
```bash
# Basic summary and packet listing
python sniffer.py -r sample.pcap

# Detailed layer-by-layer breakdown with full hexdumps
python sniffer.py -r sample.pcap -v

# Run with security alerts enabled
python sniffer.py -r sample.pcap --alerts
```

#### Live Packet Capture (Requires Admin / root)
```bash
# Capture 20 packets on interface Wi-Fi:
python sniffer.py -i "Wi-Fi" -c 20

# Capture only HTTP traffic using Berkeley Packet Filter (BPF):
python sniffer.py -i "Ethernet" -f "tcp port 80" -c 50

# Capture packets and write directly to an output PCAP file:
python sniffer.py -i "Wi-Fi" -c 100 -o live_capture.pcap
```

---

## 🧠 How It Works: Network Protocol Anatomy

When data moves across the internet, it follows the **OSI 7-Layer / TCP/IP model**. Sniffsense unpacks each layer in order:

```text
+-------------------------------------------------------------+
| Layer 2: Ethernet Frame (MAC addresses, EtherType)         |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| Layer 3: Network / IP (Source & Dest IP, TTL, Protocol ID)   |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| Layer 4: Transport (TCP / UDP Ports, Flags, Sequence #)      |
+-------------------------------------------------------------+
                              |
+-------------------------------------------------------------+
| Layer 7: Application (HTTP, DNS, Payloads, Raw Bytes)       |
+-------------------------------------------------------------+
```

### Supported Protocols:
1. **Ethernet (Layer 2)**: Resolves hardware MAC addresses and frame EtherType (`0x0800` for IPv4, `0x0806` for ARP, `0x86dd` for IPv6).
2. **ARP (Layer 2/3)**: Address Resolution Protocol mapping IP addresses to physical MAC addresses via `Who-has` requests and `Is-at` replies.
3. **IPv4 & IPv6 (Layer 3)**: Dissects IP addressing, Time-to-Live (TTL decrements to prevent infinite routing loops), and identification tags.
4. **ICMP & ICMPv6 (Control Layer)**: Diagnoses connectivity via Echo Request (Type 8) and Echo Reply (Type 0).
5. **TCP (Layer 4)**: Dissects sequence and acknowledgement numbers, flow control window sizes, checksums, and control flags.
6. **UDP (Layer 4)**: Fast, connectionless datagram transport decoding port numbers and length headers.
7. **DNS (Layer 7)**: Decodes transaction IDs, query names, query types (`A`, `AAAA`, `MX`, `NS`), and resolved answers.
8. **HTTP (Layer 7)**: Extracts methods (`GET`, `POST`), target paths, Host headers, status codes, and body content.

### The TCP Three-Way Handshake
To establish a reliable stream, TCP clients and servers execute a synchronized handshake:
1. **SYN**: Client sends `flags=[SYN]`, `seq=X` to request a connection.
2. **SYN-ACK**: Server acknowledges with `flags=[SYN, ACK]`, `seq=Y`, `ack=X+1`.
3. **ACK**: Client acknowledges with `flags=[ACK]`, `seq=X+1`, `ack=Y+1`.

Sniffsense decodes and flags every step in this lifecycle.

---

## 🚨 Security Alert Rules

Sniffsense implements two heuristic detection rules via `AlertEngine`:

### 1. Cleartext Credential Exposure
- **How it works**: Monitors unencrypted Layer 7 HTTP payloads for sensitive patterns:
  - Form/Query fields: `password=`, `passwd=`, `pwd=`, `username=`, `user=`, `token=`.
  - Headers: `Authorization: Basic <base64>`, which encodes username:password pairs without encryption.
- **Why it matters**: Demonstrates why HTTP must be replaced with HTTPS (TLS) on all modern networks.

### 2. TCP SYN Port Scan Detection
- **How it works**: Tracks `SYN`-only packets from source IPs across distinct destination ports in a rolling 10-second sliding window.
- **Trigger**: When a single source IP targets more than 5 distinct destination ports within that window, Sniffsense flags a potential port scan (e.g. Nmap reconnaissance).

> ⚠️ **Educational Note**: These heuristic detection rules are simplified rules intended for instructional demonstration and forensic walkthroughs. Production intrusion detection systems (IDS) like Snort or Zeek use deep stateful flow reassembly and anomaly engines.

---

## 🧪 Testing & Verification

Sniffsense includes a complete automated test suite as well as reproducible offline test data.

### Automated Unit Tests
Run the 14 automated unit tests covering all protocols and security rules:
```bash
pytest test_sniffer.py -v
```

### Manual Live Traffic Generation
To generate live traffic for testing:
```bash
# 1. ICMP traffic
ping google.com

# 2. DNS query
nslookup example.com

# 3. Plaintext HTTP (Unencrypted)
curl http://neverssl.com

# 4. Cleartext Credential Test
curl -d "username=admin&password=secretpassword" http://httpbin.org/post
```

See [TEST_PLAN.md](TEST_PLAN.md) and [TEST_RESULTS.md](TEST_RESULTS.md) for full test matrices and results.

---

## ⚠️ Limitations

1. **Encrypted HTTPS/TLS Payloads**: As designed by TLS, application payloads sent over port 443 are cryptographically encrypted. Sniffsense can view IP endpoints, TCP handshake flags, and packet timing, but cannot read plaintext HTTPS content without a TLS inspection proxy.
2. **Privilege Requirements**: Sniffing live traffic requires Administrator (Windows) or root (Linux/macOS) privileges to access raw sockets or Npcap packet drivers.
3. **Promiscuous Mode Scope**: A packet sniffer only intercepts packets routed to the local host's NIC, broadcast frames, or traffic explicitly mirrored (via SPAN / port mirroring) to that interface on a switched network.

---

## ⚖️ Legal & Ethical Notice

> [!IMPORTANT]
> **This software is created strictly for authorized educational research, academic study, and defensive network troubleshooting.**  
> Capturing network traffic without explicit, written authorization from the network owner may violate privacy laws, institutional policies, and computer fraud statutes (e.g., the U.S. Computer Fraud and Abuse Act or equivalent international legislation).  
> **Always ensure you have explicit permission before monitoring any network.**

---

## 🔮 Future Improvements

- [ ] TLS Server Name Indication (SNI) parsing to extract hostnames from encrypted HTTPS handshakes.
- [ ] Export filtered packets directly to `.csv` and `.json`.
- [ ] Real-time GeoIP lookup mapping source and destination IPs to countries.
- [ ] WebSocket-based live streaming from backend to dashboard.

---

## 📄 License

This project is open-source and licensed under the **[MIT License](LICENSE)**.
