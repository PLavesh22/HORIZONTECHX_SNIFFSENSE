"""
web_dashboard.py - Professional SOC Network Packet Analyzer Dashboard.

A high-performance web interface for Sniffsense designed in a professional SOC/monitoring
tool aesthetic (GitHub / Datadog dark & light theme, WCAG AA compliant).

Endpoints:
  GET  /                 -> Serves the single-page application dashboard (with no-cache headers)
  GET  /api/packets      -> Returns all parsed packets and alerts as JSON
  GET  /api/stats        -> Returns aggregated protocol and IP statistics
  GET  /api/interfaces   -> Returns available network adapters
  POST /api/load_sample  -> Reloads and parses sample.pcap
  POST /api/upload_pcap  -> Uploads and parses a custom .pcap file
  POST /api/clear        -> Clears the active packet buffer
  POST /api/start_capture-> Starts live packet capture thread
  POST /api/stop_capture -> Halts live packet capture thread
"""

from __future__ import annotations

import datetime
import io
import json
import os
import re
import socket
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

# Scapy imports
from scapy.all import conf, PcapReader, sniff
from scapy.packet import Packet

# Core parser logic (unmodified)
from parser import parse_packet
from utils import AlertEngine, format_hexdump, PacketStats

# Base directory resolution
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLE_PCAP_PATH = os.path.join(BASE_DIR, "sample.pcap")


# ============================================================================
# SELF-HEALING: VERIFY OR GENERATE SAMPLE.PCAP
# ============================================================================
def ensure_sample_pcap_exists() -> None:
    """Verifies that sample.pcap exists and is not empty; generates it if missing."""
    if not os.path.exists(SAMPLE_PCAP_PATH) or os.path.getsize(SAMPLE_PCAP_PATH) == 0:
        print("[*] sample.pcap missing or empty. Generating comprehensive sample capture...")
        try:
            from generate_sample_pcap import create_sample_pcap
            create_sample_pcap(SAMPLE_PCAP_PATH)
            print(f"[+] Successfully created sample capture at {SAMPLE_PCAP_PATH}")
        except Exception as e:
            print(f"[!] Failed to auto-generate sample.pcap: {e}")


# ============================================================================
# APPLICATION STATE & IN-MEMORY PACKET STORE
# ============================================================================
class DashboardState:
    """Thread-safe in-memory store for parsed packets, metrics, and capture jobs."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.packets: List[Dict[str, Any]] = []
        self.stats = PacketStats()
        self.alert_engine = AlertEngine()
        self.alerts: List[Dict[str, Any]] = []
        self.is_capturing: bool = False
        self.stop_event = threading.Event()
        self.capture_thread: Optional[threading.Thread] = None
        self.active_source: str = "None"
        self.last_error: Optional[str] = None

    def clear(self) -> None:
        """Reset all packet records, metrics, and alerts."""
        with self.lock:
            self.packets.clear()
            self.stats = PacketStats()
            self.alert_engine = AlertEngine()
            self.alerts.clear()
            self.active_source = "None"
            self.last_error = None

    def add_packet(self, raw_pkt: Packet) -> Dict[str, Any]:
        """
        Parse packet using parse_packet and sanitize it for JSON serialization.
        Converts bytes and set types to standard JSON-safe types.
        """
        info = parse_packet(raw_pkt)
        with self.lock:
            idx = len(self.packets) + 1
            info["index"] = idx

            # Full raw packet bytes (all layers: L2 Ethernet + L3 IP + L4 Transport + L7 Payload)
            raw_packet_bytes = bytes(raw_pkt)
            info["raw_hexdump"] = format_hexdump(raw_packet_bytes, max_bytes=None)
            info["raw_bytes_len"] = len(raw_packet_bytes)

            # Application payload (if present)
            payload = info.get("payload_bytes", b"")
            if payload and len(payload) > 0:
                info["payload_hexdump"] = format_hexdump(payload, max_bytes=None)
                info["payload_bytes_len"] = len(payload)
                info["has_payload"] = True
            else:
                info["payload_hexdump"] = "No payload (e.g. ARP)"
                info["payload_bytes_len"] = 0
                info["has_payload"] = False

            # Backward-compatible hexdump field (set to full raw packet dump)
            info["hexdump"] = info["raw_hexdump"]

            # Sanitize types: remove raw bytes and convert sets to lists for JSON safety
            info["payload_bytes"] = None
            if "tcp_flags" in info and isinstance(info["tcp_flags"], (set, tuple)):
                info["tcp_flags"] = sorted(list(info["tcp_flags"]))

            self.packets.append(info)
            self.stats.update(info)

            # Security inspection
            triggered = self.alert_engine.inspect(info)
            for alert_text in triggered:
                self.alerts.append({
                    "packet_index": idx,
                    "timestamp": info["timestamp_str"],
                    "src_ip": info.get("src_ip", "Unknown"),
                    "dst_ip": info.get("dst_ip", "Unknown"),
                    "message": alert_text,
                    "type": "port_scan" if "PORT SCAN" in alert_text else "credential",
                })

        return info


STATE = DashboardState()


def load_pcap_file(pcap_path: str) -> int:
    """
    Load and parse a PCAP file into the dashboard state.
    Returns packet count parsed or 0 on error.
    """
    if not os.path.exists(pcap_path):
        STATE.last_error = f"PCAP file not found: {pcap_path}"
        return 0

    STATE.clear()
    STATE.active_source = os.path.basename(pcap_path)
    count = 0
    try:
        reader = PcapReader(pcap_path)
        for pkt in reader:
            STATE.add_packet(pkt)
            count += 1
        reader.close()
        STATE.last_error = None
    except Exception as e:
        STATE.last_error = f"Failed to parse PCAP file: {e}"
        print(f"[!] Error loading {pcap_path}: {e}")
    return count


def live_capture_worker(interface: Optional[str], bpf_filter: str, count: int) -> None:
    """Background worker for live packet sniffing."""
    STATE.is_capturing = True
    STATE.last_error = None
    try:
        sniff(
            iface=interface if interface else None,
            filter=bpf_filter if bpf_filter else None,
            count=count if count > 0 else 0,
            prn=STATE.add_packet,
            stop_filter=lambda x: STATE.stop_event.is_set(),
            store=False,
        )
    except Exception as e:
        STATE.last_error = f"Capture error: {e}"
        print(f"[!] Live capture error: {e}")
    finally:
        STATE.is_capturing = False
        STATE.stop_event.clear()


# ============================================================================
# SELF-CONTAINED PROFESSIONAL SOC HTML / JAVASCRIPT FRONTEND
# ============================================================================
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title>Sniffsense - Network Traffic Monitor</title>

  <!-- Google Font: Inter -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>

  <!-- Optional Chart.js (with automatic fallback if offline/blocked) -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <style>
    /* =====================================================================
       CSS VARIABLES THEME SYSTEM (Dark default, Flat SOC aesthetic, WCAG AA)
       ===================================================================== */
    :root {
      --bg: #0D1117;
      --surface: #161B22;
      --elevated: #1F2630;
      --border: #30363D;
      --text: #E6EDF3;
      --muted: #9DA7B3;          /* WCAG AA: 5.6:1 on #161B22, 6.7:1 on #0D1117 */
      --subtext: #BAC4CE;        /* High-contrast secondary text (7.9:1) */
      --accent: #2F81F7;
      --success: #3FB950;
      --warning: #D29922;
      --danger: #F85149;
    }

    /* Light Theme Variation (WCAG AA Compliant) */
    :root.light-theme, body.light-theme {
      --bg: #F6F8FA;
      --surface: #FFFFFF;
      --elevated: #F3F4F6;
      --border: #D0D7DE;
      --text: #1F2328;
      --muted: #57606A;          /* WCAG AA: 5.8:1 on #FFFFFF */
      --subtext: #424A53;        /* High-contrast secondary text */
      --accent: #0969DA;
      --success: #1A7F37;
      --warning: #9A6700;
      --danger: #CF222E;
    }

    html, body {
      height: 100%;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }

    /* Flat SOC Card */
    .soc-card {
      background-color: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      transition: border-color 0.15s ease, background-color 0.15s ease;
    }
    .soc-card:hover {
      border-color: var(--muted);
    }

    /* High-Visibility Table Rows: Selection & Security Alerts */
    .row-selected {
      background-color: rgba(47, 129, 247, 0.18) !important;
      border-left: 4px solid var(--accent) !important;
    }
    :root.light-theme .row-selected, body.light-theme .row-selected {
      background-color: rgba(9, 105, 218, 0.14) !important;
      border-left: 4px solid var(--accent) !important;
    }

    .row-alert {
      background-color: rgba(248, 81, 73, 0.08) !important;
      border-left: 4px solid var(--danger) !important;
    }
    :root.light-theme .row-alert, body.light-theme .row-alert {
      background-color: rgba(207, 34, 46, 0.08) !important;
      border-left: 4px solid var(--danger) !important;
    }

    .row-alert-selected {
      background-color: rgba(248, 81, 73, 0.22) !important;
      border-left: 4px solid var(--danger) !important;
      box-shadow: inset 0 0 0 1px rgba(248, 81, 73, 0.35);
    }
    :root.light-theme .row-alert-selected, body.light-theme .row-alert-selected {
      background-color: rgba(207, 34, 46, 0.18) !important;
      border-left: 4px solid var(--danger) !important;
    }

    /* Buttons */
    .soc-btn-outline {
      background-color: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 500;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .soc-btn-outline:hover {
      background-color: var(--elevated);
      border-color: var(--muted);
    }

    .soc-btn-primary {
      background-color: var(--accent);
      border: 1px solid var(--accent);
      color: #FFFFFF;
      border-radius: 6px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      cursor: pointer;
      transition: filter 0.15s ease;
    }
    .soc-btn-primary:hover {
      filter: brightness(1.1);
    }

    /* Soft, low-saturation protocol badges matching donut chart colors */
    .badge-TCP {
      background-color: rgba(56, 139, 253, 0.15);
      color: #58A6FF;
      border: 1px solid rgba(56, 139, 253, 0.35);
    }
    .badge-UDP {
      background-color: rgba(163, 113, 247, 0.15);
      color: #BC8CFF;
      border: 1px solid rgba(163, 113, 247, 0.35);
    }
    .badge-DNS {
      background-color: rgba(63, 185, 80, 0.15);
      color: #56D364;
      border: 1px solid rgba(63, 185, 80, 0.35);
    }
    .badge-HTTP {
      background-color: rgba(210, 153, 34, 0.15);
      color: #E3B341;
      border: 1px solid rgba(210, 153, 34, 0.35);
    }
    .badge-ICMP {
      background-color: rgba(227, 179, 65, 0.15);
      color: #F2CC60;
      border: 1px solid rgba(227, 179, 65, 0.35);
    }
    .badge-ICMPv6 {
      background-color: rgba(6, 182, 212, 0.15);
      color: #22D3EE;
      border: 1px solid rgba(6, 182, 212, 0.35);
    }
    .badge-ARP {
      background-color: rgba(247, 120, 186, 0.15);
      color: #F778BA;
      border: 1px solid rgba(247, 120, 186, 0.35);
    }
    .badge-IPv4, .badge-IPv6, .badge-ETH {
      background-color: rgba(139, 148, 158, 0.15);
      color: #8B949E;
      border: 1px solid rgba(139, 148, 158, 0.35);
    }

    /* Light Theme Protocol Badges */
    :root.light-theme .badge-TCP, body.light-theme .badge-TCP { background-color: rgba(9, 105, 218, 0.1); color: #0969DA; border-color: rgba(9, 105, 218, 0.3); }
    :root.light-theme .badge-UDP, body.light-theme .badge-UDP { background-color: rgba(130, 80, 223, 0.1); color: #8250DF; border-color: rgba(130, 80, 223, 0.3); }
    :root.light-theme .badge-DNS, body.light-theme .badge-DNS { background-color: rgba(26, 127, 55, 0.1); color: #1A7F37; border-color: rgba(26, 127, 55, 0.3); }
    :root.light-theme .badge-HTTP, body.light-theme .badge-HTTP { background-color: rgba(154, 103, 0, 0.1); color: #9A6700; border-color: rgba(154, 103, 0, 0.3); }
    :root.light-theme .badge-ICMP, body.light-theme .badge-ICMP { background-color: rgba(154, 103, 0, 0.1); color: #9A6700; border-color: rgba(154, 103, 0, 0.3); }
    :root.light-theme .badge-ICMPv6, body.light-theme .badge-ICMPv6 { background-color: rgba(8, 145, 178, 0.12); color: #0891B2; border-color: rgba(8, 145, 178, 0.35); }
    :root.light-theme .badge-ARP, body.light-theme .badge-ARP { background-color: rgba(191, 57, 137, 0.1); color: #BF3989; border-color: rgba(191, 57, 137, 0.3); }

    /* Custom Scrollbar */
    .custom-scroll::-webkit-scrollbar { width: 6px; height: 6px; }
    .custom-scroll::-webkit-scrollbar-track { background: var(--bg); }
    .custom-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
    .custom-scroll::-webkit-scrollbar-thumb:hover { background: var(--muted); }

    /* Collapsible Accordion Arrow */
    details summary::-webkit-details-marker { display: none; }
    details[open] summary .arrow-icon { transform: rotate(90deg); }
  </style>
</head>
<body class="h-screen flex flex-col overflow-hidden select-none m-0 p-0">

  <!-- =====================================================================
       1. TOP NAVIGATION BAR (Header & Actions - Fully Visible, Never Clipped)
       ===================================================================== -->
  <header class="bg-[var(--surface)] border-b border-[var(--border)] px-6 py-3 flex items-center justify-between shrink-0 sticky top-0 z-30 min-h-[58px] shadow-sm">
    <div class="flex items-center space-x-3.5">
      <!-- Radar Wave Icon (Flat, No Neon) -->
      <div class="w-8 h-8 rounded-md bg-[var(--elevated)] border border-[var(--border)] flex items-center justify-center text-[var(--accent)]">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4.93 19.07a10 10 0 010-14.14m14.14 0a10 10 0 010 14.14m-10.6-3.54a5 5 0 010-7.07m7.07 0a5 5 0 010 7.07M12 12h.01"/></svg>
      </div>
      <div>
        <div class="flex items-center space-x-2">
          <h1 class="text-sm font-bold text-[var(--text)] tracking-tight">Sniffsense</h1>
          <span class="text-[10px] px-1.5 py-0.5 rounded font-mono font-medium bg-[var(--elevated)] text-[var(--muted)] border border-[var(--border)]">SOC v1.2</span>
          <span id="activeSourceTag" class="text-[11px] px-2 py-0.5 rounded font-mono text-[var(--text)] bg-[var(--elevated)] border border-[var(--border)]">sample.pcap</span>
        </div>
        <p class="text-[11px] text-[var(--muted)]">Network Protocol & Threat Telemetry</p>
      </div>
    </div>

    <!-- Right Controls -->
    <div class="flex items-center space-x-2.5">
      <!-- Live Capture Interface Dropdown -->
      <div class="flex items-center space-x-1.5 bg-[var(--surface)] border border-[var(--border)] rounded-md px-2 py-1">
        <svg class="w-3.5 h-3.5 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
        <select id="interfaceSelect" class="bg-transparent text-xs text-[var(--text)] focus:outline-none max-w-[130px] truncate cursor-pointer">
          <option value="">Default Interface</option>
        </select>
        <button id="toggleCaptureBtn" onclick="toggleLiveCapture()" class="soc-btn-primary !py-0.5 !px-2 !text-[11px]">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          <span id="captureBtnText">Capture</span>
        </button>
      </div>

      <!-- Reload Sample Button -->
      <button onclick="loadSamplePcap()" title="Reload sample.pcap file" class="soc-btn-outline">
        <svg class="w-3.5 h-3.5 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
        <span>Reload sample.pcap</span>
      </button>

      <!-- Upload PCAP Button -->
      <label class="soc-btn-outline">
        <svg class="w-3.5 h-3.5 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
        <span>Upload .pcap</span>
        <input type="file" id="pcapFileInput" accept=".pcap,.pcapng" class="hidden" onchange="uploadPcapFile(this)">
      </label>

      <!-- Clear Button -->
      <button onclick="clearPackets()" title="Clear active buffer" class="soc-btn-outline hover:!text-[var(--danger)] hover:!border-[var(--danger)]">
        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
        <span>Clear</span>
      </button>

      <!-- Light / Dark Theme Toggle Button -->
      <button onclick="toggleTheme()" title="Toggle Light / Dark mode" class="soc-btn-outline !px-2">
        <svg id="themeToggleIcon" class="w-3.5 h-3.5 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
      </button>
    </div>
  </header>

  <!-- Loading State Indicator Overlay -->
  <div id="loadingOverlay" class="hidden bg-[var(--surface)] border-b border-[var(--border)] px-6 py-2 flex items-center space-x-2 text-xs text-[var(--accent)] shrink-0">
    <svg class="w-3.5 h-3.5 animate-spin" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 2v4m0 12v4m10-10h-4M6 12H2m15.07-7.07l-2.83 2.83M7.76 16.24l-2.83 2.83m14.14 0l-2.83-2.83M7.76 7.76L4.93 4.93"/></svg>
    <span>Processing network packet stream...</span>
  </div>

  <!-- Global Error Notification Banner -->
  <div id="errorBanner" class="hidden bg-rose-950/60 border-b border-[var(--danger)] px-6 py-2.5 text-xs text-rose-200 flex items-center justify-between shrink-0">
    <div class="flex items-center space-x-2">
      <svg class="w-4 h-4 text-[var(--danger)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      <span id="errorMessageText">Parsing error</span>
    </div>
    <button onclick="dismissError()" class="text-rose-400 hover:text-white font-bold px-2 py-0.5">&times;</button>
  </div>

  <!-- =====================================================================
       2. METRICS & KPI CARDS (8px grid spacing, muted labels, white numbers)
       ===================================================================== -->
  <section class="bg-[var(--bg)] px-6 py-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 shrink-0">
    <!-- Card 1: Total Packets -->
    <div class="soc-card p-3.5 flex items-center justify-between">
      <div>
        <p class="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">Total Packets</p>
        <p id="statTotalPackets" class="text-2xl font-bold text-[var(--text)] mt-1">0</p>
      </div>
      <div class="w-9 h-9 rounded-md bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--border)] flex items-center justify-center">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      </div>
    </div>

    <!-- Card 2: Data Volume -->
    <div class="soc-card p-3.5 flex items-center justify-between">
      <div>
        <p class="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">Data Volume</p>
        <p id="statTotalBytes" class="text-2xl font-bold text-[var(--text)] mt-1">0 B</p>
      </div>
      <div class="w-9 h-9 rounded-md bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--border)] flex items-center justify-center">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/></svg>
      </div>
    </div>

    <!-- Card 3: Protocols Decoded (Consistent with Donut Chart) -->
    <div class="soc-card p-3.5 flex items-center justify-between" title="Distinct top-level protocols (L4-L7) decoded from network traffic, matching the donut chart breakdown.">
      <div>
        <p class="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold flex items-center space-x-1">
          <span>Protocols Decoded</span>
          <span class="cursor-help text-[10px] px-1 rounded bg-[var(--elevated)] border border-[var(--border)] text-[var(--muted)]" title="Count of unique top-level protocols (e.g. HTTP, TCP, DNS, ICMP, ARP)">Top</span>
        </p>
        <p id="statProtocolsCount" class="text-2xl font-bold text-[var(--text)] mt-1">0</p>
      </div>
      <div class="w-9 h-9 rounded-md bg-[var(--accent)]/10 text-[var(--accent)] border border-[var(--border)] flex items-center justify-center">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
      </div>
    </div>

    <!-- Card 4: Security Alerts (Neutral when 0, Red only when > 0) -->
    <div class="soc-card p-3.5 flex items-center justify-between">
      <div>
        <p class="text-[11px] uppercase tracking-wider text-[var(--muted)] font-semibold">Security Alerts</p>
        <p id="statAlertsCount" class="text-2xl font-bold text-[var(--text)] mt-1">0</p>
      </div>
      <div id="statAlertsIconBox" class="w-9 h-9 rounded-md bg-[var(--border)]/40 text-[var(--muted)] border border-[var(--border)] flex items-center justify-center">
        <svg id="statAlertsIcon" class="w-4 h-4" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
      </div>
    </div>
  </section>

  <!-- =====================================================================
       3. SECURITY ALERTS BANNER (16px Padding, Collapsible & Dismissible)
       ===================================================================== -->
  <div id="alertsBannerContainer" class="hidden bg-rose-950/30 border-y border-[var(--danger)]/50 px-4 py-2 shrink-0 transition-all">
    <div class="flex items-center justify-between">
      <div class="flex items-center space-x-2.5 text-xs">
        <div class="flex items-center space-x-1.5 font-bold text-[var(--danger)]">
          <svg class="w-4 h-4 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span>ANOMALY WARNINGS DETECTED:</span>
        </div>
        <span id="alertsSummaryText" class="text-[var(--text)] font-semibold">0 alert(s)</span>
      </div>
      <div class="flex items-center space-x-2">
        <button onclick="toggleAlertsList()" id="toggleAlertsListBtn" class="text-[11px] text-[var(--muted)] hover:text-[var(--text)] px-2 py-0.5 rounded border border-[var(--border)] bg-[var(--surface)] font-medium">Collapse</button>
        <button onclick="dismissAlertsBanner()" title="Dismiss warning banner" class="text-rose-400 hover:text-white font-bold px-1.5 py-0.5 rounded text-sm transition">&times;</button>
      </div>
    </div>
    <!-- Quick filter pills -->
    <div id="alertsQuickPills" class="flex flex-wrap gap-2 mt-2"></div>
  </div>

  <!-- =====================================================================
       4. VISUALIZATION ROW: Collapsed by default, Ultra-compact h-20
       ===================================================================== -->
  <div class="px-4 py-1.5 bg-[var(--bg)] flex items-center justify-between text-xs text-[var(--muted)] shrink-0 border-b border-[var(--border)]/40">
    <div class="flex items-center space-x-2">
      <span class="font-semibold uppercase tracking-wider text-[10px] text-[var(--muted)] font-mono">Telemetry Charts</span>
    </div>
    <button onclick="toggleChartsCollapse()" class="soc-btn-outline !py-0.5 !px-2 !text-[11px] flex items-center space-x-1" id="chartsCollapseBtn" title="Toggle telemetry charts display">
      <svg id="chartsCollapseIcon" class="w-3.5 h-3.5 transition-transform" style="transform: rotate(180deg);" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="18 15 12 9 6 15"/></svg>
      <span id="chartsCollapseText">Show Charts</span>
    </button>
  </div>

  <section id="chartsSection" class="hidden bg-[var(--bg)] px-4 pb-2.5 pt-2 grid grid-cols-1 md:grid-cols-3 gap-3 shrink-0 transition-all">
    <!-- Chart 1: Donut Distribution (Top-level protocols only with center total) -->
    <div class="soc-card p-3 flex flex-col">
      <div class="flex items-center justify-between mb-1">
        <h2 class="text-xs font-bold text-[var(--text)] uppercase tracking-wider flex items-center space-x-1.5">
          <svg class="w-3.5 h-3.5 text-[var(--accent)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21.21 15.89A10 10 0 118 2.83"/><path d="M22 12A10 10 0 0012 2v10z"/></svg>
          <span>Protocol Distribution</span>
        </h2>
        <span class="text-[10px] text-[var(--muted)] font-mono">Top-Level Protocols</span>
      </div>
      <div id="donutContainer" class="relative h-20 flex items-center justify-center">
        <canvas id="protocolDonutChart"></canvas>
      </div>
    </div>

    <!-- Chart 2: Traffic Timeline (Bucket Bars + Packets/Bytes Toggle) -->
    <div class="soc-card p-3 flex flex-col md:col-span-2">
      <div class="flex items-center justify-between mb-1">
        <div class="flex items-center space-x-2">
          <h2 class="text-xs font-bold text-[var(--text)] uppercase tracking-wider flex items-center space-x-1.5">
            <svg class="w-3.5 h-3.5 text-[var(--accent)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>
            <span>Traffic Timeline</span>
          </h2>
          <span id="timelineBucketLabel" class="text-[10px] text-[var(--muted)] font-mono">1s buckets</span>
        </div>

        <!-- Metric Toggle: Packets vs Bytes -->
        <div class="flex items-center space-x-1 bg-[var(--surface)] p-0.5 rounded border border-[var(--border)]">
          <button id="timelineMetricPackets" onclick="setTimelineMetric('packets')" class="px-2 py-0.5 text-[10px] rounded font-semibold transition bg-[var(--accent)] text-white shadow-sm">Packets</button>
          <button id="timelineMetricBytes" onclick="setTimelineMetric('bytes')" class="px-2 py-0.5 text-[10px] rounded font-medium transition text-[var(--muted)] hover:text-[var(--text)]">Bytes</button>
        </div>
      </div>
      <div id="timelineContainer" class="relative h-20">
        <canvas id="timelineChart"></canvas>
      </div>
    </div>
  </section>

  <!-- =====================================================================
       5. FILTER & SEARCH TOOLBAR (Default: ALL, Inter font, WCAG contrast)
       ===================================================================== -->
  <div class="bg-[var(--surface)] border-y border-[var(--border)] px-6 py-2.5 flex items-center justify-between shrink-0 shadow-sm z-10">
    <!-- Search Bar -->
    <div class="flex items-center space-x-2 flex-1 max-w-xl">
      <div class="relative w-full">
        <svg class="w-4 h-4 absolute left-3 top-2.5 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input type="text" id="searchInput" oninput="renderTable()" placeholder="Search by IP, port, protocol, keyword (e.g. 192.168.1.1, TCP, GET, SYN)..." class="w-full bg-[var(--elevated)] border border-[var(--border)] rounded-md pl-9 pr-3 py-1.5 text-xs text-[var(--text)] placeholder-[var(--muted)] focus:outline-none focus:border-[var(--accent)] mono">
      </div>
      <button onclick="clearSearch()" class="soc-btn-outline !py-1 !px-2 !text-[11px]">Reset</button>
    </div>

    <!-- Protocol Filter Chips (Default: ALL) -->
    <div class="flex items-center space-x-1.5 ml-4" id="protocolFilterContainer">
      <button onclick="setFilter('ALL')" class="proto-btn px-3 py-1 text-xs rounded-md font-semibold bg-[var(--accent)] text-white shadow-sm" data-proto="ALL">All</button>
      <button onclick="setFilter('TCP')" class="proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]" data-proto="TCP">TCP</button>
      <button onclick="setFilter('UDP')" class="proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]" data-proto="UDP">UDP</button>
      <button onclick="setFilter('DNS')" class="proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]" data-proto="DNS">DNS</button>
      <button onclick="setFilter('HTTP')" class="proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]" data-proto="HTTP">HTTP</button>
      <button onclick="setFilter('ICMP')" class="proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]" data-proto="ICMP">ICMP</button>
      <button onclick="setFilter('ARP')" class="proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]" data-proto="ARP">ARP</button>
    </div>
  </div>

  <!-- =====================================================================
       6. MAIN SPLIT WORKSPACE: Table on Left, Inspector on Right
       ===================================================================== -->
  <main class="flex-1 flex overflow-hidden">
    <!-- Packet Stream Table -->
    <div class="flex-1 flex flex-col border-r border-[var(--border)] overflow-hidden bg-[var(--bg)]">
      <div class="flex-1 overflow-y-auto custom-scroll" id="tableScrollContainer" tabindex="0" onkeydown="handleTableKeyNav(event)">
        <table class="w-full text-left text-xs border-collapse">
          <thead class="bg-[var(--surface)] text-[var(--muted)] sticky top-0 border-b border-[var(--border)] select-none shadow-sm z-10 font-semibold">
            <tr>
              <th class="py-2.5 px-4 w-16 text-center">#</th>
              <th class="py-2.5 px-4 w-28">Timestamp</th>
              <th class="py-2.5 px-4 w-24">Protocol</th>
              <th class="py-2.5 px-4 w-72">Source -> Destination</th>
              <th class="py-2.5 px-4 w-20">Length</th>
              <th class="py-2.5 px-4">Summary & Info</th>
            </tr>
          </thead>
          <tbody id="packetTableBody" class="divide-y divide-[var(--border)]">
            <!-- Populated dynamically -->
          </tbody>
        </table>
      </div>

      <!-- Table Status Footer (16px padding + Keyboard shortcuts) -->
      <footer class="bg-[var(--surface)] border-t border-[var(--border)] px-4 py-2 flex items-center justify-between text-xs text-[var(--muted)] shrink-0 select-none">
        <div class="flex items-center space-x-3">
          <span>Showing <strong id="visibleCount" class="text-[var(--text)]">0</strong> of <strong id="totalCount" class="text-[var(--text)]">0</strong> packets</span>
          <span class="text-[var(--border)]">|</span>
          <span class="flex items-center space-x-1">
            <kbd class="px-1.5 py-0.5 rounded bg-[var(--elevated)] text-[var(--text)] border border-[var(--border)] font-mono text-[10px]">&#8593;</kbd>
            <kbd class="px-1.5 py-0.5 rounded bg-[var(--elevated)] text-[var(--text)] border border-[var(--border)] font-mono text-[10px]">&#8595;</kbd>
            <span>Navigate</span>
          </span>
          <span class="text-[var(--border)]">|</span>
          <span class="flex items-center space-x-1">
            <kbd class="px-1.5 py-0.5 rounded bg-[var(--elevated)] text-[var(--text)] border border-[var(--border)] font-mono text-[10px]">/</kbd>
            <span>Search</span>
          </span>
          <span class="text-[var(--border)]">|</span>
          <span class="flex items-center space-x-1">
            <kbd class="px-1.5 py-0.5 rounded bg-[var(--elevated)] text-[var(--text)] border border-[var(--border)] font-mono text-[10px]">Esc</kbd>
            <span>Reset</span>
          </span>
        </div>
        <div class="flex items-center space-x-2">
          <span class="w-2 h-2 rounded-full bg-[var(--success)]"></span>
          <span>Host: <span class="text-[var(--text)] font-mono">http://localhost:5000</span></span>
        </div>
      </footer>
    </div>

    <!-- Packet Inspector Panel (Collapsible sections & field explanations) -->
    <aside id="inspectorPane" class="w-[480px] lg:w-[540px] bg-[var(--surface)] flex flex-col overflow-hidden shrink-0 border-l border-[var(--border)] shadow-md">
      <!-- Inspector Header with "Copy packet as hex" button -->
      <div class="p-3 bg-[var(--elevated)] border-b border-[var(--border)] flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <svg class="w-4 h-4 text-[var(--accent)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          <h2 class="text-xs font-bold text-[var(--text)] uppercase tracking-wider">Packet Inspector</h2>
        </div>
        <div class="flex items-center space-x-2">
          <button id="copyHexBtn" onclick="copySelectedPacketHex()" class="soc-btn-outline !py-0.5 !px-2 !text-[11px] flex items-center space-x-1 text-[var(--accent)] hover:text-white" title="Copy raw packet bytes as hex to clipboard">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
            <span id="copyHexText">Copy Hex</span>
          </button>
          <span id="selectedPacketBadge" class="text-xs px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text)] font-mono border border-[var(--border)] font-semibold">No packet selected</span>
        </div>
      </div>

      <!-- Inspector Scrollable Accordions -->
      <div id="inspectorContent" class="flex-1 overflow-y-auto p-4 custom-scroll space-y-3 text-xs">
        <div class="text-center text-[var(--muted)] py-20">
          <svg class="w-8 h-8 mx-auto text-[var(--muted)] mb-2 opacity-50" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122"/></svg>
          <p class="font-medium text-[var(--text)]">Select a packet from the table</p>
          <p class="text-[11px] text-[var(--muted)] mt-1">Detailed protocol layers and raw payload will appear here.</p>
        </div>
      </div>
    </aside>
  </main>

  <!-- =====================================================================
       7. JAVASCRIPT CONTROLLERS & DATA LOGIC (Fail-Safe, Zero Stale Cache)
       ===================================================================== -->
  <script>
    let allPackets = [];
    let allAlerts = [];
    let selectedPacketIndex = null;
    let currentFilter = 'ALL';
    let isCapturing = false;

    let donutChartInstance = null;
    let timelineChartInstance = null;

    // Protocol Colors matching badges and donut slices distinctly (ICMPv6 cyan != ARP pink)
    const PROTO_COLORS = {
      'TCP': '#388BFD',
      'UDP': '#8957E5',
      'DNS': '#3FB950',
      'HTTP': '#D29922',
      'ICMP': '#E3B341',
      'ICMPv6': '#06B6D4',
      'ARP': '#F778BA',
      'IPv4': '#54AEFF',
      'IPv6': '#A371F7',
      'Ethernet': '#8B949E',
      'Other': '#8B949E'
    };

    // Extract ONLY the top-level protocol from a packet (L7 -> L4 -> L3/L2)
    function getTopLevelProtocol(pkt) {
      if (!pkt || !pkt.protocols) return 'Other';
      const protos = pkt.protocols;
      if (protos.includes('HTTP')) return 'HTTP';
      if (protos.includes('DNS')) return 'DNS';
      if (protos.includes('ICMPv6')) return 'ICMPv6';
      if (protos.includes('ICMP')) return 'ICMP';
      if (protos.includes('TCP')) return 'TCP';
      if (protos.includes('UDP')) return 'UDP';
      if (protos.includes('ARP')) return 'ARP';
      if (protos.includes('IPv6')) return 'IPv6';
      if (protos.includes('IPv4')) return 'IPv4';
      return 'Ethernet';
    }

    // Timeline metric state ('packets' or 'bytes')
    let timelineMetric = 'packets';

    function setTimelineMetric(metric) {
      timelineMetric = metric;
      const pktBtn = document.getElementById('timelineMetricPackets');
      const bytesBtn = document.getElementById('timelineMetricBytes');
      if (metric === 'bytes') {
        if (bytesBtn) bytesBtn.className = 'px-2 py-0.5 text-[10px] rounded font-semibold transition bg-[var(--accent)] text-white shadow-sm';
        if (pktBtn) pktBtn.className = 'px-2 py-0.5 text-[10px] rounded font-medium transition text-[var(--muted)] hover:text-[var(--text)]';
      } else {
        if (pktBtn) pktBtn.className = 'px-2 py-0.5 text-[10px] rounded font-semibold transition bg-[var(--accent)] text-white shadow-sm';
        if (bytesBtn) bytesBtn.className = 'px-2 py-0.5 text-[10px] rounded font-medium transition text-[var(--muted)] hover:text-[var(--text)]';
      }
      updateCharts();
    }

    // Collapsible Charts Section with localStorage memory
    function toggleChartsCollapse() {
      const section = document.getElementById('chartsSection');
      if (!section) return;
      const isHidden = section.classList.toggle('hidden');
      localStorage.setItem('sniffsense_charts_collapsed', isHidden ? 'true' : 'false');
      updateChartsCollapseUI(isHidden);
    }

    function updateChartsCollapseUI(isHidden) {
      const icon = document.getElementById('chartsCollapseIcon');
      const text = document.getElementById('chartsCollapseText');
      if (icon) icon.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
      if (text) text.innerText = isHidden ? 'Show Charts' : 'Hide Charts';
      if (!isHidden) {
        if (donutChartInstance) donutChartInstance.resize();
        if (timelineChartInstance) timelineChartInstance.resize();
      }
    }

    // Plain-English Field Tooltips
    const FIELD_GLOSSARY = {
      'Source MAC': 'Physical hardware address (NIC) of sending device.',
      'Destination MAC': 'Hardware address of next hop receiver or router.',
      'EtherType': 'Layer 3 protocol encapsulated within this Ethernet frame.',
      'Source IP': 'Originating logical host IP address.',
      'Destination IP': 'Target destination host IP address.',
      'Time to Live (TTL)': 'Router hop count limit; decrements at each hop to prevent routing loops.',
      'Hop Limit': 'IPv6 equivalent of TTL; prevents infinite routing loops.',
      'Header Length': 'Size of IPv4 header in bytes (standard: 20 bytes).',
      'Total Length': 'Entire size of IP packet including header and data.',
      'Protocol Number': 'Transport protocol encapsulated (6=TCP, 17=UDP, 1=ICMP).',
      'Source Port': 'Port number on originating client machine.',
      'Destination Port': 'Target service port (e.g. 80=HTTP, 53=DNS).',
      'Sequence Number': 'Byte stream offset ensuring packets are assembled in exact order.',
      'Acknowledgment': 'Confirms byte sequence successfully received by listener.',
      'Flags': 'Control bits (SYN=Open, ACK=Confirm, FIN=Close, RST=Abort, PSH=Push).',
      'Window Size': 'Advertised buffer space available for flow control.',
      'Checksum': 'Redundancy check value used to verify header integrity.',
      'Type & Meaning': 'Diagnostic message category (e.g. Type 8 Echo Request for Ping).',
      'Transaction ID': 'Identifier matching asynchronous query with nameserver answer.',
      'Query Domain': 'Fully Qualified Domain Name (FQDN) being looked up.',
      'Answer IP/Data': 'Resolved routable IP address returned by nameserver.',
      'Method': 'HTTP action requested (GET=Retrieve page, POST=Submit form/credentials).',
      'Host': 'Target virtual domain header in HTTP request.'
    };

    // --- LIGHT / DARK THEME TOGGLE ---
    function initTheme() {
      const saved = localStorage.getItem('sniffsense_theme');
      if (saved === 'light') {
        document.body.classList.add('light-theme');
        document.documentElement.classList.add('light-theme');
        updateThemeIcon(true);
      } else {
        updateThemeIcon(false);
      }
    }

    function toggleTheme() {
      const isLight = document.body.classList.toggle('light-theme');
      document.documentElement.classList.toggle('light-theme', isLight);
      localStorage.setItem('sniffsense_theme', isLight ? 'light' : 'dark');
      updateThemeIcon(isLight);
      fetchStatsAndRenderCharts();
    }

    function updateThemeIcon(isLight) {
      const icon = document.getElementById('themeToggleIcon');
      if (icon) {
        if (isLight) {
          // Moon icon
          icon.innerHTML = '<path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>';
        } else {
          // Sun icon
          icon.innerHTML = '<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>';
        }
      }
    }

    // --- DATA LOADING & FETCHING (Fail-Safe against network/Chart issues) ---
    async function fetchData() {
      showLoading(true);
      try {
        // Cache buster guarantees fresh data from server
        const cacheBuster = '?t=' + Date.now();
        console.log('[Sniffsense] Fetching packets from /api/packets...');

        const pktsRes = await fetch('/api/packets' + cacheBuster);
        if (!pktsRes.ok) {
          throw new Error('Server returned HTTP ' + pktsRes.status + ' for /api/packets');
        }

        const pktsData = await pktsRes.json();
        console.log('[Sniffsense] Received packet telemetry:', pktsData);

        if (pktsData.last_error) {
          showError(pktsData.last_error);
        } else {
          dismissError();
        }

        allPackets = pktsData.packets || [];
        allAlerts = pktsData.alerts || [];
        isCapturing = pktsData.is_capturing || false;

        document.getElementById('activeSourceTag').innerText = pktsData.active_source || 'None';
        updateCaptureButton(isCapturing);

        // Update Stat Cards immediately
        document.getElementById('statTotalPackets').innerText = allPackets.length.toLocaleString();
        document.getElementById('totalCount').innerText = allPackets.length;
        updateAlertsCard(allAlerts.length);
        renderAlertsBanner();

        // 1. RENDER TABLE IMMEDIATELY!
        renderTable();

        // 2. Auto-select first packet if none selected
        if (selectedPacketIndex === null && allPackets.length > 0) {
          selectPacket(allPackets[0].index);
        }

        // 3. Fetch auxiliary statistics independently so nothing can block table
        fetchStatsAndRenderCharts();

        // 4. Fetch interfaces in background
        fetchInterfaces();
      } catch (err) {
        console.error('[Sniffsense Error] Fatal fetch failure:', err);
        showError('Failed to fetch packet telemetry: ' + err.message);
      } finally {
        showLoading(false);
      }
    }

    async function fetchStatsAndRenderCharts() {
      try {
        const res = await fetch('/api/stats?t=' + Date.now());
        if (!res.ok) return;
        const statsData = await res.json();
        document.getElementById('statTotalBytes').innerText = formatBytes(statsData.total_bytes);
        document.getElementById('statProtocolsCount').innerText = Object.keys(statsData.protocol_counts || {}).length;
        updateCharts(statsData.protocol_counts);
      } catch (e) {
        console.warn('[Sniffsense] Non-fatal stats fetch warning:', e);
      }
    }

    async function fetchInterfaces() {
      try {
        const res = await fetch('/api/interfaces?t=' + Date.now());
        if (res.ok) {
          const ifaces = await res.json();
          populateInterfaces(ifaces);
        }
      } catch (e) {}
    }

    function updateAlertsCard(count) {
      const countEl = document.getElementById('statAlertsCount');
      const iconBox = document.getElementById('statAlertsIconBox');
      const iconEl = document.getElementById('statAlertsIcon');

      countEl.innerText = count;

      if (count === 0) {
        iconBox.className = 'w-9 h-9 rounded-md bg-[var(--border)]/40 text-[var(--muted)] border border-[var(--border)] flex items-center justify-center';
        iconEl.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>';
      } else {
        iconBox.className = 'w-9 h-9 rounded-md bg-rose-950/40 text-[var(--danger)] border border-[var(--danger)] flex items-center justify-center';
        iconEl.innerHTML = '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
      }
    }

    function renderAlertsBanner() {
      const container = document.getElementById('alertsBannerContainer');
      const textEl = document.getElementById('alertsSummaryText');
      const pillsEl = document.getElementById('alertsQuickPills');

      if (allAlerts.length === 0) {
        container.classList.add('hidden');
        return;
      }

      container.classList.remove('hidden');
      textEl.innerText = `${allAlerts.length} security warning(s) flagged during capture`;
      pillsEl.innerHTML = '';

      allAlerts.forEach(a => {
        const pill = document.createElement('button');
        pill.className = 'px-2 py-0.5 rounded bg-rose-950/50 hover:bg-rose-900/60 text-rose-200 border border-[var(--danger)]/50 text-[11px] font-mono transition flex items-center space-x-1.5';
        pill.title = 'Click to filter table to related packets';
        pill.onclick = () => filterToAlert(a);

        pill.innerHTML = `<span>#${a.packet_index}</span> <span class="font-bold text-[var(--danger)]">${a.type === 'port_scan' ? 'SYN Scan' : 'Creds Exposed'}</span> <span>(${a.src_ip})</span>`;
        pillsEl.appendChild(pill);
      });
    }

    function filterToAlert(alertObj) {
      document.getElementById('searchInput').value = alertObj.src_ip;
      renderTable();
      selectPacket(alertObj.packet_index);
    }

    // --- CHARTS (With Safe Offline Fallback & Top-Level Counts) ---

    // Custom Chart.js Plugin: Center Text for Donut (Total Packet Count)
    const centerTextPlugin = {
      id: 'centerTextPlugin',
      afterDraw(chart) {
        if (chart.config.type !== 'doughnut') return;
        const { ctx, chartArea } = chart;
        if (!chartArea) return;
        const centerX = (chartArea.left + chartArea.right) / 2;
        const centerY = (chartArea.top + chartArea.bottom) / 2;
        const isLight = document.body.classList.contains('light-theme');

        ctx.save();
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        // Total count in center
        ctx.font = 'bold 16px Inter, sans-serif';
        ctx.fillStyle = isLight ? '#1F2328' : '#E6EDF3';
        ctx.fillText(allPackets.length.toLocaleString(), centerX, centerY - 6);

        // Subtitle "Packets"
        ctx.font = '600 9px Inter, sans-serif';
        ctx.fillStyle = isLight ? '#57606A' : '#9DA7B3';
        ctx.fillText('Packets', centerX, centerY + 8);

        ctx.restore();
      }
    };

    function updateCharts() {
      // Graceful check if Chart.js is loaded
      if (typeof Chart === 'undefined') {
        console.info('[Sniffsense] Chart.js not active, skipping canvas render.');
        return;
      }

      const isLight = document.body.classList.contains('light-theme');
      const textColor = isLight ? '#57606A' : '#9DA7B3';
      const borderColor = isLight ? '#FFFFFF' : '#161B22';
      const gridColor = isLight ? 'rgba(208, 222, 222, 0.45)' : 'rgba(48, 54, 61, 0.45)';
      const accentColor = isLight ? '#0969DA' : '#2F81F7';

      try {
        // -------------------------------------------------------------------
        // 1. DONUT CHART: Count ONLY each packet's top-level protocol
        // -------------------------------------------------------------------
        const topLevelCounts = {};
        allPackets.forEach(pkt => {
          const proto = getTopLevelProtocol(pkt);
          topLevelCounts[proto] = (topLevelCounts[proto] || 0) + 1;
        });

        // Keep "Protocols Decoded" KPI card strictly synchronized with donut chart slices
        const distinctProtoCount = Object.keys(topLevelCounts).length;
        const statProtoEl = document.getElementById('statProtocolsCount');
        if (statProtoEl) statProtoEl.innerText = distinctProtoCount;

        const donutLabels = Object.keys(topLevelCounts);
        const donutData = Object.values(topLevelCounts);
        const donutColors = donutLabels.map(p => PROTO_COLORS[p] || '#8B949E');

        if (!donutChartInstance) {
          const ctx = document.getElementById('protocolDonutChart').getContext('2d');
          donutChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: {
              labels: donutLabels,
              datasets: [{
                data: donutData,
                backgroundColor: donutColors,
                borderColor: borderColor,
                borderWidth: 1.5,
                hoverOffset: 3
              }]
            },
            plugins: [centerTextPlugin],
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: {
                legend: {
                  position: 'right',
                  labels: {
                    color: textColor,
                    font: { size: 10, family: 'Inter' },
                    boxWidth: 8,
                    padding: 6
                  }
                },
                tooltip: {
                  callbacks: {
                    label: function(ctx) {
                      const count = ctx.parsed;
                      const total = allPackets.length || 1;
                      const pct = ((count / total) * 100).toFixed(1);
                      return ` ${ctx.label}: ${count} (${pct}%)`;
                    }
                  }
                }
              },
              cutout: '66%'
            }
          });
        } else {
          donutChartInstance.data.labels = donutLabels;
          donutChartInstance.data.datasets[0].data = donutData;
          donutChartInstance.data.datasets[0].backgroundColor = donutColors;
          donutChartInstance.data.datasets[0].borderColor = borderColor;
          donutChartInstance.options.plugins.legend.labels.color = textColor;
          donutChartInstance.update();
        }

        // -------------------------------------------------------------------
        // 2. TIMELINE CHART: Discrete bucket bars for crystal-clear readability
        // -------------------------------------------------------------------
        let timelineLabels = [];
        let timelineData = [];
        let bucketUnitText = '1s';

        if (allPackets.length > 0) {
          const epochs = allPackets
            .map(p => p.timestamp_epoch || p.timestamp)
            .filter(t => typeof t === 'number' && !isNaN(t));

          if (epochs.length > 0) {
            const minEpoch = Math.min(...epochs);
            const maxEpoch = Math.max(...epochs);
            const span = maxEpoch - minEpoch;

            // Choose fixed bucket size: 0.25s for short bursts (< 3s), 1s otherwise
            let bucketSize = 1.0;
            if (span < 3.0) {
              bucketSize = 0.25;
              bucketUnitText = '0.25s';
            } else if (span > 180.0) {
              bucketSize = 5.0;
              bucketUnitText = '5s';
            } else {
              bucketUnitText = '1s';
            }

            const numBuckets = Math.max(1, Math.floor((maxEpoch - minEpoch) / bucketSize) + 1);
            timelineData = new Array(numBuckets).fill(0);
            timelineLabels = [];

            for (let i = 0; i < numBuckets; i++) {
              const offset = i * bucketSize;
              timelineLabels.push(bucketSize < 1.0 ? `+${offset.toFixed(2)}s` : `+${Math.round(offset)}s`);
            }

            allPackets.forEach(p => {
              const ep = p.timestamp_epoch || p.timestamp;
              if (typeof ep !== 'number' || isNaN(ep)) return;
              const idx = Math.min(numBuckets - 1, Math.floor((ep - minEpoch) / bucketSize));
              if (timelineMetric === 'bytes') {
                timelineData[idx] += (p.length || 0);
              } else {
                timelineData[idx] += 1;
              }
            });

            // Fix artificial drop at end: trim trailing zero-traffic buckets if span ended early
            while (timelineData.length > 1 && timelineData[timelineData.length - 1] === 0) {
              timelineData.pop();
              timelineLabels.pop();
            }
          }
        }

        if (timelineLabels.length === 0) {
          timelineLabels = ['0s'];
          timelineData = [0];
        }

        const bucketLabelEl = document.getElementById('timelineBucketLabel');
        if (bucketLabelEl) bucketLabelEl.innerText = `${bucketUnitText} buckets`;

        const yAxisTitle = timelineMetric === 'bytes' ? 'Data Volume (Bytes)' : 'Packet Count';

        if (!timelineChartInstance) {
          const ctx2 = document.getElementById('timelineChart').getContext('2d');
          timelineChartInstance = new Chart(ctx2, {
            type: 'bar',
            data: {
              labels: timelineLabels,
              datasets: [{
                label: yAxisTitle,
                data: timelineData,
                backgroundColor: isLight ? 'rgba(9, 105, 218, 0.75)' : 'rgba(47, 129, 247, 0.75)',
                hoverBackgroundColor: isLight ? '#0969DA' : '#58A6FF',
                borderColor: accentColor,
                borderWidth: 1,
                borderRadius: 3,
                barPercentage: 0.65
              }]
            },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              scales: {
                x: {
                  display: true,
                  grid: { color: gridColor },
                  ticks: { color: textColor, font: { size: 9, family: 'Inter' } },
                  title: {
                    display: true,
                    text: `Time (${bucketUnitText} buckets)`,
                    color: textColor,
                    font: { size: 10, weight: '500', family: 'Inter' }
                  }
                },
                y: {
                  display: true,
                  beginAtZero: true,
                  min: 0,
                  grid: { color: gridColor },
                  ticks: { color: textColor, font: { size: 9, family: 'Inter' }, precision: 0 },
                  title: {
                    display: true,
                    text: yAxisTitle,
                    color: textColor,
                    font: { size: 10, weight: '500', family: 'Inter' }
                  }
                }
              },
              plugins: {
                legend: { display: false },
                tooltip: {
                  callbacks: {
                    label: function(ctx) {
                      return timelineMetric === 'bytes'
                        ? ` Volume: ${formatBytes(ctx.parsed.y)}`
                        : ` Traffic: ${ctx.parsed.y} packet(s)`;
                    }
                  }
                }
              }
            }
          });
        } else {
          timelineChartInstance.data.labels = timelineLabels;
          timelineChartInstance.data.datasets[0].data = timelineData;
          timelineChartInstance.data.datasets[0].label = yAxisTitle;
          timelineChartInstance.data.datasets[0].backgroundColor = isLight ? 'rgba(9, 105, 218, 0.75)' : 'rgba(47, 129, 247, 0.75)';
          timelineChartInstance.data.datasets[0].hoverBackgroundColor = isLight ? '#0969DA' : '#58A6FF';
          timelineChartInstance.data.datasets[0].borderColor = accentColor;
          timelineChartInstance.options.scales.x.grid.color = gridColor;
          timelineChartInstance.options.scales.x.ticks.color = textColor;
          timelineChartInstance.options.scales.x.title.color = textColor;
          timelineChartInstance.options.scales.x.title.text = `Time (${bucketUnitText} buckets)`;
          timelineChartInstance.options.scales.y.grid.color = gridColor;
          timelineChartInstance.options.scales.y.ticks.color = textColor;
          timelineChartInstance.options.scales.y.title.color = textColor;
          timelineChartInstance.options.scales.y.title.text = yAxisTitle;
          timelineChartInstance.update();
        }
      } catch (err) {
        console.warn('[Sniffsense] Canvas rendering error:', err);
      }
    }

    // --- TABLE RENDERING & FILTERING ---
    function setFilter(proto) {
      currentFilter = proto;
      document.querySelectorAll('.proto-btn').forEach(btn => {
        if (btn.dataset.proto === proto) {
          btn.className = 'proto-btn px-3 py-1 text-xs rounded-md font-semibold bg-[var(--accent)] text-white shadow-sm';
        } else {
          btn.className = 'proto-btn px-2.5 py-1 text-xs rounded-md font-medium text-[var(--text)] bg-[var(--surface)] hover:bg-[var(--elevated)] border border-[var(--border)]';
        }
      });
      renderTable();
    }

    function clearSearch() {
      document.getElementById('searchInput').value = '';
      setFilter('ALL');
    }

    function renderTable() {
      const search = document.getElementById('searchInput').value.toLowerCase().trim();
      const tbody = document.getElementById('packetTableBody');
      tbody.innerHTML = '';

      // Build alert lookup map by packet index for fast alert badges & row highlights
      const alertMap = new Map();
      allAlerts.forEach(a => alertMap.set(a.packet_index, a));

      let visible = 0;

      allPackets.forEach((pkt) => {
        // Protocol filter
        if (currentFilter !== 'ALL' && !pkt.protocols.includes(currentFilter)) {
          return;
        }

        // Search text check
        if (search) {
          const matchStr = `${pkt.index} ${pkt.timestamp_str} ${pkt.protocols.join(' ')} ${pkt.src_ip || ''} ${pkt.dst_ip || ''} ${pkt.src_port || ''} ${pkt.dst_port || ''} ${pkt.summary}`.toLowerCase();
          if (!matchStr.includes(search)) {
            return;
          }
        }

        visible++;
        const tr = document.createElement('tr');
        const isSelected = (selectedPacketIndex === pkt.index);
        const alert = alertMap.get(pkt.index);

        tr.id = `row-pkt-${pkt.index}`;

        // High-visibility selection and security alert styling
        let rowClasses = 'cursor-pointer transition border-b border-[var(--border)] ';
        if (isSelected && alert) {
          rowClasses += 'row-alert-selected ';
        } else if (isSelected) {
          rowClasses += 'row-selected ';
        } else if (alert) {
          rowClasses += 'row-alert ';
        } else {
          rowClasses += 'hover:bg-[var(--elevated)] ';
        }
        tr.className = rowClasses;
        tr.onclick = () => selectPacket(pkt.index);

        const mainProto = getTopLevelProtocol(pkt);

        const endpoints = (pkt.src_port && pkt.dst_port)
          ? `${pkt.src_ip}:${pkt.src_port} -> ${pkt.dst_ip}:${pkt.dst_port}`
          : `${pkt.src_ip || 'Local'} -> ${pkt.dst_ip || 'Remote'}`;

        // Column 1: # Index with warning icon if flagged by alert engine
        let indexColContent = '';
        if (alert) {
          indexColContent = `
            <div class="flex items-center justify-center space-x-1" title="Security Warning: ${escapeHtml(alert.message)}">
              <svg class="w-3.5 h-3.5 text-[var(--danger)] shrink-0 inline" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              <span class="font-bold text-[var(--danger)]">${pkt.index}</span>
            </div>
          `;
        } else {
          indexColContent = `<span class="text-[var(--muted)] mono font-medium">${pkt.index}</span>`;
        }

        tr.innerHTML = `
          <td class="py-2.5 px-4 text-center mono font-medium">${indexColContent}</td>
          <td class="py-2.5 px-4 text-[var(--muted)] mono">${pkt.timestamp_str}</td>
          <td class="py-2.5 px-4"><span class="badge-${mainProto} px-2 py-0.5 rounded text-[11px] font-semibold font-sans uppercase">${mainProto}</span></td>
          <td class="py-2.5 px-4 text-[var(--text)] font-semibold truncate max-w-xs mono">${endpoints}</td>
          <td class="py-2.5 px-4 text-[var(--muted)] mono">${pkt.length} B</td>
          <td class="py-2.5 px-4 text-[var(--text)] font-sans truncate max-w-md">${escapeHtml(pkt.summary.split('|').slice(2).join('|').trim())}</td>
        `;
        tbody.appendChild(tr);
      });

      // PART 1: EMPTY STATE
      if (visible === 0) {
        const emptyTr = document.createElement('tr');
        emptyTr.innerHTML = `
          <td colspan="6" class="py-16 text-center text-[var(--muted)]">
            <svg class="w-8 h-8 mx-auto text-[var(--muted)] mb-2 opacity-60" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/></svg>
            <p class="font-semibold text-[var(--text)]">No packets loaded.</p>
            <p class="text-xs text-[var(--muted)] mt-1">Upload a .pcap or reload the sample.</p>
            <button onclick="loadSamplePcap()" class="soc-btn-primary mt-3">
              <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
              <span>Reload sample.pcap</span>
            </button>
          </td>
        `;
        tbody.appendChild(emptyTr);
      }

      document.getElementById('visibleCount').innerText = visible;
      document.getElementById('totalCount').innerText = allPackets.length;
    }

    // --- KEYBOARD NAVIGATION (Arrow keys) ---
    function handleTableKeyNav(e) {
      if (!allPackets.length) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const currentIndex = selectedPacketIndex || 1;
        let nextIndex = currentIndex;

        if (e.key === 'ArrowDown') {
          nextIndex = Math.min(allPackets.length, currentIndex + 1);
        } else if (e.key === 'ArrowUp') {
          nextIndex = Math.max(1, currentIndex - 1);
        }

        selectPacket(nextIndex);

        const targetRow = document.getElementById(`row-pkt-${nextIndex}`);
        if (targetRow) {
          targetRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
      }
    }

    // --- PACKET INSPECTOR ---
    function selectPacket(index) {
      selectedPacketIndex = index;
      const pkt = allPackets.find(p => p.index === index);
      if (!pkt) return;

      document.getElementById('selectedPacketBadge').innerText = `Packet #${pkt.index} (${pkt.length} Bytes)`;

      const container = document.getElementById('inspectorContent');
      let html = '';

      // Layer 2: Ethernet
      if (pkt.layers.Ethernet) {
        const eth = pkt.layers.Ethernet;
        html += renderAccordionSection('Layer 2: Ethernet Frame', 'text-[var(--accent)]', true, [
          ['Source MAC', eth.src_mac],
          ['Destination MAC', eth.dst_mac],
          ['EtherType', eth.type_hex]
        ]);
      }

      // Layer 2/3: ARP
      if (pkt.layers.ARP) {
        const arp = pkt.layers.ARP;
        html += renderAccordionSection('Layer 2/3: ARP (Address Resolution Protocol)', 'text-[#DB61A2]', true, [
          ['Operation', arp.operation],
          ['Sender MAC / IP', `${arp.hw_src} / ${arp.ip_src}`],
          ['Target MAC / IP', `${arp.hw_dst} / ${arp.ip_dst}`]
        ]);
      }

      // Layer 3: IPv4
      if (pkt.layers.IPv4) {
        const ip = pkt.layers.IPv4;
        html += renderAccordionSection('Layer 3: IPv4 Datagram', 'text-[var(--accent)]', true, [
          ['Source IP', ip.src_ip],
          ['Destination IP', ip.dst_ip],
          ['Time to Live (TTL)', `${ip.ttl} hops`],
          ['Header Length', `${ip.header_len} bytes`],
          ['Total Length', `${ip.total_len} bytes`],
          ['Protocol Number', ip.protocol_num]
        ]);
      }

      // Layer 3: IPv6
      if (pkt.layers.IPv6) {
        const ip6 = pkt.layers.IPv6;
        html += renderAccordionSection('Layer 3: IPv6 Datagram', 'text-[var(--accent)]', true, [
          ['Source IP', ip6.src_ip],
          ['Destination IP', ip6.dst_ip],
          ['Hop Limit', `${ip6.hop_limit} hops`],
          ['Payload Length', `${ip6.payload_len} bytes`],
          ['Next Header', ip6.next_header]
        ]);
      }

      // Layer 4: TCP
      if (pkt.layers.TCP) {
        const tcp = pkt.layers.TCP;
        html += renderAccordionSection('Layer 4: TCP Segment (Reliable)', 'text-[#58A6FF]', true, [
          ['Source Port', tcp.src_port],
          ['Destination Port', tcp.dst_port],
          ['Sequence Number', tcp.seq],
          ['Acknowledgment', tcp.ack],
          ['Flags', tcp.flags_formatted],
          ['Window Size', tcp.window],
          ['Checksum', tcp.checksum]
        ]);
      }

      // Layer 4: UDP
      if (pkt.layers.UDP) {
        const udp = pkt.layers.UDP;
        html += renderAccordionSection('Layer 4: UDP Datagram', 'text-[#BC8CFF]', true, [
          ['Source Port', udp.sport || udp.src_port],
          ['Destination Port', udp.dport || udp.dst_port],
          ['Length', `${udp.length} bytes`],
          ['Checksum', udp.checksum]
        ]);
      }

      // Layer 4: ICMP
      if (pkt.layers.ICMP) {
        const icmp = pkt.layers.ICMP;
        html += renderAccordionSection('Layer 4: ICMP Control Message', 'text-[#F2CC60]', true, [
          ['Type & Meaning', `${icmp.type}: ${icmp.meaning}`],
          ['Code', icmp.code],
          ['Checksum', icmp.checksum]
        ]);
      }

      // Layer 7: DNS
      if (pkt.layers.DNS) {
        const dns = pkt.layers.DNS;
        const rows = [
          ['Transaction ID', `0x${dns.id.toString(16)}`],
          ['Message Type', dns.qr]
        ];
        (dns.queries || []).forEach(q => rows.push(['Query Domain', `${q.name} [${q.type}]`]));
        (dns.answers || []).forEach(a => rows.push(['Answer IP/Data', a]));
        html += renderAccordionSection('Layer 7: DNS (Domain Name System)', 'text-[#56D364]', true, rows);
      }

      // Layer 7: HTTP
      if (pkt.layers.HTTP) {
        const http = pkt.layers.HTTP;
        const rows = Object.entries(http).map(([k, v]) => [k, v]);
        html += renderAccordionSection('Layer 7: HTTP Application Data', 'text-[#E3B341]', true, rows);
      }

      // Application Payload Section (or clear empty notice)
      if (pkt.has_payload) {
        html += `
          <details class="soc-card overflow-hidden" open>
            <summary class="px-3 py-2 bg-[var(--elevated)] cursor-pointer flex items-center justify-between font-semibold text-[var(--text)] border-b border-[var(--border)]">
              <span class="flex items-center space-x-2">
                <svg class="w-3.5 h-3.5 text-[var(--accent)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                <span>Layer 7: Application Payload</span>
              </span>
              <span class="text-[11px] text-[var(--accent)] font-mono font-semibold">${pkt.payload_bytes_len} Bytes</span>
            </summary>
            <div class="p-3 bg-[var(--bg)]">
              <pre class="mono text-[11px] text-[var(--text)] bg-[var(--surface)] p-2.5 rounded overflow-x-auto leading-relaxed border border-[var(--border)]">${escapeHtml(pkt.payload_hexdump)}</pre>
            </div>
          </details>
        `;
      } else {
        html += `
          <div class="soc-card p-3 bg-[var(--surface)] border border-[var(--border)] flex items-center justify-between">
            <div class="flex items-center space-x-2.5">
              <svg class="w-4 h-4 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
              <div>
                <span class="font-semibold text-xs text-[var(--text)]">Application Payload:</span>
                <span class="text-xs text-[var(--muted)] font-mono ml-1.5">No payload (e.g. ARP)</span>
              </div>
            </div>
            <span class="text-[10px] text-[var(--muted)] bg-[var(--elevated)] px-2 py-0.5 rounded border border-[var(--border)] font-mono">0 Bytes</span>
          </div>
        `;
      }

      // Full Raw Packet Hex & ASCII Dump (All Layers: L2-L7)
      html += `
        <details class="soc-card overflow-hidden" open>
          <summary class="px-3 py-2 bg-[var(--elevated)] cursor-pointer flex items-center justify-between font-semibold text-[var(--text)] border-b border-[var(--border)]">
            <span class="flex items-center space-x-2">
              <svg class="w-3.5 h-3.5 text-[var(--muted)]" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><line x1="9" y1="9" x2="9" y2="15"/><line x1="15" y1="9" x2="15" y2="15"/></svg>
              <span>Full Raw Packet Hex & ASCII Dump (All Layers)</span>
            </span>
            <span class="text-[11px] text-[var(--subtext)] font-mono font-semibold">${pkt.raw_bytes_len || pkt.length} Bytes Total</span>
          </summary>
          <div class="p-3 bg-[var(--bg)]">
            <pre class="mono text-[11px] text-[var(--text)] bg-[var(--surface)] p-2.5 rounded overflow-x-auto leading-relaxed border border-[var(--border)]">${escapeHtml(pkt.raw_hexdump || pkt.hexdump)}</pre>
          </div>
        </details>
      `;

      container.innerHTML = html;
      renderTable();
    }

    function renderAccordionSection(title, colorClass, defaultOpen, fields) {
      const rows = fields.map(([label, val]) => {
        const explanation = FIELD_GLOSSARY[label] || '';
        return `
          <div class="py-1 border-b border-[var(--border)]/40 flex flex-col justify-between">
            <div class="flex items-center justify-between">
              <span class="text-[var(--subtext)] font-medium text-[11px] font-sans">${escapeHtml(String(label))}:</span>
              <span class="text-[var(--text)] font-mono text-right max-w-[260px] truncate text-[11px] font-medium">${escapeHtml(String(val))}</span>
            </div>
            ${explanation ? `<span class="text-[11px] text-[var(--subtext)] opacity-95 mt-0.5 font-sans leading-normal">${escapeHtml(explanation)}</span>` : ''}
          </div>
        `;
      }).join('');

      return `
        <details class="soc-card overflow-hidden" ${defaultOpen ? 'open' : ''}>
          <summary class="px-3 py-2 bg-[var(--elevated)] cursor-pointer flex items-center justify-between font-semibold ${colorClass} border-b border-[var(--border)]">
            <div class="flex items-center space-x-2">
              <span>${escapeHtml(title)}</span>
            </div>
            <svg class="w-3.5 h-3.5 text-[var(--muted)] arrow-icon transition-transform" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="9 18 15 12 9 6"/></svg>
          </summary>
          <div class="p-3 space-y-1 bg-[var(--surface)]">
            ${rows}
          </div>
        </details>
      `;
    }

    // --- BUTTON ACTIONS ---
    async function loadSamplePcap() {
      showLoading(true);
      try {
        const res = await fetch('/api/load_sample', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
          selectedPacketIndex = null;
          await fetchData();
        } else {
          showError(data.message || 'Failed to reload sample.pcap');
        }
      } catch (err) {
        showError(`Network failure while reloading sample: ${err.message}`);
      } finally {
        showLoading(false);
      }
    }

    async function clearPackets() {
      showLoading(true);
      try {
        await fetch('/api/clear', { method: 'POST' });
        selectedPacketIndex = null;
        document.getElementById('inspectorContent').innerHTML = `
          <div class="text-center text-[var(--muted)] py-20">
            <p class="font-medium text-[var(--text)]">Cleared all packets.</p>
          </div>
        `;
        document.getElementById('selectedPacketBadge').innerText = 'No packet selected';
        await fetchData();
      } catch (err) {
        showError(`Clear error: ${err.message}`);
      } finally {
        showLoading(false);
      }
    }

    async function uploadPcapFile(input) {
      if (!input.files || input.files.length === 0) return;
      const file = input.files[0];
      const formData = new FormData();
      formData.append('pcap', file);

      showLoading(true);
      try {
        const res = await fetch('/api/upload_pcap', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.status === 'ok') {
          selectedPacketIndex = null;
          await fetchData();
        } else {
          showError(data.message || 'PCAP upload failed');
        }
      } catch (err) {
        showError(`Upload error: ${err.message}`);
      } finally {
        showLoading(false);
        input.value = '';
      }
    }

    function populateInterfaces(interfaces) {
      const select = document.getElementById('interfaceSelect');
      if (select.children.length > 1) return;
      (interfaces || []).forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name;
        opt.innerText = `${iface.name} (${iface.ip})`;
        select.appendChild(opt);
      });
    }

    async function toggleLiveCapture() {
      const iface = document.getElementById('interfaceSelect').value;
      if (!isCapturing) {
        try {
          const res = await fetch('/api/start_capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interface: iface, count: 0, filter: '' })
          });
          const data = await res.json();
          if (data.status === 'ok') {
            isCapturing = true;
            updateCaptureButton(true);
          } else {
            showError(data.message || 'Could not start capture.');
          }
        } catch (e) {
          showError(`Start capture error: ${e.message}`);
        }
      } else {
        try {
          await fetch('/api/stop_capture', { method: 'POST' });
          isCapturing = false;
          updateCaptureButton(false);
        } catch (e) {
          showError(`Stop capture error: ${e.message}`);
        }
      }
    }

    function updateCaptureButton(active) {
      const btn = document.getElementById('toggleCaptureBtn');
      const text = document.getElementById('captureBtnText');
      if (active) {
        btn.className = 'soc-btn-primary !bg-[var(--danger)] !border-[var(--danger)] !py-0.5 !px-2 !text-[11px] animate-pulse';
        text.innerText = 'Stop';
      } else {
        btn.className = 'soc-btn-primary !py-0.5 !px-2 !text-[11px]';
        text.innerText = 'Capture';
      }
    }

    function showLoading(show) {
      const el = document.getElementById('loadingOverlay');
      if (el) {
        if (show) el.classList.remove('hidden');
        else el.classList.add('hidden');
      }
    }

    function showError(msg) {
      const banner = document.getElementById('errorBanner');
      const text = document.getElementById('errorMessageText');
      text.innerText = msg;
      banner.classList.remove('hidden');
    }

    function dismissError() {
      document.getElementById('errorBanner').classList.add('hidden');
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // --- ACTIONS: ALERTS & CLIPBOARD ---
    function dismissAlertsBanner() {
      const banner = document.getElementById('alertsBannerContainer');
      if (banner) banner.classList.add('hidden');
    }

    function toggleAlertsList() {
      const pills = document.getElementById('alertsQuickPills');
      const btn = document.getElementById('toggleAlertsListBtn');
      if (!pills || !btn) return;
      const isHidden = pills.classList.toggle('hidden');
      btn.innerText = isHidden ? 'Expand' : 'Collapse';
    }

    function copySelectedPacketHex() {
      if (!selectedPacketIndex) return;
      const pkt = allPackets.find(p => p.index === selectedPacketIndex);
      if (!pkt) return;
      const textToCopy = pkt.raw_hexdump || pkt.hexdump || '';
      navigator.clipboard.writeText(textToCopy).then(() => {
        const textEl = document.getElementById('copyHexText');
        if (textEl) {
          textEl.innerText = 'Copied!';
          setTimeout(() => { textEl.innerText = 'Copy Hex'; }, 1600);
        }
      }).catch(err => {
        console.error('Clipboard copy error:', err);
      });
    }

    // --- GLOBAL KEYBOARD SHORTCUTS ---
    window.addEventListener('keydown', (e) => {
      // Don't intercept when user is typing in search input (except Escape)
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
        if (e.key === 'Escape') {
          clearSearch();
          e.target.blur();
        }
        return;
      }
      if (e.key === '/') {
        e.preventDefault();
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
          searchInput.focus();
          searchInput.select();
        }
      } else if (e.key === 'Escape') {
        clearSearch();
      } else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
        handleTableKeyNav(e);
      }
    });

    // --- INITIALIZATION ---
    initTheme();

    // Collapse charts section by default (unless user explicitly saved 'false')
    const savedChartsState = localStorage.getItem('sniffsense_charts_collapsed');
    const shouldCollapse = (savedChartsState === null) ? true : (savedChartsState === 'true');
    const chartsSec = document.getElementById('chartsSection');
    if (chartsSec) {
      if (shouldCollapse) chartsSec.classList.add('hidden');
      else chartsSec.classList.remove('hidden');
    }
    updateChartsCollapseUI(shouldCollapse);

    fetchData();
    // Background polling every 3s for live updates
    setInterval(fetchData, 3000);
  </script>
</body>
</html>
"""


# ============================================================================
# HTTP REQUEST HANDLER & REST API (With No-Cache Headers)
# ============================================================================
class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Processes HTTP requests for dashboard API and serves HTML SPA."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default access logs to keep terminal quiet."""
        pass

    def send_json(self, data: Any, status: int = 200) -> None:
        """Serializes data using custom default handler to ensure 100% JSON safety."""
        try:
            payload = json.dumps(
                data,
                default=lambda o: list(o) if isinstance(o, (set, tuple)) else str(o)
            ).encode("utf-8")
        except Exception as e:
            err_data = {"error": f"Serialization failure: {e}"}
            payload = json.dumps(err_data).encode("utf-8")
            status = 500

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        # Strictly prevent browser from caching stale JSON responses
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed_path = self.path.split("?")[0]

        # 1. Root route: Serve HTML dashboard with no-cache headers
        if parsed_path in ("/", "/index.html"):
            html_bytes = HTML_TEMPLATE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_bytes)))
            # Strictly prevent browser from serving stale cached HTML
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(html_bytes)
            return

        # 2. API: Get Packets, Alerts, & Status
        elif parsed_path == "/api/packets":
            with STATE.lock:
                data = {
                    "packets": STATE.packets,
                    "alerts": STATE.alerts,
                    "active_source": STATE.active_source,
                    "is_capturing": STATE.is_capturing,
                    "last_error": STATE.last_error,
                }
            self.send_json(data)
            return

        # 3. API: Get Session Statistics
        elif parsed_path == "/api/stats":
            with STATE.lock:
                stats = STATE.stats
                data = {
                    "total_packets": stats.total_packets,
                    "total_bytes": stats.total_bytes,
                    "protocol_counts": dict(stats.protocol_counts),
                    "top_sources": stats.src_ip_counts.most_common(5),
                    "top_destinations": stats.dst_ip_counts.most_common(5),
                }
            self.send_json(data)
            return

        # 4. API: List Interfaces
        elif parsed_path == "/api/interfaces":
            iface_list = []
            try:
                for k, iface in conf.ifaces.items():
                    iface_list.append({
                        "name": getattr(iface, "name", k),
                        "ip": getattr(iface, "ip", "None") or "None",
                        "mac": getattr(iface, "mac", "None") or "None",
                        "desc": getattr(iface, "description", "") or "",
                    })
            except Exception:
                pass
            self.send_json(iface_list)
            return

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        parsed_path = self.path.split("?")[0]

        # 1. API: Reload sample.pcap
        if parsed_path == "/api/load_sample":
            ensure_sample_pcap_exists()
            count = load_pcap_file(SAMPLE_PCAP_PATH)
            if count > 0:
                self.send_json({"status": "ok", "loaded": count})
            else:
                self.send_json({"status": "error", "message": STATE.last_error or "sample.pcap empty"}, 500)
            return

        # 2. API: Clear Packets
        elif parsed_path == "/api/clear":
            STATE.clear()
            self.send_json({"status": "ok"})
            return

        # 3. API: Upload .pcap file
        elif parsed_path == "/api/upload_pcap":
            content_length = int(self.headers.get("content-length", 0))
            body_bytes = self.rfile.read(content_length)
            content_type = self.headers.get("content-type", "")

            boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
            if boundary_match:
                boundary = boundary_match.group(1).encode("utf-8")
                parts = body_bytes.split(b"--" + boundary)
                for part in parts:
                    if b'filename="' in part:
                        header_and_body = part.split(b"\r\n\r\n", 1)
                        if len(header_and_body) == 2:
                            pcap_data = header_and_body[1].rstrip(b"\r\n")
                            temp_path = os.path.join(BASE_DIR, "uploaded_temp.pcap")
                            with open(temp_path, "wb") as f:
                                f.write(pcap_data)
                            count = load_pcap_file(temp_path)
                            STATE.active_source = "Uploaded File"
                            try:
                                os.remove(temp_path)
                            except Exception:
                                pass
                            self.send_json({"status": "ok", "loaded": count})
                            return

            self.send_json({"status": "error", "message": "Failed to parse uploaded file"}, 400)
            return

        # 4. API: Start Live Capture
        elif parsed_path == "/api/start_capture":
            content_length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body) if body else {}

            iface = data.get("interface")
            bpf_filter = data.get("filter", "")
            count = data.get("count", 0)

            if not STATE.is_capturing:
                STATE.clear()
                STATE.active_source = f"Live: {iface or 'Default'}"
                STATE.stop_event.clear()
                t = threading.Thread(target=live_capture_worker, args=(iface, bpf_filter, count), daemon=True)
                STATE.capture_thread = t
                t.start()
                self.send_json({"status": "ok"})
            else:
                self.send_json({"status": "error", "message": "Capture already running"}, 400)
            return

        # 5. API: Stop Live Capture
        elif parsed_path == "/api/stop_capture":
            if STATE.is_capturing:
                STATE.stop_event.set()
                self.send_json({"status": "ok"})
            else:
                self.send_json({"status": "error", "message": "Not capturing"}, 400)
            return

        else:
            self.send_response(404)
            self.end_headers()


class ReusableThreadingServer(ThreadingHTTPServer):
    """Threading HTTP Server that allows immediate address reuse."""
    allow_reuse_address = True


def run_dashboard(host: str = "0.0.0.0", port: int = 5000) -> None:
    """Start the multi-threaded web dashboard server."""
    # Ensure sample.pcap exists and preload it
    ensure_sample_pcap_exists()
    count = load_pcap_file(SAMPLE_PCAP_PATH)
    print(f"[*] Preloaded {count} packets from '{SAMPLE_PCAP_PATH}' into web dashboard.")

    server_address = (host, port)
    httpd = ReusableThreadingServer(server_address, DashboardRequestHandler)

    print("=" * 72)
    print("           SNIFFSENSE SOC DASHBOARD IS RUNNING")
    print("=" * 72)
    print(f"[*] Local Host Link:   http://localhost:{port}")
    print(f"[*] Network Host Link: http://127.0.0.1:{port}")
    print("[*] Open either link above in your web browser to explore packets!")
    print("[*] Press Ctrl+C in this terminal to stop the dashboard.")
    print("=" * 72)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped by user.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_dashboard(host="0.0.0.0", port=port)
