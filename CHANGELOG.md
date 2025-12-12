# Changelog

All notable changes to **AetherisNET** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-12

### 🚀 New Features

#### 📊 Visual Dashboard Upgrade (Btop Style)
- **Grid Layout UI:** Complete redesign of the TUI using a windowed/box architecture for better organization (Header, Stats, Graph, Logs).
- **ASCII Sparkline Graphs:** Added a real-time traffic load graph (` ▂▃▄▅▆▇█`) to visualize Packets Per Second (PPS).
- **Color Coding:** Implemented dynamic coloring for different protocols (Green for TCP, Yellow for UDP, Red for Alerts/HTTPS).

#### 🕵️ Application Layer Sniffing
- **Deep Packet Inspection (DPI):** Added logic to inspect packet payloads beyond Layer 4.
- **HTTP Parsing:** Now extracts and displays HTTP Methods (`GET`, `POST`) and Host headers for unencrypted traffic.
- **HTTPS Detection:** Identifies TLS Handshakes (Client Hello) to signal connections to secure sites (Port 443).
- **DNS Monitoring:** Decodes DNS Queries (Port 53) to show accessed domains in real-time.
- **ARP Support:** Added structure for parsing ARP packets (Request/Reply).

### 🛡️ Security & Detection
- **XMAS Scan Detection:** Added logic to detect Nmap XMAS scans (FIN+URG+PSH flags).
- **NULL Scan Detection:** Added logic to identify TCP packets with no flags set.

### 🐛 Bug Fixes & Improvements
- **Anti-Noise Filter:** Implemented a filter to ignore "noisy" discovery protocols like SSDP (Port 1900) and mDNS (Port 5353) to keep logs clean.
- **Performance Optimization:** Batched packet processing in the UI loop to prevent interface lag during high traffic.

---

## [0.1.0] - Initial Beta Release

### 🚀 New Features

#### 🛡️ Intrusion Detection System (IDS) Engine
- **SYN Scan Detection:** implemented a heuristic engine to identify potential port scanning attacks based on SYN packet frequency.
- **Traffic Analysis:** Real-time monitoring of incoming packets to flag suspicious patterns.

#### 📡 Core Networking & Packet Analysis
- **Raw Socket Engine:** Implemented a low-level listener using `AF_PACKET` for direct Layer 2 access, bypassing the OS network stack for maximum visibility.
- **Full Stack Protocol Parsing:**
  - **Layer 2 (Data Link):** Ethernet frame unpacking (MAC source/destination, EtherType).
  - **Layer 3 (Network):** IPv4 header parsing including checksums, TTL, and IP addressing.
  - **Layer 4 (Transport):** Complete parsing logic for TCP (flags, sequence numbers) and UDP headers.

#### 🖥️ User Interface & UX
- **Real-Time TUI (Terminal User Interface):** Integrated `curses` library to create a dashboard-style display within the terminal, replacing standard stdout logging.
- **CLI Configuration:** Added `argparse` support to allow "Pro" configuration via command-line arguments (e.g., interface selection, verbose modes) at runtime.

### ♻️ Refactoring & Architecture
- **Modular Design:** Refactored the monolithic script into a modular project structure for better scalability and separation of concerns.
- **Clean Architecture:** Initialized a "clean version" of the raw socket engine to ensure code stability and readability.

### 🐛 Bug Fixes & Security
- **False Positive Reduction:** Fixed IDS logic to ignore local IP traffic, preventing self-flagging during scans.
- **Data Hygiene:** Removed sensitive data traces from the repository history.

### 🔧 Chore & Configuration
- **Project Setup:** Established initial Git configuration and robust `.gitignore` rules.