# Changelog

All notable changes to **AetherisNET** are documented in this file.

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and Semantic Versioning.

## [0.2.1] - 2025-12-12

### Repository & Docs

- Translated repository documentation to English for wider discoverability (README, CONTRIBUTING, CHANGELOG).
- Improved `README.md` with badges, clearer quickstart, demo placeholder, and stronger star CTA.
- Added `LICENSE` (MIT), `CODE_OF_CONDUCT.md`, and updated contributing guidelines.

### Packaging & CI

- Added basic packaging metadata (`pyproject.toml`, `setup.cfg`) and a `requirements.txt` (dev deps).
- CI workflow: `.github/workflows/ci.yml` for lint/compile checks on push/PR.
- Release workflow: `.github/workflows/release.yml` to create releases from tag pushes.

### Repo Quality

- Added GitHub templates for bug reports and pull requests.
- Added flake8 configuration and basic linting guidance.
- Bumped package version metadata in `aetheris/__init__.py` to `0.2.0`.

### Notes

- These changes are primarily focused on improving project visibility, governance, and contributor onboarding to help attract more users and contributors.

## [0.2.0] - 2025-12-12

### New Features

- Visual dashboard revamp with a grid/box layout (header, stats, graph, logs).
- Real-time ASCII sparkline graph to show Packets Per Second (PPS).
- Color coding for protocols and alerts.
- Application-layer inspection for HTTP, TLS handshakes, and DNS queries.
- Basic ARP parsing support.

### Security & Detection

- XMAS scan detection (FIN+URG+PSH)
- NULL scan detection (no TCP flags set)

### Bug Fixes & Improvements

- Noise filtering for discovery protocols (SSDP/mDNS) to reduce log spam.
- Batch processing in the main loop to improve UI responsiveness under load.

## [0.1.0] - Initial Beta Release

### Major Features

- Heuristic SYN scan detection based on per-source SYN counters.
- Raw socket listener (`AF_PACKET`) for Layer 2 visibility.
- Protocol parsers for Ethernet, IPv4, TCP, UDP, and ARP.
- Curses-based real-time dashboard and CLI configuration.
