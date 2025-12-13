# AetherisNET

[![CI](https://github.com/alexandrusu1/AetherisNET/actions/workflows/ci.yml/badge.svg)](https://github.com/alexandrusu1/AetherisNET/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/alexandrusu1/AetherisNET?style=social)](https://github.com/alexandrusu1/AetherisNET/stargazers)

Lightweight terminal-based IDS for real-time network monitoring. Built with Python using raw sockets and curses TUI.

## Features

- Real-time dashboard with traffic stats and PPS graph
- Protocol parsing: Ethernet, IPv4, TCP, UDP, ARP
- Threat detection: SYN flood, XMAS scan
- Application layer: HTTP, TLS handshake, DNS queries
- PCAP export

## Requirements

- Python 3.10+
- Linux (requires `AF_PACKET` raw sockets)
- Root privileges

## Quick Start

```bash
git clone https://github.com/alexandrusu1/AetherisNET.git
cd AetherisNET
sudo python main.py -i eth0
```

## Options

| Flag | Description |
|------|-------------|
| `-i` | Network interface (eth0, wlan0) |
| `-t` | SYN flood threshold (default: 15) |
| `-l` | Threat log file (default: threats.log) |
| `-p` | Save to PCAP file |
| `--host-only` | Filter traffic to/from local host |

## Example

```bash
sudo python main.py -i eth0 -p capture.pcap --host-only
```

## Project Structure

```
aetheris/
├── parsers.py   # Packet parsing
├── ui.py        # TUI dashboard
└── utils.py     # Helpers & PCAP
```

## Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

For authorized use only. Do not monitor networks without permission. See full disclaimer in the license.

