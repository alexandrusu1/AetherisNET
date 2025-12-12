# AetherisNET

[![CI](https://github.com/alexandrusu1/AetherisNET/actions/workflows/ci.yml/badge.svg)](https://github.com/alexandrusu1/AetherisNET/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/alexandrusu1/AetherisNET?style=social)](https://github.com/alexandrusu1/AetherisNET/stargazers)

AetherisNET is a lightweight, terminal-first Intrusion Detection System (IDS) implemented in Python. It provides a simple, extensible foundation for monitoring network traffic in real-time using raw sockets and a curses-based TUI.

## Features
- Real-time TUI dashboard using `curses` (statistics, PPS chart, live event log)
- Parsers for: Ethernet, IPv4, TCP, UDP, ARP
- Detection heuristics: SYN flood and XMAS scan
- Basic application-layer inspection for HTTP, TLS handshakes, and DNS queries
- Optional PCAP saving for captured packets

## Requirements
- Python 3.10 or newer
- Root privileges are required to open raw sockets (`AF_PACKET`) on Linux

## Quickstart
1. Clone the repository:

```bash
git clone https://github.com/alexandrusu1/AetherisNET.git
cd AetherisNET
```

2. (Optional) Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install development dependencies:

```bash
pip install -r requirements.txt
```

## Usage
- Run the TUI dashboard (requires root privileges):

```bash
sudo python main.py -i eth0
```

- Important options:
  - `-i, --interface` — network interface to bind (e.g. `eth0`, `wlan0`).
  - `-t, --threshold` — SYN threshold for flood detection (default: `15`).
  - `-l, --log` — threat log file (default: `threats.log`).
  - `-p, --pcap` — save packets to a PCAP file (e.g. `dump.pcap`).

## Example
Capture traffic on interface `eth0` and save PCAP:

```bash
sudo python main.py -i eth0 -p dump.pcap
```

## Project layout
- `aetheris/` — core modules
  - `parsers.py` — low-level packet parsing
  - `ui.py` — curses-based dashboard and main loop
  - `utils.py` — helpers, logging, and PCAP writer

## Contributing
We welcome contributions — see `CONTRIBUTING.md` for details.

## Releases & Changelog
See `CHANGELOG.md` for release notes and history.

## How you can help this project grow
- Star the repository — it helps others discover the project.
- Open issues for bugs and feature requests.
- Share a short demo or writeups on social media (Twitter/X, Reddit, Hacker News).

## License
This project is licensed under the MIT License — see `LICENSE`.

## Ethics & Legal / Disclaimer

AetherisNET is a network monitoring and analysis tool and may capture sensitive information. Do not run this software on networks where you do not have explicit permission to monitor traffic. Always obtain consent from network owners and follow local laws and organizational policies before using this tool. The maintainers and contributors are not responsible for any misuse, damage, or legal consequences resulting from improper use. Use AetherisNET only for legitimate testing, research, or learning in controlled environments or on networks you own or manage.
# AetherisNET

[![CI](https://github.com/alexandrusu1/AetherisNET/actions/workflows/ci.yml/badge.svg)](https://github.com/alexandrusu1/AetherisNET/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/alexandrusu1/AetherisNET?style=social)](https://github.com/alexandrusu1/AetherisNET/stargazers)

AetherisNET is a lightweight, terminal-first Intrusion Detection System (IDS) implemented in Python. It provides a simple, extensible foundation for monitoring network traffic in real-time using raw sockets and a curses-based TUI.


## Features
- Real-time TUI dashboard using `curses` (statistics, PPS chart, live event log)
- Parsers for: Ethernet, IPv4, TCP, UDP, ARP
- Detection heuristics: SYN flood and XMAS scan
- Basic application-layer inspection for HTTP, TLS handshakes, and DNS queries
- Optional PCAP saving for captured packets

## Requirements
- Python 3.10 or newer
- Root privileges are required to open raw sockets (`AF_PACKET`) on Linux

## Quickstart
1. Clone the repository:

```bash
git clone https://github.com/alexandrusu1/AetherisNET.git
cd AetherisNET
```

2. (Optional) Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install development dependencies:

```bash
pip install -r requirements.txt
```

## Usage
- Run the TUI dashboard (requires root privileges):

```bash
sudo python main.py -i eth0
```

- Important options:
  - `-i, --interface` — network interface to bind (e.g. `eth0`, `wlan0`).
  - `-t, --threshold` — SYN threshold for flood detection (default: `15`).
  - `-l, --log` — threat log file (default: `threats.log`).
  - `-p, --pcap` — save packets to a PCAP file (e.g. `dump.pcap`).

## Example
Capture traffic on interface `eth0` and save PCAP:

```bash
sudo python main.py -i eth0 -p dump.pcap
```

## Project layout
- `aetheris/` — core modules
  - `parsers.py` — low-level packet parsing
  - `ui.py` — curses-based dashboard and main loop
  - `utils.py` — helpers, logging, and PCAP writer

## Contributing
We welcome contributions — see `CONTRIBUTING.md` for details.

## Releases & Changelog
See `CHANGELOG.md` for release notes and history.


You can generate a demo GIF locally using `asciinema` + `agg` or `ttyrec` + `gifenc` and then add it to `docs/demo.gif`.

## How you can help this project grow
- Star the repository — it helps others discover the project.
- Open issues for bugs and feature requests.
- Share a short demo or writeups on social media (Twitter/X, Reddit, Hacker News).

## License
This project is licensed under the MIT License — see `LICENSE`.

