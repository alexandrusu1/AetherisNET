import argparse
import curses
import sys
from aetheris.ui import start_dashboard
from aetheris.utils import init_pcap

def main():
    parser = argparse.ArgumentParser(description="AetherisNET - Enterprise Grade Network IDS")
    
    parser.add_argument("-i", "--interface", 
                        help="Network interface to bind to (e.g., wlan0, eth0)", 
                        default=None)
    
    parser.add_argument("-t", "--threshold", 
                        type=int, 
                        help="SYN Flood detection threshold (default: 15)", 
                        default=15)
    
    parser.add_argument("-l", "--log", 
                        help="Log file path (default: threats.log)", 
                        default="threats.log")
    
    parser.add_argument("-p", "--pcap", 
                        help="Save captured traffic to PCAP file (e.g., dump.pcap)", 
                        default=None)
    parser.add_argument("--host-only",
                        help="Only process packets where local host is source or destination (reduces noise)",
                        action="store_true",
                        default=False)
    
    args = parser.parse_args()
    
    if args.pcap:
        init_pcap(args.pcap)
    
    try:
        curses.wrapper(start_dashboard, args)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        sys.stderr.write(f"Critical Error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()