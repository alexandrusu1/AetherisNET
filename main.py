import argparse
import curses
import sys


from aetheris.ui import start_dashboard

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
    
    args = parser.parse_args()
    
    try:

        curses.wrapper(start_dashboard, args)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Critial Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()