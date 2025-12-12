import socket
import sys
import time

def effect():
    print(".", end="", flush=True)
    time.sleep(1)
    
    print(".", end="", flush=True)
    time.sleep(1)
    
    print(".", end="", flush=True)
    time.sleep(1)
    
    print()

def start_sniffer():
    print(r"""
    _    _____ _______ _    _ ______ _____  _____  _____ _   _ ______ _______ 
   | |  |  ___|_   _| |  | |  ____|  __ \|_   _|/ ____| \ | |  ____|__   __|
  / _ \ | |__   | | | |__| | |__  | |__) | | | | (___ |  \| | |__     | |   
 / /_\ \|  __|  | | |  __  |  __| |  _  /  | |  \___ \| . ` |  __|    | |   
/ ____ \| |___  | | | |  | | |____| | \ \ _| |_ ____) | |\  | |____   | |   
/_/    \_\____| |_| |_|  |_|______|_|  \_\_____|_____/|_| \_|______|  |_|   
    
    [*] [Linux] AetherisNET v0.1 - Network Traffic Analyzer
          
    """)

    ETH_P_ALL = 3

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError:
        print("\n[!] CRITICAL ERROR: Access denied.")
        print("[!] Raw sockets require ROOT privileges. Please run with 'sudo'.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error initializing socket: {e}")
        sys.exit(1)

    print("[*] Sniffer started successfully. Listening for packets", end="")
    effect()


    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            print(f" > Packet captured: {len(raw_data)} bytes | Interface: {addr[0]}")
            
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer",end="")
        effect()
        sys.exit(0)


if __name__ == "__main__":
    start_sniffer()