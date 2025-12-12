import socket
import sys
import time
import struct

def effect():
    print(".", end="", flush=True)
    time.sleep(1)
    
    print(".", end="", flush=True)
    time.sleep(1)
    
    print(".", end="", flush=True)
    time.sleep(1)
    
    print()

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ethernet_frame(data):

    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def start_sniffer():
    print(r"""
    _    _____ _______ _    _ ______ _____  _____  _____ _   _ ______ _______ 
   | |  |  ___|_   _| |  | |  ____|  __ \|_   _|/ ____| \ | |  ____|__   __|
  / _ \ | |__   | | | |__| | |__  | |__) | | | | (___ |  \| | |__     | |   
 / /_\ \|  __|  | | |  __  |  __| |  _  /  | |  \___ \| . ` |  __|    | |   
/ ____ \| |___  | | | |  | | |____| | \ \ _| |_ ____) | |\  | |____   | |   
/_/    \_\____| |_| |_|  |_|______|_|  \_\_____|_____/|_| \_|______|  |_|   
    
    [*] [Linux] AetherisNET v0.2 - Ethernet Decoder
          
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
            

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            print(f"[+] Ethernet Frame | Dest: {dest_mac} | Src: {src_mac} | Protocol: {eth_proto}")
            
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer", end="")
        effect()
        sys.exit(0)


if __name__ == "__main__":
    start_sniffer()