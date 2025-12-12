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

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return socket.inet_ntoa(addr)

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
    
    [*] [Linux] AetherisNET v0.3 - IPv4 Layer Decoder
          
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

    print("[*] Sniffer started successfully. Listening for IPv4 traffic", end="")
    effect()

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

          
            if eth_proto == 8:
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                
                print(f"IPv4 Packet | SRC: {src} ==> DEST: {target} | Protocol: {proto}")
            
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer", end="")
        effect()
        sys.exit(0)

if __name__ == "__main__":
    start_sniffer()