import socket
import sys
import time
import struct
from collections import defaultdict

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

syn_counter = defaultdict(int)
THRESHOLD = 15 

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

def ipv4(addr):
    return socket.inet_ntoa(addr)

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x3F 
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

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
    
    [*] [Linux] AetherisNET v0.5 - Security Brain (IDS Engine)
          
    """)

    ETH_P_ALL = 3

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except PermissionError:
        print(f"\n{RED}[!] CRITICAL ERROR: Access denied. Run with sudo.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[*] IDS Engine Initialized. Watching for Port Scanners{RESET}", end="")
    effect()

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            if eth_proto == 8: 
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                
                if proto == 6: 
                    src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)

                    if (flags & 0x02) and not (flags & 0x10):
                        syn_counter[src] += 1
                        
                        if syn_counter[src] > THRESHOLD:
                            print(f"{RED}[!!!] ALERT: PORT SCAN DETECTED from {src} -> Targets Hit: {syn_counter[src]}{RESET}")
                        else:
                            print(f"{YELLOW}[?] Suspicious SYN Packet: {src}:{src_port} -> {target}:{dest_port}{RESET}")
                            
                    else:
                        pass
                
                
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer", end="")
        effect()
        sys.exit(0)

if __name__ == "__main__":
    start_sniffer()