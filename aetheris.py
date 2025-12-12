import socket
import sys

def start_sniffer():
    print("[*] AetherisNET: Initializing Raw Socket Engine...")

    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[!] Refused acces.")
        print("[!] Raw Sockets needs ROOT permisions.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Socket creation error: {e}")
        sys.exit(1)

    print("[*] Engine Online. Waiting for packets (CTRL+C to stop)...")
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            
    
            print(f"> Packet intercepted: {len(raw_data)} bytes from {addr[0]}")
            
    except KeyboardInterrupt:
        print("\n[*] AetherisNET: Shutting down.")
        sys.exit(0)

if __name__ == "__main__":
    start_sniffer()