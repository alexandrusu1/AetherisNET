import socket
import sys
import time
import struct
import curses
import argparse
from datetime import datetime
from collections import defaultdict

ETH_P_ALL = 3

stats = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "TOTAL": 0,
    "ALERTS": 0
}

syn_counter = defaultdict(int)
logs = [] 
MAX_LOGS = 10 

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4(addr):
    return socket.inet_ntoa(addr)

def log_threat(message, log_file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

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

def draw_dashboard(stdscr, args):
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)

    curses.curs_set(0)
    stdscr.nodelay(True) 

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        if args.interface:
            sniffer.bind((args.interface, 0))
        sniffer.setblocking(False) 
    except PermissionError:
        stdscr.addstr(0, 0, "CRITICAL ERROR: Run with SUDO!", curses.color_pair(2))
        stdscr.refresh()
        time.sleep(3)
        return
    except OSError:
        stdscr.addstr(0, 0, f"ERROR: Interface {args.interface} not found!", curses.color_pair(2))
        stdscr.refresh()
        time.sleep(3)
        return

    while True:
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        if height < 12 or width < 40:
            stdscr.addstr(0, 0, "Terminal too small!", curses.color_pair(2))
            stdscr.addstr(1, 0, "Please resize...", curses.color_pair(2))
            stdscr.refresh()
            time.sleep(0.5)
            continue

        try:
            title = f" AetherisNET v1.2 - Monitoring: {args.interface if args.interface else 'ALL'} "
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            safe_width = width - 1
            stdscr.addstr(0, 0, (title + " " * width)[:safe_width]) 
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

            stdscr.addstr(2, 2, f"TOTAL PACKETS: {stats['TOTAL']}")
            stdscr.addstr(3, 2, f"TCP TRAFFIC:   {stats['TCP']}", curses.color_pair(1))
            stdscr.addstr(4, 2, f"UDP TRAFFIC:   {stats['UDP']}", curses.color_pair(3))
            
            alert_style = curses.color_pair(2) | curses.A_BOLD if stats['ALERTS'] > 0 else curses.color_pair(1)
            stdscr.addstr(6, 2, f"[!] THREATS DETECTED: {stats['ALERTS']}", alert_style)
            
            if stats['ALERTS'] > 0:
                stdscr.addstr(6, 40, f"(Logged to {args.log})", curses.color_pair(3))

            stdscr.addstr(8, 0, "-" * (width - 1)) 
            stdscr.addstr(9, 2, "LIVE TRAFFIC LOGS:", curses.A_UNDERLINE)

            row = 11
            for log in logs[-MAX_LOGS:]: 
                if row < height - 1:
                    color = curses.color_pair(2) if "ALERT" in log else curses.color_pair(1)
                    stdscr.addstr(row, 2, log[:width-4], color)
                    row += 1
        except curses.error:
            pass

        try:
            raw_data, addr = sniffer.recvfrom(65535)
            stats['TOTAL'] += 1
            
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            if eth_proto == 8: 
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                
                log_msg = ""

                if proto == 6: 
                    stats['TCP'] += 1
                    src_port, dest_port, seq, ack, flags, data = tcp_segment(data)
                    
                    if (flags & 0x02) and not (flags & 0x10): 
                        syn_counter[src] += 1
                        if syn_counter[src] > args.threshold:
                            stats['ALERTS'] += 1
                            msg = f"ALERT: SYN SCAN from {src} -> {target}"
                            log_msg = f"[!!!] {msg}"
                            log_threat(msg, args.log)
                        else:
                            log_msg = f"[?] SUSPICIOUS: SYN packet {src} -> {target}"
                    else:
                        log_msg = f"[TCP] {src}:{src_port} -> {target}:{dest_port}"

                elif proto == 17: 
                    stats['UDP'] += 1
                    src_port, dest_port, size, data = udp_segment(data)
                    log_msg = f"[UDP] {src}:{src_port} -> {target}:{dest_port}"
                
                else:
                    stats['ICMP'] += 1
                    log_msg = f"[IPv4-Other] {src} -> {target}"

                if log_msg:
                    logs.append(log_msg)
                    if len(logs) > MAX_LOGS:
                        logs.pop(0)
                        
        except BlockingIOError:
            time.sleep(0.01)
        except Exception:
            pass

        try:
            key = stdscr.getch()
            if key == ord('q'):
                break
        except:
            pass
        
        stdscr.refresh()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AetherisNET - Raw Socket IDS & Traffic Analyzer")
    parser.add_argument("-i", "--interface", help="Network interface to bind to (e.g., wlan0, eth0)", default=None)
    parser.add_argument("-t", "--threshold", type=int, help="SYN Flood detection threshold (default: 15)", default=15)
    parser.add_argument("-l", "--log", help="Log file path (default: threats.log)", default="threats.log")
    
    args = parser.parse_args()
    
    curses.wrapper(draw_dashboard, args)