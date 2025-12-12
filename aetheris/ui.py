import curses
import socket
import time
from collections import defaultdict
from .parsers import ethernet_frame, ipv4_packet, tcp_segment, udp_segment
from .utils import log_threat, get_local_ip 

ETH_P_ALL = 3
MAX_LOGS = 10 

stats = {
    "TCP": 0, "UDP": 0, "ICMP": 0, "TOTAL": 0, "ALERTS": 0
}
syn_counter = defaultdict(int)
logs = [] 

def start_dashboard(stdscr, args):
    LOCAL_IP = get_local_ip()
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
            stdscr.refresh()
            time.sleep(0.5)
            continue

        try:
            title = f" AetherisNET v1.4 - Monitoring: {args.interface if args.interface else 'ALL'} "
            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
            safe_width = width - 1
            stdscr.addstr(0, 0, (title + " " * width)[:safe_width]) 
            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)

            stdscr.addstr(1, 2, f"MY IP: {LOCAL_IP}", curses.color_pair(4))

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
                        
                        if src == LOCAL_IP:
                            log_msg = f"[OUT] Connecting to {target}:{dest_port}"
                        else:
                            syn_counter[src] += 1
                            if syn_counter[src] > args.threshold:
                                stats['ALERTS'] += 1
                                msg = f"ALERT: SYN SCAN from {src} -> {target}"
                                log_msg = f"[!!!] {msg}"
                                log_threat(msg, args.log)
                            else:
                                log_msg = f"[?] INBOUND SYN: {src} -> {target}"
                        
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