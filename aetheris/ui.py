import curses
import socket
import time
from collections import defaultdict, deque
from .parsers import ethernet_frame, ipv4_packet, tcp_segment, udp_segment, parse_application_layer, arp_packet
from .utils import log_threat, get_local_ip, save_pcap

ETH_P_ALL = 3
MAX_LOGS = 12 
HISTORY_SIZE = 60 

stats = {
    "TCP": 0, "UDP": 0, "ICMP": 0, "TOTAL": 0, "ALERTS": 0, "PPS": 0
}
syn_counter = defaultdict(int)
logs = [] 
traffic_history = deque([0] * HISTORY_SIZE, maxlen=HISTORY_SIZE)

def draw_box(stdscr, y, x, h, w, title, color_pair):
    try:
        stdscr.attron(color_pair)
        stdscr.addch(y, x, curses.ACS_ULCORNER)
        stdscr.addch(y, x + w - 1, curses.ACS_URCORNER)
        stdscr.addch(y + h - 1, x, curses.ACS_LLCORNER)
        stdscr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
        stdscr.hline(y, x + 1, curses.ACS_HLINE, w - 2)
        stdscr.hline(y + h - 1, x + 1, curses.ACS_HLINE, w - 2)
        stdscr.vline(y + 1, x, curses.ACS_VLINE, h - 2)
        stdscr.vline(y + 1, x + w - 1, curses.ACS_VLINE, h - 2)
        if title:
            stdscr.addstr(y, x + 2, f" {title} ")
        stdscr.attroff(color_pair)
    except curses.error:
        pass

def draw_chart(stdscr, y, x, h, w, data, color_pair):
    if not data: return
    max_val = max(data) if max(data) > 0 else 1
    
    for i, value in enumerate(data):
        if i >= w - 2: break
        bar_height = int((value / max_val) * (h - 2))
        col_x = x + 1 + i
        for row in range(bar_height):
            plot_y = (y + h - 2) - row
            try:
                stdscr.addstr(plot_y, col_x, "█", color_pair)
            except: pass

def start_dashboard(stdscr, args):
    LOCAL_IP = get_local_ip()
    
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)

    curses.curs_set(0)
    stdscr.nodelay(True) 

    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        if args.interface:
            sniffer.bind((args.interface, 0))
        sniffer.setblocking(False) 
    except Exception as e:
        stdscr.addstr(0,0, f"Error: {e}", curses.color_pair(2))
        stdscr.refresh()
        time.sleep(2)
        return

    last_time = time.time()
    packet_count_second = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        current_time = time.time()
        if current_time - last_time >= 1:
            stats['PPS'] = packet_count_second
            traffic_history.append(packet_count_second)
            packet_count_second = 0
            last_time = current_time

        draw_box(stdscr, 0, 0, 3, w, "AetherisNET IDS", curses.color_pair(4))
        stdscr.addstr(1, 2, f"IFACE: {args.interface if args.interface else 'ALL'} | IP: {LOCAL_IP} | PPS: {stats['PPS']}", curses.color_pair(1))

        stats_width = 30
        draw_box(stdscr, 3, 0, 10, stats_width, "Statistics", curses.color_pair(4))
        stdscr.addstr(4, 2, f"TCP Pkts:  {stats['TCP']}", curses.color_pair(1))
        stdscr.addstr(5, 2, f"UDP Pkts:  {stats['UDP']}", curses.color_pair(3))
        stdscr.addstr(6, 2, f"ICMP Pkts: {stats['ICMP']}", curses.color_pair(5))
        stdscr.addstr(7, 2, f"TOTAL:     {stats['TOTAL']}", curses.color_pair(4))
        
        alert_color = curses.color_pair(2) | curses.A_BLINK if stats['ALERTS'] > 0 else curses.color_pair(1)
        stdscr.addstr(9, 2, f"THREATS:   {stats['ALERTS']}", alert_color)

        graph_width = w - stats_width
        draw_box(stdscr, 3, stats_width, 10, graph_width, "Traffic Load (PPS)", curses.color_pair(4))
        draw_chart(stdscr, 3, stats_width, 10, graph_width, list(traffic_history), curses.color_pair(5))

        logs_height = h - 13
        if logs_height > 3:
            draw_box(stdscr, 13, 0, logs_height, w, "Live Event Log", curses.color_pair(4))
            row = 14
            for log in logs[- (logs_height - 2):]:
                if row < h - 1:
                    c = curses.color_pair(2) if "ALERT" in log or "[!!!]" in log else curses.color_pair(1)
                    stdscr.addstr(row, 2, log[:w-4], c)
                    row += 1

        try:
            for _ in range(15):
                raw_data, addr = sniffer.recvfrom(65535)

                if args.pcap:
                    save_pcap(raw_data)

                packet_count_second += 1
                stats['TOTAL'] += 1

                dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

      
                if eth_proto == 0x0800:
                    version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                   
                    if args.host_only and src != LOCAL_IP and target != LOCAL_IP:
                        continue
                    log_msg = ""
                    app_layer_info = None

                    if proto == 6:
                        stats['TCP'] += 1
                        src_port, dest_port, seq, ack, flags, data = tcp_segment(data)
                        
                        app_layer_info = parse_application_layer(data, src_port, dest_port)

                        if app_layer_info:
                            if "Encrypted Data" not in app_layer_info:
                                log_msg = app_layer_info
                        
                        elif (flags & 0x02) and not (flags & 0x10):
                            
                            if not args.host_only or src != LOCAL_IP:
                                syn_counter[src] += 1
                                if syn_counter[src] > args.threshold:
                                    stats['ALERTS'] += 1
                                    msg = f"ALERT: SYN FLOOD {src} -> {target}"
                                    log_msg = f"[!!!] {msg}"
                                    log_threat(msg, args.log)
                                else:
                                    log_msg = f"[S] SYN: {src} -> {target}"
                        elif (flags & 0x01) and (flags & 0x20) and (flags & 0x08):
                             stats['ALERTS'] += 1
                             msg = f"ALERT: XMAS SCAN {src}"
                             log_msg = f"[!!!] {msg}"
                             log_threat(msg, args.log)
                        else:
                            log_msg = f"[TCP] {src}:{src_port} -> {dest_port} F:{flags}"

                    elif proto == 17:
                        stats['UDP'] += 1
                        src_port, dest_port, size, data = udp_segment(data)
                        
                        if src_port in [1900, 5353] or dest_port in [1900, 5353]:
                            continue

                        app_layer_info = parse_application_layer(data, src_port, dest_port)
                        if app_layer_info:
                            log_msg = app_layer_info
                        else:
                            log_msg = f"[UDP] {src}:{src_port} -> {dest_port}"
                    
                    elif proto == 1:
                        stats['ICMP'] += 1
                        log_msg = f"[ICMP] Ping {src} -> {target}"

                    if log_msg:
                        logs.append(log_msg)
                        if len(logs) > 50: logs.pop(0)

                elif eth_proto == 0x0806:
 
                    try:
                        sender_ip, target_ip, opcode, sender_mac, target_mac = arp_packet(data)
                        log_msg = f"[ARP] {sender_ip} -> {target_ip} ({opcode})"
                        stats['TOTAL'] += 0
                    except Exception:
                        pass

            else:

                continue

        except BlockingIOError:
            pass
        except Exception:
            pass

        try:
            key = stdscr.getch()
            if key == ord('q'): break
        except: pass
        
        stdscr.refresh()
        time.sleep(0.05)