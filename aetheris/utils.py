import socket
import struct
import time
from datetime import datetime


class PcapLogger:
    def __init__(self, filename):
        self.filename = filename
        self._write_global_header()

    def _write_global_header(self):
        global_header = struct.pack('<I H H i I I I',
            0xa1b2c3d4, 2, 4, 0, 0, 65535, 1
        )
        with open(self.filename, 'wb') as f:
            f.write(global_header)

    def write_packet(self, raw_data):
        ts = time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1000000)
        length = len(raw_data)
        pkt_header = struct.pack('<I I I I', sec, usec, length, length)
        with open(self.filename, 'ab') as f:
            f.write(pkt_header)
            f.write(raw_data)


pcap_engine = None


def init_pcap(filename):
    global pcap_engine
    pcap_engine = PcapLogger(filename)


def save_pcap(raw_data):
    if pcap_engine:
        pcap_engine.write_packet(raw_data)


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4(addr):
    return socket.inet_ntoa(addr)


def log_threat(message, log_file):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
