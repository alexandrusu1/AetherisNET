import struct
import socket
from .utils import get_mac_addr, ipv4

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

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

def arp_packet(data):
    htype, ptype, hlen, plen, opcode, sender_mac, sender_ip, target_mac, target_ip = struct.unpack('! 2s 2s 1s 1s 2s 6s 4s 6s 4s', data[:28])
    return socket.inet_ntoa(sender_ip), socket.inet_ntoa(target_ip), int.from_bytes(opcode, "big")

def parse_application_layer(data, src_port, dest_port):
    if src_port in [80, 8080] or dest_port in [80, 8080]:
        try:
            text = data.decode('utf-8', errors='ignore')
            if "GET /" in text or "POST /" in text or "HTTP/1." in text:
                lines = text.split('\r\n')
                request_line = lines[0][:50]
                host = next((line for line in lines if "Host:" in line), "")
                return f"[HTTP] {request_line} {host}"
        except:
            pass

    if src_port == 443 or dest_port == 443:
        try:
            if len(data) > 0 and data[0] == 0x16: 
                return f"[HTTPS] TLS Handshake"
            elif len(data) > 0 and data[0] == 0x17:
                return f"[HTTPS] Encrypted Data"
        except:
            pass

    if src_port == 53 or dest_port == 53:
        try:
            idx = 12
            domain_parts = []
            while idx < len(data):
                length = data[idx]
                if length == 0: break
                if length > 63: return "[DNS] (Complex)"
                idx += 1
                domain_parts.append(data[idx:idx+length].decode('utf-8', errors='ignore'))
                idx += length
            
            if domain_parts:
                domain = ".".join(domain_parts)
                if len(domain) > 3:
                    return f"[DNS] Query: {domain}"
        except:
            pass

    return None