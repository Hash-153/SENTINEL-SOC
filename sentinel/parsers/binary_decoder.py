"""Low-level binary protocol decoders for Ethernet and IPv4."""

import socket
import struct
import time
from typing import Optional, Tuple
from sentinel.core.models import (
    EthernetFrame,
    IPv4Header,
    IpProtocol,
    DecodedPacket,
)


def format_mac_address(mac_bytes: bytes) -> str:
    """Format a 6-byte sequence into standard MAC address notation."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def format_ipv4_address(ip_bytes: bytes) -> str:
    """Convert a 4-byte packed IPv4 address to dotted-decimal notation."""
    try:
        return socket.inet_ntoa(ip_bytes)
    except Exception:
        return ".".join(str(b) for b in ip_bytes)


class BinaryDecoder:
    """Zero-dependency bit-level binary network protocol decoder."""

    @staticmethod
    def decode_ethernet(data: bytes) -> Tuple[Optional[EthernetFrame], bytes]:
        """Decode Ethernet II frame header (14 bytes)."""
        if len(data) < 14:
            return None, data

        dst_mac_raw, src_mac_raw, eth_type = struct.unpack("!6s6sH", data[:14])
        payload = data[14:]

        frame = EthernetFrame(
            src_mac=format_mac_address(src_mac_raw),
            dst_mac=format_mac_address(dst_mac_raw),
            eth_type=eth_type,
            payload=payload,
        )
        return frame, payload

    @staticmethod
    def decode_ipv4(data: bytes) -> Tuple[Optional[IPv4Header], bytes]:
        """Decode IPv4 header (minimum 20 bytes)."""
        if len(data) < 20:
            return None, data

        header_fixed = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version_ihl = header_fixed[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4

        if version != 4 or ihl < 20 or len(data) < ihl:
            return None, data

        tos = header_fixed[1]
        total_length = header_fixed[2]
        identification = header_fixed[3]
        flags_fragment = header_fixed[4]
        flags = flags_fragment >> 13
        fragment_offset = flags_fragment & 0x1FFF
        ttl = header_fixed[5]
        protocol_num = header_fixed[6]
        checksum = header_fixed[7]
        src_ip = format_ipv4_address(header_fixed[8])
        dst_ip = format_ipv4_address(header_fixed[9])

        payload = data[ihl:]
        if total_length > 0 and len(data) >= total_length:
            payload = data[ihl:total_length]

        header = IPv4Header(
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=IpProtocol.from_int(protocol_num),
            checksum=checksum,
            src_ip=src_ip,
            dst_ip=dst_ip,
            payload=payload,
        )
        return header, payload


def decode_packet(raw_bytes: bytes, timestamp: Optional[float] = None) -> DecodedPacket:
    """Decode raw wire bytes into a fully populated DecodedPacket dataclass."""
    from sentinel.parsers.tcp_decoder import TCPDecoder
    from sentinel.parsers.udp_decoder import UDPDecoder
    from sentinel.parsers.dns_decoder import DNSDecoder
    from sentinel.parsers.http_decoder import HTTPDecoder

    pkt_ts = timestamp if timestamp is not None else time.time()
    packet = DecodedPacket(
        timestamp=pkt_ts,
        raw_length=len(raw_bytes),
        raw_data=raw_bytes,
    )

    remaining = raw_bytes

    # 1. Attempt Ethernet parsing
    eth_frame, eth_payload = BinaryDecoder.decode_ethernet(remaining)
    if eth_frame and (eth_frame.eth_type == 0x0800 or eth_frame.eth_type == 0x86DD):
        packet.eth = eth_frame
        remaining = eth_payload

    # 2. Attempt IPv4 parsing
    ip_header, ip_payload = BinaryDecoder.decode_ipv4(remaining)
    if ip_header:
        packet.ip = ip_header
        remaining = ip_payload

        # 3. Layer 4 parsing
        if ip_header.protocol == IpProtocol.TCP:
            tcp_header, tcp_payload = TCPDecoder.decode(remaining)
            if tcp_header:
                packet.tcp = tcp_header
                remaining = tcp_payload

                # 4. Layer 7 inspection
                http_trans = HTTPDecoder.decode(tcp_payload, tcp_header.src_port, tcp_header.dst_port)
                if http_trans:
                    packet.http = http_trans

        elif ip_header.protocol == IpProtocol.UDP:
            udp_header, udp_payload = UDPDecoder.decode(remaining)
            if udp_header:
                packet.udp = udp_header
                remaining = udp_payload

                # 4. DNS inspection
                if udp_header.src_port == 53 or udp_header.dst_port == 53:
                    dns_msg = DNSDecoder.decode(udp_payload)
                    if dns_msg:
                        packet.dns = dns_msg

    return packet
