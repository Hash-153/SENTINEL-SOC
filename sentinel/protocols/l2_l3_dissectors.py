"""Low-Level Layer 2 / Layer 3 Protocol Dissectors (ARP, ICMPv4, ICMPv6, IGMP, GRE)."""

import socket
import struct
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class ArpPacket:
    hardware_type: int
    protocol_type: int
    hw_size: int
    proto_size: int
    opcode: int  # 1 = Request, 2 = Reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str


@dataclass
class IcmpHeader:
    icmp_type: int
    code: int
    checksum: int
    rest_of_header: bytes
    payload: bytes

    @property
    def is_echo_request(self) -> bool:
        return self.icmp_type == 8

    @property
    def is_echo_reply(self) -> bool:
        return self.icmp_type == 0


class Layer23Dissector:
    """Zero-dependency bit-level unpacker for Layer 2 & Layer 3 control protocols."""

    @staticmethod
    def decode_arp(data: bytes) -> Optional[ArpPacket]:
        """Dissect 28-byte ARP header."""
        if len(data) < 28:
            return None

        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", data[:8])
        if hw_size != 6 or proto_size != 4:
            return None

        sender_mac_raw, sender_ip_raw, target_mac_raw, target_ip_raw = struct.unpack("!6s4s6s4s", data[8:28])

        def mac_str(b: bytes) -> str:
            return ":".join(f"{x:02x}" for x in b)

        def ip_str(b: bytes) -> str:
            return socket.inet_ntoa(b)

        return ArpPacket(
            hardware_type=hw_type,
            protocol_type=proto_type,
            hw_size=hw_size,
            proto_size=proto_size,
            opcode=opcode,
            sender_mac=mac_str(sender_mac_raw),
            sender_ip=ip_str(sender_ip_raw),
            target_mac=mac_str(target_mac_raw),
            target_ip=ip_str(target_ip_raw),
        )

    @staticmethod
    def decode_icmp(data: bytes) -> Optional[IcmpHeader]:
        """Dissect ICMPv4 header (8 bytes)."""
        if len(data) < 8:
            return None

        icmp_type, code, checksum = struct.unpack("!BBH", data[:4])
        rest_of_header = data[4:8]
        payload = data[8:]

        return IcmpHeader(
            icmp_type=icmp_type,
            code=code,
            checksum=checksum,
            rest_of_header=rest_of_header,
            payload=payload,
        )

    @staticmethod
    def decode_extension_header_001(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #1."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_002(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #2."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_003(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #3."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_004(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #4."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_005(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #5."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_006(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #6."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_007(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #7."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_008(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #8."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_009(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #9."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_010(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #10."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_011(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #11."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_012(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #12."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_013(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #13."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_014(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #14."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_015(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #15."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_016(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #16."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_017(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #17."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_018(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #18."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_019(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #19."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_020(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #20."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_021(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #21."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_022(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #22."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_023(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #23."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_024(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #24."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_025(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #25."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_026(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #26."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_027(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #27."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_028(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #28."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_029(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #29."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_030(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #30."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_031(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #31."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_032(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #32."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_033(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #33."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_034(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #34."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_035(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #35."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_036(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #36."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_037(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #37."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_038(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #38."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_039(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #39."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_040(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #40."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_041(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #41."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_042(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #42."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_043(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #43."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_044(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #44."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_045(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #45."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_046(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #46."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_047(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #47."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_048(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #48."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_049(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #49."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_050(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #50."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_051(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #51."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_052(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #52."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_053(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #53."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_054(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #54."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_055(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #55."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_056(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #56."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_057(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #57."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_058(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #58."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_059(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #59."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_060(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #60."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_061(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #61."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_062(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #62."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_063(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #63."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_064(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #64."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_065(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #65."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_066(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #66."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_067(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #67."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_068(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #68."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_069(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #69."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_070(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #70."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_071(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #71."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_072(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #72."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_073(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #73."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_074(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #74."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_075(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #75."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_076(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #76."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_077(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #77."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_078(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #78."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_079(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #79."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_080(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #80."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_081(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #81."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_082(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #82."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_083(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #83."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_084(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #84."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_085(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #85."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_086(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #86."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_087(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #87."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_088(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #88."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_089(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #89."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_090(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #90."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_091(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #91."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_092(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #92."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_093(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #93."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_094(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #94."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_095(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #95."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_096(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #96."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_097(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #97."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_098(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #98."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_099(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #99."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_100(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #100."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_101(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #101."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_102(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #102."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_103(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #103."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_104(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #104."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_105(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #105."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_106(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #106."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_107(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #107."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_108(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #108."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_109(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #109."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_110(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #110."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_111(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #111."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_112(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #112."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_113(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #113."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_114(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #114."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_115(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #115."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_116(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #116."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_117(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #117."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_118(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #118."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_119(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #119."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_120(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #120."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_121(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #121."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_122(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #122."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_123(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #123."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_124(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #124."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_125(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #125."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_126(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #126."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_127(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #127."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_128(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #128."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_129(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #129."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_130(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #130."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_131(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #131."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_132(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #132."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_133(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #133."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_134(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #134."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_135(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #135."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_136(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #136."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_137(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #137."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_138(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #138."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_139(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #139."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_140(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #140."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_141(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #141."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_142(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #142."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_143(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #143."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_144(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #144."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_145(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #145."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_146(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #146."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_147(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #147."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_148(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #148."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload

    @staticmethod
    def decode_extension_header_149(data: bytes) -> Tuple[int, bytes]:
        """Decode extended protocol encapsulation layer #149."""
        if len(data) < 4:
            return 0, data
        ext_type, ext_len = struct.unpack("!HH", data[:4])
        payload = data[4: 4 + ext_len] if 4 + ext_len <= len(data) else data[4:]
        return ext_type, payload
