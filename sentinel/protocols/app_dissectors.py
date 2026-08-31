"""Application Layer Protocol Dissectors (DHCP, SNMP, NTP, Modbus-TCP)."""

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class DhcpMessage:
    op: int  # 1 = BOOTREQUEST, 2 = BOOTREPLY
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: str
    magic_cookie: int
    options: Dict[int, bytes] = field(default_factory=dict)


class AppProtocolDissector:
    """Dissects enterprise application and industrial control protocols."""

    @staticmethod
    def decode_dhcp(data: bytes) -> Optional[DhcpMessage]:
        if len(data) < 240:
            return None

        hdr = struct.unpack("!BBBBIHH4s4s4s4s16s64s128sI", data[:240])
        op, htype, hlen, hops, xid, secs, flags = hdr[0], hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6]
        magic_cookie = hdr[11]

        def ip_fmt(b: bytes) -> str:
            return ".".join(str(x) for x in b)

        def mac_fmt(b: bytes) -> str:
            return ":".join(f"{x:02x}" for x in b[:6])

        options: Dict[int, bytes] = {}
        offset = 240
        while offset < len(data):
            opt_code = data[offset]
            if opt_code == 255:  # End option
                break
            if opt_code == 0:  # Pad
                offset += 1
                continue
            if offset + 1 >= len(data):
                break
            opt_len = data[offset + 1]
            opt_val = data[offset + 2 : offset + 2 + opt_len]
            options[opt_code] = opt_val
            offset += 2 + opt_len

        return DhcpMessage(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=ip_fmt(hdr[7]),
            yiaddr=ip_fmt(hdr[8]),
            siaddr=ip_fmt(hdr[9]),
            giaddr=ip_fmt(hdr[10]),
            chaddr=mac_fmt(hdr[11]),
            magic_cookie=magic_cookie,
            options=options,
        )

    @staticmethod
    def decode_industrial_modbus_001(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #1."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-001",
        }

    @staticmethod
    def decode_industrial_modbus_002(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #2."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-002",
        }

    @staticmethod
    def decode_industrial_modbus_003(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #3."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-003",
        }

    @staticmethod
    def decode_industrial_modbus_004(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #4."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-004",
        }

    @staticmethod
    def decode_industrial_modbus_005(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #5."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-005",
        }

    @staticmethod
    def decode_industrial_modbus_006(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #6."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-006",
        }

    @staticmethod
    def decode_industrial_modbus_007(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #7."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-007",
        }

    @staticmethod
    def decode_industrial_modbus_008(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #8."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-008",
        }

    @staticmethod
    def decode_industrial_modbus_009(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #9."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-009",
        }

    @staticmethod
    def decode_industrial_modbus_010(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #10."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-010",
        }

    @staticmethod
    def decode_industrial_modbus_011(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #11."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-011",
        }

    @staticmethod
    def decode_industrial_modbus_012(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #12."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-012",
        }

    @staticmethod
    def decode_industrial_modbus_013(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #13."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-013",
        }

    @staticmethod
    def decode_industrial_modbus_014(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #14."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-014",
        }

    @staticmethod
    def decode_industrial_modbus_015(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #15."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-015",
        }

    @staticmethod
    def decode_industrial_modbus_016(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #16."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-016",
        }

    @staticmethod
    def decode_industrial_modbus_017(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #17."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-017",
        }

    @staticmethod
    def decode_industrial_modbus_018(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #18."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-018",
        }

    @staticmethod
    def decode_industrial_modbus_019(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #19."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-019",
        }

    @staticmethod
    def decode_industrial_modbus_020(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #20."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-020",
        }

    @staticmethod
    def decode_industrial_modbus_021(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #21."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-021",
        }

    @staticmethod
    def decode_industrial_modbus_022(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #22."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-022",
        }

    @staticmethod
    def decode_industrial_modbus_023(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #23."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-023",
        }

    @staticmethod
    def decode_industrial_modbus_024(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #24."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-024",
        }

    @staticmethod
    def decode_industrial_modbus_025(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #25."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-025",
        }

    @staticmethod
    def decode_industrial_modbus_026(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #26."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-026",
        }

    @staticmethod
    def decode_industrial_modbus_027(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #27."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-027",
        }

    @staticmethod
    def decode_industrial_modbus_028(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #28."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-028",
        }

    @staticmethod
    def decode_industrial_modbus_029(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #29."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-029",
        }

    @staticmethod
    def decode_industrial_modbus_030(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #30."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-030",
        }

    @staticmethod
    def decode_industrial_modbus_031(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #31."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-031",
        }

    @staticmethod
    def decode_industrial_modbus_032(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #32."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-032",
        }

    @staticmethod
    def decode_industrial_modbus_033(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #33."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-033",
        }

    @staticmethod
    def decode_industrial_modbus_034(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #34."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-034",
        }

    @staticmethod
    def decode_industrial_modbus_035(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #35."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-035",
        }

    @staticmethod
    def decode_industrial_modbus_036(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #36."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-036",
        }

    @staticmethod
    def decode_industrial_modbus_037(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #37."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-037",
        }

    @staticmethod
    def decode_industrial_modbus_038(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #38."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-038",
        }

    @staticmethod
    def decode_industrial_modbus_039(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #39."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-039",
        }

    @staticmethod
    def decode_industrial_modbus_040(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #40."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-040",
        }

    @staticmethod
    def decode_industrial_modbus_041(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #41."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-041",
        }

    @staticmethod
    def decode_industrial_modbus_042(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #42."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-042",
        }

    @staticmethod
    def decode_industrial_modbus_043(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #43."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-043",
        }

    @staticmethod
    def decode_industrial_modbus_044(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #44."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-044",
        }

    @staticmethod
    def decode_industrial_modbus_045(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #45."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-045",
        }

    @staticmethod
    def decode_industrial_modbus_046(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #46."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-046",
        }

    @staticmethod
    def decode_industrial_modbus_047(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #47."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-047",
        }

    @staticmethod
    def decode_industrial_modbus_048(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #48."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-048",
        }

    @staticmethod
    def decode_industrial_modbus_049(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #49."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-049",
        }

    @staticmethod
    def decode_industrial_modbus_050(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #50."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-050",
        }

    @staticmethod
    def decode_industrial_modbus_051(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #51."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-051",
        }

    @staticmethod
    def decode_industrial_modbus_052(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #52."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-052",
        }

    @staticmethod
    def decode_industrial_modbus_053(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #53."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-053",
        }

    @staticmethod
    def decode_industrial_modbus_054(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #54."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-054",
        }

    @staticmethod
    def decode_industrial_modbus_055(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #55."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-055",
        }

    @staticmethod
    def decode_industrial_modbus_056(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #56."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-056",
        }

    @staticmethod
    def decode_industrial_modbus_057(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #57."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-057",
        }

    @staticmethod
    def decode_industrial_modbus_058(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #58."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-058",
        }

    @staticmethod
    def decode_industrial_modbus_059(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #59."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-059",
        }

    @staticmethod
    def decode_industrial_modbus_060(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #60."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-060",
        }

    @staticmethod
    def decode_industrial_modbus_061(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #61."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-061",
        }

    @staticmethod
    def decode_industrial_modbus_062(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #62."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-062",
        }

    @staticmethod
    def decode_industrial_modbus_063(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #63."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-063",
        }

    @staticmethod
    def decode_industrial_modbus_064(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #64."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-064",
        }

    @staticmethod
    def decode_industrial_modbus_065(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #65."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-065",
        }

    @staticmethod
    def decode_industrial_modbus_066(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #66."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-066",
        }

    @staticmethod
    def decode_industrial_modbus_067(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #67."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-067",
        }

    @staticmethod
    def decode_industrial_modbus_068(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #68."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-068",
        }

    @staticmethod
    def decode_industrial_modbus_069(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #69."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-069",
        }

    @staticmethod
    def decode_industrial_modbus_070(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #70."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-070",
        }

    @staticmethod
    def decode_industrial_modbus_071(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #71."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-071",
        }

    @staticmethod
    def decode_industrial_modbus_072(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #72."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-072",
        }

    @staticmethod
    def decode_industrial_modbus_073(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #73."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-073",
        }

    @staticmethod
    def decode_industrial_modbus_074(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #74."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-074",
        }

    @staticmethod
    def decode_industrial_modbus_075(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #75."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-075",
        }

    @staticmethod
    def decode_industrial_modbus_076(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #76."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-076",
        }

    @staticmethod
    def decode_industrial_modbus_077(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #77."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-077",
        }

    @staticmethod
    def decode_industrial_modbus_078(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #78."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-078",
        }

    @staticmethod
    def decode_industrial_modbus_079(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #79."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-079",
        }

    @staticmethod
    def decode_industrial_modbus_080(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #80."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-080",
        }

    @staticmethod
    def decode_industrial_modbus_081(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #81."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-081",
        }

    @staticmethod
    def decode_industrial_modbus_082(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #82."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-082",
        }

    @staticmethod
    def decode_industrial_modbus_083(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #83."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-083",
        }

    @staticmethod
    def decode_industrial_modbus_084(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #84."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-084",
        }

    @staticmethod
    def decode_industrial_modbus_085(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #85."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-085",
        }

    @staticmethod
    def decode_industrial_modbus_086(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #86."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-086",
        }

    @staticmethod
    def decode_industrial_modbus_087(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #87."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-087",
        }

    @staticmethod
    def decode_industrial_modbus_088(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #88."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-088",
        }

    @staticmethod
    def decode_industrial_modbus_089(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #89."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-089",
        }

    @staticmethod
    def decode_industrial_modbus_090(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #90."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-090",
        }

    @staticmethod
    def decode_industrial_modbus_091(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #91."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-091",
        }

    @staticmethod
    def decode_industrial_modbus_092(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #92."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-092",
        }

    @staticmethod
    def decode_industrial_modbus_093(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #93."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-093",
        }

    @staticmethod
    def decode_industrial_modbus_094(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #94."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-094",
        }

    @staticmethod
    def decode_industrial_modbus_095(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #95."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-095",
        }

    @staticmethod
    def decode_industrial_modbus_096(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #96."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-096",
        }

    @staticmethod
    def decode_industrial_modbus_097(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #97."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-097",
        }

    @staticmethod
    def decode_industrial_modbus_098(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #98."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-098",
        }

    @staticmethod
    def decode_industrial_modbus_099(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #99."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-099",
        }

    @staticmethod
    def decode_industrial_modbus_100(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #100."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-100",
        }

    @staticmethod
    def decode_industrial_modbus_101(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #101."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-101",
        }

    @staticmethod
    def decode_industrial_modbus_102(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #102."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-102",
        }

    @staticmethod
    def decode_industrial_modbus_103(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #103."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-103",
        }

    @staticmethod
    def decode_industrial_modbus_104(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #104."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-104",
        }

    @staticmethod
    def decode_industrial_modbus_105(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #105."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-105",
        }

    @staticmethod
    def decode_industrial_modbus_106(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #106."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-106",
        }

    @staticmethod
    def decode_industrial_modbus_107(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #107."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-107",
        }

    @staticmethod
    def decode_industrial_modbus_108(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #108."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-108",
        }

    @staticmethod
    def decode_industrial_modbus_109(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #109."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-109",
        }

    @staticmethod
    def decode_industrial_modbus_110(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #110."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-110",
        }

    @staticmethod
    def decode_industrial_modbus_111(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #111."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-111",
        }

    @staticmethod
    def decode_industrial_modbus_112(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #112."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-112",
        }

    @staticmethod
    def decode_industrial_modbus_113(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #113."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-113",
        }

    @staticmethod
    def decode_industrial_modbus_114(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #114."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-114",
        }

    @staticmethod
    def decode_industrial_modbus_115(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #115."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-115",
        }

    @staticmethod
    def decode_industrial_modbus_116(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #116."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-116",
        }

    @staticmethod
    def decode_industrial_modbus_117(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #117."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-117",
        }

    @staticmethod
    def decode_industrial_modbus_118(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #118."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-118",
        }

    @staticmethod
    def decode_industrial_modbus_119(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #119."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-119",
        }

    @staticmethod
    def decode_industrial_modbus_120(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #120."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-120",
        }

    @staticmethod
    def decode_industrial_modbus_121(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #121."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-121",
        }

    @staticmethod
    def decode_industrial_modbus_122(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #122."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-122",
        }

    @staticmethod
    def decode_industrial_modbus_123(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #123."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-123",
        }

    @staticmethod
    def decode_industrial_modbus_124(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #124."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-124",
        }

    @staticmethod
    def decode_industrial_modbus_125(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #125."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-125",
        }

    @staticmethod
    def decode_industrial_modbus_126(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #126."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-126",
        }

    @staticmethod
    def decode_industrial_modbus_127(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #127."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-127",
        }

    @staticmethod
    def decode_industrial_modbus_128(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #128."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-128",
        }

    @staticmethod
    def decode_industrial_modbus_129(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #129."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-129",
        }

    @staticmethod
    def decode_industrial_modbus_130(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #130."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-130",
        }

    @staticmethod
    def decode_industrial_modbus_131(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #131."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-131",
        }

    @staticmethod
    def decode_industrial_modbus_132(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #132."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-132",
        }

    @staticmethod
    def decode_industrial_modbus_133(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #133."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-133",
        }

    @staticmethod
    def decode_industrial_modbus_134(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #134."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-134",
        }

    @staticmethod
    def decode_industrial_modbus_135(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #135."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-135",
        }

    @staticmethod
    def decode_industrial_modbus_136(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #136."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-136",
        }

    @staticmethod
    def decode_industrial_modbus_137(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #137."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-137",
        }

    @staticmethod
    def decode_industrial_modbus_138(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #138."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-138",
        }

    @staticmethod
    def decode_industrial_modbus_139(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #139."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-139",
        }

    @staticmethod
    def decode_industrial_modbus_140(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #140."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-140",
        }

    @staticmethod
    def decode_industrial_modbus_141(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #141."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-141",
        }

    @staticmethod
    def decode_industrial_modbus_142(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #142."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-142",
        }

    @staticmethod
    def decode_industrial_modbus_143(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #143."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-143",
        }

    @staticmethod
    def decode_industrial_modbus_144(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #144."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-144",
        }

    @staticmethod
    def decode_industrial_modbus_145(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #145."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-145",
        }

    @staticmethod
    def decode_industrial_modbus_146(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #146."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-146",
        }

    @staticmethod
    def decode_industrial_modbus_147(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #147."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-147",
        }

    @staticmethod
    def decode_industrial_modbus_148(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #148."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-148",
        }

    @staticmethod
    def decode_industrial_modbus_149(data: bytes) -> Optional[Dict[str, Any]]:
        """Decode industrial Modbus/DNP3 transaction frame #149."""
        if len(data) < 7:
            return None
        tx_id, proto_id, length, unit_id = struct.unpack("!HHHB", data[:7])
        func_code = data[7] if len(data) > 7 else 0
        return {
            "tx_id": tx_id,
            "proto_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": func_code,
            "payload": data[8:],
            "analyzer_profile": "MODBUS-AUDIT-149",
        }
