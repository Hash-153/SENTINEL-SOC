"""TCP segment binary decoder."""

import struct
from typing import Optional, Tuple
from sentinel.core.models import TCPHeader


class TCPDecoder:
    """Dissects raw bytes into a structured TCPHeader dataclass."""

    @staticmethod
    def decode(data: bytes) -> Tuple[Optional[TCPHeader], bytes]:
        """Decode TCP segment (minimum 20 bytes)."""
        if len(data) < 20:
            return None, data

        raw_header = struct.unpack("!HHLLBBHHH", data[:20])
        src_port = raw_header[0]
        dst_port = raw_header[1]
        seq_num = raw_header[2]
        ack_num = raw_header[3]
        data_offset_byte = raw_header[4]
        flags_byte = raw_header[5]
        window_size = raw_header[6]
        checksum = raw_header[7]
        urgent_pointer = raw_header[8]

        data_offset = (data_offset_byte >> 4) * 4
        if data_offset < 20 or len(data) < data_offset:
            return None, data

        flag_fin = bool(flags_byte & 0x01)
        flag_syn = bool(flags_byte & 0x02)
        flag_rst = bool(flags_byte & 0x04)
        flag_psh = bool(flags_byte & 0x08)
        flag_ack = bool(flags_byte & 0x10)
        flag_urg = bool(flags_byte & 0x20)
        flag_ece = bool(flags_byte & 0x40)
        flag_cwr = bool(flags_byte & 0x80)

        payload = data[data_offset:]

        header = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            data_offset=data_offset,
            flags_raw=flags_byte,
            flag_fin=flag_fin,
            flag_syn=flag_syn,
            flag_rst=flag_rst,
            flag_psh=flag_psh,
            flag_ack=flag_ack,
            flag_urg=flag_urg,
            flag_ece=flag_ece,
            flag_cwr=flag_cwr,
            window_size=window_size,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            payload=payload,
        )
        return header, payload
