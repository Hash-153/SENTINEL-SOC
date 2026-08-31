"""UDP datagram binary decoder."""

import struct
from typing import Optional, Tuple
from sentinel.core.models import UDPHeader


class UDPDecoder:
    """Dissects raw bytes into a structured UDPHeader dataclass."""

    @staticmethod
    def decode(data: bytes) -> Tuple[Optional[UDPHeader], bytes]:
        """Decode UDP datagram (8 bytes header)."""
        if len(data) < 8:
            return None, data

        src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])

        # UDP payload: total length includes 8-byte header
        payload = data[8:]
        if 8 <= length <= len(data):
            payload = data[8:length]

        header = UDPHeader(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
            payload=payload,
        )
        return header, payload
