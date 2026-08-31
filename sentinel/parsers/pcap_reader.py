"""Pure-Python standard-library PCAP binary file parser and writer."""

import os
import struct
import time
from typing import Iterator, Tuple, Optional
from sentinel.core.models import DecodedPacket
from sentinel.parsers.binary_decoder import decode_packet

PCAP_MAGIC_MICROSEC = 0xA1B2C3D4
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1
PCAP_MAGIC_NANOSEC = 0xA1B23C4D


class PcapReader:
    """Zero-dependency PCAP binary file parser."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self._endianness = ">"
        self._is_nanosec = False
        self.snaplen = 65535
        self.link_type = 1  # 1 = Ethernet

    def __iter__(self) -> Iterator[DecodedPacket]:
        return self.read_packets()

    def read_packets(self) -> Iterator[DecodedPacket]:
        """Read and decode all packets sequentially from PCAP."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"PCAP file not found: {self.file_path}")

        with open(self.file_path, "rb") as f:
            # 24-byte Global Header
            global_header = f.read(24)
            if len(global_header) < 24:
                return

            magic = struct.unpack("!I", global_header[:4])[0]
            if magic == PCAP_MAGIC_MICROSEC:
                self._endianness = ">"
            elif magic == PCAP_MAGIC_SWAPPED:
                self._endianness = "<"
            elif magic == PCAP_MAGIC_NANOSEC:
                self._endianness = ">"
                self._is_nanosec = True
            else:
                # Check little-endian standard magic
                magic_le = struct.unpack("<I", global_header[:4])[0]
                if magic_le == PCAP_MAGIC_MICROSEC:
                    self._endianness = "<"
                elif magic_le == PCAP_MAGIC_NANOSEC:
                    self._endianness = "<"
                    self._is_nanosec = True
                else:
                    raise ValueError(f"Invalid PCAP magic number: 0x{magic:08x}")

            fmt = f"{self._endianness}IHHiIII"
            _, _, _, _, _, self.snaplen, self.link_type = struct.unpack(fmt, global_header)

            pkt_hdr_fmt = f"{self._endianness}IIII"

            while True:
                pkt_hdr_bytes = f.read(16)
                if len(pkt_hdr_bytes) < 16:
                    break

                ts_sec, ts_usec, incl_len, _ = struct.unpack(pkt_hdr_fmt, pkt_hdr_bytes)
                packet_data = f.read(incl_len)
                if len(packet_data) < incl_len:
                    break

                timestamp = ts_sec + (ts_usec / (1e9 if self._is_nanosec else 1e6))
                decoded = decode_packet(packet_data, timestamp=timestamp)
                yield decoded


class PcapWriter:
    """Zero-dependency PCAP binary file writer."""

    def __init__(self, file_path: str, link_type: int = 1) -> None:
        self.file_path = file_path
        self.link_type = link_type
        self._file = open(file_path, "wb")
        self._write_global_header()

    def _write_global_header(self) -> None:
        # Standard libpcap global header: Magic 0xa1b2c3d4, v2.4, tz 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        header = struct.pack("!IHHiIII", PCAP_MAGIC_MICROSEC, 2, 4, 0, 0, 65535, self.link_type)
        self._file.write(header)
        self._file.flush()

    def write_packet(self, data: bytes, timestamp: Optional[float] = None) -> None:
        """Write raw packet bytes with standard 16-byte packet header."""
        ts = timestamp if timestamp is not None else time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        incl_len = len(data)
        orig_len = len(data)

        header = struct.pack("!IIII", ts_sec, ts_usec, incl_len, orig_len)
        self._file.write(header)
        self._file.write(data)
        self._file.flush()

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
