"""DNS wire protocol binary decoder and label unpacker."""

import struct
from typing import Optional, Tuple, List
from sentinel.core.models import DNSMessage, DNSQuestion, DNSRecord


class DNSDecoder:
    """Zero-dependency DNS packet parser with pointer decompression."""

    @staticmethod
    def _decode_name(data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
        """Decode standard DNS label sequence and compression offset pointers."""
        if depth > 10:  # Prevent infinite loops in corrupted pointers
            return "<invalid-ptr-loop>", offset

        labels: List[str] = []
        original_offset = offset
        jumped = False

        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break

            # Check if pointer (top 2 bits set: 0xC0)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer_offset = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                pointed_name, _ = DNSDecoder._decode_name(data, pointer_offset, depth + 1)
                labels.append(pointed_name)
                break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                label = data[offset : offset + length].decode("ascii", errors="replace")
                labels.append(label)
                offset += length

        final_name = ".".join(labels)
        return final_name, (original_offset if jumped else offset)

    @classmethod
    def decode(cls, data: bytes) -> Optional[DNSMessage]:
        """Decode raw DNS wire data."""
        if len(data) < 12:
            return None

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])

        is_response = bool((flags >> 15) & 0x01)
        opcode = (flags >> 11) & 0x0F
        authoritative = bool((flags >> 10) & 0x01)
        truncated = bool((flags >> 9) & 0x01)
        recursion_desired = bool((flags >> 8) & 0x01)
        recursion_available = bool((flags >> 7) & 0x01)
        response_code = flags & 0x0F

        message = DNSMessage(
            tx_id=tx_id,
            is_response=is_response,
            opcode=opcode,
            authoritative=authoritative,
            truncated=truncated,
            recursion_desired=recursion_desired,
            recursion_available=recursion_available,
            response_code=response_code,
        )

        offset = 12

        # Parse Questions
        for _ in range(min(qdcount, 50)):
            if offset >= len(data):
                break
            qname, offset = cls._decode_name(data, offset)
            if offset + 4 <= len(data):
                qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
                offset += 4
                message.questions.append(DNSQuestion(name=qname, qtype=qtype, qclass=qclass))

        # Parse Answers
        for _ in range(min(ancount, 50)):
            if offset >= len(data):
                break
            rname, offset = cls._decode_name(data, offset)
            if offset + 10 <= len(data):
                rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
                offset += 10
                rdata_bytes = data[offset : offset + rdlength]
                offset += rdlength

                rdata_str = ""
                if rtype == 1 and rdlength == 4:  # A Record (IPv4)
                    rdata_str = ".".join(str(b) for b in rdata_bytes)
                else:
                    rdata_str = rdata_bytes.hex()

                message.answers.append(
                    DNSRecord(name=rname, rtype=rtype, rclass=rclass, ttl=ttl, data=rdata_str)
                )

        return message
