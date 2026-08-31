"""Unit tests for binary packet parsers and protocol dissectors."""

import os
import tempfile
import unittest
from sentinel.parsers.binary_decoder import (
    BinaryDecoder,
    decode_packet,
    format_mac_address,
    format_ipv4_address,
)
from sentinel.parsers.tcp_decoder import TCPDecoder
from sentinel.parsers.udp_decoder import UDPDecoder
from sentinel.parsers.dns_decoder import DNSDecoder
from sentinel.parsers.http_decoder import HTTPDecoder
from sentinel.parsers.pcap_reader import PcapWriter, PcapReader
from sentinel.capture.synthetic_generator import (
    build_ethernet_frame,
    build_ipv4_packet,
    build_tcp_segment,
    build_udp_datagram,
    build_dns_query,
    build_full_packet,
)
from sentinel.core.models import IpProtocol


class TestProtocolParsers(unittest.TestCase):

    def test_mac_formatting(self):
        raw_mac = bytes([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        self.assertEqual(format_mac_address(raw_mac), "00:1a:2b:3c:4d:5e")

    def test_ipv4_formatting(self):
        raw_ip = bytes([192, 168, 1, 100])
        self.assertEqual(format_ipv4_address(raw_ip), "192.168.1.100")

    def test_ethernet_decoder(self):
        payload = b"TESTPAYLOAD"
        raw_frame = build_ethernet_frame("00:11:22:33:44:55", "66:77:88:99:AA:BB", 0x0800, payload)
        frame, extracted_payload = BinaryDecoder.decode_ethernet(raw_frame)

        self.assertIsNotNone(frame)
        self.assertEqual(frame.src_mac, "00:11:22:33:44:55")
        self.assertEqual(frame.dst_mac, "66:77:88:99:aa:bb")
        self.assertEqual(frame.eth_type, 0x0800)
        self.assertEqual(extracted_payload, payload)

    def test_ipv4_decoder(self):
        payload = b"IP_PAYLOAD_BYTES"
        raw_ip = build_ipv4_packet("10.0.0.1", "10.0.0.2", protocol=6, payload=payload, ttl=128)
        header, extracted_payload = BinaryDecoder.decode_ipv4(raw_ip)

        self.assertIsNotNone(header)
        self.assertEqual(header.src_ip, "10.0.0.1")
        self.assertEqual(header.dst_ip, "10.0.0.2")
        self.assertEqual(header.protocol, IpProtocol.TCP)
        self.assertEqual(header.ttl, 128)
        self.assertEqual(extracted_payload, payload)

    def test_tcp_decoder_flags(self):
        # Flags: SYN (0x02) | ACK (0x10) = 0x12
        payload = b"TCP_DATA"
        raw_tcp = build_tcp_segment(src_port=8080, dst_port=443, flags=0x12, payload=payload, seq_num=500, ack_num=1000)
        tcp_hdr, extracted_payload = TCPDecoder.decode(raw_tcp)

        self.assertIsNotNone(tcp_hdr)
        self.assertEqual(tcp_hdr.src_port, 8080)
        self.assertEqual(tcp_hdr.dst_port, 443)
        self.assertEqual(tcp_hdr.seq_num, 500)
        self.assertEqual(tcp_hdr.ack_num, 1000)
        self.assertTrue(tcp_hdr.flag_syn)
        self.assertTrue(tcp_hdr.flag_ack)
        self.assertFalse(tcp_hdr.flag_fin)
        self.assertFalse(tcp_hdr.flag_rst)
        self.assertEqual(extracted_payload, payload)

    def test_udp_decoder(self):
        payload = b"UDP_DATAGRAM_CONTENT"
        raw_udp = build_udp_datagram(src_port=53, dst_port=53123, payload=payload)
        udp_hdr, extracted_payload = UDPDecoder.decode(raw_udp)

        self.assertIsNotNone(udp_hdr)
        self.assertEqual(udp_hdr.src_port, 53)
        self.assertEqual(udp_hdr.dst_port, 53123)
        self.assertEqual(udp_hdr.length, 8 + len(payload))
        self.assertEqual(extracted_payload, payload)

    def test_dns_decoder(self):
        dns_query = build_dns_query("secure.internal.bank.corp", tx_id=0xCAFE)
        dns_msg = DNSDecoder.decode(dns_query)

        self.assertIsNotNone(dns_msg)
        self.assertEqual(dns_msg.tx_id, 0xCAFE)
        self.assertFalse(dns_msg.is_response)
        self.assertEqual(len(dns_msg.questions), 1)
        self.assertEqual(dns_msg.questions[0].name, "secure.internal.bank.corp")
        self.assertEqual(dns_msg.questions[0].qtype, 1)

    def test_http_request_decoder(self):
        raw_http = (
            b"POST /api/v1/authenticate HTTP/1.1\r\n"
            b"Host: auth.internal\r\n"
            b"Content-Type: application/json\r\n"
            b"User-Agent: SentinelAgent/1.0\r\n\r\n"
            b'{"user": "admin", "token": "abc"}'
        )
        http_trans = HTTPDecoder.decode(raw_http)

        self.assertIsNotNone(http_trans)
        self.assertTrue(http_trans.is_request)
        self.assertEqual(http_trans.method, "POST")
        self.assertEqual(http_trans.uri, "/api/v1/authenticate")
        self.assertEqual(http_trans.headers.get("host"), "auth.internal")
        self.assertEqual(http_trans.headers.get("content-type"), "application/json")
        self.assertEqual(http_trans.body, b'{"user": "admin", "token": "abc"}')

    def test_http_response_decoder(self):
        raw_http = (
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"Server: Apache-Mock\r\n"
            b"Content-Length: 13\r\n\r\n"
            b"Access Denied"
        )
        http_trans = HTTPDecoder.decode(raw_http)

        self.assertIsNotNone(http_trans)
        self.assertFalse(http_trans.is_request)
        self.assertEqual(http_trans.status_code, 401)
        self.assertEqual(http_trans.reason_phrase, "Unauthorized")
        self.assertEqual(http_trans.body, b"Access Denied")

    def test_pcap_read_write_roundtrip(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            pcap_path = tmp.name

        try:
            pkt1 = build_full_packet("192.168.1.10", "192.168.1.20", 1234, 80, "TCP", payload=b"PCAP_TEST_1")
            pkt2 = build_full_packet("192.168.1.30", "8.8.8.8", 53111, 53, "UDP", payload=b"PCAP_TEST_2")

            with PcapWriter(pcap_path) as writer:
                writer.write_packet(pkt1, timestamp=1600000000.5)
                writer.write_packet(pkt2, timestamp=1600000001.5)

            reader = PcapReader(pcap_path)
            read_pkts = list(reader.read_packets())

            self.assertEqual(len(read_pkts), 2)
            self.assertEqual(read_pkts[0].src_ip, "192.168.1.10")
            self.assertEqual(read_pkts[0].dst_ip, "192.168.1.20")
            self.assertEqual(read_pkts[0].src_port, 1234)
            self.assertEqual(read_pkts[0].dst_port, 80)
            self.assertEqual(read_pkts[0].payload, b"PCAP_TEST_1")

            self.assertEqual(read_pkts[1].src_ip, "192.168.1.30")
            self.assertEqual(read_pkts[1].dst_ip, "8.8.8.8")
            self.assertEqual(read_pkts[1].src_port, 53111)
            self.assertEqual(read_pkts[1].dst_port, 53)
            self.assertEqual(read_pkts[1].payload, b"PCAP_TEST_2")

        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)


if __name__ == "__main__":
    unittest.main()
