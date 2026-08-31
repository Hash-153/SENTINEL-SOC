"""Cross-platform raw socket packet capture engine."""
import socket
import sys
import threading
import time
from typing import Callable, Optional
from sentinel.parsers.binary_decoder import decode_packet
from sentinel.core.models import DecodedPacket

SIO_RCVALL = 0x98000001
RCVALL_ON = 1
RCVALL_OFF = 0


class LiveSocketCapture:
    def __init__(self, interface_ip: Optional[str] = None, packet_callback: Optional[Callable[[DecodedPacket], None]] = None) -> None:
        self.interface_ip = interface_ip
        self.packet_callback = packet_callback
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None

    def _create_socket(self) -> socket.socket:
        if sys.platform.startswith("win"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            bind_ip = self.interface_ip or socket.gethostbyname(socket.gethostname())
            sock.bind((bind_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            try:
                sock.ioctl(SIO_RCVALL, RCVALL_ON)
            except Exception as e:
                sock.close()
                raise PermissionError(f"Administrator privileges required for raw socket capture: {e}")
            return sock
        else:
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface_ip:
                    sock.bind((self.interface_ip, 0))
                return sock
            except PermissionError:
                raise PermissionError("Root privileges (sudo) required for raw socket capture on Linux.")

    def start(self) -> None:
        self._sock = self._create_socket()
        self._running = True
        self._capture_thread = threading.Thread(target=self._capture_loop, name="LiveCaptureThread", daemon=True)
        self._capture_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                if sys.platform.startswith("win"):
                    self._sock.ioctl(SIO_RCVALL, RCVALL_OFF)
                self._sock.close()
            except Exception:
                pass
            self._sock = None

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=1.0)

    def _capture_loop(self) -> None:
        while self._running and self._sock:
            try:
                raw_data, _ = self._sock.recvfrom(65535)
                if not raw_data:
                    continue
                packet = decode_packet(raw_data, timestamp=time.time())
                if self.packet_callback:
                    self.packet_callback(packet)
            except Exception:
                if not self._running:
                    break
                time.sleep(0.05)
