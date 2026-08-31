"""HTTP/1.1 protocol stream parser and header extractor."""

from typing import Optional, Dict
from sentinel.core.models import HTTPTransaction

HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT"}


class HTTPDecoder:
    """Dissects plaintext HTTP/1.1 requests and responses."""

    @staticmethod
    def decode(payload: bytes, src_port: int = 0, dst_port: int = 0) -> Optional[HTTPTransaction]:
        """Attempt to decode HTTP payload into structured transaction."""
        if not payload or len(payload) < 10:
            return None

        # Check for HTTP Request
        first_space = payload.find(b" ")
        if first_space != -1 and first_space <= 7:
            potential_method = payload[:first_space].upper()
            if potential_method in HTTP_METHODS:
                return HTTPDecoder._parse_request(payload)

        # Check for HTTP Response
        if payload.startswith(b"HTTP/1.0 ") or payload.startswith(b"HTTP/1.1 "):
            return HTTPDecoder._parse_response(payload)

        return None

    @staticmethod
    def _parse_request(payload: bytes) -> Optional[HTTPTransaction]:
        try:
            header_end = payload.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = payload.find(b"\n\n")
                if header_end == -1:
                    header_end = len(payload)
                body_start = min(header_end + 2, len(payload))
            else:
                body_start = header_end + 4

            headers_raw = payload[:header_end].decode("latin-1", errors="replace")
            lines = headers_raw.splitlines()
            if not lines:
                return None

            request_line = lines[0].split(" ")
            if len(request_line) < 2:
                return None

            method = request_line[0].upper()
            uri = request_line[1]
            version = request_line[2] if len(request_line) > 2 else "HTTP/1.1"

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

            body = payload[body_start:]

            return HTTPTransaction(
                is_request=True,
                method=method,
                uri=uri,
                version=version,
                headers=headers,
                body=body,
            )
        except Exception:
            return None

    @staticmethod
    def _parse_response(payload: bytes) -> Optional[HTTPTransaction]:
        try:
            header_end = payload.find(b"\r\n\r\n")
            if header_end == -1:
                header_end = payload.find(b"\n\n")
                if header_end == -1:
                    header_end = len(payload)
                body_start = min(header_end + 2, len(payload))
            else:
                body_start = header_end + 4

            headers_raw = payload[:header_end].decode("latin-1", errors="replace")
            lines = headers_raw.splitlines()
            if not lines:
                return None

            status_line = lines[0].split(" ", 2)
            version = status_line[0]
            status_code = int(status_line[1]) if len(status_line) > 1 and status_line[1].isdigit() else 200
            reason = status_line[2] if len(status_line) > 2 else "OK"

            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()

            body = payload[body_start:]

            return HTTPTransaction(
                is_request=False,
                version=version,
                status_code=status_code,
                reason_phrase=reason,
                headers=headers,
                body=body,
            )
        except Exception:
            return None
