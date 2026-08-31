"""Alert emission channels and formatting sinks."""
import datetime
import json
import socket
import sys
from abc import ABC, abstractmethod
from typing import Optional
from sentinel.core.models import SecurityEvent, Incident, AlertSeverity


class AlertChannel(ABC):
    @abstractmethod
    def emit_event(self, event: SecurityEvent) -> None: pass
    @abstractmethod
    def emit_incident(self, incident: Incident) -> None: pass


class ConsoleAlertChannel(AlertChannel):
    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def emit_event(self, event: SecurityEvent) -> None:
        dt = datetime.datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{event.severity.value}]"
        src = f"{event.src_ip}:{event.src_port}" if event.src_port else (event.src_ip or "N/A")
        dst = f"{event.dst_ip}:{event.dst_port}" if event.dst_port else (event.dst_ip or "N/A")
        output = f"{prefix} {dt} | {event.category.value} | {event.title}\n   Src: {src} -> Dst: {dst} ({event.protocol})\n   Details: {event.description}\n"
        if event.raw_evidence:
            output += f"   Evidence: {event.raw_evidence[:100]}\n"
        sys.stdout.write(output + "\n")
        sys.stdout.flush()

    def emit_incident(self, incident: Incident) -> None:
        dt = datetime.datetime.fromtimestamp(incident.created_at).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{incident.severity.value}]"
        banner = "=" * 70
        output = (
            f"\n{banner}\n{prefix} SECURITY INCIDENT SYNTHESIS: {incident.title}\n"
            f"   Time: {dt} | Attacker IP: {incident.src_ip} | Targets: {', '.join(incident.target_ips)}\n"
            f"   Correlated Events: {incident.event_count} | Status: {incident.status}\n"
            f"   Summary: {incident.summary}\n{banner}\n"
        )
        sys.stdout.write(output)
        sys.stdout.flush()


class JsonLogAlertChannel(AlertChannel):
    def __init__(self, log_path: str = "sentinel_alerts.jsonl") -> None:
        self.log_path = log_path

    def emit_event(self, event: SecurityEvent) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def emit_incident(self, incident: Incident) -> None:
        with open(self.log_path, "a", encoding="utf-8") as f:
            payload = {"type": "INCIDENT", "data": incident.to_dict()}
            f.write(json.dumps(payload) + "\n")


class LocalSocketAlertChannel(AlertChannel):
    def __init__(self, host: str = "127.0.0.1", port: int = 5140) -> None:
        self.host = host
        self.port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def emit_event(self, event: SecurityEvent) -> None:
        try:
            msg = json.dumps(event.to_dict()).encode("utf-8")
            self._sock.sendto(msg, (self.host, self.port))
        except Exception:
            pass

    def emit_incident(self, incident: Incident) -> None:
        try:
            msg = json.dumps({"type": "INCIDENT", "data": incident.to_dict()}).encode("utf-8")
            self._sock.sendto(msg, (self.host, self.port))
        except Exception:
            pass
