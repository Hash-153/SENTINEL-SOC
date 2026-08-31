"""Central Sentinel NIDS & SIEM daemon service orchestrator."""
import time
from typing import List, Optional
from sentinel.core.config import SentinelConfig
from sentinel.core.dispatcher import SentinelDispatcher
from sentinel.core.models import DecodedPacket, SecurityEvent, Incident
from sentinel.analyzers.signature_engine import SignatureEngine
from sentinel.analyzers.port_scan_detector import PortScanDetector
from sentinel.analyzers.brute_force_detector import BruteForceDetector
from sentinel.analyzers.anomaly_engine import AnomalyEngine
from sentinel.analyzers.correlation_engine import CorrelationEngine
from sentinel.storage.database import DatabaseManager
from sentinel.storage.event_repository import EventRepository
from sentinel.alerting.alert_manager import AlertManager
from sentinel.capture.live_socket import LiveSocketCapture


class SentinelService:
    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self.config = config or SentinelConfig()
        self.dispatcher = SentinelDispatcher()
        self.db_manager = DatabaseManager(self.config.db.db_path, self.config.db.enable_wal)
        self.event_repo = EventRepository(
            self.db_manager,
            self.config.db.batch_flush_interval_sec,
            self.config.db.batch_max_size,
        )
        self.alert_manager = AlertManager(self.config.alerting)
        self.sig_engine = SignatureEngine()
        self.scan_detector = PortScanDetector(self.config.detection)
        self.brute_detector = BruteForceDetector(self.config.detection)
        self.anomaly_engine = AnomalyEngine(self.config.detection)
        self.correlation_engine = CorrelationEngine(correlation_window_sec=60.0)
        self.live_capture: Optional[LiveSocketCapture] = None
        self._running = False

        self.dispatcher.packet_bus.subscribe(self._on_packet_received)
        self.dispatcher.event_bus.subscribe(self._on_event_detected)
        self.dispatcher.incident_bus.subscribe(self._on_incident_synthesized)

    def start(self) -> None:
        self._running = True
        self.dispatcher.start()
        self.event_repo.start()

    def stop(self) -> None:
        self._running = False
        if self.live_capture:
            self.live_capture.stop()
        self.dispatcher.stop()
        self.event_repo.stop()
        self.db_manager.close()

    def ingest_packet(self, packet: DecodedPacket) -> None:
        self.dispatcher.packet_bus.publish(packet)

    def start_live_capture(self, interface_ip: Optional[str] = None) -> None:
        self.live_capture = LiveSocketCapture(
            interface_ip=interface_ip or self.config.capture_interface,
            packet_callback=self.ingest_packet,
        )
        self.live_capture.start()

    def _on_packet_received(self, packet: DecodedPacket) -> None:
        events: List[SecurityEvent] = []
        events.extend(self.sig_engine.inspect_packet(packet))
        events.extend(self.scan_detector.inspect_packet(packet))
        events.extend(self.brute_detector.inspect_packet(packet))
        events.extend(self.anomaly_engine.inspect_packet(packet))
        for event in events:
            self.dispatcher.event_bus.publish(event)

    def _on_event_detected(self, event: SecurityEvent) -> None:
        self.event_repo.save_event(event)
        self.alert_manager.handle_event(event)
        incident = self.correlation_engine.process_event(event)
        if incident:
            self.dispatcher.incident_bus.publish(incident)

    def _on_incident_synthesized(self, incident: Incident) -> None:
        self.event_repo.save_incident(incident)
        self.alert_manager.handle_incident(incident)
