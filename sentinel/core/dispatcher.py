"""Asynchronous thread-safe event dispatcher and pub/sub message bus."""

import queue
import threading
from typing import Callable, List, TypeVar, Generic
from sentinel.core.models import DecodedPacket, SecurityEvent, Incident

T = TypeVar("T")


class EventQueue(Generic[T]):
    """Thread-safe generic FIFO queue with non-blocking dispatching."""

    def __init__(self, maxsize: int = 10000) -> None:
        self._queue: queue.Queue[T] = queue.Queue(maxsize=maxsize)
        self._subscribers: List[Callable[[T], None]] = []
        self._lock = threading.Lock()
        self._running = False
        self._worker_thread: threading.Thread | None = None

    def subscribe(self, callback: Callable[[T], None]) -> None:
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def publish(self, item: T) -> bool:
        try:
            self._queue.put_nowait(item)
            return True
        except queue.Full:
            # Drop or backpressure when congested
            return False

    def start(self, name: str = "DispatcherWorker") -> None:
        self._running = True
        self._worker_thread = threading.Thread(target=self._run_loop, name=name, daemon=True)
        self._worker_thread.start()

    def stop(self) -> None:
        self._running = False
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)

    def _run_loop(self) -> None:
        while self._running:
            try:
                item = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            with self._lock:
                callbacks = list(self._subscribers)

            for cb in callbacks:
                try:
                    cb(item)
                except Exception as ex:
                    # Isolate subscriber failures
                    pass
            self._queue.task_done()


class SentinelDispatcher:
    """Central event coordinator orchestrating packet ingestion, analysis, storage, and alerts."""

    def __init__(self) -> None:
        self.packet_bus: EventQueue[DecodedPacket] = EventQueue(maxsize=20000)
        self.event_bus: EventQueue[SecurityEvent] = EventQueue(maxsize=10000)
        self.incident_bus: EventQueue[Incident] = EventQueue(maxsize=2000)

    def start(self) -> None:
        self.packet_bus.start("PacketDispatcher")
        self.event_bus.start("EventDispatcher")
        self.incident_bus.start("IncidentDispatcher")

    def stop(self) -> None:
        self.packet_bus.stop()
        self.event_bus.stop()
        self.incident_bus.stop()
