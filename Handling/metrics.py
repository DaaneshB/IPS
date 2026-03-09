from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any, Optional

import Configurations.config as config


class PerformanceMetrics:
    """Thread-safe throughput and detection-latency counters.

    Extracted from sniffer so tests exercise the production class directly
    without importing scapy on the capture side.
    """

    def __init__(self, window_size: int = 1000) -> None:
        self.packet_count: int = 0
        self.detection_times: deque[float] = deque(maxlen=window_size)
        self.packets_per_second: float = 0
        self.last_window_start: float = time.time()
        self.window_size = window_size
        self._lock = threading.Lock()

    def record_packet(self, detection_time: float = 0) -> None:
        with self._lock:
            self.packet_count += 1
            if detection_time > 0:
                self.detection_times.append(detection_time)
            if self.packet_count % self.window_size == 0:
                elapsed = time.time() - self.last_window_start
                self.packets_per_second = self.window_size / elapsed if elapsed > 0 else 0
                self.last_window_start = time.time()

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            avg_detection = (
                sum(self.detection_times) / len(self.detection_times)
                if self.detection_times else 0
            )
            return {
                "packets_processed": self.packet_count,
                "packets_per_second": round(self.packets_per_second, 2),
                "avg_detection_time_ms": round(avg_detection * 1000, 3),
            }


class ThresholdTracker:
    """Sliding-window counter per IP to reduce false-positive blocking."""

    _SWEEP_INTERVAL: float = 30.0

    def __init__(self, count: Optional[int] = None, window: Optional[int] = None) -> None:
        self._count_override = count
        self._window_override = window
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_sweep: float = time.time()

    @property
    def count(self) -> int:
        return self._count_override if self._count_override is not None else config.THRESHOLD_COUNT

    @property
    def window(self) -> int:
        return self._window_override if self._window_override is not None else config.THRESHOLD_WINDOW_SECONDS

    def should_block(self, ip: str) -> bool:
        now = time.time()
        window = self.window
        count = self.count
        with self._lock:
            q = self.hits[ip]
            while q and now - q[0] > window:
                q.popleft()
            q.append(now)
            hit_count = len(q)
            if hit_count >= count:
                # Reset so a blocked IP doesn't retain state; also frees the deque.
                del self.hits[ip]
                return True
            self._sweep_locked(now, window)
            return False

    def _sweep_locked(self, now: float, window: float) -> None:
        """Drop per-IP entries whose windows have fully expired.

        Called under self._lock. Cheap amortized cost: only runs a full sweep
        every _SWEEP_INTERVAL seconds so the hot path stays O(1).
        """
        if now - self._last_sweep < self._SWEEP_INTERVAL:
            return
        self._last_sweep = now
        expired = [ip for ip, q in self.hits.items() if not q or now - q[-1] > window]
        for ip in expired:
            del self.hits[ip]
