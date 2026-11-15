# modules/bandwidth.py — NetScope v2.0 Bandwidth Monitor

import time
import threading
from collections import deque

from modules.utils import format_bytes


class BandwidthMonitor:
    """Rolling-window bandwidth tracker."""

    def __init__(self, window_seconds: int = 5):
        self.window = window_seconds
        self._samples: deque = deque()   # (timestamp, bytes)
        self._peak = 0.0
        self._lock = threading.Lock()

    # ── Called by sniffer for every captured packet ───────────
    def add_packet(self, *args, **kwargs):
        """
        Flexible signature — accepts any of:
            add_packet(pkt)
            add_packet(pkt, size)
            add_packet(size)
            add_packet(pkt, length=123)
        """
        n = 0
        try:
            # Explicit keyword
            if "size" in kwargs:
                n = int(kwargs["size"])
            elif "length" in kwargs:
                n = int(kwargs["length"])
            elif len(args) >= 2:
                # Second positional arg assumed to be size
                try:
                    n = int(args[1])
                except Exception:
                    n = len(args[0])
            elif len(args) == 1:
                a = args[0]
                if isinstance(a, int):
                    n = a
                else:
                    n = len(a)
        except Exception:
            n = 0

        if n <= 0:
            return

        now = time.time()
        with self._lock:
            self._samples.append((now, n))
            self._prune(now)
            current = self._current_rate_locked()
            if current > self._peak:
                self._peak = current

    # Aliases
    def update(self, *args, **kwargs):
        self.add_packet(*args, **kwargs)

    def add_bytes(self, n: int):
        self.add_packet(int(n))

    # ── Internals ─────────────────────────────────────────────
    def _prune(self, now):
        cutoff = now - self.window
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def _current_rate_locked(self):
        total = sum(b for _, b in self._samples)
        return total / self.window if self.window else 0.0

    # ── Public API used by main.py ────────────────────────────
    def get_speed_formatted(self) -> str:
        with self._lock:
            self._prune(time.time())
            r = self._current_rate_locked()
        return f"{format_bytes(r)}/s"

    def get_peak_formatted(self) -> str:
        with self._lock:
            p = self._peak
        return f"{format_bytes(p)}/s"

    def get_current_speed(self) -> float:
        with self._lock:
            self._prune(time.time())
            return self._current_rate_locked()

    def get_peak_speed(self) -> float:
        with self._lock:
            return self._peak

    def get_rates(self):
        with self._lock:
            self._prune(time.time())
            r = self._current_rate_locked()
        return r, r

    def reset(self):
        with self._lock:
            self._samples.clear()
            self._peak = 0.0