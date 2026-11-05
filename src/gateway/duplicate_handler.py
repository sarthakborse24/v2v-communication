"""
V2X Gateway Simulator — Gateway Duplicate Message Handler
==========================================================
Detects and drops duplicate safety messages using a sliding-window cache
indexed by (vehicle_id, msg_cnt) tuples.

Standards References:
  - IEEE 1609.2-2016: Section 7.4.2 (Duplicate detection)
  - SAE J2735: MsgCount 0..127 sequence numbers
"""

from __future__ import annotations

import time
from typing import Dict, Optional, Tuple

from common.exceptions import DuplicateMessageError
from common.message_types import DEDUP_WINDOW_SECONDS
from monitoring.logger import get_logger

log = get_logger("gateway.duplicate_handler")


class DuplicateHandler:
    """Maintains a sliding-window cache of observed (source_id, msg_cnt) tuples."""

    def __init__(self, window_seconds: float = DEDUP_WINDOW_SECONDS):
        self.window_seconds = window_seconds
        # Maps (source_id, msg_cnt) -> reception_timestamp_seconds
        self._cache: Dict[Tuple[bytes, int], float] = {}

    @property
    def cached_count(self) -> int:
        return len(self._cache)

    def prune_stale_entries(self, current_time_s: float) -> None:
        """Evict records older than window_seconds."""
        cutoff = current_time_s - self.window_seconds
        stale_keys = [k for k, ts in self._cache.items() if ts < cutoff]
        for k in stale_keys:
            del self._cache[k]

    def is_duplicate(
        self,
        source_id: bytes,
        msg_cnt: int,
        current_time_s: Optional[float] = None,
    ) -> bool:
        """Check if (source_id, msg_cnt) has been seen within window_seconds."""
        now = current_time_s if current_time_s is not None else time.time()
        self.prune_stale_entries(now)
        key = (source_id, msg_cnt)
        return key in self._cache

    def record_message(
        self,
        source_id: bytes,
        msg_cnt: int,
        current_time_s: Optional[float] = None,
    ) -> None:
        """Store (source_id, msg_cnt) with the current timestamp."""
        now = current_time_s if current_time_s is not None else time.time()
        self._cache[(source_id, msg_cnt)] = now

    def check_and_record(
        self,
        source_id: bytes,
        msg_cnt: int,
        current_time_s: Optional[float] = None,
    ) -> None:
        """Atomically check for duplicate and record if novel.

        Raises:
            DuplicateMessageError: If the message was already seen in the current window.
        """
        now = current_time_s if current_time_s is not None else time.time()
        if self.is_duplicate(source_id, msg_cnt, now):
            log.warning(
                f"Duplicate detected: source={source_id.hex()} msg_cnt={msg_cnt} (dropping)"
            )
            raise DuplicateMessageError(
                f"Duplicate message from source {source_id.hex()} with msg_cnt {msg_cnt}"
            )
        self.record_message(source_id, msg_cnt, now)

