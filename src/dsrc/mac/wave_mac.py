"""
V2X Gateway Simulator — IEEE 1609.4 WAVE MAC Sublayer
======================================================
Standards References:
  - IEEE 1609.4-2016: Multi-Channel Operation (CCH/SCH intervals, Guard interval)
  - IEEE 802.11e: Enhanced Distributed Channel Access (EDCA) QoS parameters
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
import queue
import random
from typing import Dict, List, Optional, Tuple

from common.message_types import (
    BSM_DEFAULT_CHANNEL,
    BSM_EDCA_CATEGORY,
    EDCACategory,
    WAVEChannel,
)
from dsrc.wave.wave_frame import WAVEFrame
from monitoring.logger import get_logger

log = get_logger("dsrc.mac")


class ChannelInterval(str, Enum):
    """IEEE 1609.4 Sync Interval phases."""
    CCH_INTERVAL = "CCH"
    SCH_INTERVAL = "SCH"
    GUARD_INTERVAL = "GUARD"


class ChannelAccessMode(str, Enum):
    """IEEE 1609.4 Radio Access Modes."""
    ALTERNATING = "alternating"   # 50 ms CCH / 50 ms SCH
    CONTINUOUS_CCH = "continuous_cch"  # Dedicated safety radio fixed to CCH
    CONTINUOUS_SCH = "continuous_sch"


@dataclass
class EDCAParameters:
    """802.11e EDCA Contention Parameters per Access Category."""
    aifsn: int
    cw_min: int
    cw_max: int


# Standards-defined EDCA parameters for IEEE 802.11p WAVE (10 MHz OFDM)
# Slot time = 13 µs, SIFS = 32 µs per 802.11p §17.3
EDCA_TABLE: Dict[EDCACategory, EDCAParameters] = {
    EDCACategory.AC_VO: EDCAParameters(aifsn=2, cw_min=3, cw_max=7),     # Safety/BSM
    EDCACategory.AC_VI: EDCAParameters(aifsn=3, cw_min=7, cw_max=15),
    EDCACategory.AC_BE: EDCAParameters(aifsn=6, cw_min=15, cw_max=1023),
    EDCACategory.AC_BK: EDCAParameters(aifsn=9, cw_min=15, cw_max=1023),
}

SLOT_TIME_US = 13.0   # 10 MHz channel slot time (µs)
SIFS_TIME_US = 32.0   # Short Interframe Space (µs)


class WAVEMAC:
    """Simulates IEEE 1609.4 multi-channel operation and EDCA channel access."""

    def __init__(
        self,
        access_mode: ChannelAccessMode = ChannelAccessMode.CONTINUOUS_CCH,
        sync_interval_ms: float = 100.0,
        cch_interval_ms: float = 50.0,
        guard_interval_ms: float = 4.0,
        service_channel: WAVEChannel = WAVEChannel.SCH_172,
    ):
        self.access_mode = access_mode
        self.sync_interval_ms = sync_interval_ms
        self.cch_interval_ms = cch_interval_ms
        self.guard_interval_ms = guard_interval_ms
        self.service_channel = service_channel

        # Queues per EDCA category: AC_VO has highest priority
        self._queues: Dict[EDCACategory, List[WAVEFrame]] = {
            EDCACategory.AC_VO: [],
            EDCACategory.AC_VI: [],
            EDCACategory.AC_BE: [],
            EDCACategory.AC_BK: [],
        }

    def get_current_interval(self, current_time_ms: float) -> Tuple[ChannelInterval, WAVEChannel]:
        """Determine whether the radio is currently in CCH, SCH, or Guard phase.

        Per IEEE 1609.4 §6.3:
          Each 100 ms sync cycle consists of:
            0.0 to 4.0 ms: Guard Interval
            4.0 to 50.0 ms: CCH Interval (CH 178)
            50.0 to 54.0 ms: Guard Interval
            54.0 to 100.0 ms: SCH Interval (service channel)
        """
        if self.access_mode == ChannelAccessMode.CONTINUOUS_CCH:
            return ChannelInterval.CCH_INTERVAL, WAVEChannel.CCH_178
        elif self.access_mode == ChannelAccessMode.CONTINUOUS_SCH:
            return ChannelInterval.SCH_INTERVAL, self.service_channel

        # Alternating access mode
        offset_ms = current_time_ms % self.sync_interval_ms
        guard = self.guard_interval_ms

        if offset_ms < guard:
            return ChannelInterval.GUARD_INTERVAL, WAVEChannel.CCH_178
        elif offset_ms < self.cch_interval_ms:
            return ChannelInterval.CCH_INTERVAL, WAVEChannel.CCH_178
        elif offset_ms < (self.cch_interval_ms + guard):
            return ChannelInterval.GUARD_INTERVAL, self.service_channel
        else:
            return ChannelInterval.SCH_INTERVAL, self.service_channel

    def calculate_edca_backoff_us(
        self,
        category: EDCACategory = BSM_EDCA_CATEGORY,
        attempt: int = 0,
        rng: Optional[random.Random] = None,
    ) -> float:
        """Compute 802.11e EDCA backoff delay in microseconds.

        Formula:
          AIFS = SIFS + AIFSN * SlotTime
          Backoff = random(0, CW) * SlotTime
          Delay = AIFS + Backoff
        """
        params = EDCA_TABLE[category]
        # Exponential backoff: CW doubled up to cw_max
        cw = min(params.cw_max, ((params.cw_min + 1) * (2 ** attempt)) - 1)
        r = rng.randint(0, cw) if rng else random.randint(0, cw)

        aifs_us = SIFS_TIME_US + (params.aifsn * SLOT_TIME_US)
        backoff_us = r * SLOT_TIME_US
        return aifs_us + backoff_us

    def enqueue_frame(self, frame: WAVEFrame) -> None:
        """Queue frame into its designated EDCA priority queue."""
        cat = frame.edca_category
        self._queues[cat].append(frame)

    def dequeue_next_frame(self) -> Optional[WAVEFrame]:
        """Strict-priority dequeue: drains AC_VO first, then VI, BE, BK."""
        for cat in [EDCACategory.AC_VO, EDCACategory.AC_VI, EDCACategory.AC_BE, EDCACategory.AC_BK]:
            if self._queues[cat]:
                return self._queues[cat].pop(0)
        return None

    def time_until_channel_ready_ms(
        self,
        target_channel: WAVEChannel,
        current_time_ms: float,
    ) -> float:
        """Calculate wait time until radio will be active on target channel.

        Returns 0.0 if already on target channel and outside guard interval.
        """
        if self.access_mode == ChannelAccessMode.CONTINUOUS_CCH:
            return 0.0 if target_channel == WAVEChannel.CCH_178 else float("inf")

        interval, cur_chan = self.get_current_interval(current_time_ms)
        if interval != ChannelInterval.GUARD_INTERVAL and cur_chan == target_channel:
            return 0.0

        offset_ms = current_time_ms % self.sync_interval_ms
        guard = self.guard_interval_ms

        if target_channel == WAVEChannel.CCH_178:
            # Need next CCH start: at guard ms of current or next cycle
            if offset_ms < guard:
                return guard - offset_ms
            else:
                return (self.sync_interval_ms - offset_ms) + guard
        else:
            # Need next SCH start: at (cch_interval + guard) ms
            sch_start = self.cch_interval_ms + guard
            if offset_ms < sch_start:
                return sch_start - offset_ms
            else:
                return (self.sync_interval_ms - offset_ms) + sch_start

