"""
V2X Gateway Simulator — 3GPP LTE-V2X Release 14 MAC Sublayer
=============================================================
Standards References:
  - 3GPP TS 36.321 Release 14: Section 5.14 (SL-SCH MAC procedures)
  - 3GPP TS 36.212 Release 14: SCI Format 1 generation
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Dict, List, Optional, Tuple

from common.message_types import (
    BSM_DEFAULT_V2X_PRIORITY,
    V2XPriority,
)
from cv2x.pc5.resource_pool import Mode4ResourcePool
from cv2x.pc5.sidelink import (
    SCIFormat1,
    SidelinkTransportBlock,
    V2X_BROADCAST_L2_ID,
)
from monitoring.logger import get_logger

log = get_logger("cv2x.mac")


@dataclass
class SidelinkTransmissionUnit:
    """Represents a scheduled C-V2X transmission unit (SCI on PSCCH + TB on PSSCH)."""
    sci: SCIFormat1
    transport_block: SidelinkTransportBlock
    scheduled_subframe: int
    subchannel_index: int
    raw_sci_bytes: bytes
    raw_tb_bytes: bytes


class LTEMAC:
    """Coordinates LTE-V2X SL-SCH prioritization, SCI-1 creation, and Mode 4 scheduling."""

    def __init__(
        self,
        source_l2_id: bytes = b"\x00\x00\x01",
        resource_pool: Optional[Mode4ResourcePool] = None,
        default_mcs: int = 10,
    ):
        if len(source_l2_id) != 3:
            raise ValueError(f"Source L2 ID must be 3 bytes, got {len(source_l2_id)}")

        self.source_l2_id = source_l2_id
        self.resource_pool = resource_pool if resource_pool is not None else Mode4ResourcePool()
        self.default_mcs = default_mcs

        # Priority queues: index 0 (highest) to 7 (lowest)
        self._priority_queues: Dict[int, List[SidelinkTransportBlock]] = {
            prio: [] for prio in range(8)
        }

    def prepare_transmission(
        self,
        payload: bytes,
        priority: V2XPriority = BSM_DEFAULT_V2X_PRIORITY,
        current_subframe: int = 0,
        dest_l2_id: bytes = V2X_BROADCAST_L2_ID,
        mcs_index: Optional[int] = None,
        rng: Optional[random.Random] = None,
    ) -> SidelinkTransmissionUnit:
        """Create TB and SCI Format 1, then allocate a Mode 4 resource.

        Steps:
          1. Wrap payload in SidelinkTransportBlock with CRC-24A.
          2. Execute Mode 4 autonomous sensing to select (subframe, subchannel).
          3. Generate SCI Format 1 metadata matching the allocation.
          4. Return SidelinkTransmissionUnit for PHY processing.
        """
        tb = SidelinkTransportBlock(
            payload=payload,
            source_l2_id=self.source_l2_id,
            dest_l2_id=dest_l2_id,
        )
        raw_tb = tb.serialize(compute_crc=True)

        # Mode 4 sensing-based selection
        scheduled_sf, subch, _ = self.resource_pool.select_resource(
            current_subframe=current_subframe,
            priority=int(priority),
            rng=rng,
        )

        # Construct SCI Format 1 (3GPP TS 36.212 §8.4.1)
        used_mcs = mcs_index if mcs_index is not None else self.default_mcs
        sci = SCIFormat1(
            priority=int(priority),
            resource_reservation=3,  # 100 ms SPS period (10 Hz BSM)
            freq_resource_location=subch,
            time_gap=0,              # No HARQ retransmission for broadcast safety
            mcs=used_mcs,
            retx_index=0,
        )
        raw_sci = sci.serialize()

        return SidelinkTransmissionUnit(
            sci=sci,
            transport_block=tb,
            scheduled_subframe=scheduled_sf,
            subchannel_index=subch,
            raw_sci_bytes=raw_sci,
            raw_tb_bytes=raw_tb,
        )

