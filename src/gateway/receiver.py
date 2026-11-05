"""
V2X Gateway Simulator — Gateway Ingress Receiver
=================================================
Demultiplexes incoming frames from DSRC (IEEE 802.11p) and LTE-C-V2X (PC5 Sidelink),
stripping lower-layer framing to present the security/transport payload to the validator.

Standards References:
  - IEEE 802.11p-2010 (WAVE MAC)
  - IEEE 1609.3 (WSMP)
  - 3GPP TS 36.212 / TS 36.321 (PC5 PSCCH / PSSCH)
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Optional, Tuple

from common.exceptions import (
    ValidationError,
    WaveFrameError,
)
from common.message_types import (
    GatewayDirection,
    StackType,
)
from cv2x.pc5.sidelink import (
    SCIFormat1,
    SidelinkTransportBlock,
)
from dsrc.wave.wave_frame import WAVEFrame
from dsrc.wave.wsmp import WSMPacket
from monitoring.logger import get_logger

log = get_logger("gateway.receiver")


@dataclass
class IngressPacket:
    """Represents a standardized packet parsed at the gateway ingress."""
    source_stack: StackType
    ingress_timestamp_ms: int
    raw_spdu_bytes: bytes
    source_mac_or_l2_id: bytes
    sequence_or_msg_id: int
    metadata: dict  # Stack-specific metadata (e.g. WSMP fields or SCI fields)


class GatewayReceiver:
    """Handles ingress packet reception and layer-1/layer-2 stripping."""

    def receive_dsrc(
        self,
        frame_bytes: bytes,
        current_time_ms: Optional[int] = None,
    ) -> IngressPacket:
        """Parse raw IEEE 802.11p WAVE frame, strip MAC and WSMP headers."""
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)

        # 1. Dissect 802.11p frame and verify FCS
        wave_frame = WAVEFrame.deserialize(frame_bytes, verify_fcs=True)

        # 2. Dissect WSMP header
        wsm = WSMPacket.deserialize(wave_frame.payload)

        log.debug(
            f"Ingress DSRC frame: src={wave_frame.source_mac.hex()} "
            f"psid=0x{wsm.psid:04X} spdu_len={len(wsm.payload)}B"
        )

        return IngressPacket(
            source_stack=StackType.DSRC,
            ingress_timestamp_ms=now_ms,
            raw_spdu_bytes=wsm.payload,
            source_mac_or_l2_id=wave_frame.source_mac,
            sequence_or_msg_id=wave_frame.seq_num,
            metadata={
                "psid": wsm.psid,
                "edca_category": wave_frame.edca_category,
                "channel_number": wsm.channel_number,
                "tx_power_dbm": wsm.tx_power_dbm,
            },
        )

    def receive_cv2x(
        self,
        sci_bytes: bytes,
        tb_bytes: bytes,
        current_time_ms: Optional[int] = None,
    ) -> IngressPacket:
        """Parse C-V2X PSCCH SCI Format 1 and PSSCH Transport Block, strip L2 framing."""
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)

        # 1. Dissect SCI Format 1
        sci = SCIFormat1.deserialize(sci_bytes)

        # 2. Dissect Transport Block and verify CRC-24A
        tb = SidelinkTransportBlock.deserialize(tb_bytes, verify_crc=True)

        log.debug(
            f"Ingress C-V2X packet: src_l2={tb.source_l2_id.hex()} "
            f"prio={sci.priority} mcs={sci.mcs} spdu_len={len(tb.payload)}B"
        )

        return IngressPacket(
            source_stack=StackType.CV2X,
            ingress_timestamp_ms=now_ms,
            raw_spdu_bytes=tb.payload,
            source_mac_or_l2_id=tb.source_l2_id,
            sequence_or_msg_id=sci.time_gap,
            metadata={
                "priority": sci.priority,
                "resource_reservation": sci.resource_reservation,
                "freq_resource_location": sci.freq_resource_location,
                "mcs": sci.mcs,
                "dest_l2_id": tb.dest_l2_id,
            },
        )

