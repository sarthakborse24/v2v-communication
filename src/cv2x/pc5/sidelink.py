"""
V2X Gateway Simulator — 3GPP LTE-V2X Release 14 PC5 Sidelink Protocols
=======================================================================
Implements:
  - Sidelink Control Information (SCI) Format 1 (3GPP TS 36.212 §8.4.1)
  - SL-SCH Transport Block (TB) Encapsulation (3GPP TS 36.321 §5.14)

Standards References:
  - 3GPP TS 36.212 Release 14: Section 8.4.1 (SCI format 1)
  - 3GPP TS 36.213 Release 14: Section 14 (Sidelink procedures)
  - 3GPP TS 36.321 Release 14: Section 5.14 (SL-SCH data transfer)

DEVIATIONS:
  - L10: Confirmed 6 standard fields in SCI Format 1. Secondary-source
    "Timing Advance" field is excluded per TS 36.212 §8.4.1.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
import zlib
from typing import Optional, Tuple

from common.exceptions import (
    PC5Error,
    SCIFormatError,
    TransportBlockError,
)
from common.message_types import (
    BSM_DEFAULT_V2X_PRIORITY,
    V2XPriority,
)


# Standard 3GPP V2X Broadcast Layer-2 Destination ID (24 bits)
# Source: 3GPP TS 36.321 §5.14.2.2 / TS 23.285
V2X_BROADCAST_L2_ID = b"\xff\xff\xff"


# ---------------------------------------------------------------------------
# CRC-24A Calculation (3GPP TS 36.212 §5.1.1)
# Polynomial: D^24 + D^23 + D^18 + D^17 + D^14 + D^11 + D^10 + D^7 + D^6 + D^5 + D^4 + D^3 + D + 1
# Hex generator: 0x1864CFB
# ---------------------------------------------------------------------------

CRC24A_POLY = 0x1864CFB


def compute_crc24a(data: bytes) -> int:
    """Compute 24-bit CRC-24A over data per 3GPP TS 36.212 §5.1.1."""
    crc = 0x000000
    for byte in data:
        crc ^= (byte << 16)
        for _ in range(8):
            if crc & 0x800000:
                crc = ((crc << 1) ^ CRC24A_POLY) & 0xFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFF
    return crc


# ---------------------------------------------------------------------------
# SCI Format 1 (3GPP TS 36.212 §8.4.1)
# ---------------------------------------------------------------------------

# Resource Reservation Interval mapping (3GPP TS 36.213 Table 14.2.1-1)
RRI_MAPPING_MS = {
    0: 0,       # No reservation
    1: 20,      # 20 ms
    2: 50,      # 50 ms
    3: 100,     # 100 ms (standard for 10 Hz BSM)
    4: 200,     # 200 ms
    5: 300,     # 300 ms
    6: 400,     # 400 ms
    7: 500,     # 500 ms
    8: 600,     # 600 ms
    9: 700,     # 700 ms
    10: 800,    # 800 ms
    11: 900,    # 900 ms
    12: 1000,   # 1000 ms
}


@dataclass
class SCIFormat1:
    """3GPP Release 14 Sidelink Control Information Format 1.

    Carried on PSCCH (Physical Sidelink Control Channel, 2 PRBs fixed).
    Transmitted concurrently with PSSCH to inform receiving UEs how to decode
    the Transport Block.

    Fields (TS 36.212 §8.4.1):
      - priority: 3 bits (0..7; 0=highest)
      - resource_reservation: 4 bits (0=no res, 1..12=RRI period ms)
      - freq_resource_location: 5 bits (sub-channel index, 0..31)
      - time_gap: 4 bits (subframe offset to retransmission, 0..15; 0=none)
      - mcs: 5 bits (Modulation and Coding Scheme for PSSCH, 0..31)
      - retx_index: 1 bit (0=initial transmission, 1=retransmission)
    """
    priority: int = 1               # 3 bits (0..7, default: 1 = SAFETY_HIGH)
    resource_reservation: int = 3   # 4 bits (default: 3 = 100 ms for 10 Hz BSM)
    freq_resource_location: int = 0 # 5 bits (sub-channel index)
    time_gap: int = 0               # 4 bits (0 = no HARQ retransmission)
    mcs: int = 10                   # 5 bits (16-QAM default)
    retx_index: int = 0             # 1 bit (0 = initial transmission)

    def __post_init__(self):
        self.validate()

    def validate(self) -> None:
        """Validate field bit widths per 3GPP TS 36.212 §8.4.1."""
        if not (0 <= self.priority <= 7):
            raise SCIFormatError(f"priority {self.priority} out of bounds [0..7] (3 bits)")
        if not (0 <= self.resource_reservation <= 15):
            raise SCIFormatError(
                f"resource_reservation {self.resource_reservation} out of bounds [0..15] (4 bits)"
            )
        if not (0 <= self.freq_resource_location <= 31):
            raise SCIFormatError(
                f"freq_resource_location {self.freq_resource_location} out of bounds [0..31] (5 bits)"
            )
        if not (0 <= self.time_gap <= 15):
            raise SCIFormatError(f"time_gap {self.time_gap} out of bounds [0..15] (4 bits)")
        if not (0 <= self.mcs <= 31):
            raise SCIFormatError(f"mcs {self.mcs} out of bounds [0..31] (5 bits)")
        if self.retx_index not in (0, 1):
            raise SCIFormatError(f"retx_index {self.retx_index} must be 0 or 1 (1 bit)")

    @property
    def reservation_interval_ms(self) -> int:
        """Return the SPS resource reservation period in ms."""
        return RRI_MAPPING_MS.get(self.resource_reservation, 0)

    def serialize(self) -> bytes:
        """Pack SCI Format 1 into 4 octets (32 bits with 10 trailing padding bits).

        Bit Packing:
          Bit 31..29: priority (3b)
          Bit 28..25: resource_reservation (4b)
          Bit 24..20: freq_resource_location (5b)
          Bit 19..16: time_gap (4b)
          Bit 15..11: mcs (5b)
          Bit 10:     retx_index (1b)
          Bit 9..0:   padding zeros (10b)
        """
        self.validate()
        word = (
            ((self.priority & 0x07) << 29)
            | ((self.resource_reservation & 0x0F) << 25)
            | ((self.freq_resource_location & 0x1F) << 20)
            | ((self.time_gap & 0x0F) << 16)
            | ((self.mcs & 0x1F) << 11)
            | ((self.retx_index & 0x01) << 10)
        )
        return struct.pack("!I", word)

    @classmethod
    def deserialize(cls, data: bytes) -> SCIFormat1:
        """Unpack SCI Format 1 from binary."""
        if len(data) < 4:
            raise SCIFormatError(f"SCI Format 1 truncated: {len(data)} bytes (requires 4)")

        word = struct.unpack("!I", data[:4])[0]
        priority = (word >> 29) & 0x07
        res_res = (word >> 25) & 0x0F
        freq_loc = (word >> 20) & 0x1F
        time_gap = (word >> 16) & 0x0F
        mcs = (word >> 11) & 0x1F
        retx_idx = (word >> 10) & 0x01

        return cls(
            priority=priority,
            resource_reservation=res_res,
            freq_resource_location=freq_loc,
            time_gap=time_gap,
            mcs=mcs,
            retx_index=retx_idx,
        )


# ---------------------------------------------------------------------------
# Sidelink Transport Block (SL-SCH PDU)
# ---------------------------------------------------------------------------

@dataclass
class SidelinkTransportBlock:
    """Represents a 3GPP Release 14 SL-SCH Transport Block carried on PSSCH.

    Format:
      [3 bytes: Source Layer-2 ID]
      [3 bytes: Destination Layer-2 ID (0xFFFFFF for broadcast)]
      [2 bytes: Payload length]
      [N bytes: Payload (IEEE 1609.2 SPDU)]
      [3 bytes: CRC-24A]
    """
    payload: bytes
    source_l2_id: bytes = b"\x00\x00\x01"
    dest_l2_id: bytes = V2X_BROADCAST_L2_ID

    def serialize(self, compute_crc: bool = True) -> bytes:
        """Encode Transport Block into wire format."""
        if len(self.source_l2_id) != 3 or len(self.dest_l2_id) != 3:
            raise TransportBlockError("Source and Destination L2 IDs must be exactly 3 bytes")

        buf = bytearray()
        buf.extend(self.source_l2_id)
        buf.extend(self.dest_l2_id)
        buf.extend(struct.pack("!H", len(self.payload)))
        buf.extend(self.payload)

        if compute_crc:
            crc = compute_crc24a(bytes(buf))
            buf.extend(bytes([(crc >> 16) & 0xFF, (crc >> 8) & 0xFF, crc & 0xFF]))

        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes, verify_crc: bool = True) -> SidelinkTransportBlock:
        """Decode Transport Block from wire format."""
        # 3 (src) + 3 (dst) + 2 (len) + 3 (crc) = 11 bytes minimum
        if len(data) < 11:
            raise TransportBlockError(f"Transport Block truncated: {len(data)} bytes (minimum 11)")

        if verify_crc:
            body = data[:-3]
            expected_crc = (data[-3] << 16) | (data[-2] << 8) | data[-1]
            actual_crc = compute_crc24a(body)
            if expected_crc != actual_crc:
                raise TransportBlockError(
                    f"Transport Block CRC-24A mismatch: expected 0x{expected_crc:06X}, computed 0x{actual_crc:06X}"
                )

        src_id = data[:3]
        dst_id = data[3:6]
        payload_len = struct.unpack("!H", data[6:8])[0]
        rem = data[8:-3]

        if len(rem) < payload_len:
            raise TransportBlockError(
                f"Transport Block payload truncated: expected {payload_len}, got {len(rem)}"
            )

        payload = rem[:payload_len]
        return cls(
            payload=payload,
            source_l2_id=src_id,
            dest_l2_id=dst_id,
        )

