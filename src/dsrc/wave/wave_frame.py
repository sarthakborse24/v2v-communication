"""
V2X Gateway Simulator — IEEE 802.11p WAVE Frame Encapsulation
==============================================================
Standards References:
  - IEEE 802.11p-2010: OCB (Outside the Context of a BSS) MAC Frame
  - IEEE 802.11e: EDCA QoS Control Field (TID mapping for AC_VO)
  - IEEE 802.2 / SNAP: LLC/SNAP encapsulation with EtherType 0x88DC (WSMP)
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
import zlib
from typing import Optional, Tuple

from common.exceptions import (
    InvalidEtherTypeError,
    WaveFrameError,
)
from common.message_types import (
    BSM_EDCA_CATEGORY,
    EDCACategory,
    ETHERTYPE_WSMP,
)


# Standard 802.11p Broadcast MAC address
BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"

# LLC/SNAP header constants
LLC_SNAP_PREFIX = b"\xaa\xaa\x03\x00\x00\x00"  # DSAP(0xAA) + SSAP(0xAA) + Control(0x03) + OUI(0x000000)


def mac_to_str(mac: bytes) -> str:
    """Format 6-byte MAC address as human-readable string."""
    return ":".join(f"{b:02x}" for b in mac)


def str_to_mac(mac_str: str) -> bytes:
    """Parse MAC address string into 6 bytes."""
    parts = mac_str.strip().split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {mac_str}")
    return bytes(int(p, 16) for p in parts)


@dataclass
class WAVEFrame:
    """Represents an IEEE 802.11p OCB QoS-Data MAC Frame carrying WSMP.

    Header format:
      [2 bytes: Frame Control (Type=Data, Subtype=QoS Data = 0x0088)]
      [2 bytes: Duration/ID]
      [6 bytes: Address 1 (Destination / RA) - default Broadcast]
      [6 bytes: Address 2 (Transmitter / TA)]
      [6 bytes: Address 3 (BSSID) - default Broadcast in OCB mode]
      [2 bytes: Sequence Control (4b Fragment + 12b Sequence Number)]
      [2 bytes: QoS Control (TID 0..7; TID 6/7 = AC_VO for BSM)]
      [8 bytes: LLC/SNAP Header (DSAP 0xAA, SSAP 0xAA, Ctrl 0x03, OUI 0x000000, EtherType 0x88DC)]
      [N bytes: Frame Body (WSMP packet bytes)]
      [4 bytes: FCS (CRC-32)]
    """
    payload: bytes  # Raw WSMP packet bytes
    source_mac: bytes = b"\x00\x00\x00\x00\x00\x01"
    dest_mac: bytes = BROADCAST_MAC
    bssid: bytes = BROADCAST_MAC  # Wildcard in 802.11p OCB mode
    seq_num: int = 0
    frag_num: int = 0
    edca_category: EDCACategory = BSM_EDCA_CATEGORY
    ethertype: int = ETHERTYPE_WSMP

    def serialize(self, compute_fcs: bool = True) -> bytes:
        """Serialize 802.11p MAC frame to wire format."""
        if len(self.source_mac) != 6 or len(self.dest_mac) != 6 or len(self.bssid) != 6:
            raise WaveFrameError("All MAC addresses must be exactly 6 bytes")

        buf = bytearray()

        # Frame Control: 0x0088 (QoS Data, To DS=0, From DS=0)
        fc = 0x0088
        buf.extend(struct.pack("<H", fc))

        # Duration/ID: 0
        buf.extend(struct.pack("<H", 0))

        # Address 1 (RA / Destination)
        buf.extend(self.dest_mac)

        # Address 2 (TA / Source)
        buf.extend(self.source_mac)

        # Address 3 (BSSID - wildcard broadcast in OCB mode)
        buf.extend(self.bssid)

        # Sequence Control: 4 bits frag + 12 bits sequence number
        seq_ctrl = ((self.seq_num & 0x0FFF) << 4) | (self.frag_num & 0x0F)
        buf.extend(struct.pack("<H", seq_ctrl))

        # QoS Control: TID in bits 0..3 (TID 6 for AC_VO)
        tid = 6 if self.edca_category == EDCACategory.AC_VO else int(self.edca_category)
        qos_ctrl = tid & 0x0F
        buf.extend(struct.pack("<H", qos_ctrl))

        # LLC/SNAP Header (8 bytes)
        buf.extend(LLC_SNAP_PREFIX)
        buf.extend(struct.pack("!H", self.ethertype))

        # Frame Body (WSMP payload)
        buf.extend(self.payload)

        # 4-byte FCS (CRC-32)
        if compute_fcs:
            fcs = zlib.crc32(bytes(buf)) & 0xFFFFFFFF
            buf.extend(struct.pack("<I", fcs))

        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes, verify_fcs: bool = True) -> WAVEFrame:
        """Parse 802.11p MAC frame from bytes."""
        # Minimum header = 24 (MAC) + 2 (QoS) + 8 (LLC/SNAP) + 4 (FCS) = 38 bytes
        if len(data) < 38:
            raise WaveFrameError(f"802.11p frame truncated: {len(data)} bytes (minimum 38)")

        # Verify FCS if present
        if verify_fcs:
            expected_fcs = struct.unpack("<I", data[-4:])[0]
            computed_fcs = zlib.crc32(data[:-4]) & 0xFFFFFFFF
            if expected_fcs != computed_fcs:
                raise WaveFrameError(
                    f"FCS checksum mismatch: expected 0x{expected_fcs:08X}, computed 0x{computed_fcs:08X}"
                )

        body_with_fcs = data[:-4]

        # Parse MAC header fields
        fc = struct.unpack("<H", body_with_fcs[:2])[0]
        dest_mac = body_with_fcs[4:10]
        source_mac = body_with_fcs[10:16]
        bssid = body_with_fcs[16:22]
        seq_ctrl = struct.unpack("<H", body_with_fcs[22:24])[0]
        seq_num = (seq_ctrl >> 4) & 0x0FFF
        frag_num = seq_ctrl & 0x0F

        # QoS control
        qos_ctrl = struct.unpack("<H", body_with_fcs[24:26])[0]
        tid = qos_ctrl & 0x0F
        edca = EDCACategory.AC_VO if tid in (6, 7) else EDCACategory.AC_BE

        # LLC/SNAP header (offset 26..34)
        snap = body_with_fcs[26:32]
        if snap != LLC_SNAP_PREFIX:
            raise WaveFrameError(f"Invalid LLC/SNAP header: {snap.hex()}")

        ethertype = struct.unpack("!H", body_with_fcs[32:34])[0]
        if ethertype != ETHERTYPE_WSMP:
            raise InvalidEtherTypeError(
                f"Invalid EtherType in WAVE frame: 0x{ethertype:04X}; expected 0x{ETHERTYPE_WSMP:04X} (WSMP)"
            )

        payload = body_with_fcs[34:]
        return cls(
            payload=payload,
            source_mac=source_mac,
            dest_mac=dest_mac,
            bssid=bssid,
            seq_num=seq_num,
            frag_num=frag_num,
            edca_category=edca,
            ethertype=ethertype,
        )
