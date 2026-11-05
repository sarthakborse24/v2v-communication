"""
V2X Gateway Simulator — IEEE 1609.3 WSMP (WAVE Short Message Protocol)
======================================================================
Standards References:
  - IEEE 1609.3-2016: Section 8 (WSMP Specification)
  - IEEE 1609.3-2016: Section 8.1.3 (Variable-length PSID encoding)
  - IEEE 1609.3 Annex: EtherType 0x88DC
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Optional, Tuple

from common.exceptions import (
    PSIDEncodingError,
    WSMPError,
    WSMPLengthError,
    WSMPVersionError,
)
from common.message_types import (
    ETHERTYPE_WSMP,
    PSID,
)


# ---------------------------------------------------------------------------
# Variable-Length PSID Encoding & Decoding (IEEE 1609.3 §8.1.3)
# ---------------------------------------------------------------------------

def encode_variable_psid(psid: int) -> bytes:
    """Encode an integer PSID into 1–4 octets per IEEE 1609.3 §8.1.3.

    Encoding rules:
      - 0xxxxxxx                        -> 1 octet  (0x00 .. 0x7F)
      - 10xxxxxx xxxxxxxx               -> 2 octets (0x80 .. 0x3FFF)
      - 110xxxxx xxxxxxxx xxxxxxxx      -> 3 octets (0x4000 .. 0x1FFFFF)
      - 1110xxxx xxxxxxxx xxxxxxxx...   -> 4 octets (0x200000 .. 0x0FFFFFFF)

    Raises:
        PSIDEncodingError: If PSID is negative or exceeds 0x0FFFFFFF.
    """
    if psid < 0 or psid > 0x0FFFFFFF:
        raise PSIDEncodingError(f"PSID 0x{psid:X} out of valid range [0..0x0FFFFFFF]")

    if psid <= 0x7F:
        return bytes([psid])
    elif psid <= 0x3FFF:
        b0 = 0x80 | ((psid >> 8) & 0x3F)
        b1 = psid & 0xFF
        return bytes([b0, b1])
    elif psid <= 0x1FFFFF:
        b0 = 0xC0 | ((psid >> 16) & 0x1F)
        b1 = (psid >> 8) & 0xFF
        b2 = psid & 0xFF
        return bytes([b0, b1, b2])
    else:  # 0x200000 .. 0x1FFFFFFF
        b0 = 0xE0 | ((psid >> 24) & 0x0F)
        b1 = (psid >> 16) & 0xFF
        b2 = (psid >> 8) & 0xFF
        b3 = psid & 0xFF
        return bytes([b0, b1, b2, b3])


def decode_variable_psid(data: bytes) -> Tuple[int, bytes]:
    """Decode variable-length PSID from the start of data.

    Returns:
        Tuple of (psid_int, remaining_bytes).

    Raises:
        PSIDEncodingError: If data is empty or truncated.
    """
    if not data:
        raise PSIDEncodingError("Cannot decode PSID from empty bytes")

    b0 = data[0]

    if (b0 & 0x80) == 0:
        # 1 octet (0xxxxxxx)
        return b0, data[1:]

    elif (b0 & 0xC0) == 0x80:
        # 2 octets (10xxxxxx)
        if len(data) < 2:
            raise PSIDEncodingError("Truncated 2-octet PSID")
        psid = ((b0 & 0x3F) << 8) | data[1]
        return psid, data[2:]

    elif (b0 & 0xE0) == 0xC0:
        # 3 octets (110xxxxx)
        if len(data) < 3:
            raise PSIDEncodingError("Truncated 3-octet PSID")
        psid = ((b0 & 0x1F) << 16) | (data[1] << 8) | data[2]
        return psid, data[3:]

    elif (b0 & 0xF0) == 0xE0:
        # 4 octets (1110xxxx)
        if len(data) < 4:
            raise PSIDEncodingError("Truncated 4-octet PSID")
        psid = ((b0 & 0x0F) << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
        return psid, data[4:]

    else:
        raise PSIDEncodingError(f"Invalid PSID leading octet: 0x{b0:02X}")


# ---------------------------------------------------------------------------
# WAVE Short Message (WSMP Packet)
# ---------------------------------------------------------------------------

@dataclass
class WSMPacket:
    """Represents an IEEE 1609.3 WSMP frame.

    Fields:
      - subtype: 4 bits (0 = standard single-hop)
      - n_ext: bool (WAVE IE Extension present)
      - version: 3 bits (standard: 3)
      - tpid: 1 octet (0 = PSID only)
      - psid: Provider Service Identifier (default: 0x20 for BSM)
      - channel_number: Optional WAVE channel override
      - data_rate: Optional transmit data rate
      - tx_power_dbm: Optional transmit power level
      - payload: WSM payload bytes (e.g. IEEE 1609.2 SPDU)
    """
    payload: bytes
    psid: int = PSID.BSM
    subtype: int = 0
    n_ext: bool = False
    version: int = 3
    tpid: int = 0
    channel_number: Optional[int] = None
    data_rate: Optional[int] = None
    tx_power_dbm: Optional[int] = None

    def serialize(self) -> bytes:
        """Encode WSMP packet to binary format.

        Layout:
          [1 octet: Subtype (4b) | N-Ext (1b) | Version (3b)]
          [1 octet: TPID]
          [1..4 octets: Variable PSID]
          [Optional WAVE IE Extension if n_ext is True]
          [2 octets: Payload length (big-endian)]
          [N octets: Payload]
        """
        buf = bytearray()

        # WSMP-N Header: 1 octet
        n_ext_bit = 1 if (self.n_ext or self.channel_number is not None) else 0
        b0 = ((self.subtype & 0x0F) << 4) | (n_ext_bit << 3) | (self.version & 0x07)
        buf.append(b0)

        # WSMP-T Header: TPID (1 octet)
        buf.append(self.tpid & 0xFF)

        # Variable PSID
        psid_bytes = encode_variable_psid(self.psid)
        buf.extend(psid_bytes)

        # WAVE Element Extension (WIE) if present
        if n_ext_bit:
            # 3 octets: Channel (1B), DataRate (1B), TxPower (1B)
            ch = self.channel_number if self.channel_number is not None else 178
            rate = self.data_rate if self.data_rate is not None else 6  # 6 Mbps default
            pwr = (self.tx_power_dbm + 128) if self.tx_power_dbm is not None else 148  # +20 dBm offset
            buf.extend([ch & 0xFF, rate & 0xFF, pwr & 0xFF])

        # WSM Data Length (2 octets)
        buf.extend(struct.pack("!H", len(self.payload)))

        # Payload
        buf.extend(self.payload)
        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes) -> WSMPacket:
        """Parse WSMP packet from binary bytes."""
        if len(data) < 4:
            raise WSMPError(f"WSMP packet truncated: {len(data)} bytes")

        b0 = data[0]
        subtype = (b0 >> 4) & 0x0F
        n_ext = bool((b0 >> 3) & 0x01)
        version = b0 & 0x07

        if version != 3:
            raise WSMPVersionError(f"Unsupported WSMP version: {version}; expected 3")

        tpid = data[1]
        ptr = 2

        # Variable-length PSID
        psid, rem = decode_variable_psid(data[ptr:])
        ptr = len(data) - len(rem)

        # WIE extension if present
        channel_num = None
        data_rate = None
        tx_pwr = None
        if n_ext:
            if len(rem) < 3:
                raise WSMPError("Truncated WAVE Element Extension (WIE)")
            channel_num = rem[0]
            data_rate = rem[1]
            tx_pwr = rem[2] - 128
            rem = rem[3:]
            ptr += 3

        # Payload length (2 octets)
        if len(rem) < 2:
            raise WSMPError("Truncated WSM length field")
        payload_len = struct.unpack("!H", rem[:2])[0]
        rem = rem[2:]

        if len(rem) < payload_len:
            raise WSMPLengthError(
                f"WSMP payload length mismatch: declared {payload_len}, available {len(rem)}"
            )

        payload = rem[:payload_len]
        return cls(
            payload=payload,
            psid=psid,
            subtype=subtype,
            n_ext=n_ext,
            version=version,
            tpid=tpid,
            channel_number=channel_num,
            data_rate=data_rate,
            tx_power_dbm=tx_pwr,
        )
