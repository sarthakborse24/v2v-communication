"""
Unit Tests for IEEE 1609.3 WSMP (WAVE Short Message Protocol)
==============================================================
Standards References:
  - IEEE 1609.3-2016: Section 8
  - IEEE 1609.3-2016: Section 8.1.3 (Variable PSID encoding)
"""

import pytest

from common.exceptions import (
    PSIDEncodingError,
    WSMPError,
    WSMPLengthError,
    WSMPVersionError,
)
from common.message_types import PSID
from dsrc.wave.wsmp import (
    WSMPacket,
    decode_variable_psid,
    encode_variable_psid,
)


class TestVariablePSID:
    """Tests for variable-length PSID encoding/decoding per IEEE 1609.3 §8.1.3."""

    def test_psid_1_octet_bsm(self):
        """BSM PSID 0x20 must encode to exactly 1 octet (0x20)."""
        encoded = encode_variable_psid(PSID.BSM)
        assert encoded == b"\x20"
        decoded, rem = decode_variable_psid(encoded)
        assert decoded == PSID.BSM
        assert rem == b""

    def test_psid_1_octet_boundaries(self):
        # 0x00
        b0 = encode_variable_psid(0x00)
        assert b0 == b"\x00"
        assert decode_variable_psid(b0)[0] == 0x00

        # 0x7F (maximum 1-octet PSID)
        b7f = encode_variable_psid(0x7F)
        assert b7f == b"\x7F"
        assert decode_variable_psid(b7f)[0] == 0x7F

    def test_psid_2_octets(self):
        # 0x80 (minimum 2-octet PSID)
        b80 = encode_variable_psid(0x80)
        assert len(b80) == 2
        assert decode_variable_psid(b80)[0] == 0x80

        # 0x3FFF (maximum 2-octet PSID)
        b3fff = encode_variable_psid(0x3FFF)
        assert len(b3fff) == 2
        assert decode_variable_psid(b3fff)[0] == 0x3FFF

    def test_psid_3_octets(self):
        # 0x4000 (minimum 3-octet PSID)
        b4k = encode_variable_psid(0x4000)
        assert len(b4k) == 3
        assert decode_variable_psid(b4k)[0] == 0x4000

        # 0x1FFFFF (maximum 3-octet PSID)
        b_max3 = encode_variable_psid(0x1FFFFF)
        assert len(b_max3) == 3
        assert decode_variable_psid(b_max3)[0] == 0x1FFFFF

    def test_psid_4_octets(self):
        # 0x200000 (minimum 4-octet PSID)
        b200k = encode_variable_psid(0x200000)
        assert len(b200k) == 4
        assert decode_variable_psid(b200k)[0] == 0x200000

        # 0x0FFFFFFF (maximum 4-octet PSID)
        b_max4 = encode_variable_psid(0x0FFFFFFF)
        assert len(b_max4) == 4
        assert decode_variable_psid(b_max4)[0] == 0x0FFFFFFF

    def test_psid_out_of_bounds_raises(self):
        with pytest.raises(PSIDEncodingError):
            encode_variable_psid(-1)
        with pytest.raises(PSIDEncodingError):
            encode_variable_psid(0x10000000)

    def test_decode_empty_raises(self):
        with pytest.raises(PSIDEncodingError):
            decode_variable_psid(b"")

    def test_decode_truncated_2_octet(self):
        with pytest.raises(PSIDEncodingError):
            decode_variable_psid(b"\x85")  # High bit 10 indicates 2 bytes, but only 1 provided


class TestWSMPacket:
    """Tests for WSMP frame building, serialization, and parsing."""

    def test_wsmp_roundtrip(self):
        payload = b"IEEE-1609.2-SPDU-TEST-PAYLOAD"
        pkt = WSMPacket(
            payload=payload,
            psid=PSID.BSM,
            subtype=0,
            version=3,
        )
        raw = pkt.serialize()
        assert len(raw) > len(payload)

        recovered = WSMPacket.deserialize(raw)
        assert recovered.payload == payload
        assert recovered.psid == PSID.BSM
        assert recovered.version == 3
        assert recovered.subtype == 0

    def test_wsmp_with_wave_element_extension(self):
        """Test with WIE extension (channel, rate, power)."""
        payload = b"PayloadWithWIE"
        pkt = WSMPacket(
            payload=payload,
            psid=PSID.BSM,
            channel_number=178,
            data_rate=12,
            tx_power_dbm=20,
        )
        raw = pkt.serialize()
        recovered = WSMPacket.deserialize(raw)

        assert recovered.payload == payload
        assert recovered.channel_number == 178
        assert recovered.data_rate == 12
        assert recovered.tx_power_dbm == 20

    def test_unsupported_version_raises(self):
        # Forge packet with version = 4
        bad_b0 = (0 << 4) | (0 << 3) | 4
        raw = bytes([bad_b0, 0x00, 0x20, 0x00, 0x04]) + b"test"
        with pytest.raises(WSMPVersionError):
            WSMPacket.deserialize(raw)

    def test_payload_length_mismatch_raises(self):
        pkt = WSMPacket(payload=b"12345678")
        raw = pkt.serialize()
        # Truncate 3 bytes off the end
        truncated = raw[:-3]
        with pytest.raises(WSMPLengthError):
            WSMPacket.deserialize(truncated)

    def test_truncated_header_raises(self):
        with pytest.raises(WSMPError):
            WSMPacket.deserialize(b"\x03")
