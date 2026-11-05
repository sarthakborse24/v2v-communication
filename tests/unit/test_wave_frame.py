"""
Unit Tests for IEEE 802.11p WAVE Frame Encapsulation
=====================================================
Standards References:
  - IEEE 802.11p-2010 (OCB Mode)
  - IEEE 802.2 / SNAP (EtherType 0x88DC)
"""

import pytest

from common.exceptions import (
    InvalidEtherTypeError,
    WaveFrameError,
)
from common.message_types import (
    BSM_EDCA_CATEGORY,
    EDCACategory,
    ETHERTYPE_WSMP,
)
from dsrc.wave.wave_frame import (
    BROADCAST_MAC,
    WAVEFrame,
    mac_to_str,
    str_to_mac,
)


class TestWAVEFrame:
    """Tests for 802.11p OCB MAC frame assembly, CRC-32 verification, and LLC/SNAP parsing."""

    def test_wave_frame_roundtrip(self):
        payload = b"WSMP-PAYLOAD-FOR-WAVE-FRAME"
        src_mac = b"\x00\x11\x22\x33\x44\x55"

        frame = WAVEFrame(
            payload=payload,
            source_mac=src_mac,
            dest_mac=BROADCAST_MAC,
            seq_num=42,
            edca_category=BSM_EDCA_CATEGORY,
        )

        wire_bytes = frame.serialize(compute_fcs=True)
        assert len(wire_bytes) == len(payload) + 38  # 38 bytes header + FCS

        recovered = WAVEFrame.deserialize(wire_bytes, verify_fcs=True)
        assert recovered.payload == payload
        assert recovered.source_mac == src_mac
        assert recovered.dest_mac == BROADCAST_MAC
        assert recovered.bssid == BROADCAST_MAC
        assert recovered.seq_num == 42
        assert recovered.ethertype == ETHERTYPE_WSMP
        assert recovered.edca_category == EDCACategory.AC_VO

    def test_corrupted_fcs_fails(self):
        """1-bit flip in the frame payload or header must trigger FCS checksum mismatch."""
        frame = WAVEFrame(payload=b"Original Payload")
        wire_bytes = frame.serialize(compute_fcs=True)

        # Flip 1 bit in payload area
        corrupted = bytearray(wire_bytes)
        corrupted[30] ^= 0x01

        with pytest.raises(WaveFrameError) as exc_info:
            WAVEFrame.deserialize(bytes(corrupted), verify_fcs=True)
        assert "FCS checksum mismatch" in str(exc_info.value)

    def test_invalid_ethertype_raises(self):
        """Frame with non-WSMP EtherType (e.g. standard IPv4 0x0800) must be rejected."""
        frame = WAVEFrame(payload=b"IP packet", ethertype=0x0800)
        wire_bytes = frame.serialize(compute_fcs=True)

        with pytest.raises(InvalidEtherTypeError):
            WAVEFrame.deserialize(wire_bytes, verify_fcs=True)

    def test_truncated_frame_raises(self):
        with pytest.raises(WaveFrameError):
            WAVEFrame.deserialize(b"\x00" * 20)

    def test_mac_string_conversion(self):
        mac = b"\x00\x1a\x2b\x3c\x4d\x5e"
        mac_str = mac_to_str(mac)
        assert mac_str == "00:1a:2b:3c:4d:5e"
        assert str_to_mac(mac_str) == mac
