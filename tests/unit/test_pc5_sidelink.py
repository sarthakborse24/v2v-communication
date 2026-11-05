"""
Unit Tests for 3GPP Release 14 PC5 Sidelink Protocols
======================================================
Standards References:
  - 3GPP TS 36.212 Release 14: Section 8.4.1 (SCI Format 1)
  - 3GPP TS 36.321 Release 14: Section 5.14 (SL-SCH Transport Block)
"""

import pytest

from common.exceptions import (
    PC5Error,
    SCIFormatError,
    TransportBlockError,
)
from cv2x.pc5.sidelink import (
    RRI_MAPPING_MS,
    SCIFormat1,
    SidelinkTransportBlock,
    compute_crc24a,
)


class TestSCIFormat1:
    """Tests for SCI Format 1 packing, unpacking, and constraint validation."""

    def test_sci1_roundtrip(self):
        sci = SCIFormat1(
            priority=1,
            resource_reservation=3,
            freq_resource_location=2,
            time_gap=4,
            mcs=10,
            retx_index=0,
        )
        raw = sci.serialize()
        assert len(raw) == 4

        recovered = SCIFormat1.deserialize(raw)
        assert recovered.priority == 1
        assert recovered.resource_reservation == 3
        assert recovered.freq_resource_location == 2
        assert recovered.time_gap == 4
        assert recovered.mcs == 10
        assert recovered.retx_index == 0
        assert recovered.reservation_interval_ms == 100

    def test_sci1_boundaries(self):
        # Maximum field values
        sci_max = SCIFormat1(
            priority=7,
            resource_reservation=15,
            freq_resource_location=31,
            time_gap=15,
            mcs=31,
            retx_index=1,
        )
        raw = sci_max.serialize()
        rec_max = SCIFormat1.deserialize(raw)
        assert rec_max.priority == 7
        assert rec_max.resource_reservation == 15
        assert rec_max.freq_resource_location == 31
        assert rec_max.time_gap == 15
        assert rec_max.mcs == 31
        assert rec_max.retx_index == 1

        # Minimum field values
        sci_min = SCIFormat1(
            priority=0,
            resource_reservation=0,
            freq_resource_location=0,
            time_gap=0,
            mcs=0,
            retx_index=0,
        )
        rec_min = SCIFormat1.deserialize(sci_min.serialize())
        assert rec_min.priority == 0
        assert rec_min.reservation_interval_ms == 0

    def test_priority_out_of_bounds(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1(priority=8)
        with pytest.raises(SCIFormatError):
            SCIFormat1(priority=-1)

    def test_resource_reservation_out_of_bounds(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1(resource_reservation=16)

    def test_freq_resource_location_out_of_bounds(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1(freq_resource_location=32)

    def test_time_gap_out_of_bounds(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1(time_gap=16)

    def test_mcs_out_of_bounds(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1(mcs=32)

    def test_retx_index_invalid(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1(retx_index=2)

    def test_truncated_sci_bytes(self):
        with pytest.raises(SCIFormatError):
            SCIFormat1.deserialize(b"\x00\x00")


class TestTransportBlock:
    """Tests for SL-SCH Transport Block encapsulation and CRC-24A."""

    def test_transport_block_roundtrip(self):
        payload = b"SPDU-PAYLOAD-FOR-C-V2X-TEST"
        src = b"\x00\x01\x02"
        dst = b"\xff\xff\xff"

        tb = SidelinkTransportBlock(
            payload=payload,
            source_l2_id=src,
            dest_l2_id=dst,
        )
        raw = tb.serialize(compute_crc=True)
        # Header (3+3+2) + Payload + CRC-24A (3) = len(payload) + 11
        assert len(raw) == len(payload) + 11

        recovered = SidelinkTransportBlock.deserialize(raw, verify_crc=True)
        assert recovered.payload == payload
        assert recovered.source_l2_id == src
        assert recovered.dest_l2_id == dst

    def test_crc24a_corrupted_payload_fails(self):
        tb = SidelinkTransportBlock(payload=b"Original Payload")
        raw = tb.serialize(compute_crc=True)

        # Corrupt 1 byte in payload
        corrupted = bytearray(raw)
        corrupted[10] ^= 0x01

        with pytest.raises(TransportBlockError) as exc_info:
            SidelinkTransportBlock.deserialize(bytes(corrupted), verify_crc=True)
        assert "CRC-24A mismatch" in str(exc_info.value)

    def test_invalid_l2_id_length(self):
        with pytest.raises(TransportBlockError):
            tb = SidelinkTransportBlock(payload=b"test", source_l2_id=b"\x00\x01")
            tb.serialize()

    def test_truncated_transport_block(self):
        with pytest.raises(TransportBlockError):
            SidelinkTransportBlock.deserialize(b"\x00" * 5)
