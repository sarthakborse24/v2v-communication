"""
Unit Tests for SAE J2735 BSM Codec (UPER)
===========================================
Standards References:
  - SAE J2735-2020: BasicSafetyMessage Part I
  - ITU-T X.691: UPER encoding
"""

import json
from pathlib import Path
import pytest

from common.bsm_codec import (
    BasicSafetyMessage,
    decode_bsm_uper,
    encode_bsm_uper,
)
from common.exceptions import (
    BSMDecodeError,
    BSMEncodeError,
    ConstraintViolationError,
)


@pytest.fixture
def sample_bsm() -> BasicSafetyMessage:
    """Fixture providing a standard valid BSM."""
    return BasicSafetyMessage(
        msg_cnt=42,
        vehicle_id=b"\x12\x34\x56\x78",
        sec_mark=12345,
        lat=374270000,      # 37.4270000° N
        lon=-1220000000,    # -122.0000000° W
        elev=150,           # 15.0 m
        semi_major=50,
        semi_minor=30,
        orientation=10000,
        transmission="forwardGears",
        speed=1500,         # 30.0 m/s = 108 km/h
        heading=7200,       # 90.0° (East)
        steering=5,
        accel_lon=10,
        accel_lat=0,
        accel_vert=0,
        yaw_rate=0,
        wheel_brakes=b"\x00",
        traction="unavailable",
        abs="unavailable",
        scs="unavailable",
        brake_boost="unavailable",
        aux_brakes="unavailable",
        width=200,
        length=450,
    )


class TestBSMCodec:
    """Core BSM encode/decode functionality tests."""

    def test_encode_decode_roundtrip(self, sample_bsm):
        """A BSM encoded to UPER and decoded must yield identical fields."""
        raw = encode_bsm_uper(sample_bsm)
        assert isinstance(raw, bytes)
        assert len(raw) > 0

        decoded = decode_bsm_uper(raw)
        assert decoded.msg_cnt == sample_bsm.msg_cnt
        assert decoded.vehicle_id == sample_bsm.vehicle_id
        assert decoded.sec_mark == sample_bsm.sec_mark
        assert decoded.lat == sample_bsm.lat
        assert decoded.lon == sample_bsm.lon
        assert decoded.elev == sample_bsm.elev
        assert decoded.semi_major == sample_bsm.semi_major
        assert decoded.semi_minor == sample_bsm.semi_minor
        assert decoded.orientation == sample_bsm.orientation
        assert decoded.transmission == sample_bsm.transmission
        assert decoded.speed == sample_bsm.speed
        assert decoded.heading == sample_bsm.heading
        assert decoded.steering == sample_bsm.steering
        assert decoded.accel_lon == sample_bsm.accel_lon
        assert decoded.accel_lat == sample_bsm.accel_lat
        assert decoded.accel_vert == sample_bsm.accel_vert
        assert decoded.yaw_rate == sample_bsm.yaw_rate
        assert decoded.width == sample_bsm.width
        assert decoded.length == sample_bsm.length

    def test_compact_size(self, sample_bsm):
        """UPER encoding for BSM Part I should be compact (typically 30–50 bytes)."""
        raw = encode_bsm_uper(sample_bsm)
        assert 25 <= len(raw) <= 60, f"Unexpected UPER size: {len(raw)} bytes"

    def test_create_helper(self):
        """Test BSM creation from human-friendly units."""
        bsm = BasicSafetyMessage.create(
            msg_cnt=1,
            vehicle_id=b"\xaa\xbb\xcc\xdd",
            lat_deg=37.7749,
            lon_deg=-122.4194,
            speed_mps=25.0,
            heading_deg=180.0,
            sec_mark=30000,
            elev_m=10.0,
        )
        assert bsm.msg_cnt == 1
        assert bsm.vehicle_id == b"\xaa\xbb\xcc\xdd"
        assert abs(bsm.lat_degrees - 37.7749) < 1e-6
        assert abs(bsm.lon_degrees - (-122.4194)) < 1e-6
        assert abs(bsm.speed_mps - 25.0) < 0.05
        assert abs(bsm.speed_kmh - 90.0) < 0.1
        assert abs(bsm.heading_degrees - 180.0) < 0.1

    def test_boundary_values(self):
        """Test encoding and decoding of boundary values."""
        # Minimum boundary values
        bsm_min = BasicSafetyMessage(
            msg_cnt=0,
            vehicle_id=b"\x00\x00\x00\x00",
            sec_mark=0,
            lat=-900_000_000,
            lon=-1_799_999_999,
            elev=-4096,
            semi_major=0,
            semi_minor=0,
            orientation=0,
            transmission="neutral",
            speed=0,
            heading=0,
            steering=-126,
            accel_lon=-2000,
            accel_lat=-2000,
            accel_vert=-127,
            yaw_rate=-32767,
            width=0,
            length=0,
        )
        raw_min = encode_bsm_uper(bsm_min)
        dec_min = decode_bsm_uper(raw_min)
        assert dec_min.msg_cnt == 0
        assert dec_min.lat == -900_000_000
        assert dec_min.lon == -1_799_999_999
        assert dec_min.elev == -4096
        assert dec_min.speed == 0
        assert dec_min.heading == 0

        # Maximum boundary values
        bsm_max = BasicSafetyMessage(
            msg_cnt=127,
            vehicle_id=b"\xff\xff\xff\xff",
            sec_mark=65535,
            lat=900_000_001,
            lon=1_800_000_001,
            elev=61439,
            semi_major=255,
            semi_minor=255,
            orientation=65535,
            transmission="unavailable",
            speed=8191,
            heading=28800,
            steering=127,
            accel_lon=2001,
            accel_lat=2001,
            accel_vert=127,
            yaw_rate=32767,
            width=1023,
            length=4095,
        )
        raw_max = encode_bsm_uper(bsm_max)
        dec_max = decode_bsm_uper(raw_max)
        assert dec_max.msg_cnt == 127
        assert dec_max.speed == 8191
        assert dec_max.heading == 28800


class TestBSMConstraints:
    """Constraint enforcement tests."""

    def test_msg_cnt_overflow(self, sample_bsm):
        sample_bsm.msg_cnt = 128
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()
        with pytest.raises(ConstraintViolationError):
            encode_bsm_uper(sample_bsm)

    def test_msg_cnt_underflow(self, sample_bsm):
        sample_bsm.msg_cnt = -1
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()

    def test_invalid_vehicle_id_length(self, sample_bsm):
        sample_bsm.vehicle_id = b"\x01\x02\x03"  # Only 3 bytes
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()

    def test_lat_out_of_bounds(self, sample_bsm):
        sample_bsm.lat = 900_000_002
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()

    def test_speed_out_of_bounds(self, sample_bsm):
        sample_bsm.speed = 8192
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()

    def test_heading_out_of_bounds(self, sample_bsm):
        sample_bsm.heading = 28801
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()

    def test_invalid_transmission(self, sample_bsm):
        sample_bsm.transmission = "invalidGear"
        with pytest.raises(ConstraintViolationError):
            sample_bsm.validate()


class TestBSMDecodeErrors:
    """Handling of invalid/corrupted UPER input."""

    def test_decode_empty_bytes(self):
        with pytest.raises(BSMDecodeError):
            decode_bsm_uper(b"")

    def test_decode_truncated_bytes(self, sample_bsm):
        raw = encode_bsm_uper(sample_bsm)
        truncated = raw[: len(raw) // 2]
        with pytest.raises(BSMDecodeError):
            decode_bsm_uper(truncated)

    def test_decode_garbage_bytes(self):
        with pytest.raises(BSMDecodeError):
            decode_bsm_uper(b"\xde\xad\xbe\xef" * 5)


class TestBSMFixture:
    """Verify loading from JSON fixture."""

    def test_load_sample_json_fixture(self):
        fixture_path = Path(__file__).resolve().parents[1] / "fixtures" / "sample_bsm.json"
        assert fixture_path.exists()
        with fixture_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        bsm = BasicSafetyMessage(
            msg_cnt=data["msg_cnt"],
            vehicle_id=bytes.fromhex(data["vehicle_id"]),
            sec_mark=data["sec_mark"],
            lat=data["lat"],
            lon=data["lon"],
            elev=data["elev"],
            semi_major=data["semi_major"],
            semi_minor=data["semi_minor"],
            orientation=data["orientation"],
            transmission="forwardGears",
            speed=data["speed"],
            heading=data["heading"],
            width=data["width"],
            length=data["length"],
        )
        raw = encode_bsm_uper(bsm)
        decoded = decode_bsm_uper(raw)
        assert decoded.msg_cnt == 42
        assert decoded.vehicle_id == bytes.fromhex("AABBCCDD")

