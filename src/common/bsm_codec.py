"""
V2X Gateway Simulator — SAE J2735 BSM Part I Codec
===================================================
ASN.1 UPER encoder and decoder for SAE J2735 BasicSafetyMessage Part I.

Standards References:
  - SAE J2735-2020: Section 7 (BasicSafetyMessage, BSMcoreData)
  - ITU-T X.691: Unaligned Packed Encoding Rules (UPER)
  - IEEE 1609.3: PSID 0x20 for BSM

DEVIATION L2:
  Hand-crafted BSM Part I subset (14 mandatory fields). Part II optional
  extensions are omitted due to proprietary SAE ASN.1 distribution restrictions.
  See docs/deviations.md for full rationale.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import threading

import asn1tools

from common.exceptions import (
    BSMDecodeError,
    BSMEncodeError,
    ConstraintViolationError,
)
from common.message_types import (
    BSM_ELEV_MAX,
    BSM_ELEV_MIN,
    BSM_ELEV_UNKNOWN,
    BSM_HEADING_MAX,
    BSM_HEADING_MIN,
    BSM_LAT_MAX,
    BSM_LAT_MIN,
    BSM_LENGTH_MAX,
    BSM_LON_MAX,
    BSM_LON_MIN,
    BSM_MSG_CNT_MAX,
    BSM_MSG_CNT_MIN,
    BSM_SPEED_MAX,
    BSM_SPEED_MIN,
    BSM_TEMP_ID_LENGTH,
    BSM_WIDTH_MAX,
)

# ---------------------------------------------------------------------------
# ASN.1 Database Cache (Thread-safe)
# ---------------------------------------------------------------------------

_ASN1_DB: Optional[asn1tools.compiler.Specification] = None
_ASN1_LOCK = threading.Lock()
_ASN1_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "asn1" / "BSM_PartI_Subset_v1.asn"


def get_asn1_db() -> asn1tools.compiler.Specification:
    """Return the cached compiled ASN.1 specification (UPER codec)."""
    global _ASN1_DB
    if _ASN1_DB is None:
        with _ASN1_LOCK:
            if _ASN1_DB is None:
                if not _ASN1_SCHEMA_PATH.exists():
                    raise FileNotFoundError(f"ASN.1 schema not found: {_ASN1_SCHEMA_PATH}")
                _ASN1_DB = asn1tools.compile_files(
                    str(_ASN1_SCHEMA_PATH),
                    codec="uper",
                )
    return _ASN1_DB


# ---------------------------------------------------------------------------
# BasicSafetyMessage Dataclass (J2735 Part I)
# ---------------------------------------------------------------------------

@dataclass
class BasicSafetyMessage:
    """SAE J2735 Basic Safety Message (Part I Mandatory Core Data).

    Units and conventions per SAE J2735-2020:
      - msg_cnt: 0..127 sequence counter
      - vehicle_id: 4-byte temporary pseudonym identifier
      - sec_mark: millisecond within current minute (0..65535)
      - lat: 1/10 microdegrees (-900000000..900000000; 900000001=unavailable)
      - lon: 1/10 microdegrees (-1799999999..1800000000; 1800000001=unavailable)
      - elev: 0.1 m (-4096..61439; -4096=unknown)
      - semi_major: 0..255 (units: 5 cm; 255=unavailable)
      - semi_minor: 0..255 (units: 5 cm; 255=unavailable)
      - orientation: 0..65535 (0.0054932° per step; 65535=unavailable)
      - transmission: 'neutral'|'park'|'forwardGears'|'reverseGears'|'reserved1'|'reserved2'|'reserved3'|'unavailable'
      - speed: 0..8191 (units: 0.02 m/s; 8191=unavailable)
      - heading: 0..28800 (units: 0.0125°; 28800=unavailable)
      - steering: -126..127 (units: 1.5°; -128=unavailable)
      - accel_lon: -2000..2001 (units: 0.01 m/s²; 2001=unavailable)
      - accel_lat: -2000..2001 (units: 0.01 m/s²; 2001=unavailable)
      - accel_vert: -127..127 (units: 0.02 g; -128=unavailable)
      - yaw_rate: -32767..32767 (units: 0.01 deg/s; -32768=unavailable)
      - wheel_brakes: bytes of length 1 (4 bits used) or tuple (bytes, int)
      - traction: 'unavailable'|'off'|'on'|'engaged'
      - abs: 'unavailable'|'off'|'on'|'engaged'
      - scs: 'unavailable'|'off'|'on'|'engaged'
      - brake_boost: 'unavailable'|'notApplied'|'applied'
      - aux_brakes: 'unavailable'|'off'|'on'|'reserved'
      - width: 0..1023 (cm; 0=unavailable)
      - length: 0..4095 (cm; 0=unavailable)
    """

    msg_cnt: int
    vehicle_id: bytes
    sec_mark: int
    lat: int
    lon: int
    elev: int = 0
    semi_major: int = 255
    semi_minor: int = 255
    orientation: int = 65535
    transmission: str = "forwardGears"
    speed: int = 0
    heading: int = 0
    steering: int = 0
    accel_lon: int = 0
    accel_lat: int = 0
    accel_vert: int = 0
    yaw_rate: int = 0
    wheel_brakes: bytes = b"\x00"
    traction: str = "unavailable"
    abs: str = "unavailable"
    scs: str = "unavailable"
    brake_boost: str = "unavailable"
    aux_brakes: str = "unavailable"
    width: int = 200
    length: int = 450

    # -----------------------------------------------------------------------
    # Convenience Helpers
    # -----------------------------------------------------------------------

    @property
    def lat_degrees(self) -> float:
        """Latitude in decimal degrees (-90.0 to +90.0)."""
        return self.lat / 10_000_000.0

    @property
    def lon_degrees(self) -> float:
        """Longitude in decimal degrees (-180.0 to +180.0)."""
        return self.lon / 10_000_000.0

    @property
    def speed_mps(self) -> float:
        """Speed in metres per second (m/s)."""
        if self.speed == 8191:
            return float("nan")
        return self.speed * 0.02

    @property
    def speed_kmh(self) -> float:
        """Speed in kilometres per hour (km/h)."""
        return self.speed_mps * 3.6

    @property
    def heading_degrees(self) -> float:
        """Heading in decimal degrees (0.0 to 360.0, 0=North)."""
        if self.heading == 28800:
            return float("nan")
        return self.heading * 0.0125

    @classmethod
    def create(
        cls,
        msg_cnt: int,
        vehicle_id: bytes,
        lat_deg: float,
        lon_deg: float,
        speed_mps: float = 0.0,
        heading_deg: float = 0.0,
        sec_mark: int = 0,
        elev_m: float = 0.0,
        width_cm: int = 200,
        length_cm: int = 450,
        transmission: str = "forwardGears",
    ) -> BasicSafetyMessage:
        """Construct a BSM from human-friendly units."""
        lat_raw = int(round(lat_deg * 10_000_000))
        lon_raw = int(round(lon_deg * 10_000_000))
        elev_raw = int(round(elev_m * 10))
        speed_raw = min(8191, max(0, int(round(speed_mps / 0.02))))
        heading_raw = min(28800, max(0, int(round(heading_deg / 0.0125))))

        return cls(
            msg_cnt=msg_cnt,
            vehicle_id=vehicle_id,
            sec_mark=sec_mark,
            lat=lat_raw,
            lon=lon_raw,
            elev=elev_raw,
            speed=speed_raw,
            heading=heading_raw,
            width=width_cm,
            length=length_cm,
            transmission=transmission,
        )

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    def validate(self) -> None:
        """Validate all field constraints per SAE J2735.

        Raises:
            ConstraintViolationError: If any field is outside its allowable bounds.
        """
        if not (BSM_MSG_CNT_MIN <= self.msg_cnt <= BSM_MSG_CNT_MAX):
            raise ConstraintViolationError(
                f"msg_cnt {self.msg_cnt} out of bounds [{BSM_MSG_CNT_MIN}..{BSM_MSG_CNT_MAX}]"
            )

        if not isinstance(self.vehicle_id, bytes) or len(self.vehicle_id) != BSM_TEMP_ID_LENGTH:
            raise ConstraintViolationError(
                f"vehicle_id must be {BSM_TEMP_ID_LENGTH} bytes, got {len(self.vehicle_id) if isinstance(self.vehicle_id, bytes) else type(self.vehicle_id)}"
            )

        if not (0 <= self.sec_mark <= 65535):
            raise ConstraintViolationError(f"sec_mark {self.sec_mark} out of bounds [0..65535]")

        if not (BSM_LAT_MIN <= self.lat <= 900_000_001):
            raise ConstraintViolationError(f"lat {self.lat} out of bounds [{BSM_LAT_MIN}..900000001]")

        if not (-1_799_999_999 <= self.lon <= 1_800_000_001):
            raise ConstraintViolationError(f"lon {self.lon} out of bounds [-1799999999..1800000001]")

        if not (BSM_ELEV_MIN <= self.elev <= BSM_ELEV_MAX):
            raise ConstraintViolationError(f"elev {self.elev} out of bounds [{BSM_ELEV_MIN}..{BSM_ELEV_MAX}]")

        if not (BSM_SPEED_MIN <= self.speed <= BSM_SPEED_MAX):
            raise ConstraintViolationError(f"speed {self.speed} out of bounds [{BSM_SPEED_MIN}..{BSM_SPEED_MAX}]")

        if not (BSM_HEADING_MIN <= self.heading <= BSM_HEADING_MAX):
            raise ConstraintViolationError(f"heading {self.heading} out of bounds [{BSM_HEADING_MIN}..{BSM_HEADING_MAX}]")

        if not (-126 <= self.steering <= 127):
            raise ConstraintViolationError(f"steering {self.steering} out of bounds [-126..127]")

        if not (0 <= self.width <= BSM_WIDTH_MAX):
            raise ConstraintViolationError(f"width {self.width} out of bounds [0..{BSM_WIDTH_MAX}]")

        if not (0 <= self.length <= BSM_LENGTH_MAX):
            raise ConstraintViolationError(f"length {self.length} out of bounds [0..{BSM_LENGTH_MAX}]")

        valid_transmissions = {
            "neutral", "park", "forwardGears", "reverseGears",
            "reserved1", "reserved2", "reserved3", "unavailable",
        }
        if self.transmission not in valid_transmissions:
            raise ConstraintViolationError(f"Invalid transmission state: {self.transmission}")

    # -----------------------------------------------------------------------
    # Dictionary Conversion
    # -----------------------------------------------------------------------

    def to_asn1_dict(self) -> Dict[str, Any]:
        """Convert to the nested dictionary expected by the compiled ASN.1 UPER codec."""
        self.validate()

        # wheelBrakes is a BIT STRING (SIZE(4)) in the ASN.1 schema
        # In asn1tools, BIT STRING is represented as a tuple: (bytes, number_of_bits)
        if isinstance(self.wheel_brakes, bytes):
            wb_tuple = (self.wheel_brakes[:1], 4)
        elif isinstance(self.wheel_brakes, tuple):
            wb_tuple = self.wheel_brakes
        else:
            wb_tuple = (b"\x00", 4)

        return {
            "coreData": {
                "msgCnt": self.msg_cnt,
                "id": self.vehicle_id,
                "secMark": self.sec_mark,
                "lat": self.lat,
                "long": self.lon,
                "elev": self.elev,
                "accuracy": {
                    "semiMajor": self.semi_major,
                    "semiMinor": self.semi_minor,
                    "orientation": self.orientation,
                },
                "transmission": self.transmission,
                "speed": self.speed,
                "heading": self.heading,
                "angle": self.steering,
                "accelSet": {
                    "long": self.accel_lon,
                    "lat": self.accel_lat,
                    "vert": self.accel_vert,
                    "yaw": self.yaw_rate,
                },
                "brakes": {
                    "wheelBrakes": wb_tuple,
                    "traction": self.traction,
                    "abs": self.abs,
                    "scs": self.scs,
                    "brakeBoost": self.brake_boost,
                    "auxBrakes": self.aux_brakes,
                },
                "size": {
                    "width": self.width,
                    "length": self.length,
                },
            }
        }

    @classmethod
    def from_asn1_dict(cls, data: Dict[str, Any]) -> BasicSafetyMessage:
        """Construct BasicSafetyMessage from the decoded ASN.1 dictionary."""
        try:
            core = data["coreData"]
            acc = core.get("accuracy", {})
            accel = core.get("accelSet", {})
            brakes = core.get("brakes", {})
            size = core.get("size", {})

            # Extract wheelBrakes bit string
            wb = brakes.get("wheelBrakes", (b"\x00", 4))
            wb_bytes = wb[0] if isinstance(wb, tuple) else (wb if isinstance(wb, bytes) else b"\x00")

            msg = cls(
                msg_cnt=core["msgCnt"],
                vehicle_id=core["id"],
                sec_mark=core["secMark"],
                lat=core["lat"],
                lon=core["long"],
                elev=core.get("elev", 0),
                semi_major=acc.get("semiMajor", 255),
                semi_minor=acc.get("semiMinor", 255),
                orientation=acc.get("orientation", 65535),
                transmission=core.get("transmission", "forwardGears"),
                speed=core.get("speed", 0),
                heading=core.get("heading", 0),
                steering=core.get("angle", 0),
                accel_lon=accel.get("long", 0),
                accel_lat=accel.get("lat", 0),
                accel_vert=accel.get("vert", 0),
                yaw_rate=accel.get("yaw", 0),
                wheel_brakes=wb_bytes,
                traction=brakes.get("traction", "unavailable"),
                abs=brakes.get("abs", "unavailable"),
                scs=brakes.get("scs", "unavailable"),
                brake_boost=brakes.get("brakeBoost", "unavailable"),
                aux_brakes=brakes.get("auxBrakes", "unavailable"),
                width=size.get("width", 200),
                length=size.get("length", 450),
            )
            msg.validate()
            return msg
        except KeyError as exc:
            raise BSMDecodeError(f"Missing mandatory ASN.1 field: {exc}") from exc
        except ConstraintViolationError as exc:
            raise BSMDecodeError(f"Decoded BSM violates constraints: {exc}") from exc
        except Exception as exc:
            raise BSMDecodeError(f"Failed to parse BSM dictionary: {exc}") from exc


# ---------------------------------------------------------------------------
# Public Encode / Decode Functions
# ---------------------------------------------------------------------------

def encode_bsm_uper(bsm: BasicSafetyMessage) -> bytes:
    """Encode a BasicSafetyMessage into UPER bytes per SAE J2735.

    Args:
        bsm: Validated BasicSafetyMessage instance.

    Returns:
        Compact UPER-encoded bytes (typically 30–45 bytes).

    Raises:
        ConstraintViolationError: If any field violates ASN.1 constraint boundaries.
        BSMEncodeError: If UPER bit-stream compilation fails.
    """
    bsm.validate()
    db = get_asn1_db()
    d = bsm.to_asn1_dict()
    try:
        return db.encode("BasicSafetyMessage", d, check_constraints=True)
    except Exception as exc:
        raise BSMEncodeError(f"UPER encoding failed: {exc}") from exc


def decode_bsm_uper(data: bytes) -> BasicSafetyMessage:
    """Decode UPER bytes into a BasicSafetyMessage instance.

    Args:
        data: Over-the-air UPER-encoded byte stream.

    Returns:
        BasicSafetyMessage instance.

    Raises:
        BSMDecodeError: If byte stream is truncated, invalid, or malformed.
    """
    if not data:
        raise BSMDecodeError("Empty payload: cannot decode BSM from 0 bytes")
    db = get_asn1_db()
    try:
        decoded_dict = db.decode("BasicSafetyMessage", data)
    except Exception as exc:
        raise BSMDecodeError(f"UPER decoding failed: {exc}") from exc

    return BasicSafetyMessage.from_asn1_dict(decoded_dict)

