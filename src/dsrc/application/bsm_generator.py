"""
V2X Gateway Simulator — DSRC BSM Application Generator
=======================================================
Generates periodic SAE J2735 Basic Safety Messages for DSRC vehicles.

Standards References:
  - SAE J2735-2020: BasicSafetyMessage Part I
  - IEEE 1609.3: PSID 0x20 for BSM
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from common.bsm_codec import (
    BasicSafetyMessage,
    encode_bsm_uper,
)
from common.message_types import (
    BSM_MSG_CNT_MAX,
    PSID,
)


class BSMGenerator:
    """Maintains vehicle state and generates standards-grounded BSM messages."""

    def __init__(
        self,
        vehicle_id: bytes,
        width_cm: int = 200,
        length_cm: int = 450,
    ):
        if len(vehicle_id) != 4:
            raise ValueError(f"TemporaryID must be exactly 4 bytes, got {len(vehicle_id)}")

        self.vehicle_id = vehicle_id
        self.width_cm = width_cm
        self.length_cm = length_cm
        self._msg_cnt = 0

    @property
    def current_msg_cnt(self) -> int:
        return self._msg_cnt

    def update_vehicle_id(self, new_id: bytes) -> None:
        """Update temporary pseudonym ID (called during pseudonym certificate rotation)."""
        if len(new_id) != 4:
            raise ValueError("TemporaryID must be 4 bytes")
        self.vehicle_id = new_id

    def build_bsm(
        self,
        lat_deg: float,
        lon_deg: float,
        speed_mps: float = 0.0,
        heading_deg: float = 0.0,
        elev_m: float = 0.0,
        accel_lon_mps2: float = 0.0,
        accel_lat_mps2: float = 0.0,
        yaw_rate_deg_s: float = 0.0,
        sec_mark: Optional[int] = None,
        transmission: str = "forwardGears",
    ) -> BasicSafetyMessage:
        """Create a validated BasicSafetyMessage with automatic sequence counter management."""
        if sec_mark is None:
            # Current millisecond within the current minute per SAE J2735 DSecond (0..65535)
            sec_mark = int((time.time() % 60) * 1000)

        # Scale acceleration values: 0.01 m/s² units
        accel_lon_raw = min(2001, max(-2000, int(round(accel_lon_mps2 / 0.01))))
        accel_lat_raw = min(2001, max(-2000, int(round(accel_lat_mps2 / 0.01))))
        # Scale yaw rate: 0.01 deg/s units
        yaw_rate_raw = min(32767, max(-32767, int(round(yaw_rate_deg_s / 0.01))))

        bsm = BasicSafetyMessage.create(
            msg_cnt=self._msg_cnt,
            vehicle_id=self.vehicle_id,
            lat_deg=lat_deg,
            lon_deg=lon_deg,
            speed_mps=speed_mps,
            heading_deg=heading_deg,
            sec_mark=sec_mark,
            elev_m=elev_m,
            width_cm=self.width_cm,
            length_cm=self.length_cm,
            transmission=transmission,
        )
        bsm.accel_lon = accel_lon_raw
        bsm.accel_lat = accel_lat_raw
        bsm.yaw_rate = yaw_rate_raw

        # Increment message counter modulo 128 (0..127) per SAE J2735 MsgCount
        self._msg_cnt = (self._msg_cnt + 1) % (BSM_MSG_CNT_MAX + 1)

        return bsm

    def generate_uper_bsm(
        self,
        lat_deg: float,
        lon_deg: float,
        speed_mps: float = 0.0,
        heading_deg: float = 0.0,
        elev_m: float = 0.0,
        accel_lon_mps2: float = 0.0,
        accel_lat_mps2: float = 0.0,
        yaw_rate_deg_s: float = 0.0,
        sec_mark: Optional[int] = None,
        transmission: str = "forwardGears",
    ) -> Tuple[BasicSafetyMessage, bytes]:
        """Convenience method returning both the BSM dataclass and UPER-encoded bytes."""
        bsm = self.build_bsm(
            lat_deg=lat_deg,
            lon_deg=lon_deg,
            speed_mps=speed_mps,
            heading_deg=heading_deg,
            elev_m=elev_m,
            accel_lon_mps2=accel_lon_mps2,
            accel_lat_mps2=accel_lat_mps2,
            yaw_rate_deg_s=yaw_rate_deg_s,
            sec_mark=sec_mark,
            transmission=transmission,
        )
        uper_bytes = encode_bsm_uper(bsm)
        return bsm, uper_bytes

