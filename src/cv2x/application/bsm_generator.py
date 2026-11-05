"""
V2X Gateway Simulator — C-V2X BSM Application Generator
========================================================
Generates periodic SAE J2735 Basic Safety Messages for LTE-C-V2X vehicles
with 3GPP V2X priority mapping (TS 36.321 §5.14.1).

Standards References:
  - SAE J2735-2020: BasicSafetyMessage Part I
  - 3GPP TS 36.321 Release 14: Sidelink Priority (ProSe / V2X)
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from common.bsm_codec import (
    BasicSafetyMessage,
    encode_bsm_uper,
)
from common.message_types import (
    BSM_DEFAULT_V2X_PRIORITY,
    BSM_MSG_CNT_MAX,
    PSID,
    V2XPriority,
)


class CV2XBSMGenerator:
    """Generates BSM messages tailored for C-V2X sidelink transmission."""

    def __init__(
        self,
        vehicle_id: bytes,
        width_cm: int = 200,
        length_cm: int = 450,
        default_priority: V2XPriority = BSM_DEFAULT_V2X_PRIORITY,
    ):
        if len(vehicle_id) != 4:
            raise ValueError(f"TemporaryID must be exactly 4 bytes, got {len(vehicle_id)}")

        self.vehicle_id = vehicle_id
        self.width_cm = width_cm
        self.length_cm = length_cm
        self.default_priority = default_priority
        self._msg_cnt = 0

    @property
    def current_msg_cnt(self) -> int:
        return self._msg_cnt

    def update_vehicle_id(self, new_id: bytes) -> None:
        """Update temporary pseudonym ID (called on pseudonym certificate rotation)."""
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
        """Build validated BasicSafetyMessage dataclass with 0..127 sequence counter."""
        if sec_mark is None:
            sec_mark = int((time.time() % 60) * 1000)

        accel_lon_raw = min(2001, max(-2000, int(round(accel_lon_mps2 / 0.01))))
        accel_lat_raw = min(2001, max(-2000, int(round(accel_lat_mps2 / 0.01))))
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
        priority: Optional[V2XPriority] = None,
    ) -> Tuple[BasicSafetyMessage, bytes, V2XPriority]:
        """Convenience method returning (BSM, UPER_bytes, V2XPriority)."""
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
        assigned_prio = priority if priority is not None else self.default_priority
        return bsm, uper_bytes, assigned_prio

