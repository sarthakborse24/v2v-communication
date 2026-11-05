"""
V2X Simulation Engine — Vehicle Node
====================================
Simulated vehicular host implementing:
  - Protocol stack attachment (DSRCStack, CV2XStack, or DualStack)
  - Kinematic updates driven by MobilityModel
  - SAE J2735 BSM generation and signing (10 Hz)
  - Inbound packet decoding, verification, and statistics tracking

Standards References:
  - SAE J2735: BasicSafetyMessage Part I
  - IEEE 1609.2: SignedData SPDU transmission and verification
  - IEEE 802.11p / 3GPP Rel-14 PC5
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Dict, Optional, Tuple, Union

from common.bsm_codec import BasicSafetyMessage
from cv2x.mac.lte_mac import SidelinkTransmissionUnit
from cv2x.stack import CV2XStack
from dsrc.stack import DSRCStack
from dsrc.wave.wave_frame import WAVEFrame
from monitoring.logger import get_logger
from vehicles.mobility_model import (
    LinearMobilityModel,
    MobilityModel,
    cartesian_to_wgs84,
)

log = get_logger("vehicles.vehicle")


class VehicleTechnology(str, Enum):
    DSRC = "DSRC"
    CV2X = "CV2X"
    DUAL_STACK = "DUAL_STACK"


@dataclass
class VehicleStats:
    """Per-vehicle transmission and reception metrics."""
    tx_bsm_count: int = 0
    rx_bsm_count: int = 0
    rx_dropped_snr: int = 0
    rx_security_failed: int = 0
    rx_latencies_ms: list[float] = field(default_factory=list)


class Vehicle:
    """Simulated vehicle entity."""

    def __init__(
        self,
        vehicle_id: str,
        station_id: int,
        technology: Union[VehicleTechnology, str] = VehicleTechnology.DSRC,
        mobility_model: Optional[MobilityModel] = None,
        dsrc_stack: Optional[DSRCStack] = None,
        cv2x_stack: Optional[CV2XStack] = None,
        ref_lat: float = 37.7749,
        ref_lon: float = -122.4194,
        ref_elev_m: float = 10.0,
    ):
        self.vehicle_id = vehicle_id
        self.station_id = station_id
        if isinstance(technology, str):
            technology = VehicleTechnology(technology.upper())
        self.technology = technology

        self.mobility_model = mobility_model or LinearMobilityModel()
        self.dsrc_stack = dsrc_stack
        self.cv2x_stack = cv2x_stack

        self.ref_lat = ref_lat
        self.ref_lon = ref_lon
        self.ref_elev_m = ref_elev_m

        # Kinematic state
        self.x: float = 0.0
        self.y: float = 0.0
        self.z: float = 1.5
        self.speed_mps: float = 0.0
        self.heading_deg: float = 0.0
        self.lat: float = ref_lat
        self.lon: float = ref_lon
        self.elev: float = ref_elev_m + 1.5

        # Metrics
        self.stats = VehicleStats()
        self._last_update_time: float = 0.0

        # Initialize position at t=0
        self.update_state(0.0)

    def update_state(self, t_seconds: float) -> None:
        """Update vehicle kinematics from its mobility model at time t."""
        self.x, self.y, self.z = self.mobility_model.get_position(t_seconds)
        self.speed_mps = self.mobility_model.get_speed_mps(t_seconds)
        self.heading_deg = self.mobility_model.get_heading_deg(t_seconds)
        self.lat, self.lon, self.elev = cartesian_to_wgs84(
            self.x, self.y, self.z,
            ref_lat=self.ref_lat,
            ref_lon=self.ref_lon,
            ref_elev_m=self.ref_elev_m,
        )
        self._last_update_time = t_seconds

    def generate_bsm_payload(
        self,
        current_time_s: float,
        sim_time_s: Optional[float] = None,
        target_stack: str = "AUTO",
    ) -> Union[bytes, SidelinkTransmissionUnit]:
        """Generate and encode a signed BSM for outbound transmission."""
        kinematic_time = sim_time_s if sim_time_s is not None else current_time_s
        self.update_state(kinematic_time)

        stack_choice = target_stack.upper()
        if stack_choice == "AUTO":
            stack_choice = "DSRC" if self.technology == VehicleTechnology.DSRC else "CV2X"

        now_ms = int(current_time_s * 1000.0)

        if stack_choice == "DSRC":
            if self.dsrc_stack is None:
                raise RuntimeError(f"Vehicle {self.vehicle_id} has no DSRC stack")
            frame_bytes, bsm, spdu, airtime_us = self.dsrc_stack.transmit_bsm(
                lat_deg=self.lat,
                lon_deg=self.lon,
                elev_m=self.elev,
                speed_mps=self.speed_mps,
                heading_deg=self.heading_deg,
                current_time_ms=now_ms,
            )
            self.stats.tx_bsm_count += 1
            return frame_bytes
        else:
            if self.cv2x_stack is None:
                raise RuntimeError(f"Vehicle {self.vehicle_id} has no CV2X stack")
            tx_unit, bsm, spdu, airtime_ms = self.cv2x_stack.transmit_bsm(
                lat_deg=self.lat,
                lon_deg=self.lon,
                elev_m=self.elev,
                speed_mps=self.speed_mps,
                heading_deg=self.heading_deg,
                current_time_ms=now_ms,
            )
            self.stats.tx_bsm_count += 1
            return tx_unit

    def receive_frame(
        self,
        frame: Union[bytes, SidelinkTransmissionUnit, WAVEFrame],
        rx_power_dbm: float,
        sinr_db: float,
        current_time_s: float,
    ) -> Optional[Dict[str, Any]]:
        """Process inbound frame received over the wireless channel.

        Returns decoded BSM dictionary if successful, or None if dropped.
        """
        now_ms = int(current_time_s * 1000.0)
        try:
            if isinstance(frame, (bytes, WAVEFrame)):
                if self.dsrc_stack is None:
                    return None
                frame_bytes = frame.serialize(compute_fcs=True) if isinstance(frame, WAVEFrame) else frame
                bsm, header_info, cert = self.dsrc_stack.receive_frame(
                    frame_bytes, rx_power_dbm=rx_power_dbm, current_time_ms=now_ms
                )
                bsm_dict = bsm.to_asn1_dict()
                sec_mark = bsm.sec_mark
            elif isinstance(frame, SidelinkTransmissionUnit):
                if self.cv2x_stack is None:
                    return None
                bsm, header_info, cert = self.cv2x_stack.receive_sidelink(
                    sci_bytes=frame.raw_sci_bytes,
                    tb_bytes=frame.raw_tb_bytes,
                    rx_power_dbm=rx_power_dbm,
                    current_time_ms=now_ms,
                )
                bsm_dict = bsm.to_asn1_dict()
                sec_mark = bsm.sec_mark
            else:
                return None

            self.stats.rx_bsm_count += 1
            # Record transmission latency if secMark is available
            cur_sec_mark = now_ms % 60000
            latency_ms = (cur_sec_mark - sec_mark) % 60000
            self.stats.rx_latencies_ms.append(float(latency_ms))
            return bsm_dict

        except Exception as exc:
            log.debug(f"Vehicle {self.vehicle_id} failed to process frame: {exc}")
            self.stats.rx_security_failed += 1
            return None
