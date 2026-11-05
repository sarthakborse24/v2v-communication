"""
V2X Gateway Simulator — Complete LTE-C-V2X Release 14 Protocol Stack
=====================================================================
Integrates all C-V2X layers:
  - Application: SAE J2735 BSM Generation with V2X Priority Tagging
  - Security:    IEEE 1609.2 ECDSA Signing & Verification
  - Sidelink:    3GPP TS 36.212 SCI Format 1 + TS 36.321 SL-SCH Transport Block
  - MAC:         Mode 4 Autonomous Sensing-Based Resource Selection (TS 36.213)
  - Physical:    [SIMULATION MODEL] 1.0 ms Subframe Airtime & Reception
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from common.bsm_codec import (
    BasicSafetyMessage,
    decode_bsm_uper,
)
from common.exceptions import (
    PC5Error,
    SecurityError,
    TransportBlockError,
)
from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
)
from common.ieee1609_2.spdu import (
    HeaderInfo,
    Ieee1609Dot2Data,
)
from common.message_types import (
    BSM_DEFAULT_V2X_PRIORITY,
    PSID,
    V2XPriority,
)
from cv2x.application.bsm_generator import CV2XBSMGenerator
from cv2x.mac.lte_mac import (
    LTEMAC,
    SidelinkTransmissionUnit,
)
from cv2x.pc5.resource_pool import Mode4ResourcePool
from cv2x.pc5.sidelink import (
    SCIFormat1,
    SidelinkTransportBlock,
    V2X_BROADCAST_L2_ID,
)
from cv2x.phy.lte_phy import (
    LTE_V2X_MCS_TABLE,
    LTEPhyModel,
    PSCCH_SENSITIVITY_DBM,
)
from cv2x.security.pc5_security import (
    CV2XCertificateManager,
    CV2XSecurityHandler,
)
from monitoring.logger import get_logger

log = get_logger("cv2x.stack")


class CV2XStack:
    """Full implementation of an LTE-C-V2X Release 14 PC5 OBU protocol stack."""

    def __init__(
        self,
        vehicle_name: str,
        cert_store: CertificateStore,
        source_l2_id: bytes = b"\x00\x00\x01",
        default_mcs: int = 10,
        tx_power_dbm: float = 23.0,
        num_subchannels: int = 4,
    ):
        if len(source_l2_id) != 3:
            raise ValueError(f"Source L2 ID must be 3 bytes, got {len(source_l2_id)}")

        self.vehicle_name = vehicle_name
        self.source_l2_id = source_l2_id
        self.cert_store = cert_store

        # Sublayer instances
        self.cert_manager = CV2XCertificateManager(
            vehicle_name=vehicle_name,
            cert_store=cert_store,
        )
        temp_id = self.cert_manager.active_temporary_id()
        self.bsm_generator = CV2XBSMGenerator(vehicle_id=temp_id)

        self.security = CV2XSecurityHandler(
            cert_manager=self.cert_manager,
            cert_store=cert_store,
        )

        self.resource_pool = Mode4ResourcePool(num_subchannels=num_subchannels)
        self.mac = LTEMAC(
            source_l2_id=source_l2_id,
            resource_pool=self.resource_pool,
            default_mcs=default_mcs,
        )
        self.phy = LTEPhyModel(default_mcs=default_mcs, tx_power_dbm=tx_power_dbm)

    def transmit_bsm(
        self,
        lat_deg: float,
        lon_deg: float,
        speed_mps: float = 0.0,
        heading_deg: float = 0.0,
        elev_m: float = 0.0,
        priority: V2XPriority = BSM_DEFAULT_V2X_PRIORITY,
        current_time_ms: Optional[int] = None,
        include_full_cert: bool = False,
    ) -> Tuple[SidelinkTransmissionUnit, BasicSafetyMessage, Ieee1609Dot2Data, float]:
        """Execute complete C-V2X outbound transmission pipeline:
        BSM -> UPER -> 1609.2 Sign -> Mode 4 Resource Selection -> SCI-1 & TB -> PHY.

        Returns:
            Tuple of (SidelinkTransmissionUnit, bsm, spdu, airtime_ms).
        """
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)
        current_subframe = now_ms  # 1 ms = 1 subframe

        # 1. Application: Generate BSM and UPER encode
        bsm, bsm_bytes, assigned_prio = self.bsm_generator.generate_uper_bsm(
            lat_deg=lat_deg,
            lon_deg=lon_deg,
            speed_mps=speed_mps,
            heading_deg=heading_deg,
            elev_m=elev_m,
            sec_mark=now_ms % 60_000,
            priority=priority,
        )

        # 2. Security: Sign with active pseudonym certificate
        spdu = self.security.sign_bsm(
            bsm_bytes=bsm_bytes,
            generation_time_ms=now_ms,
            include_full_cert=include_full_cert,
        )
        spdu_bytes = spdu.to_bytes()

        # 3. MAC & Mode 4 Sidelink: Prepare TB, allocate resource, build SCI Format 1
        tx_unit = self.mac.prepare_transmission(
            payload=spdu_bytes,
            priority=assigned_prio,
            current_subframe=current_subframe,
            dest_l2_id=V2X_BROADCAST_L2_ID,
            mcs_index=self.phy.default_mcs,
        )

        # 4. PHY: Subframe airtime is 1.0 ms
        airtime_ms = self.phy.subframe_duration_ms

        return tx_unit, bsm, spdu, airtime_ms

    def receive_sidelink(
        self,
        sci_bytes: bytes,
        tb_bytes: bytes,
        rx_power_dbm: float = -70.0,
        current_subframe: int = 0,
        current_time_ms: Optional[int] = None,
    ) -> Tuple[BasicSafetyMessage, HeaderInfo, Certificate]:
        """Execute complete C-V2X inbound reception pipeline:
        PSCCH check -> PSSCH check -> SCI decode -> TB CRC-24A -> 1609.2 Verify -> BSM decode.

        Returns:
            Tuple of (BasicSafetyMessage, HeaderInfo, signer_cert).

        Raises:
            PC5Error: If signal is below sensitivity or CRC-24A fails.
            SecurityError: If IEEE 1609.2 verification or replay check fails.
        """
        # 1. PHY: Check PSCCH sensitivity
        if rx_power_dbm < PSCCH_SENSITIVITY_DBM:
            raise PC5Error(f"PSCCH signal {rx_power_dbm} dBm below sensitivity {PSCCH_SENSITIVITY_DBM} dBm")

        # 2. Control Channel: Decode SCI Format 1
        sci = SCIFormat1.deserialize(sci_bytes)

        # 3. Check PSSCH sensitivity for announced MCS
        mcs_entry = LTE_V2X_MCS_TABLE.get(sci.mcs, LTE_V2X_MCS_TABLE[10])
        if rx_power_dbm < mcs_entry.sensitivity_dbm:
            raise PC5Error(
                f"PSSCH signal {rx_power_dbm} dBm below MCS {sci.mcs} sensitivity {mcs_entry.sensitivity_dbm} dBm"
            )

        # 4. Record observed transmission into Mode 4 sensing window for future avoidance
        self.resource_pool.record_sensed_transmission(
            subframe_index=current_subframe,
            subchannel_index=sci.freq_resource_location,
            sci=sci,
            measured_rssi_dbm=rx_power_dbm,
        )

        # 5. Shared Channel: Decode Transport Block and verify CRC-24A
        tb = SidelinkTransportBlock.deserialize(tb_bytes, verify_crc=True)

        # 6. Security: Parse and verify IEEE 1609.2 SPDU
        spdu = Ieee1609Dot2Data.from_bytes(tb.payload)
        bsm_bytes, hdr, cert = self.security.verify_spdu(
            spdu=spdu,
            current_time_ms=current_time_ms,
        )

        # 7. Application: Decode UPER bytes into BSM dataclass
        bsm = decode_bsm_uper(bsm_bytes)

        return bsm, hdr, cert

