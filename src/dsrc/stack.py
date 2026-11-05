"""
V2X Gateway Simulator — Complete DSRC WAVE Protocol Stack
==========================================================
Integrates all DSRC layers:
  - Application: SAE J2735 BSM Generation
  - Security:    IEEE 1609.2 ECDSA Signing & Verification
  - Network:     IEEE 1609.3 WSMP Header Encapsulation
  - Data Link:   IEEE 802.11p MAC OCB Frame + IEEE 1609.4 Multi-Channel Queuing
  - Physical:    [SIMULATION MODEL] IEEE 802.11p 10 MHz OFDM Airtime & Reception
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from common.bsm_codec import (
    BasicSafetyMessage,
    decode_bsm_uper,
)
from common.exceptions import (
    SecurityError,
    WaveFrameError,
    WSMPError,
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
    BSM_DEFAULT_CHANNEL,
    BSM_EDCA_CATEGORY,
    ETHERTYPE_WSMP,
    PSID,
    WAVEChannel,
)
from dsrc.application.bsm_generator import BSMGenerator
from dsrc.mac.wave_mac import (
    ChannelAccessMode,
    WAVEMAC,
)
from dsrc.phy.dsrc_phy import (
    DSRC_MCS_TABLE,
    DSRCPhyModel,
)
from dsrc.security.certificate_manager import DSRCCertificateManager
from dsrc.security.signer import DSRCSecuritySigner
from dsrc.security.verifier import DSRCSecurityVerifier
from dsrc.wave.wave_frame import (
    BROADCAST_MAC,
    WAVEFrame,
)
from dsrc.wave.wsmp import WSMPacket
from monitoring.logger import get_logger

log = get_logger("dsrc.stack")


class DSRCStack:
    """Full implementation of a DSRC OBU protocol stack."""

    def __init__(
        self,
        vehicle_name: str,
        cert_store: CertificateStore,
        mac_address: bytes = b"\x00\x00\x00\x00\x00\x01",
        access_mode: ChannelAccessMode = ChannelAccessMode.CONTINUOUS_CCH,
        default_mcs: int = 3,
        tx_power_dbm: float = 20.0,
    ):
        self.vehicle_name = vehicle_name
        self.mac_address = mac_address
        self.cert_store = cert_store

        # Sublayer instances
        self.cert_manager = DSRCCertificateManager(
            vehicle_name=vehicle_name,
            cert_store=cert_store,
        )
        temp_id = self.cert_manager.active_temporary_id()
        self.bsm_generator = BSMGenerator(vehicle_id=temp_id)

        self.signer = DSRCSecuritySigner(cert_manager=self.cert_manager)
        self.verifier = DSRCSecurityVerifier(cert_store=cert_store)

        self.mac = WAVEMAC(access_mode=access_mode)
        self.phy = DSRCPhyModel(default_mcs=default_mcs, tx_power_dbm=tx_power_dbm)

    def transmit_bsm(
        self,
        lat_deg: float,
        lon_deg: float,
        speed_mps: float = 0.0,
        heading_deg: float = 0.0,
        elev_m: float = 0.0,
        current_time_ms: Optional[int] = None,
        include_full_cert: bool = False,
    ) -> Tuple[bytes, BasicSafetyMessage, Ieee1609Dot2Data, float]:
        """Execute complete outbound transmission pipeline:
        BSM -> UPER -> 1609.2 Sign -> WSMP -> 802.11p Frame -> MAC Enqueue -> PHY Airtime.

        Returns:
            Tuple of (raw_802_11p_frame_bytes, bsm, spdu, airtime_us).
        """
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)

        # 1. Application: Generate BSM and UPER encode
        bsm, bsm_bytes = self.bsm_generator.generate_uper_bsm(
            lat_deg=lat_deg,
            lon_deg=lon_deg,
            speed_mps=speed_mps,
            heading_deg=heading_deg,
            elev_m=elev_m,
            sec_mark=now_ms % 60_000,
        )

        # 2. Security: Sign with active pseudonym certificate
        spdu = self.signer.sign_bsm(
            bsm_bytes=bsm_bytes,
            generation_time_ms=now_ms,
            include_full_cert=include_full_cert,
        )
        spdu_bytes = spdu.to_bytes()

        # 3. Network: Wrap SPDU in IEEE 1609.3 WSMP
        wsm = WSMPacket(
            payload=spdu_bytes,
            psid=PSID.BSM,
            channel_number=WAVEChannel.CCH_178,
            tx_power_dbm=int(self.phy.tx_power_dbm),
        )
        wsmp_bytes = wsm.serialize()

        # 4. MAC: Encapsulate in 802.11p OCB QoS frame
        wave_frame = WAVEFrame(
            payload=wsmp_bytes,
            source_mac=self.mac_address,
            dest_mac=BROADCAST_MAC,
            edca_category=BSM_EDCA_CATEGORY,
            ethertype=ETHERTYPE_WSMP,
        )
        self.mac.enqueue_frame(wave_frame)
        frame_bytes = wave_frame.serialize(compute_fcs=True)

        # 5. PHY: Calculate airtime
        airtime_us = self.phy.calculate_transmission_time_us(payload_bytes=len(frame_bytes))

        return frame_bytes, bsm, spdu, airtime_us

    def receive_frame(
        self,
        frame_bytes: bytes,
        rx_power_dbm: float = -60.0,
        current_time_ms: Optional[int] = None,
    ) -> Tuple[BasicSafetyMessage, HeaderInfo, Certificate]:
        """Execute complete inbound reception pipeline:
        PHY check -> 802.11p parse & FCS -> WSMP decode -> 1609.2 Verify -> BSM UPER decode.

        Returns:
            Tuple of (BasicSafetyMessage, HeaderInfo, signer_cert).

        Raises:
            WaveFrameError: If frame FCS or format is corrupt.
            WSMPError: If WSMP header is invalid.
            SecurityError: If IEEE 1609.2 verification or replay check fails.
        """
        # 1. PHY: Sensitivity check
        if rx_power_dbm < DSRC_MCS_TABLE[self.phy.default_mcs].sensitivity_dbm:
            raise WaveFrameError(f"Received power {rx_power_dbm} dBm below sensitivity")

        # 2. MAC: Dissect 802.11p frame and verify FCS
        wave_frame = WAVEFrame.deserialize(frame_bytes, verify_fcs=True)

        # 3. Network: Dissect WSMP header
        wsm = WSMPacket.deserialize(wave_frame.payload)

        # 4. Security: Parse SPDU and verify signature & trust chain
        spdu = Ieee1609Dot2Data.from_bytes(wsm.payload)
        bsm_bytes, hdr, cert = self.verifier.verify_bsm(
            spdu=spdu,
            current_time_ms=current_time_ms,
        )

        # 5. Application: Decode UPER bytes into BSM dataclass
        bsm = decode_bsm_uper(bsm_bytes)

        return bsm, hdr, cert
