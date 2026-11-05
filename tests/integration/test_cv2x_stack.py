"""
Integration Tests for the Complete LTE-C-V2X Protocol Stack
============================================================
Tests the full multi-layer C-V2X pipeline:
  Application (SAE J2735 BSM + V2X Priority Tagging)
    -> Security (IEEE 1609.2 ECDSA-P256 Signing)
      -> MAC & Sidelink (Mode 4 Autonomous Sensing + SL-SCH TB + SCI Format 1)
        -> PHY (1.0 ms Subframe Airtime Calculation)
          -> Receiver PHY (Sensitivity check on PSCCH & PSSCH)
            -> Receiver Control (SCI Format 1 Decoding & Sensing History Update)
              -> Receiver Shared Channel (TB Decoding & CRC-24A Check)
                -> Receiver Security (IEEE 1609.2 Verification & Replay Protection)
                  -> Receiver Application (SAE J2735 UPER Decoding)
"""

import time
import pytest

from certificates.generate_pki import build_simulated_pki
from common.exceptions import (
    PC5Error,
    ReplayDetectedError,
    TransportBlockError,
)
from common.ieee1609_2.certificates import CertificateStore
from common.message_types import V2XPriority
from cv2x.stack import CV2XStack


@pytest.fixture(scope="module")
def shared_pki() -> CertificateStore:
    return build_simulated_pki(num_vehicles=2, certs_per_vehicle=2)


class TestCV2XStackIntegration:
    """End-to-end integration tests for the C-V2X stack."""

    def test_full_pipeline_roundtrip(self, shared_pki):
        """Transmitted BSM through C-V2X stack must be received and verified identically."""
        tx_stack = CV2XStack(
            vehicle_name="Vehicle-1",
            cert_store=shared_pki,
            source_l2_id=b"\x00\x00\x01",
        )
        rx_stack = CV2XStack(
            vehicle_name="Vehicle-2",
            cert_store=shared_pki,
            source_l2_id=b"\x00\x00\x02",
        )

        now_ms = int(time.time() * 1000)

        # Transmit BSM from Vehicle-1
        tx_unit, orig_bsm, spdu, airtime_ms = tx_stack.transmit_bsm(
            lat_deg=37.7749,
            lon_deg=-122.4194,
            speed_mps=30.0,
            heading_deg=180.0,
            elev_m=5.0,
            priority=V2XPriority.SAFETY_CRITICAL,
            current_time_ms=now_ms,
        )

        assert tx_unit.sci.priority == int(V2XPriority.SAFETY_CRITICAL)
        assert airtime_ms == 1.0  # LTE subframe is 1 ms

        # Receive at Vehicle-2
        rx_bsm, rx_hdr, rx_cert = rx_stack.receive_sidelink(
            sci_bytes=tx_unit.raw_sci_bytes,
            tb_bytes=tx_unit.raw_tb_bytes,
            rx_power_dbm=-65.0,
            current_subframe=tx_unit.scheduled_subframe,
            current_time_ms=now_ms,
        )

        # Verify decoded BSM matches original transmitted BSM
        assert rx_bsm.msg_cnt == orig_bsm.msg_cnt
        assert rx_bsm.vehicle_id == orig_bsm.vehicle_id
        assert abs(rx_bsm.lat_degrees - 37.7749) < 1e-6
        assert abs(rx_bsm.lon_degrees - (-122.4194)) < 1e-6
        assert abs(rx_bsm.speed_mps - 30.0) < 0.05
        assert abs(rx_bsm.heading_degrees - 180.0) < 0.1

        # Verify security metadata
        assert rx_hdr.generation_time == now_ms
        assert "Vehicle-1" in rx_cert.to_be_signed.cert_id

        # Verify Vehicle 2 logged the transmission in its Mode 4 sensing history
        obs_key = (tx_unit.scheduled_subframe, tx_unit.subchannel_index)
        assert obs_key in rx_stack.resource_pool._sensing_history

    def test_replayed_frame_rejected(self, shared_pki):
        """A captured C-V2X message replayed outside the replay window must be rejected."""
        tx_stack = CV2XStack(vehicle_name="Vehicle-1", cert_store=shared_pki)
        rx_stack = CV2XStack(vehicle_name="Vehicle-2", cert_store=shared_pki)

        now_ms = int(time.time() * 1000)
        tx_unit, _, _, _ = tx_stack.transmit_bsm(
            lat_deg=37.0,
            lon_deg=-122.0,
            current_time_ms=now_ms,
        )

        # Replayed 5 seconds later
        with pytest.raises(ReplayDetectedError):
            rx_stack.receive_sidelink(
                sci_bytes=tx_unit.raw_sci_bytes,
                tb_bytes=tx_unit.raw_tb_bytes,
                rx_power_dbm=-65.0,
                current_time_ms=now_ms + 5000,
            )

    def test_tampered_tb_rejected_by_crc24a(self, shared_pki):
        """Tampering with Transport Block payload must trigger CRC-24A mismatch."""
        tx_stack = CV2XStack(vehicle_name="Vehicle-1", cert_store=shared_pki)
        rx_stack = CV2XStack(vehicle_name="Vehicle-2", cert_store=shared_pki)

        tx_unit, _, _, _ = tx_stack.transmit_bsm(lat_deg=37.0, lon_deg=-122.0)

        # Corrupt 1 byte in TB payload
        corrupted_tb = bytearray(tx_unit.raw_tb_bytes)
        corrupted_tb[15] ^= 0xFF

        with pytest.raises(TransportBlockError) as exc_info:
            rx_stack.receive_sidelink(
                sci_bytes=tx_unit.raw_sci_bytes,
                tb_bytes=bytes(corrupted_tb),
                rx_power_dbm=-65.0,
            )
        assert "CRC-24A mismatch" in str(exc_info.value)

    def test_weak_signal_below_pssch_sensitivity_dropped(self, shared_pki):
        """Packet received with signal power below sensitivity must be dropped."""
        tx_stack = CV2XStack(vehicle_name="Vehicle-1", cert_store=shared_pki)
        rx_stack = CV2XStack(vehicle_name="Vehicle-2", cert_store=shared_pki)

        tx_unit, _, _, _ = tx_stack.transmit_bsm(lat_deg=37.0, lon_deg=-122.0)

        with pytest.raises(PC5Error) as exc_info:
            rx_stack.receive_sidelink(
                sci_bytes=tx_unit.raw_sci_bytes,
                tb_bytes=tx_unit.raw_tb_bytes,
                rx_power_dbm=-98.0,  # Below -89 dBm PSSCH sensitivity
            )
        assert "below sensitivity" in str(exc_info.value)

    def test_pseudonym_rotation(self, shared_pki):
        """OBU pseudonym rotation should update active cert ID and temporary ID."""
        stack = CV2XStack(vehicle_name="Vehicle-1", cert_store=shared_pki)

        cert1, id1 = stack.cert_manager.get_active_credentials()
        temp_id1 = stack.cert_manager.active_temporary_id()

        cert2, temp_id2 = stack.cert_manager.rotate_pseudonym()

        assert cert2.to_be_signed.cert_id != cert1.to_be_signed.cert_id
        assert temp_id2 != temp_id1

