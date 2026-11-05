"""
Integration Tests for the Complete DSRC Protocol Stack
======================================================
Tests the full multi-layer pipeline:
  Application (SAE J2735 BSM)
    -> Security (IEEE 1609.2 ECDSA-P256 Signing)
      -> Network (IEEE 1609.3 WSMP Header)
        -> MAC (IEEE 802.11p OCB Frame + 1609.4 Queuing)
          -> PHY (Simulated Transmission Airtime)
            -> Receiver PHY
              -> Receiver MAC (802.11p Deserialization & FCS Verification)
                -> Receiver Network (WSMP Parsing)
                  -> Receiver Security (IEEE 1609.2 Verification & Replay Protection)
                    -> Receiver Application (SAE J2735 UPER Decoding)
"""

import time
import pytest

from certificates.generate_pki import build_simulated_pki
from common.exceptions import (
    ReplayDetectedError,
    SecurityError,
    WaveFrameError,
)
from common.ieee1609_2.certificates import CertificateStore
from dsrc.stack import DSRCStack


@pytest.fixture(scope="module")
def shared_pki() -> CertificateStore:
    """Module-level PKI fixture with vehicle credentials."""
    return build_simulated_pki(num_vehicles=2, certs_per_vehicle=2)


class TestDSRCStackIntegration:
    """End-to-end integration tests for the DSRC stack."""

    def test_full_pipeline_roundtrip(self, shared_pki):
        """Transmitted BSM through DSRC stack must be received and verified identically."""
        tx_stack = DSRCStack(
            vehicle_name="Vehicle-1",
            cert_store=shared_pki,
            mac_address=b"\x00\x11\x22\x33\x44\x55",
        )
        rx_stack = DSRCStack(
            vehicle_name="Vehicle-2",
            cert_store=shared_pki,
            mac_address=b"\x00\xaa\xbb\xcc\xdd\xee",
        )

        now_ms = int(time.time() * 1000)

        # Transmit BSM from Vehicle-1
        frame_bytes, orig_bsm, spdu, airtime_us = tx_stack.transmit_bsm(
            lat_deg=37.4270,
            lon_deg=-122.0000,
            speed_mps=28.5,
            heading_deg=90.0,
            elev_m=12.0,
            current_time_ms=now_ms,
        )

        assert isinstance(frame_bytes, bytes)
        assert len(frame_bytes) > 0
        assert airtime_us > 40.0  # Must include preamble/signal overhead

        # Receive at Vehicle-2 (high received power: -65 dBm)
        rx_bsm, rx_hdr, rx_cert = rx_stack.receive_frame(
            frame_bytes=frame_bytes,
            rx_power_dbm=-65.0,
            current_time_ms=now_ms,
        )

        # Verify decoded BSM matches original transmitted BSM
        assert rx_bsm.msg_cnt == orig_bsm.msg_cnt
        assert rx_bsm.vehicle_id == orig_bsm.vehicle_id
        assert abs(rx_bsm.lat_degrees - 37.4270) < 1e-6
        assert abs(rx_bsm.lon_degrees - (-122.0000)) < 1e-6
        assert abs(rx_bsm.speed_mps - 28.5) < 0.05
        assert abs(rx_bsm.heading_degrees - 90.0) < 0.1

        # Verify security metadata
        assert rx_hdr.generation_time == now_ms
        assert "Vehicle-1" in rx_cert.to_be_signed.cert_id

    def test_replayed_frame_rejected(self, shared_pki):
        """A captured frame replayed outside the replay window must be rejected."""
        tx_stack = DSRCStack(vehicle_name="Vehicle-1", cert_store=shared_pki)
        rx_stack = DSRCStack(vehicle_name="Vehicle-2", cert_store=shared_pki)

        now_ms = int(time.time() * 1000)
        # Transmitted at time T
        frame_bytes, _, _, _ = tx_stack.transmit_bsm(
            lat_deg=37.0,
            lon_deg=-122.0,
            current_time_ms=now_ms,
        )

        # Replayed 5 seconds later
        with pytest.raises(ReplayDetectedError):
            rx_stack.receive_frame(
                frame_bytes=frame_bytes,
                rx_power_dbm=-60.0,
                current_time_ms=now_ms + 5000,
            )

    def test_tampered_frame_rejected_by_fcs(self, shared_pki):
        """Tampering with a frame in transit must cause receiver FCS failure."""
        tx_stack = DSRCStack(vehicle_name="Vehicle-1", cert_store=shared_pki)
        rx_stack = DSRCStack(vehicle_name="Vehicle-2", cert_store=shared_pki)

        frame_bytes, _, _, _ = tx_stack.transmit_bsm(lat_deg=37.0, lon_deg=-122.0)

        # Corrupt one byte in the middle of the frame
        corrupted = bytearray(frame_bytes)
        corrupted[25] ^= 0xFF

        with pytest.raises(WaveFrameError) as exc_info:
            rx_stack.receive_frame(bytes(corrupted), rx_power_dbm=-60.0)
        assert "FCS" in str(exc_info.value)

    def test_weak_signal_below_sensitivity_rejected(self, shared_pki):
        """Frame received below receiver sensitivity must be dropped."""
        tx_stack = DSRCStack(vehicle_name="Vehicle-1", cert_store=shared_pki)
        rx_stack = DSRCStack(vehicle_name="Vehicle-2", cert_store=shared_pki)

        frame_bytes, _, _, _ = tx_stack.transmit_bsm(lat_deg=37.0, lon_deg=-122.0)

        with pytest.raises(WaveFrameError) as exc_info:
            rx_stack.receive_frame(frame_bytes, rx_power_dbm=-95.0)  # Below -80 dBm
        assert "below sensitivity" in str(exc_info.value)

    def test_pseudonym_rotation(self, shared_pki):
        """OBU pseudonym rotation should change active cert ID and temporary ID."""
        stack = DSRCStack(vehicle_name="Vehicle-1", cert_store=shared_pki)

        cert1, id1 = stack.cert_manager.get_active_credentials()
        temp_id1 = stack.cert_manager.active_temporary_id()

        # Explicitly rotate
        cert2, temp_id2 = stack.cert_manager.rotate_pseudonym()

        assert cert2.to_be_signed.cert_id != cert1.to_be_signed.cert_id
        assert temp_id2 != temp_id1
