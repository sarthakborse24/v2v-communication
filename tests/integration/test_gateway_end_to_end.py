"""
Integration Tests for Bidirectional DSRC <-> LTE-C-V2X Gateway
==============================================================
Validates:
  1. DSRC Vehicle -> DSRC Stack -> Gateway -> C-V2X Stack -> C-V2X Vehicle
  2. C-V2X Vehicle -> C-V2X Stack -> Gateway -> DSRC Stack -> DSRC Vehicle
  3. Security Verification & Gateway Re-signing
  4. Deduplication & Replay Protection at the Gateway
  5. Broadcast Loop Prevention & Echo Suppression
  6. Operational Metrics & Latency Tracking (< 5.0 ms)
"""

import time
import pytest

from certificates.generate_pki import build_simulated_pki
from common.exceptions import (
    DuplicateMessageError,
    LoopDetectedError,
    ReplayDetectedError,
    SecurityError,
    SignatureVerificationError,
)
from common.ieee1609_2.certificates import CertificateStore
from cv2x.stack import CV2XStack
from dsrc.stack import DSRCStack
from gateway.gateway import V2XGateway


@pytest.fixture(scope="module")
def pki_store() -> CertificateStore:
    """Simulated PKI containing vehicle and gateway credentials."""
    return build_simulated_pki(num_vehicles=2, certs_per_vehicle=2)


@pytest.fixture
def gateway(pki_store: CertificateStore) -> V2XGateway:
    """Fixture providing an initialized V2XGateway instance."""
    # Find gateway certificate and key in store
    gw_cert = next(c for c in pki_store.entity_certs.values() if "Gateway" in c.to_be_signed.cert_id)
    gw_digest = gw_cert.compute_digest8()
    gw_priv = pki_store.get_private_key(gw_digest)

    return V2XGateway(
        gateway_cert=gw_cert,
        gateway_private_key=gw_priv,
        cert_store=pki_store,
        dedup_window_seconds=2.0,
        replay_window_ms=1000,
        warn_latency_threshold_ms=5.0,
    )


class TestGatewayEndToEnd:
    """End-to-end integration tests for bidirectional gateway communication."""

    def test_dsrc_to_cv2x_forwarding(self, pki_store, gateway):
        """Vehicle 1 (DSRC) broadcasts BSM -> Gateway translates -> Vehicle 2 (C-V2X) receives."""
        dsrc_sender = DSRCStack(vehicle_name="Vehicle-1", cert_store=pki_store)
        cv2x_receiver = CV2XStack(vehicle_name="Vehicle-2", cert_store=pki_store)

        now_ms = int(time.time() * 1000)

        # 1. DSRC vehicle transmits
        dsrc_frame, orig_bsm, _, _ = dsrc_sender.transmit_bsm(
            lat_deg=37.4270,
            lon_deg=-122.0000,
            speed_mps=25.0,
            heading_deg=90.0,
            current_time_ms=now_ms,
        )

        # 2. Gateway processes DSRC frame
        cv2x_tx_unit = gateway.process_dsrc_to_cv2x(
            frame_bytes=dsrc_frame,
            current_time_ms=now_ms,
            allocated_subchannel=1,
        )

        assert cv2x_tx_unit is not None
        assert cv2x_tx_unit.subchannel_index == 1

        # 3. C-V2X vehicle receives translated transmission
        rx_bsm, rx_hdr, rx_cert = cv2x_receiver.receive_sidelink(
            sci_bytes=cv2x_tx_unit.raw_sci_bytes,
            tb_bytes=cv2x_tx_unit.raw_tb_bytes,
            rx_power_dbm=-65.0,
            current_subframe=cv2x_tx_unit.scheduled_subframe,
            current_time_ms=now_ms,
        )

        # 4. Verify decoded BSM matches original transmitted BSM exactly
        assert rx_bsm.msg_cnt == orig_bsm.msg_cnt
        assert rx_bsm.vehicle_id == orig_bsm.vehicle_id
        assert abs(rx_bsm.lat_degrees - 37.4270) < 1e-6
        assert abs(rx_bsm.lon_degrees - (-122.0000)) < 1e-6
        assert abs(rx_bsm.speed_mps - 25.0) < 0.05
        assert abs(rx_bsm.heading_degrees - 90.0) < 0.1

        # 5. Verify that signer is now the Gateway certificate
        assert "Gateway" in rx_cert.to_be_signed.cert_id

    def test_cv2x_to_dsrc_forwarding(self, pki_store, gateway):
        """Vehicle 2 (C-V2X) broadcasts BSM -> Gateway translates -> Vehicle 1 (DSRC) receives."""
        cv2x_sender = CV2XStack(vehicle_name="Vehicle-2", cert_store=pki_store)
        dsrc_receiver = DSRCStack(vehicle_name="Vehicle-1", cert_store=pki_store)

        now_ms = int(time.time() * 1000)

        # 1. C-V2X vehicle transmits
        cv2x_tx_unit, orig_bsm, _, _ = cv2x_sender.transmit_bsm(
            lat_deg=37.7749,
            lon_deg=-122.4194,
            speed_mps=31.2,
            heading_deg=270.0,
            current_time_ms=now_ms,
        )

        # 2. Gateway processes C-V2X transmission
        dsrc_wave_frame = gateway.process_cv2x_to_dsrc(
            sci_bytes=cv2x_tx_unit.raw_sci_bytes,
            tb_bytes=cv2x_tx_unit.raw_tb_bytes,
            current_time_ms=now_ms,
        )

        assert dsrc_wave_frame is not None
        serialized_wave = dsrc_wave_frame.serialize(compute_fcs=True)

        # 3. DSRC vehicle receives translated WAVE frame
        rx_bsm, rx_hdr, rx_cert = dsrc_receiver.receive_frame(
            frame_bytes=serialized_wave,
            rx_power_dbm=-65.0,
            current_time_ms=now_ms,
        )

        # 4. Verify decoded BSM matches original transmitted BSM exactly
        assert rx_bsm.msg_cnt == orig_bsm.msg_cnt
        assert rx_bsm.vehicle_id == orig_bsm.vehicle_id
        assert abs(rx_bsm.lat_degrees - 37.7749) < 1e-6
        assert abs(rx_bsm.lon_degrees - (-122.4194)) < 1e-6
        assert abs(rx_bsm.speed_mps - 31.2) < 0.05
        assert abs(rx_bsm.heading_degrees - 270.0) < 0.1

        # 5. Verify that signer is the Gateway certificate
        assert "Gateway" in rx_cert.to_be_signed.cert_id

    def test_gateway_drops_duplicate(self, pki_store, gateway):
        """Duplicate message sent within 2.0s must be dropped at the gateway."""
        dsrc_sender = DSRCStack(vehicle_name="Vehicle-1", cert_store=pki_store)

        now_ms = int(time.time() * 1000)
        dsrc_frame, _, _, _ = dsrc_sender.transmit_bsm(
            lat_deg=37.0,
            lon_deg=-122.0,
            current_time_ms=now_ms,
        )

        # First transmission succeeds
        gateway.process_dsrc_to_cv2x(frame_bytes=dsrc_frame, current_time_ms=now_ms)
        initial_dropped = gateway.metrics.dropped_duplicate

        # Re-sending identical frame within dedup window must raise DuplicateMessageError
        with pytest.raises(DuplicateMessageError):
            gateway.process_dsrc_to_cv2x(frame_bytes=dsrc_frame, current_time_ms=now_ms + 100)

        assert gateway.metrics.dropped_duplicate == initial_dropped + 1

    def test_gateway_drops_replayed_message(self, pki_store, gateway):
        """Message with generationTime outside the replay window must be dropped."""
        dsrc_sender = DSRCStack(vehicle_name="Vehicle-1", cert_store=pki_store)

        now_ms = int(time.time() * 1000)
        # Message generated 5 seconds ago
        dsrc_frame, _, _, _ = dsrc_sender.transmit_bsm(
            lat_deg=37.0,
            lon_deg=-122.0,
            current_time_ms=now_ms - 5000,
        )

        initial_dropped = gateway.metrics.dropped_security
        with pytest.raises(ReplayDetectedError):
            gateway.process_dsrc_to_cv2x(frame_bytes=dsrc_frame, current_time_ms=now_ms)

        assert gateway.metrics.dropped_security == initial_dropped + 1

    def test_gateway_loop_prevention(self, pki_store, gateway):
        """Feeding an outbound gateway frame back into the gateway must trigger LoopDetectedError."""
        dsrc_sender = DSRCStack(vehicle_name="Vehicle-1", cert_store=pki_store)

        now_ms = int(time.time() * 1000)
        dsrc_frame, _, _, _ = dsrc_sender.transmit_bsm(
            lat_deg=37.0,
            lon_deg=-122.0,
            current_time_ms=now_ms,
        )

        # 1. Translate DSRC -> C-V2X
        cv2x_tx_unit = gateway.process_dsrc_to_cv2x(
            frame_bytes=dsrc_frame,
            current_time_ms=now_ms,
        )

        # 2. Feed the translated C-V2X packet back into the gateway in reverse direction
        initial_loop_drops = gateway.metrics.dropped_loop
        with pytest.raises(LoopDetectedError):
            gateway.process_cv2x_to_dsrc(
                sci_bytes=cv2x_tx_unit.raw_sci_bytes,
                tb_bytes=cv2x_tx_unit.raw_tb_bytes,
                current_time_ms=now_ms + 5,
            )

        assert gateway.metrics.dropped_loop == initial_loop_drops + 1

    def test_gateway_performance_and_metrics(self, pki_store, gateway):
        """Gateway metrics must correctly reflect operational performance."""
        dsrc_sender = DSRCStack(vehicle_name="Vehicle-1", cert_store=pki_store)
        now_ms = int(time.time() * 1000)

        frame, _, _, _ = dsrc_sender.transmit_bsm(
            lat_deg=37.0,
            lon_deg=-122.0,
            current_time_ms=now_ms,
        )
        gateway.process_dsrc_to_cv2x(frame_bytes=frame, current_time_ms=now_ms)

        assert gateway.metrics.total_forwarded >= 1
        assert gateway.metrics.avg_latency_ms < 5.0
