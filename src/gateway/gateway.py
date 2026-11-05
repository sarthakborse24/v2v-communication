"""
V2X Gateway Simulator — Complete Bidirectional DSRC ↔ LTE-C-V2X Protocol Gateway
================================================================================
Orchestrates:
  - Ingress demultiplexing & L1/L2 stripping (GatewayReceiver)
  - Structural & semantic validation (GatewayValidator)
  - Deduplication via (source_id, msg_cnt) sliding window (DuplicateHandler)
  - Broadcast loop prevention & echo suppression (LoopPreventionHandler)
  - IEEE 1609.2 verification & re-signing (GatewaySecurityHandler)
  - Bidirectional protocol translation (GatewayTranslator)
  - Egress queuing & transit latency tracking (GatewayForwarder)

CRITICAL SECURITY & STANDARDS COMPLIANCE:
  - BSM payload bytes are preserved VERBATIM.
  - Gateway re-signs messages with its authorized Gateway Certificate.
  - Senders' trust chains are validated up to the trusted Root CA anchor.
  - Strict loop prevention eliminates broadcast echo between stacks.
"""

from __future__ import annotations

import hashlib
import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from common.bsm_codec import BasicSafetyMessage
from common.exceptions import (
    DuplicateMessageError,
    GatewayError,
    LoopDetectedError,
    SecurityError,
    TranslationError,
    ValidationError,
)
from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
)
from common.message_types import (
    GatewayDirection,
    PSID,
    REPLAY_WINDOW_MS,
    StackType,
)
from cv2x.mac.lte_mac import SidelinkTransmissionUnit
from dsrc.wave.wave_frame import WAVEFrame
from gateway.duplicate_handler import DuplicateHandler
from gateway.forwarder import (
    GatewayForwarder,
    GatewayMetrics,
)
from gateway.loop_prevention import LoopPreventionHandler
from gateway.receiver import (
    GatewayReceiver,
    IngressPacket,
)
from gateway.security_handler import GatewaySecurityHandler
from gateway.translator import GatewayTranslator
from gateway.validator import GatewayValidator
from monitoring.logger import get_logger

log = get_logger("gateway.core")


class V2XGateway:
    """Central gateway connecting DSRC and LTE-C-V2X communication domains."""

    def __init__(
        self,
        gateway_cert: Certificate,
        gateway_private_key: ec.EllipticCurvePrivateKey,
        cert_store: CertificateStore,
        gateway_mac: bytes = b"\x00\xaa\xbb\xcc\xdd\x01",
        gateway_l2_id: bytes = b"\xaa\xbb\x01",
        dedup_window_seconds: float = 2.0,
        replay_window_ms: int = REPLAY_WINDOW_MS,
        warn_latency_threshold_ms: float = 5.0,
    ):
        self.gateway_cert = gateway_cert
        self.gateway_private_key = gateway_private_key
        self.cert_store = cert_store

        # Submodules
        self.receiver = GatewayReceiver()
        self.validator = GatewayValidator(expected_psid=PSID.BSM)
        self.duplicate_handler = DuplicateHandler(window_seconds=dedup_window_seconds)
        self.loop_prevention = LoopPreventionHandler(
            gateway_cert_digest=gateway_cert.compute_digest8()
        )
        self.security_handler = GatewaySecurityHandler(
            gateway_cert=gateway_cert,
            gateway_private_key=gateway_private_key,
            cert_store=cert_store,
            replay_window_ms=replay_window_ms,
        )
        self.translator = GatewayTranslator(
            gateway_mac_address=gateway_mac,
            gateway_l2_id=gateway_l2_id,
        )
        self.forwarder = GatewayForwarder(
            warn_latency_threshold_ms=warn_latency_threshold_ms
        )

    @property
    def metrics(self) -> GatewayMetrics:
        return self.forwarder.metrics

    def process_dsrc_to_cv2x(
        self,
        frame_bytes: bytes,
        current_time_ms: Optional[int] = None,
        allocated_subchannel: int = 0,
    ) -> SidelinkTransmissionUnit:
        """Process inbound DSRC frame and forward as LTE-C-V2X PC5 transmission unit.

        Pipeline:
          1. Ingress: Dissect 802.11p frame and WSMP header.
          2. Validate: Check SPDU syntax and BSM UPER decode.
          3. Loop Check: Ensure packet does not originate from a gateway.
          4. Dedup: Reject if (vehicle_id, msg_cnt) was seen in sliding window.
          5. Verify Security: Check original ECDSA signature and trust chain.
          6. Re-sign: Sign verified BSM bytes with Gateway Certificate.
          7. Translate: Map to SidelinkTransportBlock and SCI Format 1.
          8. Egress: Record loop digest, compute latency, enqueue.
        """
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)
        self.forwarder.metrics.ingress_dsrc_count += 1

        # 1. Ingress
        try:
            packet = self.receiver.receive_dsrc(frame_bytes, current_time_ms=now_ms)
        except Exception as exc:
            self.forwarder.metrics.dropped_validation += 1
            log.warning(f"DSRC ingress parse failed: {exc}")
            raise ValidationError(f"DSRC ingress parse failed: {exc}") from exc

        # 2. Validation
        try:
            spdu, bsm = self.validator.validate_ingress_spdu(packet)
        except ValidationError as exc:
            self.forwarder.metrics.dropped_validation += 1
            log.warning(f"DSRC ingress validation failed: {exc}")
            raise

        # 3. Check Gateway Signer Loop (detect if message was signed by a gateway)
        try:
            self.loop_prevention.check_signer_is_gateway(spdu)
        except LoopDetectedError as exc:
            self.forwarder.metrics.dropped_loop += 1
            log.warning(f"DSRC ingress gateway loop detected: {exc}")
            raise

        # 4. Duplicate Detection (Checked for vehicle source_id and msg_cnt)
        try:
            self.duplicate_handler.check_and_record(
                source_id=bsm.vehicle_id,
                msg_cnt=bsm.msg_cnt,
                current_time_s=now_ms / 1000.0,
            )
        except DuplicateMessageError as exc:
            self.forwarder.metrics.dropped_duplicate += 1
            log.warning(f"DSRC duplicate dropped: {exc}")
            raise

        # 5. Check Payload Echo Loop (detect if raw payload was recently forwarded)
        try:
            self.loop_prevention.check_payload_echo(
                payload=spdu.signed_data.tbs_data.payload,
                current_time_s=now_ms / 1000.0,
            )
        except LoopDetectedError as exc:
            self.forwarder.metrics.dropped_loop += 1
            log.warning(f"DSRC ingress payload echo detected: {exc}")
            raise

        # 5. Security Verification
        try:
            bsm_bytes, hdr, sender_cert = self.security_handler.process_inbound(
                spdu=spdu,
                current_time_ms=now_ms,
            )
        except SecurityError as exc:
            self.forwarder.metrics.dropped_security += 1
            log.warning(f"DSRC security verification failed: {exc}")
            raise

        # 6. Gateway Re-Signing
        re_signed_spdu = self.security_handler.prepare_outbound(
            bsm_bytes=bsm_bytes,
            inbound_hdr=hdr,
            current_time_ms=now_ms,
        )

        # 7. Translation: DSRC -> C-V2X
        try:
            sci, tb = self.translator.translate_dsrc_to_cv2x(
                inbound_packet=packet,
                re_signed_spdu=re_signed_spdu,
                allocated_subchannel=allocated_subchannel,
            )
        except Exception as exc:
            log.error(f"DSRC -> C-V2X translation error: {exc}")
            raise TranslationError(f"Translation failed: {exc}") from exc

        # 8. Record egress digest for loop prevention
        payload_hash = hashlib.sha256(bsm_bytes).digest()
        self.loop_prevention.record_egress(payload_hash, current_time_s=now_ms / 1000.0)

        # 9. Forwarding & Latency Calculation
        latency_ms = self.forwarder.record_forwarded(
            direction=GatewayDirection.DSRC_TO_CV2X,
            ingress_timestamp_ms=packet.ingress_timestamp_ms,
            current_time_ms=now_ms,
        )

        tx_unit = SidelinkTransmissionUnit(
            sci=sci,
            transport_block=tb,
            scheduled_subframe=now_ms + 4,
            subchannel_index=allocated_subchannel,
            raw_sci_bytes=sci.serialize(),
            raw_tb_bytes=tb.serialize(compute_crc=True),
        )
        self.forwarder.enqueue_cv2x(tx_unit, latency_ms)

        log.info(
            f"Gateway successfully translated DSRC -> C-V2X in {latency_ms:.2f}ms: "
            f"vehicle_id={bsm.vehicle_id.hex()} msg_cnt={bsm.msg_cnt}"
        )
        return tx_unit

    def process_cv2x_to_dsrc(
        self,
        sci_bytes: bytes,
        tb_bytes: bytes,
        current_time_ms: Optional[int] = None,
    ) -> WAVEFrame:
        """Process inbound C-V2X sidelink transmission and forward as DSRC WAVE frame.

        Pipeline:
          1. Ingress: Dissect SCI Format 1 and Transport Block with CRC-24A.
          2. Validate: Check SPDU syntax and BSM UPER decode.
          3. Loop Check: Ensure packet does not originate from a gateway.
          4. Dedup: Reject if (vehicle_id, msg_cnt) was seen in sliding window.
          5. Verify Security: Check original ECDSA signature and trust chain.
          6. Re-sign: Sign verified BSM bytes with Gateway Certificate.
          7. Translate: Map to WSMPacket and WAVEFrame (EtherType 0x88DC, AC_VO).
          8. Egress: Record loop digest, compute latency, enqueue.
        """
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)
        self.forwarder.metrics.ingress_cv2x_count += 1

        # 1. Ingress
        try:
            packet = self.receiver.receive_cv2x(
                sci_bytes=sci_bytes,
                tb_bytes=tb_bytes,
                current_time_ms=now_ms,
            )
        except Exception as exc:
            self.forwarder.metrics.dropped_validation += 1
            log.warning(f"C-V2X ingress parse failed: {exc}")
            raise ValidationError(f"C-V2X ingress parse failed: {exc}") from exc

        # 2. Validation
        try:
            spdu, bsm = self.validator.validate_ingress_spdu(packet)
        except ValidationError as exc:
            self.forwarder.metrics.dropped_validation += 1
            log.warning(f"C-V2X ingress validation failed: {exc}")
            raise

        # 3. Check Gateway Signer Loop (detect if message was signed by a gateway)
        try:
            self.loop_prevention.check_signer_is_gateway(spdu)
        except LoopDetectedError as exc:
            self.forwarder.metrics.dropped_loop += 1
            log.warning(f"C-V2X ingress gateway loop detected: {exc}")
            raise

        # 4. Duplicate Detection
        try:
            self.duplicate_handler.check_and_record(
                source_id=bsm.vehicle_id,
                msg_cnt=bsm.msg_cnt,
                current_time_s=now_ms / 1000.0,
            )
        except DuplicateMessageError as exc:
            self.forwarder.metrics.dropped_duplicate += 1
            log.warning(f"C-V2X duplicate dropped: {exc}")
            raise

        # 5. Check Payload Echo Loop
        try:
            self.loop_prevention.check_payload_echo(
                payload=spdu.signed_data.tbs_data.payload,
                current_time_s=now_ms / 1000.0,
            )
        except LoopDetectedError as exc:
            self.forwarder.metrics.dropped_loop += 1
            log.warning(f"C-V2X ingress payload echo detected: {exc}")
            raise

        # 5. Security Verification
        try:
            bsm_bytes, hdr, sender_cert = self.security_handler.process_inbound(
                spdu=spdu,
                current_time_ms=now_ms,
            )
        except SecurityError as exc:
            self.forwarder.metrics.dropped_security += 1
            log.warning(f"C-V2X security verification failed: {exc}")
            raise

        # 6. Gateway Re-Signing
        re_signed_spdu = self.security_handler.prepare_outbound(
            bsm_bytes=bsm_bytes,
            inbound_hdr=hdr,
            current_time_ms=now_ms,
        )

        # 7. Translation: C-V2X -> DSRC
        try:
            wave_frame, _ = self.translator.translate_cv2x_to_dsrc(
                inbound_packet=packet,
                re_signed_spdu=re_signed_spdu,
            )
        except Exception as exc:
            log.error(f"C-V2X -> DSRC translation error: {exc}")
            raise TranslationError(f"Translation failed: {exc}") from exc

        # 8. Record egress digest for loop prevention
        payload_hash = hashlib.sha256(bsm_bytes).digest()
        self.loop_prevention.record_egress(payload_hash, current_time_s=now_ms / 1000.0)

        # 9. Forwarding & Latency Calculation
        latency_ms = self.forwarder.record_forwarded(
            direction=GatewayDirection.CV2X_TO_DSRC,
            ingress_timestamp_ms=packet.ingress_timestamp_ms,
            current_time_ms=now_ms,
        )
        self.forwarder.enqueue_dsrc(wave_frame, latency_ms)

        log.info(
            f"Gateway successfully translated C-V2X -> DSRC in {latency_ms:.2f}ms: "
            f"vehicle_id={bsm.vehicle_id.hex()} msg_cnt={bsm.msg_cnt}"
        )
        return wave_frame
