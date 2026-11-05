"""
V2X Gateway Simulator — Gateway Security Handler
=================================================
Executes IEEE 1609.2 security processing across stack boundaries:
  - Verifies inbound message signature and sender trust chain
  - Strips transport envelope while preserving raw BSM bytes verbatim
  - Re-signs outbound message using the Gateway's own IEEE 1609.2 certificate
  - Emits detailed security audit logs

Standards References:
  - IEEE 1609.2-2016: Section 7 (Security Processing)
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from common.exceptions import (
    SecurityError,
    SignatureVerificationError,
)
from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
)
from common.ieee1609_2.security_engine import (
    sign_message,
    verify_message,
)
from common.ieee1609_2.spdu import (
    HeaderInfo,
    Ieee1609Dot2Data,
)
from common.message_types import (
    PSID,
    REPLAY_WINDOW_MS,
)
from monitoring.logger import get_logger

log = get_logger("gateway.security_handler")


class GatewaySecurityHandler:
    """Manages cross-stack verification and authorized re-signing."""

    def __init__(
        self,
        gateway_cert: Certificate,
        gateway_private_key: ec.EllipticCurvePrivateKey,
        cert_store: CertificateStore,
        replay_window_ms: int = REPLAY_WINDOW_MS,
    ):
        self.gateway_cert = gateway_cert
        self.gateway_private_key = gateway_private_key
        self.cert_store = cert_store
        self.replay_window_ms = replay_window_ms
        self.gateway_digest = gateway_cert.compute_digest8()

    def process_inbound(
        self,
        spdu: Ieee1609Dot2Data,
        current_time_ms: Optional[int] = None,
    ) -> Tuple[bytes, HeaderInfo, Certificate]:
        """Verify inbound SPDU, checking signature, trust chain, and replay window.

        Returns:
            Tuple of (raw_bsm_bytes, HeaderInfo, sender_cert).

        Raises:
            SecurityError: If verification, chain check, or replay protection fails.
        """
        payload, hdr, sender_cert = verify_message(
            spdu=spdu,
            cert_store=self.cert_store,
            current_time_ms=current_time_ms,
            replay_window_ms=self.replay_window_ms,
            expected_psid=PSID.BSM,
        )

        sender_digest = sender_cert.compute_digest8().hex()
        log.info(
            f"Gateway verified inbound SPDU: sender_cert='{sender_cert.to_be_signed.cert_id}' "
            f"[digest: {sender_digest}] psid=0x{hdr.psid:04X} payload_len={len(payload)}B"
        )
        return payload, hdr, sender_cert

    def prepare_outbound(
        self,
        bsm_bytes: bytes,
        inbound_hdr: HeaderInfo,
        current_time_ms: Optional[int] = None,
        include_full_cert: bool = False,
    ) -> Ieee1609Dot2Data:
        """Re-sign verified BSM payload using the Gateway's certificate.

        CRITICAL SECURITY RULE:
          The raw BSM payload bytes are preserved VERBATIM. The gateway
          only replaces the security envelope with its own authentic signature.
        """
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)

        outbound_spdu = sign_message(
            payload=bsm_bytes,
            signer_cert=self.gateway_cert,
            private_key=self.gateway_private_key,
            psid=inbound_hdr.psid,
            generation_time_ms=now_ms,
            expiry_time_ms=inbound_hdr.expiry_time,
            include_full_cert=include_full_cert,
        )

        log.info(
            f"Gateway re-signed outbound SPDU: gateway_cert='{self.gateway_cert.to_be_signed.cert_id}' "
            f"[digest: {self.gateway_digest.hex()}] new_gen_time={now_ms}"
        )
        return outbound_spdu

