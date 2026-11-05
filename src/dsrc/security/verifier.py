"""
V2X Gateway Simulator — DSRC Security Verifier
==============================================
Verifies inbound DSRC WAVE safety messages against IEEE 1609.2 standards:
  - Signature validation
  - Trust chain check
  - Replay protection
  - PSID permission check
"""

from __future__ import annotations

from typing import Optional, Tuple

from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
)
from common.ieee1609_2.security_engine import verify_message
from common.ieee1609_2.spdu import (
    HeaderInfo,
    Ieee1609Dot2Data,
)
from common.message_types import (
    PSID,
    REPLAY_WINDOW_MS,
)
from monitoring.logger import get_logger

log = get_logger("dsrc.security.verifier")


class DSRCSecurityVerifier:
    """Handles IEEE 1609.2 verification for inbound DSRC messages."""

    def __init__(
        self,
        cert_store: CertificateStore,
        replay_window_ms: int = REPLAY_WINDOW_MS,
    ):
        self.cert_store = cert_store
        self.replay_window_ms = replay_window_ms

    def verify_bsm(
        self,
        spdu: Ieee1609Dot2Data,
        current_time_ms: Optional[int] = None,
    ) -> Tuple[bytes, HeaderInfo, Certificate]:
        """Verify an incoming BSM SPDU.

        Returns:
            Tuple of (raw_bsm_bytes, HeaderInfo, signer_cert).

        Raises:
            SecurityError: On signature, trust, or replay check failure.
        """
        payload, hdr, cert = verify_message(
            spdu=spdu,
            cert_store=self.cert_store,
            current_time_ms=current_time_ms,
            replay_window_ms=self.replay_window_ms,
            expected_psid=PSID.BSM,
        )

        log.debug(
            f"Verified BSM from cert '{cert.to_be_signed.cert_id}' "
            f"[digest: {cert.compute_digest8().hex()}] msg_time={hdr.generation_time}"
        )
        return payload, hdr, cert

