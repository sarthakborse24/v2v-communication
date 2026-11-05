"""
V2X Gateway Simulator — DSRC Security Signer
============================================
Signs outbound DSRC WAVE safety messages with IEEE 1609.2 SignedData SPDU.

Standards References:
  - IEEE 1609.2-2016: Section 7
  - IEEE 1609.3: PSID 0x20 for BSM
"""

from __future__ import annotations

from typing import Optional

from common.ieee1609_2.security_engine import sign_message
from common.ieee1609_2.spdu import Ieee1609Dot2Data
from common.message_types import PSID
from dsrc.security.certificate_manager import DSRCCertificateManager
from monitoring.logger import get_logger

log = get_logger("dsrc.security.signer")


class DSRCSecuritySigner:
    """Handles IEEE 1609.2 signing for outbound DSRC messages."""

    def __init__(self, cert_manager: DSRCCertificateManager):
        self.cert_manager = cert_manager

    def sign_bsm(
        self,
        bsm_bytes: bytes,
        generation_time_ms: Optional[int] = None,
        expiry_time_ms: Optional[int] = None,
        include_full_cert: bool = False,
    ) -> Ieee1609Dot2Data:
        """Sign a UPER-encoded BSM payload using the OBU's active pseudonym certificate."""
        cert, priv_key = self.cert_manager.get_active_credentials()

        spdu = sign_message(
            payload=bsm_bytes,
            signer_cert=cert,
            private_key=priv_key,
            psid=PSID.BSM,
            generation_time_ms=generation_time_ms,
            expiry_time_ms=expiry_time_ms,
            include_full_cert=include_full_cert,
        )

        log.debug(
            f"Signed BSM with cert '{cert.to_be_signed.cert_id}' "
            f"[digest: {cert.compute_digest8().hex()}] payload={len(bsm_bytes)}B"
        )
        return spdu
