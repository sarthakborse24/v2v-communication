"""
V2X Gateway Simulator — C-V2X PC5 Sidelink Security Layer
==========================================================
Handles IEEE 1609.2 security processing for LTE-V2X PC5 communications:
  - Vehicle pseudonym certificate management & rotation
  - SPDU signing with ECDSA-P256
  - Inbound SPDU verification, replay protection, and trust chain validation

Standards References:
  - IEEE 1609.2-2016: Section 6 & 7
  - 3GPP TS 36.300 / TS 36.331: V2X Sidelink Security integration
"""

from __future__ import annotations

import time
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from common.exceptions import (
    SecurityError,
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

log = get_logger("cv2x.security")


class CV2XCertificateManager:
    """Manages pseudonym credentials for a C-V2X UE."""

    def __init__(
        self,
        vehicle_name: str,
        cert_store: CertificateStore,
        rotation_interval_seconds: float = 300.0,
    ):
        self.vehicle_name = vehicle_name
        self.cert_store = cert_store
        self.rotation_interval_seconds = rotation_interval_seconds

        self._pseudonym_certs: List[Tuple[Certificate, ec.EllipticCurvePrivateKey]] = []
        for digest, cert in cert_store.entity_certs.items():
            if vehicle_name in cert.to_be_signed.cert_id:
                priv = cert_store.get_private_key(digest)
                if priv:
                    self._pseudonym_certs.append((cert, priv))

        if not self._pseudonym_certs:
            log.warning(f"No pseudonym certificates found in store matching '{vehicle_name}'")

        self._active_idx = 0
        self._last_rotation_time = time.time()

    @property
    def num_pseudonyms(self) -> int:
        return len(self._pseudonym_certs)

    def get_active_credentials(
        self, current_time: Optional[float] = None
    ) -> Tuple[Certificate, ec.EllipticCurvePrivateKey]:
        now = current_time if current_time is not None else time.time()
        if not self._pseudonym_certs:
            raise SecurityError(f"No credentials available for C-V2X UE '{self.vehicle_name}'")

        if (now - self._last_rotation_time) >= self.rotation_interval_seconds:
            self.rotate_pseudonym(current_time=now)

        return self._pseudonym_certs[self._active_idx]

    def rotate_pseudonym(self, current_time: Optional[float] = None) -> Tuple[Certificate, bytes]:
        if not self._pseudonym_certs:
            raise SecurityError("Cannot rotate: pseudonym pool is empty")

        old_idx = self._active_idx
        self._active_idx = (self._active_idx + 1) % len(self._pseudonym_certs)
        self._last_rotation_time = current_time if current_time is not None else time.time()

        new_cert, _ = self._pseudonym_certs[self._active_idx]
        temp_id = new_cert.compute_digest8()[-4:]

        log.info(
            f"Rotated pseudonym for C-V2X '{self.vehicle_name}': {old_idx} -> {self._active_idx} "
            f"[{new_cert.to_be_signed.cert_id}] temp_id={temp_id.hex()}"
        )
        return new_cert, temp_id

    def active_temporary_id(self) -> bytes:
        cert, _ = self.get_active_credentials()
        return cert.compute_digest8()[-4:]


class CV2XSecurityHandler:
    """Combines signing and verification for C-V2X sidelink communications."""

    def __init__(
        self,
        cert_manager: CV2XCertificateManager,
        cert_store: CertificateStore,
        replay_window_ms: int = REPLAY_WINDOW_MS,
    ):
        self.cert_manager = cert_manager
        self.cert_store = cert_store
        self.replay_window_ms = replay_window_ms

    def sign_bsm(
        self,
        bsm_bytes: bytes,
        generation_time_ms: Optional[int] = None,
        expiry_time_ms: Optional[int] = None,
        include_full_cert: bool = False,
    ) -> Ieee1609Dot2Data:
        """Sign a BSM payload with the active pseudonym certificate."""
        cert, priv = self.cert_manager.get_active_credentials()
        return sign_message(
            payload=bsm_bytes,
            signer_cert=cert,
            private_key=priv,
            psid=PSID.BSM,
            generation_time_ms=generation_time_ms,
            expiry_time_ms=expiry_time_ms,
            include_full_cert=include_full_cert,
        )

    def verify_spdu(
        self,
        spdu: Ieee1609Dot2Data,
        current_time_ms: Optional[int] = None,
    ) -> Tuple[bytes, HeaderInfo, Certificate]:
        """Verify an incoming C-V2X SPDU."""
        return verify_message(
            spdu=spdu,
            cert_store=self.cert_store,
            current_time_ms=current_time_ms,
            replay_window_ms=self.replay_window_ms,
            expected_psid=PSID.BSM,
        )

