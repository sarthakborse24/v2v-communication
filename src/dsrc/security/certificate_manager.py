"""
V2X Gateway Simulator — DSRC Certificate Manager
=================================================
Manages vehicle pseudonym certificate pools, active credentials,
and periodic certificate rotation for privacy preservation.

Standards References:
  - IEEE 1609.2-2016: Pseudonym Certificates
  - CAMP VSC3: Pseudonym rotation guidelines
"""

from __future__ import annotations

import time
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from common.exceptions import SecurityError
from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
)
from monitoring.logger import get_logger

log = get_logger("dsrc.security.cert_manager")


class DSRCCertificateManager:
    """Manages an OBU's pseudonym certificate pool and rotation lifecycle."""

    def __init__(
        self,
        vehicle_name: str,
        cert_store: CertificateStore,
        rotation_interval_seconds: float = 300.0,
    ):
        self.vehicle_name = vehicle_name
        self.cert_store = cert_store
        self.rotation_interval_seconds = rotation_interval_seconds

        # Find all entity certificates belonging to this vehicle
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
        """Return the currently active (Certificate, PrivateKey) tuple.

        Automatically triggers rotation if rotation interval has elapsed.
        """
        now = current_time if current_time is not None else time.time()

        if not self._pseudonym_certs:
            raise SecurityError(f"No credentials available for vehicle '{self.vehicle_name}'")

        # Check if rotation is due
        if (now - self._last_rotation_time) >= self.rotation_interval_seconds:
            self.rotate_pseudonym(current_time=now)

        return self._pseudonym_certs[self._active_idx]

    def rotate_pseudonym(self, current_time: Optional[float] = None) -> Tuple[Certificate, bytes]:
        """Explicitly rotate to the next pseudonym certificate in the pool.

        Returns:
            Tuple of (new_active_cert, new_temporary_id_4bytes).
        """
        if not self._pseudonym_certs:
            raise SecurityError("Cannot rotate: pseudonym pool is empty")

        old_idx = self._active_idx
        self._active_idx = (self._active_idx + 1) % len(self._pseudonym_certs)
        self._last_rotation_time = current_time if current_time is not None else time.time()

        new_cert, _ = self._pseudonym_certs[self._active_idx]
        # Derive 4-byte temporary ID from low 4 bytes of cert digest
        temp_id = new_cert.compute_digest8()[-4:]

        log.info(
            f"Rotated pseudonym for '{self.vehicle_name}': {old_idx} -> {self._active_idx} "
            f"[{new_cert.to_be_signed.cert_id}] temp_id={temp_id.hex()}"
        )
        return new_cert, temp_id

    def active_temporary_id(self) -> bytes:
        """Derive 4-byte SAE J2735 TemporaryID from active certificate digest."""
        cert, _ = self.get_active_credentials()
        return cert.compute_digest8()[-4:]

