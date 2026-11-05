"""
V2X Gateway Simulator — Gateway Loop Prevention
================================================
Prevents translation feedback loops and broadcast echoes between DSRC and C-V2X:
  - Gateway signature detection (drops messages signed by any known gateway)
  - Egress digest tracking (drops messages echoing back within loop window)
  - Single-hop enforcement for translated broadcast safety messages

Standards References:
  - IEEE 1609.2-2016: Signer Identifier validation
  - ETSI TS 102 890-1 / ISO 21217: V2X Gateway loop prevention
"""

from __future__ import annotations

import hashlib
import time
from typing import Dict, Optional, Set

from common.exceptions import LoopDetectedError
from common.ieee1609_2.certificates import Certificate
from common.ieee1609_2.spdu import Ieee1609Dot2Data
from monitoring.logger import get_logger

log = get_logger("gateway.loop_prevention")


class LoopPreventionHandler:
    """Enforces loop prevention across the bidirectional gateway."""

    def __init__(
        self,
        gateway_cert_digest: bytes,
        loop_cache_window_seconds: float = 3.0,
    ):
        self.gateway_cert_digest = gateway_cert_digest
        self.loop_cache_window_seconds = loop_cache_window_seconds

        # Known gateway certificate digests (including self)
        self._known_gateway_digests: Set[bytes] = {gateway_cert_digest}

        # Cache of recently translated payload hashes -> egress_timestamp
        self._egress_payload_cache: Dict[bytes, float] = {}

    def register_known_gateway(self, cert_digest: bytes) -> None:
        """Register an additional known gateway certificate digest to prevent multi-gateway echoes."""
        self._known_gateway_digests.add(cert_digest)

    def prune_cache(self, current_time_s: float) -> None:
        """Remove egress digests older than the loop detection window."""
        cutoff = current_time_s - self.loop_cache_window_seconds
        stale = [k for k, ts in self._egress_payload_cache.items() if ts < cutoff]
        for k in stale:
            del self._egress_payload_cache[k]

    def record_egress(self, payload_hash: bytes, current_time_s: Optional[float] = None) -> None:
        """Record the payload hash of an outbound translated message."""
        now = current_time_s if current_time_s is not None else time.time()
        self._egress_payload_cache[payload_hash] = now

    def check_signer_is_gateway(
        self,
        spdu: Ieee1609Dot2Data,
        signer_cert: Optional[Certificate] = None,
    ) -> None:
        """Check if message was signed by this or another known gateway.

        Raises:
            LoopDetectedError: If the signer is identified as a gateway.
        """
        if spdu.signed_data is None:
            return

        signer_info = spdu.signed_data.signer
        if signer_info.choice == "digest" and signer_info.digest in self._known_gateway_digests:
            log.warning("Loop detected: Message was signed by a gateway (dropping)")
            raise LoopDetectedError(
                f"Loop detected: Signer digest {signer_info.digest.hex()} belongs to a gateway"
            )

        if signer_cert is not None:
            cert_digest = signer_cert.compute_digest8()
            if cert_digest in self._known_gateway_digests or "Gateway" in signer_cert.to_be_signed.cert_id:
                log.warning(f"Loop detected: Signer cert '{signer_cert.to_be_signed.cert_id}' is a gateway")
                raise LoopDetectedError("Loop detected: Originating entity is a gateway")

    def check_payload_echo(
        self,
        payload: bytes,
        current_time_s: Optional[float] = None,
    ) -> None:
        """Check if raw payload matches a recently forwarded egress payload.

        Raises:
            LoopDetectedError: If the payload is an echo of recent gateway egress.
        """
        now = current_time_s if current_time_s is not None else time.time()
        self.prune_cache(now)

        payload_hash = hashlib.sha256(payload).digest()
        if payload_hash in self._egress_payload_cache:
            log.warning("Loop detected: Payload recently translated and forwarded by this gateway")
            raise LoopDetectedError("Loop detected: Echo of recently forwarded payload")

    def check_loop(
        self,
        spdu: Ieee1609Dot2Data,
        signer_cert: Optional[Certificate] = None,
        current_time_s: Optional[float] = None,
    ) -> None:
        """Check both gateway signer origin and payload echo."""
        self.check_signer_is_gateway(spdu, signer_cert)
        if spdu.signed_data is not None:
            self.check_payload_echo(spdu.signed_data.tbs_data.payload, current_time_s)
