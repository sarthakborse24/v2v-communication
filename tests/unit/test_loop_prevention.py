"""
Unit Tests for Gateway Loop Prevention
=======================================
Standards References:
  - IEEE 1609.2-2016: Signer Identifier validation
  - ETSI TS 102 890-1 / ISO 21217: V2X Gateway loop prevention
"""

import hashlib
import pytest

from common.exceptions import LoopDetectedError
from common.ieee1609_2.spdu import (
    EcdsaP256Signature,
    HeaderInfo,
    Ieee1609Dot2Data,
    SignedData,
    SignerIdentifier,
    ToBeSignedData,
)
from gateway.loop_prevention import LoopPreventionHandler


class TestLoopPreventionHandler:
    """Tests for broadcast echo and gateway loop prevention."""

    def test_direct_vehicle_message_passes(self):
        gw_digest = b"\xaa" * 8
        handler = LoopPreventionHandler(gateway_cert_digest=gw_digest)

        # Vehicle SPDU signed by vehicle digest
        v_digest = b"\x11" * 8
        spdu = Ieee1609Dot2Data(
            content_type="signedData",
            signed_data=SignedData(
                tbs_data=ToBeSignedData(payload=b"Novel Vehicle Payload"),
                signer=SignerIdentifier.from_digest(v_digest),
                signature=EcdsaP256Signature(r=b"\x01" * 32, s=b"\x02" * 32),
            ),
        )

        # Must not raise
        handler.check_loop(spdu, current_time_s=100.0)

    def test_gateway_signed_message_rejected(self):
        """A message signed by a gateway digest must be dropped as a loop."""
        gw_digest = b"\xaa" * 8
        handler = LoopPreventionHandler(gateway_cert_digest=gw_digest)

        spdu = Ieee1609Dot2Data(
            content_type="signedData",
            signed_data=SignedData(
                tbs_data=ToBeSignedData(payload=b"Echoed Payload"),
                signer=SignerIdentifier.from_digest(gw_digest),
                signature=EcdsaP256Signature(r=b"\x01" * 32, s=b"\x02" * 32),
            ),
        )

        with pytest.raises(LoopDetectedError) as exc:
            handler.check_loop(spdu, current_time_s=100.0)
        assert "belongs to a gateway" in str(exc.value)

    def test_echo_of_forwarded_payload_rejected(self):
        """A message carrying the exact payload recently forwarded by the gateway must be dropped."""
        gw_digest = b"\xaa" * 8
        handler = LoopPreventionHandler(
            gateway_cert_digest=gw_digest,
            loop_cache_window_seconds=3.0,
        )

        payload = b"Specific Safety Broadcast Payload"
        payload_hash = hashlib.sha256(payload).digest()

        # Gateway records outbound translation at time 100.0
        handler.record_egress(payload_hash, current_time_s=100.0)

        # Inbound packet at time 100.5 carries same payload from another path
        spdu = Ieee1609Dot2Data(
            content_type="signedData",
            signed_data=SignedData(
                tbs_data=ToBeSignedData(payload=payload),
                signer=SignerIdentifier.from_digest(b"\x99" * 8),  # Even if signer ID differs
                signature=EcdsaP256Signature(r=b"\x01" * 32, s=b"\x02" * 32),
            ),
        )

        with pytest.raises(LoopDetectedError) as exc:
            handler.check_loop(spdu, current_time_s=100.5)
        assert "recently forwarded" in str(exc.value)
