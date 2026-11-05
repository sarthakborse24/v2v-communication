"""
Unit Tests for Gateway Message Validator
=========================================
Standards References:
  - IEEE 1609.2-2016: Section 6
  - SAE J2735-2020: BasicSafetyMessage Part I
"""

import pytest

from common.bsm_codec import (
    BasicSafetyMessage,
    encode_bsm_uper,
)
from common.exceptions import ValidationError
from common.ieee1609_2.spdu import (
    HeaderInfo,
    Ieee1609Dot2Data,
    SignedData,
    SignerIdentifier,
    ToBeSignedData,
)
from common.message_types import (
    PSID,
    StackType,
)
from gateway.receiver import IngressPacket
from gateway.validator import GatewayValidator


@pytest.fixture
def valid_ingress_packet() -> IngressPacket:
    """Fixture providing a structurally valid IngressPacket."""
    bsm = BasicSafetyMessage.create(
        msg_cnt=10,
        vehicle_id=b"\x11\x22\x33\x44",
        lat_deg=37.5,
        lon_deg=-122.0,
        speed_mps=15.0,
    )
    bsm_bytes = encode_bsm_uper(bsm)

    hdr = HeaderInfo(psid=PSID.BSM, generation_time=1000000)
    tbs = ToBeSignedData(payload=bsm_bytes, header_info=hdr)
    sd = SignedData(
        tbs_data=tbs,
        signer=SignerIdentifier.from_digest(b"\x01" * 8),
        signature=pytest.importorskip("common.ieee1609_2.spdu").EcdsaP256Signature(
            r=b"\x02" * 32, s=b"\x03" * 32
        ),
    )
    spdu = Ieee1609Dot2Data(content_type="signedData", signed_data=sd)

    return IngressPacket(
        source_stack=StackType.DSRC,
        ingress_timestamp_ms=1000000,
        raw_spdu_bytes=spdu.to_bytes(),
        source_mac_or_l2_id=b"\x00\x11\x22\x33\x44\x55",
        sequence_or_msg_id=1,
        metadata={},
    )


class TestGatewayValidator:
    """Tests for gateway structural and semantic validation."""

    def test_valid_packet_passes(self, valid_ingress_packet):
        validator = GatewayValidator(expected_psid=PSID.BSM)
        spdu, bsm = validator.validate_ingress_spdu(valid_ingress_packet)

        assert spdu.protocol_version == 3
        assert bsm.msg_cnt == 10
        assert bsm.vehicle_id == b"\x11\x22\x33\x44"

    def test_unsecured_data_rejected(self, valid_ingress_packet):
        """Unsecured / unauthenticated packets must be rejected by the gateway."""
        unsecured_spdu = Ieee1609Dot2Data(
            content_type="unsecuredData",
            unsecured_data=b"Unsecured safety text",
        )
        packet = IngressPacket(
            source_stack=StackType.DSRC,
            ingress_timestamp_ms=1000,
            raw_spdu_bytes=unsecured_spdu.to_bytes(),
            source_mac_or_l2_id=b"\x00" * 6,
            sequence_or_msg_id=0,
            metadata={},
        )
        validator = GatewayValidator()
        with pytest.raises(ValidationError) as exc:
            validator.validate_ingress_spdu(packet)
        assert "only forwards signed safety messages" in str(exc.value)

    def test_unexpected_psid_rejected(self, valid_ingress_packet):
        """Messages with non-BSM PSID (e.g. MAP 0x22) must be rejected."""
        validator = GatewayValidator(expected_psid=PSID.MAP)
        with pytest.raises(ValidationError) as exc:
            validator.validate_ingress_spdu(valid_ingress_packet)
        assert "Unexpected PSID" in str(exc.value)

    def test_corrupted_bsm_payload_rejected(self):
        """SPDU with invalid UPER bytes inside ToBeSignedData must be rejected."""
        hdr = HeaderInfo(psid=PSID.BSM, generation_time=1000000)
        tbs = ToBeSignedData(payload=b"\xde\xad\xbe\xef" * 5, header_info=hdr)
        sd = SignedData(
            tbs_data=tbs,
            signer=SignerIdentifier.from_digest(b"\x01" * 8),
            signature=pytest.importorskip("common.ieee1609_2.spdu").EcdsaP256Signature(
                r=b"\x01" * 32, s=b"\x02" * 32
            ),
        )
        spdu = Ieee1609Dot2Data(content_type="signedData", signed_data=sd)
        packet = IngressPacket(
            source_stack=StackType.DSRC,
            ingress_timestamp_ms=1000,
            raw_spdu_bytes=spdu.to_bytes(),
            source_mac_or_l2_id=b"\x00" * 6,
            sequence_or_msg_id=0,
            metadata={},
        )

        validator = GatewayValidator(expected_psid=PSID.BSM)
        with pytest.raises(ValidationError) as exc:
            validator.validate_ingress_spdu(packet)
        assert "failed ASN.1 UPER decoding" in str(exc.value)

