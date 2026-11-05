"""
Unit Tests for Gateway Bidirectional Message Translator
========================================================
Standards References:
  - IEEE 1609.3 / IEEE 802.11p (DSRC)
  - 3GPP TS 36.212 / TS 36.321 (C-V2X)
"""

import pytest

from common.ieee1609_2.spdu import (
    EcdsaP256Signature,
    HeaderInfo,
    Ieee1609Dot2Data,
    SignedData,
    SignerIdentifier,
    ToBeSignedData,
)
from common.message_types import (
    EDCACategory,
    ETHERTYPE_WSMP,
    PSID,
    StackType,
    V2XPriority,
)
from gateway.receiver import IngressPacket
from gateway.translator import GatewayTranslator


@pytest.fixture
def translator() -> GatewayTranslator:
    return GatewayTranslator(
        gateway_mac_address=b"\x00\xaa\xbb\xcc\xdd\x01",
        gateway_l2_id=b"\xaa\xbb\x01",
        default_cv2x_mcs=10,
    )


@pytest.fixture
def sample_re_signed_spdu() -> Ieee1609Dot2Data:
    payload = b"Preserved-Raw-BSM-Bytes-12345"
    hdr = HeaderInfo(psid=PSID.BSM, generation_time=12345678)
    tbs = ToBeSignedData(payload=payload, header_info=hdr)
    sig = EcdsaP256Signature(r=b"\x01" * 32, s=b"\x02" * 32)
    sd = SignedData(
        tbs_data=tbs,
        signer=SignerIdentifier.from_digest(b"\x99" * 8),
        signature=sig,
    )
    return Ieee1609Dot2Data(content_type="signedData", signed_data=sd)


class TestGatewayTranslator:
    """Tests for protocol envelope translation."""

    def test_dsrc_to_cv2x_translation(self, translator, sample_re_signed_spdu):
        inbound_packet = IngressPacket(
            source_stack=StackType.DSRC,
            ingress_timestamp_ms=1000,
            raw_spdu_bytes=sample_re_signed_spdu.to_bytes(),
            source_mac_or_l2_id=b"\x00\x11\x22\x33\x44\x55",
            sequence_or_msg_id=5,
            metadata={"edca_category": EDCACategory.AC_VO},
        )

        sci, tb = translator.translate_dsrc_to_cv2x(
            inbound_packet=inbound_packet,
            re_signed_spdu=sample_re_signed_spdu,
            allocated_subchannel=2,
        )

        assert sci.priority == int(V2XPriority.SAFETY_HIGH)
        assert sci.freq_resource_location == 2
        assert sci.mcs == 10
        assert tb.source_l2_id == b"\xaa\xbb\x01"
        assert tb.payload == sample_re_signed_spdu.to_bytes()

    def test_cv2x_to_dsrc_translation(self, translator, sample_re_signed_spdu):
        inbound_packet = IngressPacket(
            source_stack=StackType.CV2X,
            ingress_timestamp_ms=1000,
            raw_spdu_bytes=sample_re_signed_spdu.to_bytes(),
            source_mac_or_l2_id=b"\x01\x02\x03",
            sequence_or_msg_id=0,
            metadata={"priority": 1},
        )

        wave_frame, wsm = translator.translate_cv2x_to_dsrc(
            inbound_packet=inbound_packet,
            re_signed_spdu=sample_re_signed_spdu,
        )

        assert wave_frame.source_mac == b"\x00\xaa\xbb\xcc\xdd\x01"
        assert wave_frame.ethertype == ETHERTYPE_WSMP
        assert wave_frame.edca_category == EDCACategory.AC_VO
        assert wsm.psid == PSID.BSM
        assert wsm.payload == sample_re_signed_spdu.to_bytes()
