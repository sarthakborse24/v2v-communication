"""
V2X Gateway Simulator — Gateway Message Validator
==================================================
Performs structural and semantic validation on ingress messages:
  - SPDU container syntax & version check (IEEE 1609.2)
  - PSID verification (BSM 0x20)
  - ASN.1 UPER constraint & boundary check (SAE J2735)

Standards References:
  - IEEE 1609.2-2016: Section 6
  - SAE J2735-2020: BasicSafetyMessage Part I
"""

from __future__ import annotations

from typing import Optional, Tuple

from common.bsm_codec import (
    BasicSafetyMessage,
    decode_bsm_uper,
)
from common.exceptions import (
    BSMDecodeError,
    ConstraintViolationError,
    ValidationError,
)
from common.ieee1609_2.spdu import Ieee1609Dot2Data
from common.message_types import (
    IEEE1609_2_PROTOCOL_VERSION,
    PSID,
)
from gateway.receiver import IngressPacket
from monitoring.logger import get_logger

log = get_logger("gateway.validator")


class GatewayValidator:
    """Validates ingress messages prior to security processing and translation."""

    def __init__(self, expected_psid: int = PSID.BSM):
        self.expected_psid = expected_psid

    def validate_ingress_spdu(
        self,
        packet: IngressPacket,
    ) -> Tuple[Ieee1609Dot2Data, BasicSafetyMessage]:
        """Validate SPDU envelope structure and verify embedded BSM syntax.

        Returns:
            Tuple of (parsed_spdu, decoded_bsm).

        Raises:
            ValidationError: If any structural or semantic constraint is violated.
        """
        # 1. Structural parse of SPDU
        try:
            spdu = Ieee1609Dot2Data.from_bytes(packet.raw_spdu_bytes)
        except Exception as exc:
            log.warning(f"SPDU parse failed: {exc}")
            raise ValidationError(f"Malformed IEEE 1609.2 SPDU container: {exc}") from exc

        # 2. Version check
        if spdu.protocol_version != IEEE1609_2_PROTOCOL_VERSION:
            raise ValidationError(
                f"Unsupported SPDU protocol version: {spdu.protocol_version}; expected {IEEE1609_2_PROTOCOL_VERSION}"
            )

        # 3. Content type check
        if spdu.content_type != "signedData" or spdu.signed_data is None:
            raise ValidationError(
                f"Gateway only forwards signed safety messages; received {spdu.content_type}"
            )

        # 4. HeaderInfo PSID check
        hdr = spdu.signed_data.tbs_data.header_info
        if hdr.psid != self.expected_psid:
            raise ValidationError(
                f"Unexpected PSID 0x{hdr.psid:04X}; expected 0x{self.expected_psid:04X} (BSM)"
            )

        # 5. Payload presence
        payload = spdu.signed_data.tbs_data.payload
        if not payload:
            raise ValidationError("SignedData payload is empty (0 bytes)")

        # 6. Semantic check: Ensure payload decodes to valid SAE J2735 BSM
        try:
            bsm = decode_bsm_uper(payload)
        except (BSMDecodeError, ConstraintViolationError) as exc:
            log.warning(f"BSM semantic validation failed: {exc}")
            raise ValidationError(f"Embedded BSM failed ASN.1 UPER decoding: {exc}") from exc

        log.debug(
            f"Validated ingress message: vehicle_id={bsm.vehicle_id.hex()} "
            f"msg_cnt={bsm.msg_cnt} lat={bsm.lat} lon={bsm.lon}"
        )
        return spdu, bsm

