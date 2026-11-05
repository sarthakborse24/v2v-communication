"""
V2X Gateway Simulator — IEEE 1609.2 High-Level Security Engine
===============================================================
Coordinates:
  - SPDU signing with ECDSA-P256
  - SPDU verification against CertificateStore trust chains
  - Replay protection via generationTime window
  - PSID authorization validation
  - Unicast payload encryption via AES-128-CCM (where applicable)

Standards References:
  - IEEE 1609.2-2016: Section 7 (Security processing)
  - IEEE 1609.2-2016: Section 7.4.2 (Replay protection)
"""

from __future__ import annotations

import time
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from common.exceptions import (
    CertificateNotFoundError,
    ReplayDetectedError,
    SecurityError,
    SignatureVerificationError,
    ValidationError,
)
from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
)
from common.ieee1609_2.crypto import (
    sign_ecdsa_p256,
    verify_ecdsa_p256,
)
from common.ieee1609_2.spdu import (
    EcdsaP256Signature,
    HeaderInfo,
    Ieee1609Dot2Data,
    SignedData,
    SignerIdentifier,
    ToBeSignedData,
)
from common.message_types import (
    HashAlgorithm,
    IEEE1609_2_PROTOCOL_VERSION,
    PSID,
    REPLAY_WINDOW_MS,
)
from monitoring.logger import get_logger

log = get_logger("security.engine")


def sign_message(
    payload: bytes,
    signer_cert: Certificate,
    private_key: ec.EllipticCurvePrivateKey,
    psid: int = PSID.BSM,
    generation_time_ms: Optional[int] = None,
    expiry_time_ms: Optional[int] = None,
    include_full_cert: bool = False,
) -> Ieee1609Dot2Data:
    """Construct an IEEE 1609.2 SignedData SPDU over the payload.

    Args:
        payload: Application message bytes (e.g. UPER-encoded BSM).
        signer_cert: The sender's pseudonym or entity certificate.
        private_key: Signer's P-256 private key.
        psid: Provider Service Identifier (default: 0x20 for BSM).
        generation_time_ms: Explicit timestamp in ms (defaults to current time).
        expiry_time_ms: Optional expiration timestamp in ms.
        include_full_cert: If True, include serialized cert in SPDU; if False, include 8-byte digest.

    Returns:
        Ieee1609Dot2Data containing SignedData.
    """
    now_ms = generation_time_ms if generation_time_ms is not None else int(time.time() * 1000)

    header_info = HeaderInfo(
        psid=psid,
        generation_time=now_ms,
        expiry_time=expiry_time_ms,
    )
    tbs_data = ToBeSignedData(payload=payload, header_info=header_info)
    tbs_bytes = tbs_data.serialize()

    # ECDSA-P256 sign over serialized ToBeSignedData
    r, s = sign_ecdsa_p256(private_key, tbs_bytes)
    signature = EcdsaP256Signature(r=r, s=s)

    # Signer identification
    if include_full_cert:
        signer = SignerIdentifier.from_cert_bytes(signer_cert.serialize())
    else:
        signer = SignerIdentifier.from_digest(signer_cert.compute_digest8())

    signed_data = SignedData(
        hash_id=HashAlgorithm.SHA256,
        tbs_data=tbs_data,
        signer=signer,
        signature=signature,
    )

    return Ieee1609Dot2Data(
        protocol_version=IEEE1609_2_PROTOCOL_VERSION,
        content_type="signedData",
        signed_data=signed_data,
    )


def verify_message(
    spdu: Ieee1609Dot2Data,
    cert_store: CertificateStore,
    current_time_ms: Optional[int] = None,
    replay_window_ms: int = REPLAY_WINDOW_MS,
    expected_psid: Optional[int] = PSID.BSM,
) -> Tuple[bytes, HeaderInfo, Certificate]:
    """Verify an incoming IEEE 1609.2 SignedData SPDU.

    Steps:
      1. Structural validation of SPDU
      2. Replay protection check against current_time_ms
      3. Resolution of signer certificate (from SPDU or cert_store)
      4. Certificate trust chain validation (up to root CA)
      5. PSID authorization verification
      6. Cryptographic signature check

    Returns:
        Tuple of (payload_bytes, HeaderInfo, signer_cert).

    Raises:
        ReplayDetectedError: If generationTime is outside allowable window.
        CertificateNotFoundError: If signer cert is not in store.
        CertificateChainError: If certificate chain validation fails.
        PSIDPermissionError: If signer cert lacks permission for message PSID.
        SignatureVerificationError: If cryptographic signature is invalid.
    """
    if spdu.content_type != "signedData" or spdu.signed_data is None:
        raise ValidationError(f"Expected signedData SPDU, got {spdu.content_type}")

    sd = spdu.signed_data
    hdr = sd.tbs_data.header_info
    now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)

    # 1. Replay Protection (IEEE 1609.2 §7.4.2)
    time_delta = abs(now_ms - hdr.generation_time)
    if time_delta > replay_window_ms:
        raise ReplayDetectedError(
            f"Message replay detected: generationTime={hdr.generation_time}, now={now_ms}, "
            f"delta={time_delta}ms exceeds replay window {replay_window_ms}ms"
        )

    # Check expiry if present
    if hdr.expiry_time is not None and now_ms > hdr.expiry_time:
        raise ReplayDetectedError(
            f"Message expired: expiryTime={hdr.expiry_time}, now={now_ms}"
        )

    # 2. Resolve Signer Certificate
    signer_cert: Optional[Certificate] = None
    if sd.signer.choice == "certificate":
        if sd.signer.certificate_bytes is None:
            raise ValidationError("SignerIdentifier specified 'certificate' but provided no bytes")
        signer_cert = Certificate.deserialize(sd.signer.certificate_bytes)
    elif sd.signer.choice == "digest":
        if sd.signer.digest is None:
            raise ValidationError("SignerIdentifier specified 'digest' but provided no bytes")
        signer_cert = cert_store.get_certificate(sd.signer.digest)
        if signer_cert is None:
            raise CertificateNotFoundError(
                f"Signer certificate with digest {sd.signer.digest.hex()} not found in store"
            )
    elif sd.signer.choice == "self":
        raise ValidationError("Self-signed SPDU not permitted for broadcast safety messages")
    else:
        raise ValidationError(f"Unknown signer choice: {sd.signer.choice}")

    # 3. Validate Certificate Trust Chain & PSID permissions
    cert_store.validate_chain(
        signer_cert,
        current_time_ms=now_ms,
        expected_psid=expected_psid,
    )

    # 4. Verify Cryptographic Signature
    if sd.signature is None:
        raise SignatureVerificationError("SignedData missing cryptographic signature")

    tbs_bytes = sd.tbs_data.serialize()
    verify_ecdsa_p256(
        signer_cert.public_key,
        tbs_bytes,
        sd.signature.r,
        sd.signature.s,
    )

    return sd.tbs_data.payload, hdr, signer_cert

