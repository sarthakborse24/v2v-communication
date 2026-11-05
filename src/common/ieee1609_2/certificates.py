"""
V2X Gateway Simulator — IEEE 1609.2 Certificate Data Model & Store
===================================================================
Standards References:
  - IEEE 1609.2-2016: Section 6 (Certificates)
  - IEEE 1609.2-2016: Section 6.4 (Explicit vs Implicit certificates)
  - IEEE 1609.3 Annex: PSID permissions

DEVIATIONS:
  - L3: Locally generated keys, not enrolled through USDOT SCMS.
  - L5: Explicit certificates implemented; ECQV implicit certificates stubbed.
  - L7: CRL / revocation checking is stubbed; always returns NOT_REVOKED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import struct
import time
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ec

from common.exceptions import (
    CertificateChainError,
    CertificateNotFoundError,
    PSIDPermissionError,
    SecurityError,
    ValidationError,
)
from common.ieee1609_2.crypto import (
    compute_hashed_id8,
    public_key_from_uncompressed_bytes,
    public_key_to_uncompressed_bytes,
    sha256_digest,
    sign_ecdsa_p256,
    verify_ecdsa_p256,
)
from common.ieee1609_2.spdu import EcdsaP256Signature
from common.message_types import (
    IEEE1609_2_PROTOCOL_VERSION,
    PSID,
)
from monitoring.logger import get_logger

log = get_logger("security.certificates")


# ---------------------------------------------------------------------------
# Certificate Enumerations
# ---------------------------------------------------------------------------

class CertificateType(IntEnum):
    """IEEE 1609.2 Certificate Types (§6.4)."""
    EXPLICIT = 0
    IMPLICIT = 1  # ECQV (stubbed per L5)


class IssuerChoice(IntEnum):
    """IEEE 1609.2 Issuer Identifier (§6.3.26)."""
    SELF_SIGNED = 0
    SHA256_DIGEST = 1  # 8-byte HashedId8 of issuer cert


# ---------------------------------------------------------------------------
# Validity Period (IEEE 1609.2 §6.3.17)
# ---------------------------------------------------------------------------

@dataclass
class ValidityPeriod:
    """Validity time window in milliseconds."""
    start_time_ms: int
    duration_seconds: int

    @property
    def end_time_ms(self) -> int:
        return self.start_time_ms + (self.duration_seconds * 1000)

    def is_valid_at(self, current_time_ms: int) -> bool:
        return self.start_time_ms <= current_time_ms <= self.end_time_ms

    def serialize(self) -> bytes:
        return struct.pack("!QI", self.start_time_ms, self.duration_seconds)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[ValidityPeriod, bytes]:
        if len(data) < 12:
            raise ValidationError("ValidityPeriod truncated")
        start, dur = struct.unpack("!QI", data[:12])
        return cls(start_time_ms=start, duration_seconds=dur), data[12:]


# ---------------------------------------------------------------------------
# ToBeSignedCertificate (IEEE 1609.2 §6.4.3)
# ---------------------------------------------------------------------------

@dataclass
class ToBeSignedCertificate:
    """Canonical certificate contents signed by the issuer CA.

    Fields:
      - cert_id: Human/diagnostic identifier (e.g. 'RootCA', 'Pseudonym-V1-0')
      - craca_id: 3-byte CRACA identifier
      - crl_series: CRL series integer
      - validity_period: Time window
      - app_permissions: List of PSIDs authorized (e.g. [0x20] for BSM)
      - public_key_bytes: 65 bytes uncompressed P-256 public key (0x04 || X || Y)
    """
    cert_id: str
    craca_id: bytes = b"\x00\x00\x01"
    crl_series: int = 1
    validity_period: ValidityPeriod = field(
        default_factory=lambda: ValidityPeriod(
            start_time_ms=int(time.time() * 1000) - 3600_000,
            duration_seconds=86400 * 365,  # 1 year default
        )
    )
    app_permissions: List[int] = field(default_factory=lambda: [PSID.BSM])
    public_key_bytes: bytes = b""

    def serialize(self) -> bytes:
        """Deterministic binary serialization for signing."""
        id_bytes = self.cert_id.encode("utf-8")
        buf = bytearray()
        buf.extend(b"TBSC")
        buf.extend(struct.pack("!H", len(id_bytes)))
        buf.extend(id_bytes)
        buf.extend(self.craca_id[:3].ljust(3, b"\x00"))
        buf.extend(struct.pack("!I", self.crl_series))
        buf.extend(self.validity_period.serialize())

        # Permissions: 2 bytes count + 4 bytes per PSID
        buf.extend(struct.pack("!H", len(self.app_permissions)))
        for psid in self.app_permissions:
            buf.extend(struct.pack("!I", psid))

        # Public key: 2 bytes length + key bytes
        buf.extend(struct.pack("!H", len(self.public_key_bytes)))
        buf.extend(self.public_key_bytes)
        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[ToBeSignedCertificate, bytes]:
        if len(data) < 25:
            raise ValidationError("ToBeSignedCertificate truncated")
        if data[:4] != b"TBSC":
            raise ValidationError(f"Invalid TBSC magic: {data[:4]}")
        ptr = 4

        id_len = struct.unpack("!H", data[ptr : ptr + 2])[0]
        ptr += 2
        cert_id = data[ptr : ptr + id_len].decode("utf-8", errors="replace")
        ptr += id_len

        craca_id = data[ptr : ptr + 3]
        ptr += 3

        crl_series = struct.unpack("!I", data[ptr : ptr + 4])[0]
        ptr += 4

        val_period, rem = ValidityPeriod.deserialize(data[ptr:])
        ptr = len(data) - len(rem)

        num_perms = struct.unpack("!H", data[ptr : ptr + 2])[0]
        ptr += 2
        perms = []
        for _ in range(num_perms):
            perms.append(struct.unpack("!I", data[ptr : ptr + 4])[0])
            ptr += 4

        pk_len = struct.unpack("!H", data[ptr : ptr + 2])[0]
        ptr += 2
        pk_bytes = data[ptr : ptr + pk_len]
        ptr += pk_len

        return cls(
            cert_id=cert_id,
            craca_id=craca_id,
            crl_series=crl_series,
            validity_period=val_period,
            app_permissions=perms,
            public_key_bytes=pk_bytes,
        ), data[ptr:]


# ---------------------------------------------------------------------------
# Certificate (IEEE 1609.2 §6.4.1)
# ---------------------------------------------------------------------------

@dataclass
class Certificate:
    """IEEE 1609.2 Certificate structure."""
    version: int = IEEE1609_2_PROTOCOL_VERSION
    cert_type: CertificateType = CertificateType.EXPLICIT
    issuer_choice: IssuerChoice = IssuerChoice.SELF_SIGNED
    issuer_digest: Optional[bytes] = None  # 8 bytes HashedId8 if SHA256_DIGEST
    to_be_signed: ToBeSignedCertificate = field(default_factory=ToBeSignedCertificate)
    signature: Optional[EcdsaP256Signature] = None

    def serialize(self) -> bytes:
        """Serialize complete Certificate (TBS + signature) into bytes."""
        buf = bytearray()
        buf.extend(b"CERT")
        buf.append(self.version)
        buf.append(int(self.cert_type))
        buf.append(int(self.issuer_choice))

        if self.issuer_choice == IssuerChoice.SHA256_DIGEST:
            if not self.issuer_digest or len(self.issuer_digest) != 8:
                raise ValidationError("Certificate missing 8-byte issuer digest")
            buf.extend(self.issuer_digest)

        tbsc_bytes = self.to_be_signed.serialize()
        buf.extend(struct.pack("!I", len(tbsc_bytes)))
        buf.extend(tbsc_bytes)

        if self.signature is not None:
            buf.append(0x01)
            buf.extend(self.signature.to_bytes())
        else:
            buf.append(0x00)

        return bytes(buf)

    @classmethod
    def deserialize(cls, data: bytes) -> Certificate:
        if len(data) < 8 or data[:4] != b"CERT":
            raise ValidationError("Invalid Certificate magic or truncated")
        ptr = 4
        version = data[ptr]
        cert_type = CertificateType(data[ptr + 1])
        issuer_choice = IssuerChoice(data[ptr + 2])
        ptr += 3

        issuer_digest = None
        if issuer_choice == IssuerChoice.SHA256_DIGEST:
            if len(data) < ptr + 8:
                raise ValidationError("Truncated certificate: missing issuer digest")
            issuer_digest = data[ptr : ptr + 8]
            ptr += 8

        tbsc_len = struct.unpack("!I", data[ptr : ptr + 4])[0]
        ptr += 4
        tbsc, _ = ToBeSignedCertificate.deserialize(data[ptr : ptr + tbsc_len])
        ptr += tbsc_len

        sig = None
        has_sig = data[ptr]
        ptr += 1
        if has_sig == 0x01:
            sig = EcdsaP256Signature.from_bytes(data[ptr : ptr + 64])

        return cls(
            version=version,
            cert_type=cert_type,
            issuer_choice=issuer_choice,
            issuer_digest=issuer_digest,
            to_be_signed=tbsc,
            signature=sig,
        )

    def compute_digest8(self) -> bytes:
        """Compute IEEE 1609.2 HashedId8 of this certificate."""
        return compute_hashed_id8(self.serialize())

    @property
    def public_key(self) -> ec.EllipticCurvePublicKey:
        """Return the deserialized PyCA public key."""
        return public_key_from_uncompressed_bytes(self.to_be_signed.public_key_bytes)

    def is_valid_at(self, time_ms: int) -> bool:
        return self.to_be_signed.validity_period.is_valid_at(time_ms)

    def has_psid(self, psid: int) -> bool:
        return psid in self.to_be_signed.app_permissions


# ---------------------------------------------------------------------------
# Certificate Store & Trust Validator
# ---------------------------------------------------------------------------

class CertificateStore:
    """Manages trusted root anchors, intermediate CAs, and entity certificates."""

    def __init__(self):
        # Maps digest8 -> Certificate
        self.root_cas: Dict[bytes, Certificate] = {}
        self.intermediate_cas: Dict[bytes, Certificate] = {}
        self.entity_certs: Dict[bytes, Certificate] = {}
        # Maps digest8 -> ec.EllipticCurvePrivateKey (for local signing)
        self.private_keys: Dict[bytes, ec.EllipticCurvePrivateKey] = {}

    def add_root_ca(self, cert: Certificate, private_key: Optional[ec.EllipticCurvePrivateKey] = None) -> bytes:
        """Add a trusted Root CA anchor."""
        digest = cert.compute_digest8()
        self.root_cas[digest] = cert
        if private_key:
            self.private_keys[digest] = private_key
        return digest

    def add_intermediate_ca(
        self, cert: Certificate, private_key: Optional[ec.EllipticCurvePrivateKey] = None
    ) -> bytes:
        """Add an Intermediate CA (e.g. ECA, PCA)."""
        digest = cert.compute_digest8()
        self.intermediate_cas[digest] = cert
        if private_key:
            self.private_keys[digest] = private_key
        return digest

    def add_entity_cert(
        self, cert: Certificate, private_key: Optional[ec.EllipticCurvePrivateKey] = None
    ) -> bytes:
        """Add an End-Entity certificate (pseudonym cert or gateway cert)."""
        digest = cert.compute_digest8()
        self.entity_certs[digest] = cert
        if private_key:
            self.private_keys[digest] = private_key
        return digest

    def get_certificate(self, digest8: bytes) -> Optional[Certificate]:
        """Look up certificate across entity, intermediate, and root collections."""
        return (
            self.entity_certs.get(digest8)
            or self.intermediate_cas.get(digest8)
            or self.root_cas.get(digest8)
        )

    def get_private_key(self, digest8: bytes) -> Optional[ec.EllipticCurvePrivateKey]:
        """Get private key matching certificate digest."""
        return self.private_keys.get(digest8)

    def check_revocation(self, cert: Certificate) -> str:
        """Check certificate revocation status.

        DEVIATION L7: CRL checking is STUBBED. Always returns NOT_REVOKED.
        """
        # In a production system this would consult CRLs or an SCMS OCSP endpoint
        return "NOT_REVOKED"

    def validate_chain(
        self,
        cert: Certificate,
        current_time_ms: Optional[int] = None,
        expected_psid: Optional[int] = None,
    ) -> bool:
        """Validate certificate cryptographic chain up to a trusted root CA.

        Checks:
          1. Time validity (validityPeriod) against current_time_ms
          2. PSID permission (if expected_psid provided)
          3. CRL revocation check (stubbed per L7)
          4. Issuer signature on ToBeSignedCertificate
          5. Recursive chain validation up to an authorized Root CA

        Raises:
            CertificateChainError: If validation fails.
            PSIDPermissionError: If expected_psid is not authorized.
        """
        now = current_time_ms if current_time_ms is not None else int(time.time() * 1000)

        # 1. Validity period check
        if not cert.is_valid_at(now):
            raise CertificateChainError(
                f"Certificate '{cert.to_be_signed.cert_id}' expired or not yet valid at time {now}"
            )

        # 2. PSID permission check (if requested)
        if expected_psid is not None and not cert.has_psid(expected_psid):
            raise PSIDPermissionError(
                f"Certificate '{cert.to_be_signed.cert_id}' lacks permission for PSID 0x{expected_psid:04X}. "
                f"Authorized PSIDs: {[f'0x{p:04X}' for p in cert.to_be_signed.app_permissions]}"
            )

        # 3. Revocation status
        rev_status = self.check_revocation(cert)
        if rev_status != "NOT_REVOKED":
            raise CertificateChainError(f"Certificate '{cert.to_be_signed.cert_id}' has been revoked")

        # 4. Check if root CA
        if cert.issuer_choice == IssuerChoice.SELF_SIGNED:
            digest = cert.compute_digest8()
            if digest not in self.root_cas:
                raise CertificateChainError(
                    f"Self-signed root CA '{cert.to_be_signed.cert_id}' is not in trusted root store"
                )
            # Verify self-signature
            if cert.signature is None:
                raise CertificateChainError("Root certificate missing self-signature")
            tbs_bytes = cert.to_be_signed.serialize()
            try:
                verify_ecdsa_p256(
                    cert.public_key,
                    tbs_bytes,
                    cert.signature.r,
                    cert.signature.s,
                )
            except Exception as exc:
                raise CertificateChainError(f"Root certificate self-signature invalid: {exc}") from exc
            return True

        # 5. Subordinate certificate: lookup issuer
        if cert.issuer_digest is None:
            raise CertificateChainError("Subordinate certificate missing issuer digest")

        issuer_cert = self.get_certificate(cert.issuer_digest)
        if issuer_cert is None:
            raise CertificateNotFoundError(
                f"Issuer certificate (digest {cert.issuer_digest.hex()}) not found in store"
            )

        # Verify signature on subordinate certificate using issuer's public key
        if cert.signature is None:
            raise CertificateChainError(f"Certificate '{cert.to_be_signed.cert_id}' missing signature")

        tbs_bytes = cert.to_be_signed.serialize()
        try:
            verify_ecdsa_p256(
                issuer_cert.public_key,
                tbs_bytes,
                cert.signature.r,
                cert.signature.s,
            )
        except Exception as exc:
            raise CertificateChainError(
                f"Issuer signature invalid on certificate '{cert.to_be_signed.cert_id}': {exc}"
            ) from exc

        # Recurse up the chain to verify issuer
        return self.validate_chain(issuer_cert, current_time_ms=now, expected_psid=None)

