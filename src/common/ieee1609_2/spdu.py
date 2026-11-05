"""
V2X Gateway Simulator — IEEE 1609.2 SPDU Data Structures
=========================================================
Standards References:
  - IEEE 1609.2-2016: Section 6 & 7 (Secured Protocol Data Unit - SPDU)
  - IEEE 1609.3: PSID 0x20 for BSM

Defines:
  - Ieee1609Dot2Data
  - SignedData
  - ToBeSignedData
  - HeaderInfo
  - SignerIdentifier
  - EcdsaP256Signature
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct
import time
from typing import Any, Dict, Optional, Tuple, Union

from common.exceptions import (
    SecurityError,
    ValidationError,
)
from common.ieee1609_2.crypto import (
    compute_hashed_id8,
    sha256_digest,
)
from common.message_types import (
    HashAlgorithm,
    IEEE1609_2_PROTOCOL_VERSION,
    PSID,
)


# ---------------------------------------------------------------------------
# Signer Identifier (IEEE 1609.2 §6.3.24)
# ---------------------------------------------------------------------------

@dataclass
class SignerIdentifier:
    """Signer identification choice.

    Choices:
      - 'digest': 8-byte HashedId8 of the certificate
      - 'certificate': Full Certificate object / bytes
      - 'self': Self-signed
    """
    choice: str  # 'digest' | 'certificate' | 'self'
    digest: Optional[bytes] = None  # Exactly 8 bytes if choice == 'digest'
    certificate_bytes: Optional[bytes] = None  # Serialized cert if choice == 'certificate'

    def __post_init__(self):
        if self.choice == "digest":
            if not self.digest or len(self.digest) != 8:
                raise ValidationError("SignerIdentifier 'digest' must provide exactly 8 bytes (HashedId8)")
        elif self.choice == "certificate":
            if not self.certificate_bytes:
                raise ValidationError("SignerIdentifier 'certificate' must provide certificate_bytes")
        elif self.choice == "self":
            pass
        else:
            raise ValidationError(f"Invalid SignerIdentifier choice: {self.choice}")

    @classmethod
    def from_digest(cls, digest8: bytes) -> SignerIdentifier:
        return cls(choice="digest", digest=digest8)

    @classmethod
    def from_cert_bytes(cls, cert_bytes: bytes) -> SignerIdentifier:
        return cls(choice="certificate", certificate_bytes=cert_bytes)

    @classmethod
    def self_signed(cls) -> SignerIdentifier:
        return cls(choice="self")


# ---------------------------------------------------------------------------
# ECDSA P-256 Signature (IEEE 1609.2 §6.3.29)
# ---------------------------------------------------------------------------

@dataclass
class EcdsaP256Signature:
    """Raw IEEE 1609.2 ECDSA P-256 signature components (r, s).

    Both r and s are 32 bytes each (fixed 64 bytes total).
    """
    r: bytes
    s: bytes

    def __post_init__(self):
        if len(self.r) != 32 or len(self.s) != 32:
            raise ValidationError(
                f"EcdsaP256Signature requires 32-byte r and s components, got len(r)={len(self.r)}, len(s)={len(self.s)}"
            )

    def to_bytes(self) -> bytes:
        return self.r + self.s

    @classmethod
    def from_bytes(cls, data: bytes) -> EcdsaP256Signature:
        if len(data) != 64:
            raise ValidationError(f"EcdsaP256Signature binary must be 64 bytes, got {len(data)}")
        return cls(r=data[:32], s=data[32:])


# ---------------------------------------------------------------------------
# Header Info (IEEE 1609.2 §6.3.9)
# ---------------------------------------------------------------------------

@dataclass
class HeaderInfo:
    """Security header accompanying signed data.

    Fields:
      - psid: Provider Service Identifier (e.g. 0x20 for BSM)
      - generation_time: Milliseconds timestamp (standard TAI or Unix epoch ms)
      - expiry_time: Optional millisecond expiration deadline
    """
    psid: int = PSID.BSM
    generation_time: int = field(default_factory=lambda: int(time.time() * 1000))
    expiry_time: Optional[int] = None

    def serialize(self) -> bytes:
        """Serialize HeaderInfo deterministically."""
        exp = self.expiry_time if self.expiry_time is not None else 0
        return struct.pack("!IQ Q", self.psid, self.generation_time, exp)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[HeaderInfo, bytes]:
        """Parse HeaderInfo from data, returning (header_info, remaining_bytes)."""
        if len(data) < 20:
            raise ValidationError(f"HeaderInfo requires at least 20 bytes, got {len(data)}")
        psid, gen_time, exp = struct.unpack("!IQ Q", data[:20])
        expiry = exp if exp != 0 else None
        return cls(psid=psid, generation_time=gen_time, expiry_time=expiry), data[20:]


# ---------------------------------------------------------------------------
# ToBeSignedData (IEEE 1609.2 §6.3.6)
# ---------------------------------------------------------------------------

@dataclass
class ToBeSignedData:
    """Canonical data over which the cryptographic signature is computed.

    Contains:
      - payload: Raw application bytes (e.g. UPER-encoded BSM)
      - header_info: Security metadata (PSID, timestamps)
    """
    payload: bytes
    header_info: HeaderInfo = field(default_factory=HeaderInfo)

    def serialize(self) -> bytes:
        """Deterministic serialization of ToBeSignedData for ECDSA hashing.

        Format:
          [4 bytes: magic 'TBS1']
          [HeaderInfo: 20 bytes]
          [4 bytes: payload length]
          [N bytes: payload]
        """
        hdr_bytes = self.header_info.serialize()
        return b"TBS1" + hdr_bytes + struct.pack("!I", len(self.payload)) + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple[ToBeSignedData, bytes]:
        if len(data) < 28:
            raise ValidationError(f"ToBeSignedData too short: {len(data)} bytes")
        magic = data[:4]
        if magic != b"TBS1":
            raise ValidationError(f"Invalid ToBeSignedData magic: {magic}")
        hdr, rem = HeaderInfo.deserialize(data[4:])
        if len(rem) < 4:
            raise ValidationError("ToBeSignedData truncated payload length")
        payload_len = struct.unpack("!I", rem[:4])[0]
        rem = rem[4:]
        if len(rem) < payload_len:
            raise ValidationError(
                f"ToBeSignedData truncated payload: expected {payload_len}, got {len(rem)}"
            )
        payload = rem[:payload_len]
        return cls(payload=payload, header_info=hdr), rem[payload_len:]


# ---------------------------------------------------------------------------
# SignedData (IEEE 1609.2 §6.3.4)
# ---------------------------------------------------------------------------

@dataclass
class SignedData:
    """IEEE 1609.2 SignedData container."""
    hash_id: HashAlgorithm = HashAlgorithm.SHA256
    tbs_data: ToBeSignedData = field(default_factory=lambda: ToBeSignedData(payload=b""))
    signer: SignerIdentifier = field(default_factory=SignerIdentifier.self_signed)
    signature: Optional[EcdsaP256Signature] = None


# ---------------------------------------------------------------------------
# Top-Level Ieee1609Dot2Data Container (IEEE 1609.2 §6.3.1)
# ---------------------------------------------------------------------------

@dataclass
class Ieee1609Dot2Data:
    """Top-level SPDU container for V2X safety and control messages.

    DEVIATION L5: Explicit certificates used; implicit ECQV stubbed.
    BSMs are broadcast as SignedData; broadcast safety messages are NOT encrypted.
    """
    protocol_version: int = IEEE1609_2_PROTOCOL_VERSION
    content_type: str = "signedData"  # 'signedData' | 'unsecuredData'
    signed_data: Optional[SignedData] = None
    unsecured_data: Optional[bytes] = None

    def to_bytes(self) -> bytes:
        """Serialize SPDU to compact binary envelope."""
        buf = bytearray()
        buf.append(self.protocol_version)

        if self.content_type == "signedData":
            buf.append(0x01)  # ContentType: signedData
            sd = self.signed_data
            if sd is None or sd.signature is None:
                raise ValidationError("Cannot serialize SignedData without signature")

            # Hash ID
            buf.append(int(sd.hash_id))

            # Signer choice
            if sd.signer.choice == "digest":
                buf.append(0x01)
                buf.extend(sd.signer.digest)
            elif sd.signer.choice == "certificate":
                buf.append(0x02)
                cb = sd.signer.certificate_bytes or b""
                buf.extend(struct.pack("!H", len(cb)))
                buf.extend(cb)
            elif sd.signer.choice == "self":
                buf.append(0x00)
            else:
                raise ValidationError(f"Unknown signer choice: {sd.signer.choice}")

            # 64-byte signature
            buf.extend(sd.signature.to_bytes())

            # TBS data
            tbs_bytes = sd.tbs_data.serialize()
            buf.extend(struct.pack("!I", len(tbs_bytes)))
            buf.extend(tbs_bytes)

        elif self.content_type == "unsecuredData":
            buf.append(0x00)  # ContentType: unsecuredData
            data = self.unsecured_data or b""
            buf.extend(struct.pack("!I", len(data)))
            buf.extend(data)
        else:
            raise ValidationError(f"Unsupported content type for serialization: {self.content_type}")

        return bytes(buf)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Ieee1609Dot2Data:
        """Parse SPDU from binary envelope."""
        if len(raw) < 2:
            raise ValidationError(f"SPDU truncated: {len(raw)} bytes")

        version = raw[0]
        if version != IEEE1609_2_PROTOCOL_VERSION:
            raise ValidationError(
                f"Unsupported IEEE 1609.2 version: {version}; expected {IEEE1609_2_PROTOCOL_VERSION}"
            )

        content_tag = raw[1]
        ptr = 2

        if content_tag == 0x01:  # signedData
            if len(raw) < ptr + 1:
                raise ValidationError("Truncated SPDU: missing hash_id")
            hash_id = HashAlgorithm(raw[ptr])
            ptr += 1

            # Signer
            if len(raw) < ptr + 1:
                raise ValidationError("Truncated SPDU: missing signer choice")
            signer_choice_tag = raw[ptr]
            ptr += 1

            if signer_choice_tag == 0x01:  # digest
                if len(raw) < ptr + 8:
                    raise ValidationError("Truncated SPDU: missing 8-byte digest")
                digest = raw[ptr : ptr + 8]
                ptr += 8
                signer = SignerIdentifier.from_digest(digest)
            elif signer_choice_tag == 0x02:  # certificate
                if len(raw) < ptr + 2:
                    raise ValidationError("Truncated SPDU: missing cert length")
                cert_len = struct.unpack("!H", raw[ptr : ptr + 2])[0]
                ptr += 2
                if len(raw) < ptr + cert_len:
                    raise ValidationError("Truncated SPDU: missing cert bytes")
                cert_bytes = raw[ptr : ptr + cert_len]
                ptr += cert_len
                signer = SignerIdentifier.from_cert_bytes(cert_bytes)
            elif signer_choice_tag == 0x00:  # self
                signer = SignerIdentifier.self_signed()
            else:
                raise ValidationError(f"Unknown signer choice tag: {signer_choice_tag}")

            # Signature (64 bytes)
            if len(raw) < ptr + 64:
                raise ValidationError(f"Truncated SPDU: missing 64-byte signature at offset {ptr}")
            sig_bytes = raw[ptr : ptr + 64]
            ptr += 64
            signature = EcdsaP256Signature.from_bytes(sig_bytes)

            # TBS data length and content
            if len(raw) < ptr + 4:
                raise ValidationError("Truncated SPDU: missing TBS data length")
            tbs_len = struct.unpack("!I", raw[ptr : ptr + 4])[0]
            ptr += 4
            if len(raw) < ptr + tbs_len:
                raise ValidationError(
                    f"Truncated SPDU: expected {tbs_len} bytes TBS data, got {len(raw) - ptr}"
                )
            tbs_bytes = raw[ptr : ptr + tbs_len]
            tbs_data, _ = ToBeSignedData.deserialize(tbs_bytes)

            signed_data = SignedData(
                hash_id=hash_id,
                tbs_data=tbs_data,
                signer=signer,
                signature=signature,
            )
            return cls(
                protocol_version=version,
                content_type="signedData",
                signed_data=signed_data,
            )

        elif content_tag == 0x00:  # unsecuredData
            if len(raw) < ptr + 4:
                raise ValidationError("Truncated SPDU: missing unsecured data length")
            data_len = struct.unpack("!I", raw[ptr : ptr + 4])[0]
            ptr += 4
            if len(raw) < ptr + data_len:
                raise ValidationError("Truncated SPDU: missing unsecured payload")
            payload = raw[ptr : ptr + data_len]
            return cls(
                protocol_version=version,
                content_type="unsecuredData",
                unsecured_data=payload,
            )
        else:
            raise ValidationError(f"Unknown SPDU content tag: 0x{content_tag:02X}")

