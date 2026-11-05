"""
V2X Gateway Simulator — IEEE 1609.2 Cryptographic Primitives
=============================================================
Standards References:
  - IEEE 1609.2-2016: Section 7 (Cryptographic formats and procedures)
  - NIST FIPS 186-4: Digital Signature Standard (ECDSA with Curve P-256)
  - NIST SP 800-38C: Recommendation for Block Cipher Modes of Operation: CCM Mode
  - SEC 1 v2.0: Elliptic Curve Cryptography (Point compression & representation)

Supported Suites:
  - ECDSA-NIST-P256 with SHA-256 (mandatory baseline for US WAVE)
  - AES-128-CCM (authenticated symmetric encryption for EncryptedData)

DEVIATIONS:
  - L3: Locally generated keys, not enrolled through USDOT SCMS.
  - brainpoolP256r1 is omitted due to PyCA platform variance; P-256 is the US standard.
"""

from __future__ import annotations

import hashlib
import os
from typing import Tuple, Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from common.exceptions import (
    EncryptionError,
    SignatureVerificationError,
)
from common.message_types import (
    AES_CCM_KEY_LENGTH,
    AES_CCM_TAG_LENGTH,
)


# ---------------------------------------------------------------------------
# Key Generation & Management
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a NIST P-256 (secp256r1) keypair for IEEE 1609.2 signing."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def public_key_to_uncompressed_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize P-256 public key to ANSI X9.62 uncompressed format (65 bytes: 0x04 || X || Y)."""
    return public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    )


def public_key_from_uncompressed_bytes(data: bytes) -> ec.EllipticCurvePublicKey:
    """Load P-256 public key from ANSI X9.62 point bytes."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def private_key_to_pem(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Export private key to PKCS8 PEM format."""
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def private_key_from_pem(pem_bytes: bytes) -> ec.EllipticCurvePrivateKey:
    """Load private key from PKCS8 PEM format."""
    return load_pem_private_key(pem_bytes, password=None)


# ---------------------------------------------------------------------------
# Hashing & Digest Helpers (IEEE 1609.2 §6.3.3)
# ---------------------------------------------------------------------------

def sha256_digest(data: bytes) -> bytes:
    """Compute 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def compute_hashed_id8(data: bytes) -> bytes:
    """Compute IEEE 1609.2 HashedId8 from canonical encoding.

    Per IEEE 1609.2-2016 §3.2, HashedId8 is defined as the low-order
    (least significant / trailing) 8 octets of the SHA-256 hash.
    """
    full_hash = sha256_digest(data)
    return full_hash[-8:]


# ---------------------------------------------------------------------------
# ECDSA-P256 Signing & Verification (IEEE 1609.2 §7.3.4)
# ---------------------------------------------------------------------------

def sign_ecdsa_p256(
    private_key: ec.EllipticCurvePrivateKey,
    data: bytes,
) -> Tuple[bytes, bytes]:
    """Sign data using ECDSA-NIST-P256 with SHA-256.

    Returns:
        Tuple of (r, s) where each is exactly 32 bytes (big-endian),
        matching the IEEE 1609.2 EcdsaP256Signature format.
    """
    der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r_int, s_int = decode_dss_signature(der_signature)

    r_bytes = r_int.to_bytes(32, byteorder="big")
    s_bytes = s_int.to_bytes(32, byteorder="big")
    return r_bytes, s_bytes


def verify_ecdsa_p256(
    public_key: ec.EllipticCurvePublicKey,
    data: bytes,
    r: bytes,
    s: bytes,
) -> bool:
    """Verify an IEEE 1609.2 ECDSA-NIST-P256 signature.

    Args:
        public_key: Signer's P-256 public key.
        data: Plaintext data that was signed (typically ToBeSignedData bytes).
        r: 32-byte r component.
        s: 32-byte s component.

    Returns:
        True if valid.

    Raises:
        SignatureVerificationError: If the signature is invalid or malformed.
    """
    if len(r) != 32 or len(s) != 32:
        raise SignatureVerificationError(
            f"Invalid signature component lengths: r={len(r)}, s={len(s)}; expected 32 each."
        )

    r_int = int.from_bytes(r, byteorder="big")
    s_int = int.from_bytes(s, byteorder="big")

    try:
        der_signature = encode_dss_signature(r_int, s_int)
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature as exc:
        raise SignatureVerificationError("ECDSA-P256 signature verification failed") from exc
    except Exception as exc:
        raise SignatureVerificationError(f"Signature verification error: {exc}") from exc


# ---------------------------------------------------------------------------
# AES-128-CCM Authenticated Encryption (IEEE 1609.2 §7.3.5)
# ---------------------------------------------------------------------------

def aes_128_ccm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Encrypt using AES-128-CCM with standard 16-byte authentication tag.

    Args:
        key: 16-byte symmetric key.
        nonce: 12-byte nonce (standard 1609.2 nonce length).
        plaintext: Data to encrypt.
        associated_data: Optional authenticated data (unencrypted).

    Returns:
        Ciphertext with appended 16-byte authentication tag.

    Raises:
        EncryptionError: If parameters are invalid.
    """
    if len(key) != AES_CCM_KEY_LENGTH:
        raise EncryptionError(f"AES key must be {AES_CCM_KEY_LENGTH} bytes, got {len(key)}")
    if not (7 <= len(nonce) <= 13):
        raise EncryptionError(f"CCM nonce must be 7-13 bytes, got {len(nonce)}")

    try:
        aesccm = AESCCM(key, tag_length=AES_CCM_TAG_LENGTH)
        return aesccm.encrypt(nonce, plaintext, associated_data)
    except Exception as exc:
        raise EncryptionError(f"AES-CCM encryption failed: {exc}") from exc


def aes_128_ccm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext_and_tag: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """Decrypt using AES-128-CCM with standard 16-byte authentication tag.

    Args:
        key: 16-byte symmetric key.
        nonce: 12-byte nonce.
        ciphertext_and_tag: Ciphertext with appended 16-byte authentication tag.
        associated_data: Optional authenticated data.

    Returns:
        Decrypted plaintext.

    Raises:
        EncryptionError: If authentication tag check fails or parameters invalid.
    """
    if len(key) != AES_CCM_KEY_LENGTH:
        raise EncryptionError(f"AES key must be {AES_CCM_KEY_LENGTH} bytes, got {len(key)}")

    try:
        aesccm = AESCCM(key, tag_length=AES_CCM_TAG_LENGTH)
        return aesccm.decrypt(nonce, ciphertext_and_tag, associated_data)
    except InvalidTag as exc:
        raise EncryptionError("AES-CCM authentication tag check failed (tampered ciphertext)") from exc
    except Exception as exc:
        raise EncryptionError(f"AES-CCM decryption failed: {exc}") from exc

