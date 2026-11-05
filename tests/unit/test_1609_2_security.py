"""
Unit Tests for IEEE 1609.2 Security Processing
==============================================
Standards References:
  - IEEE 1609.2-2016: ECDSA-P256, Certificates, SignedData, Replay Protection
  - NIST FIPS 186-4: Digital Signature Standard
"""

import time
import pytest

from common.exceptions import (
    CertificateChainError,
    CertificateNotFoundError,
    EncryptionError,
    PSIDPermissionError,
    ReplayDetectedError,
    SignatureVerificationError,
    ValidationError,
)
from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
    CertificateType,
    IssuerChoice,
    ToBeSignedCertificate,
    ValidityPeriod,
)
from common.ieee1609_2.crypto import (
    aes_128_ccm_decrypt,
    aes_128_ccm_encrypt,
    compute_hashed_id8,
    generate_keypair,
    public_key_to_uncompressed_bytes,
    sha256_digest,
    sign_ecdsa_p256,
    verify_ecdsa_p256,
)
from common.ieee1609_2.security_engine import (
    sign_message,
    verify_message,
)
from common.ieee1609_2.spdu import (
    EcdsaP256Signature,
    HeaderInfo,
    Ieee1609Dot2Data,
    SignedData,
    SignerIdentifier,
    ToBeSignedData,
)
from common.message_types import PSID
from certificates.generate_pki import (
    build_simulated_pki,
    issue_certificate,
)


# ---------------------------------------------------------------------------
# 1. Cryptographic Primitive Tests
# ---------------------------------------------------------------------------

class TestCryptoPrimitives:
    """Tests for core cryptographic primitives (ECDSA-P256, AES-CCM, Hashing)."""

    def test_ecdsa_p256_sign_and_verify(self):
        priv, pub = generate_keypair()
        message = b"Test safety broadcast message payload"

        r, s = sign_ecdsa_p256(priv, message)
        assert len(r) == 32
        assert len(s) == 32

        # Verify valid signature
        assert verify_ecdsa_p256(pub, message, r, s) is True

    def test_ecdsa_tampered_message_fails(self):
        priv, pub = generate_keypair()
        message = b"Original message"
        r, s = sign_ecdsa_p256(priv, message)

        tampered = b"Altered message"
        with pytest.raises(SignatureVerificationError):
            verify_ecdsa_p256(pub, tampered, r, s)

    def test_ecdsa_tampered_signature_fails(self):
        priv, pub = generate_keypair()
        message = b"Authentic message"
        r, s = sign_ecdsa_p256(priv, message)

        # Corrupt one byte of r
        r_corrupt = bytes([r[0] ^ 0xFF]) + r[1:]
        with pytest.raises(SignatureVerificationError):
            verify_ecdsa_p256(pub, message, r_corrupt, s)

    def test_ecdsa_invalid_signature_length_raises(self):
        _, pub = generate_keypair()
        with pytest.raises(SignatureVerificationError):
            verify_ecdsa_p256(pub, b"data", b"too_short", b"short")

    def test_hashed_id8_low_order_bytes(self):
        """HashedId8 must be the trailing (low-order) 8 bytes of SHA-256."""
        data = b"IEEE 1609.2 certificate payload"
        full_hash = sha256_digest(data)
        hid8 = compute_hashed_id8(data)
        assert len(hid8) == 8
        assert hid8 == full_hash[-8:]

    def test_aes_128_ccm_roundtrip(self):
        key = b"\x01" * 16
        nonce = b"\x02" * 12
        plaintext = b"Sensitive unicast V2X payload"
        aad = b"associated-data"

        ciphertext = aes_128_ccm_encrypt(key, nonce, plaintext, aad)
        # Length should be plaintext len + 16-byte tag
        assert len(ciphertext) == len(plaintext) + 16

        recovered = aes_128_ccm_decrypt(key, nonce, ciphertext, aad)
        assert recovered == plaintext

    def test_aes_128_ccm_tampered_ciphertext_fails(self):
        key = b"\x01" * 16
        nonce = b"\x02" * 12
        plaintext = b"Confidential"

        ciphertext = aes_128_ccm_encrypt(key, nonce, plaintext)
        corrupted = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        with pytest.raises(EncryptionError):
            aes_128_ccm_decrypt(key, nonce, corrupted)


# ---------------------------------------------------------------------------
# 2. SPDU Structure & Serialization Tests
# ---------------------------------------------------------------------------

class TestSPDUDataStructures:
    """Tests for ToBeSignedData and Ieee1609Dot2Data serialization."""

    def test_to_be_signed_data_roundtrip(self):
        payload = b"\xaa\xbb\xcc\xdd\xee\xff"
        hdr = HeaderInfo(psid=0x20, generation_time=1234567890, expiry_time=1234569999)
        tbs = ToBeSignedData(payload=payload, header_info=hdr)

        serialized = tbs.serialize()
        assert len(serialized) > len(payload)

        recovered, rem = ToBeSignedData.deserialize(serialized)
        assert len(rem) == 0
        assert recovered.payload == payload
        assert recovered.header_info.psid == 0x20
        assert recovered.header_info.generation_time == 1234567890
        assert recovered.header_info.expiry_time == 1234569999

    def test_spdu_signed_data_roundtrip(self):
        payload = b"BSM-UPER-BYTES-1234"
        hdr = HeaderInfo(psid=0x20, generation_time=1000000)
        tbs = ToBeSignedData(payload=payload, header_info=hdr)
        sig = EcdsaP256Signature(r=b"\x01" * 32, s=b"\x02" * 32)
        signer = SignerIdentifier.from_digest(b"\x99" * 8)

        sd = SignedData(tbs_data=tbs, signer=signer, signature=sig)
        spdu = Ieee1609Dot2Data(content_type="signedData", signed_data=sd)

        raw = spdu.to_bytes()
        recovered = Ieee1609Dot2Data.from_bytes(raw)

        assert recovered.protocol_version == 3
        assert recovered.content_type == "signedData"
        assert recovered.signed_data is not None
        assert recovered.signed_data.signer.digest == b"\x99" * 8
        assert recovered.signed_data.signature.r == b"\x01" * 32
        assert recovered.signed_data.signature.s == b"\x02" * 32
        assert recovered.signed_data.tbs_data.payload == payload

    def test_spdu_invalid_version_raises(self):
        raw = bytes([0x04, 0x01])  # Version 4 instead of 3
        with pytest.raises(ValidationError):
            Ieee1609Dot2Data.from_bytes(raw)

    def test_spdu_truncated_raises(self):
        with pytest.raises(ValidationError):
            Ieee1609Dot2Data.from_bytes(b"\x03")


# ---------------------------------------------------------------------------
# 3. Certificate & Trust Chain Tests
# ---------------------------------------------------------------------------

class TestCertificatesAndPKI:
    """Tests for Certificate data model, trust validation, and simulated PKI."""

    @pytest.fixture
    def pki_store(self) -> CertificateStore:
        return build_simulated_pki(num_vehicles=2, certs_per_vehicle=2)

    def test_simulated_pki_hierarchy(self, pki_store):
        """PKI must contain 1 root CA, 2 intermediates, 1 gateway, 4 vehicle certs."""
        assert len(pki_store.root_cas) == 1
        assert len(pki_store.intermediate_cas) == 2
        assert len(pki_store.entity_certs) == 5  # 1 gateway + 4 pseudonym certs

    def test_valid_chain_verification(self, pki_store):
        """Pseudonym certificate chain up to Root CA must pass validation."""
        # Pick one vehicle pseudonym certificate
        for digest, cert in pki_store.entity_certs.items():
            if "Vehicle" in cert.to_be_signed.cert_id:
                assert pki_store.validate_chain(cert, expected_psid=PSID.BSM) is True
                break

    def test_expired_certificate_fails(self, pki_store):
        """Certificate past its validity window must raise CertificateChainError."""
        # Find a vehicle cert
        cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)

        # Validate with time far in future
        future_time = cert.to_be_signed.validity_period.end_time_ms + 100_000
        with pytest.raises(CertificateChainError):
            pki_store.validate_chain(cert, current_time_ms=future_time)

    def test_not_yet_valid_certificate_fails(self, pki_store):
        """Certificate before its start time must raise CertificateChainError."""
        cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        past_time = cert.to_be_signed.validity_period.start_time_ms - 100_000
        with pytest.raises(CertificateChainError):
            pki_store.validate_chain(cert, current_time_ms=past_time)

    def test_unauthorized_psid_fails(self, pki_store):
        """Vehicle cert with BSM permission only must fail validation for SPAT."""
        cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        with pytest.raises(PSIDPermissionError):
            pki_store.validate_chain(cert, expected_psid=PSID.SPAT)

    def test_tampered_cert_signature_fails(self, pki_store):
        """Tampered signature on certificate must fail chain validation."""
        cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        # Corrupt certificate signature
        corrupt_r = bytes([cert.signature.r[0] ^ 0xFF]) + cert.signature.r[1:]
        bad_sig = EcdsaP256Signature(r=corrupt_r, s=cert.signature.s)
        tampered_cert = Certificate(
            version=cert.version,
            cert_type=cert.cert_type,
            issuer_choice=cert.issuer_choice,
            issuer_digest=cert.issuer_digest,
            to_be_signed=cert.to_be_signed,
            signature=bad_sig,
        )
        with pytest.raises(CertificateChainError):
            pki_store.validate_chain(tampered_cert)


# ---------------------------------------------------------------------------
# 4. High-Level Security Engine Tests (Sign & Verify)
# ---------------------------------------------------------------------------

class TestSecurityEngine:
    """End-to-end signing and verification tests."""

    @pytest.fixture
    def pki_store(self) -> CertificateStore:
        return build_simulated_pki(num_vehicles=1, certs_per_vehicle=1)

    def test_sign_and_verify_with_digest(self, pki_store):
        """Sign with digest identification and verify against certificate store."""
        # Get vehicle certificate and private key
        v_cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        v_digest = v_cert.compute_digest8()
        v_priv = pki_store.get_private_key(v_digest)

        payload = b"BSM payload bytes for verification test"
        spdu = sign_message(
            payload=payload,
            signer_cert=v_cert,
            private_key=v_priv,
            psid=PSID.BSM,
            include_full_cert=False,
        )

        assert spdu.signed_data.signer.choice == "digest"
        assert spdu.signed_data.signer.digest == v_digest

        # Verify
        rec_payload, rec_hdr, rec_cert = verify_message(
            spdu=spdu,
            cert_store=pki_store,
            expected_psid=PSID.BSM,
        )
        assert rec_payload == payload
        assert rec_hdr.psid == PSID.BSM
        assert rec_cert.to_be_signed.cert_id == v_cert.to_be_signed.cert_id

    def test_sign_and_verify_with_full_cert(self, pki_store):
        """Sign with full embedded certificate and verify."""
        v_cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        v_digest = v_cert.compute_digest8()
        v_priv = pki_store.get_private_key(v_digest)

        payload = b"Payload with full cert"
        spdu = sign_message(
            payload=payload,
            signer_cert=v_cert,
            private_key=v_priv,
            psid=PSID.BSM,
            include_full_cert=True,
        )

        assert spdu.signed_data.signer.choice == "certificate"

        rec_payload, _, _ = verify_message(spdu=spdu, cert_store=pki_store)
        assert rec_payload == payload

    def test_replay_protection_old_message_rejected(self, pki_store):
        """Message with generationTime older than replay window must be rejected."""
        v_cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        v_digest = v_cert.compute_digest8()
        v_priv = pki_store.get_private_key(v_digest)

        now_ms = int(time.time() * 1000)
        # Message was generated 5 seconds ago (replay window is 1 second)
        old_time = now_ms - 5000

        spdu = sign_message(
            payload=b"Old message",
            signer_cert=v_cert,
            private_key=v_priv,
            generation_time_ms=old_time,
        )

        with pytest.raises(ReplayDetectedError):
            verify_message(spdu=spdu, cert_store=pki_store, current_time_ms=now_ms)

    def test_replay_protection_future_message_rejected(self, pki_store):
        """Message with generationTime far in future must be rejected."""
        v_cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        v_digest = v_cert.compute_digest8()
        v_priv = pki_store.get_private_key(v_digest)

        now_ms = int(time.time() * 1000)
        future_time = now_ms + 5000

        spdu = sign_message(
            payload=b"Future message",
            signer_cert=v_cert,
            private_key=v_priv,
            generation_time_ms=future_time,
        )

        with pytest.raises(ReplayDetectedError):
            verify_message(spdu=spdu, cert_store=pki_store, current_time_ms=now_ms)

    def test_tampered_payload_in_spdu_fails(self, pki_store):
        """Modifying the signed payload without re-signing must fail verification."""
        v_cert = next(c for c in pki_store.entity_certs.values() if "Vehicle" in c.to_be_signed.cert_id)
        v_digest = v_cert.compute_digest8()
        v_priv = pki_store.get_private_key(v_digest)

        payload = b"Original safety alert"
        spdu = sign_message(payload=payload, signer_cert=v_cert, private_key=v_priv)

        # Attacker tampers with payload inside ToBeSignedData
        spdu.signed_data.tbs_data.payload = b"Forged safety alert"

        with pytest.raises(SignatureVerificationError):
            verify_message(spdu=spdu, cert_store=pki_store)

