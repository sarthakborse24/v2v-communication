"""
V2X Gateway Simulator — Domain Exceptions
==========================================
All project-specific exceptions are defined here to allow targeted catch blocks
at each layer boundary without catching broad base exceptions.

Standards References:
  - IEEE 1609.2: Security exceptions (signature, replay, cert chain)
  - IEEE 1609.3: Networking exceptions (WSMP parsing)
  - SAE J2735:   Codec exceptions
  - 3GPP TS 36.212: PC5 sidelink exceptions
"""


# ---------------------------------------------------------------------------
# Base Exception
# ---------------------------------------------------------------------------

class V2XError(Exception):
    """Root exception for all V2X simulator errors."""


# ---------------------------------------------------------------------------
# Security Exceptions (IEEE 1609.2)
# ---------------------------------------------------------------------------

class SecurityError(V2XError):
    """Root for all IEEE 1609.2 security processing failures."""


class SignatureVerificationError(SecurityError):
    """ECDSA-P256 signature verification failed.

    Raised when: cryptographic signature does not match the ToBeSignedData hash.
    Action: DROP message, log with severity ERROR.
    """


class ReplayDetectedError(SecurityError):
    """Message replay detected.

    Raised when:
      - generationTime is outside the ±1 s acceptance window, OR
      - (sourceID, msgCnt) tuple seen within the 2-second dedup window.
    Action: DROP message, log with severity WARNING.
    """


class CertificateChainError(SecurityError):
    """Certificate chain validation failed.

    Raised when:
      - A certificate in the chain has expired or not yet valid.
      - An issuer signature on a subordinate cert is invalid.
      - The root CA is not in the trusted anchor set.
    Action: DROP message, log with severity ERROR.
    """


class PSIDPermissionError(SecurityError):
    """PSID not authorised in signer's certificate appPermissions.

    Raised when the message PSID does not appear in the end-entity
    certificate's appPermissions field.
    Action: DROP message, log with severity WARNING.
    """


class CertificateNotFoundError(SecurityError):
    """Certificate referenced by digest is not in the local certificate store."""


class RevocationCheckError(SecurityError):
    """CRL / revocation check could not be completed.

    NOTE: Revocation is STUBBED. This exception is reserved for future use
    when a real CRL distribution mechanism is integrated.
    """


class EncryptionError(SecurityError):
    """AES-CCM encryption or decryption failed (used for EncryptedData only)."""


# ---------------------------------------------------------------------------
# Codec / ASN.1 Exceptions (SAE J2735)
# ---------------------------------------------------------------------------

class CodecError(V2XError):
    """Root for ASN.1 encode/decode failures."""


class BSMEncodeError(CodecError):
    """Failed to ASN.1 UPER-encode a BasicSafetyMessage."""


class BSMDecodeError(CodecError):
    """Failed to ASN.1 UPER-decode bytes into a BasicSafetyMessage."""


class ConstraintViolationError(CodecError):
    """A BSM field value violates its ASN.1 declared constraint.

    Example: msgCnt > 127, speed > 8191.
    Always check constraints before encoding to prevent silent UPER bit misalignment.
    """


# ---------------------------------------------------------------------------
# WAVE / WSMP Exceptions (IEEE 1609.3)
# ---------------------------------------------------------------------------

class WSMPError(V2XError):
    """Root for IEEE 1609.3 WSMP header parsing/construction failures."""


class WSMPVersionError(WSMPError):
    """WSMP version field value is unrecognised."""


class WSMPLengthError(WSMPError):
    """Declared WSM length does not match actual payload length."""


class PSIDEncodingError(WSMPError):
    """PSID value cannot be encoded in 1–4 bytes, or encoded bytes are malformed."""


# ---------------------------------------------------------------------------
# 802.11p Frame Exceptions (IEEE 802.11p)
# ---------------------------------------------------------------------------

class WaveFrameError(V2XError):
    """Root for 802.11p / WAVE frame construction or parsing failures."""


class InvalidEtherTypeError(WaveFrameError):
    """EtherType is not 0x88DC (WSMP) or 0x86DD (IPv6) in a WAVE frame."""


# ---------------------------------------------------------------------------
# PC5 / Sidelink Exceptions (3GPP TS 36.212, 36.213)
# ---------------------------------------------------------------------------

class PC5Error(V2XError):
    """Root for LTE-V2X PC5 sidelink layer failures."""


class SCIFormatError(PC5Error):
    """SCI Format 1 field value is out of range or the SCI PDU is malformed."""


class ResourcePoolError(PC5Error):
    """No suitable sub-channel found in Mode 4 resource pool."""


class TransportBlockError(PC5Error):
    """LTE-V2X Transport Block construction or parsing failed."""


# ---------------------------------------------------------------------------
# Gateway Exceptions
# ---------------------------------------------------------------------------

class GatewayError(V2XError):
    """Root for all gateway processing failures."""


class ValidationError(GatewayError):
    """Incoming message failed structural or semantic validation."""


class TranslationError(GatewayError):
    """Message could not be translated between DSRC and C-V2X formats."""


class DuplicateMessageError(GatewayError):
    """Message was detected as a duplicate and should be dropped."""


class LoopDetectedError(GatewayError):
    """Message has already traversed the gateway (loop prevention)."""


class ForwardingError(GatewayError):
    """Message could not be queued or forwarded to the destination stack."""


# ---------------------------------------------------------------------------
# Simulation Exceptions
# ---------------------------------------------------------------------------

class SimulationError(V2XError):
    """Root for simulation engine failures."""


class ChannelModelError(SimulationError):
    """Channel model computation failed (e.g., invalid distance or frequency)."""


class MobilityModelError(SimulationError):
    """Vehicle mobility model encountered an invalid state."""


# ---------------------------------------------------------------------------
# Not-Implemented Stubs (for features that require external infrastructure)
# ---------------------------------------------------------------------------

class SCMSNotImplementedError(NotImplementedError):
    """Real SCMS (Security Credential Management System) is not integrated.

    This simulator uses a local simulated PKI.  This error is raised if
    code attempts to contact a real SCMS endpoint.
    """


class RevocationNotImplementedError(NotImplementedError):
    """CRL / misbehaviour revocation is not implemented.

    Stub behaviour: check_revocation() always returns NOT_REVOKED and
    logs a WARNING.  Raise this only if full revocation processing is
    explicitly required.
    """


class HardwareInterfaceNotImplementedError(NotImplementedError):
    """Real radio hardware interface is not implemented.

    The hardware interface layer is a stub for future integration with
    actual DSRC or C-V2X radio devices.
    """

