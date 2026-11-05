# IEEE 1609.2 Security Design & Gateway Trust Architecture

This document specifies the cybersecurity architecture, cryptographic profiles, and trust semantics implemented in the V2X Simulator.

---

## 1. IEEE 1609.2 Security Profile

All V2X safety communications in the system adhere to the IEEE 1609.2-2016 profile:

- **Asymmetric Algorithm**: ECDSA with the NIST P-256 curve (`secp256r1`).
- **Digest Algorithm**: SHA-256 (FIPS 180-4).
- **Identifier Encoding**: HashedId8 (low-order 8 bytes of the SHA-256 digest of the certificate).
- **Symmetric Encryption (Unicast only)**: AES-128 in Galois/Counter Mode (GCM) or Counter with CBC-MAC (CCM).

> [!IMPORTANT]
> **Broadcast Safety Messages are SIGNED, NOT ENCRYPTED.**
> In accordance with SAE J2735 and IEEE 1609.2, periodic Basic Safety Messages (BSMs) are broadcast openly to maximize situational awareness for surrounding vehicles. Confidentiality (encryption) would impede immediate situational decoding and is reserved strictly for unicast communications.

---

## 2. Public Key Infrastructure (PKI) Hierarchy

The simulation generates an IEEE 1609.2-compliant explicit certificate hierarchy:

```
                  +--------------------------------+
                  |         ROOT CA CERT           |
                  |  Trust Anchor for entire fleet |
                  +--------------------------------+
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
+----------------------------------+   +----------------------------------+
|     ENROLLMENT CA (ECA) CERT     |   |     PSEUDONYM CA (PCA) CERT      |
| Long-term identity verification  |   | Issues short-lived pseudonyms    |
+----------------------------------+   +----------------------------------+
                                                         │
                         ┌───────────────────────────────┴───────────────────────────────┐
                         ▼                                                               ▼
        +----------------------------------+                            +----------------------------------+
        |   VEHICLE PSEUDONYM CERTS        |                            |       GATEWAY CA / RSU CERT      |
        | - Ephemeral (rotated frequently) |                            | - Authorized for Cross-Stack RSU |
        | - Scoped to PSID 0x20 (BSM)      |                            | - Scoped to PSID 0x20, 0x22, ... |
        +----------------------------------+                            +----------------------------------+
```

### Certificate Attributes
- `cert_id`: Unique identifier string.
- `issuer`: HashedId8 of the signing parent certificate or `self` for the Root CA.
- `validity_period`: Start and End timestamps in Unix epoch seconds.
- `app_permissions`: List of authorized PSIDs (e.g., PSID $0x0020$ for BSM).
- `verification_key`: ECDSA-P256 public key.

---

## 3. Gateway Re-Signing & Trust Semantics

### The Core Gateway Security Dilemma
When a DSRC vehicle broadcasts an SPDU, it signs the payload using its own private key. A native LTE-C-V2X vehicle expecting a Sidelink Transport Block cannot verify an 802.11p WAVE MAC frame directly. However, if the gateway merely converts the outer frame and forwards the sender's SPDU unchanged, or if the gateway modifies the message without signing, security verification fails.

### Implemented Gateway Solution: "Verify, Invariant Preserve, and Attested Re-Sign"
1. **Inbound Verification**: The gateway acts as an IEEE 1609.2 verifier. It checks the inbound vehicle's certificate against the Root CA anchor, verifies the ECDSA signature over the `ToBeSignedData`, and confirms replay window validity.
2. **Payload Preservation**: The raw UPER-encoded BSM payload bytes are kept **strictly invariant**. The gateway does NOT alter message sequence counters, timestamps, or kinematic fields of the vehicle.
3. **Gateway Attestation (Re-Sign)**:
   - The gateway strips the DSRC transmission envelope.
   - It constructs a new IEEE 1609.2 `SignedData` envelope containing the identical, unmodified BSM bytes.
   - It signs this new SPDU using the **Gateway's own trusted private key**.
   - It encapsulates the SPDU into the destination technology format (e.g. SL-SCH TB for C-V2X).
4. **Outbound Trust**: Receiving vehicles on the destination technology verify the Gateway's valid certificate and trust chain, knowing the message was verified and bridged by an authorized Roadside Unit.

---

## 4. Replay Protection & Deduplication

The architecture deploys two complementary defenses:

1. **Cryptographic Replay Window (IEEE 1609.2 §7.4.2)**:
   - Every SPDU embeds `generationTime` in microseconds.
   - Verifiers enforce $|t_{now} - generationTime| \le 1,000\text{ ms}$.
   - Out-of-window messages are dropped immediately as replays.
2. **Sliding-Window Deduplication**:
   - The gateway tracks seen $(vehicle\_id, msg\_cnt)$ tuples in a hash cache.
   - Cached entries expire after $2.0$ seconds.
   - Identical messages received on multiple antennas or repeated transmissions are dropped before translation.

---

## 5. Loop Prevention & Echo Suppression

To prevent endless feedback loops across DSRC and C-V2X:
1. **Gateway Signer Identification**: If an ingress message's SPDU signer is identified as a known Gateway (via certificate digest or cert ID), it is dropped instantly.
2. **Egress Digest Tracking**: When the gateway translates and forwards a message, it computes `SHA256(bsm_bytes)` and caches it for $3.0$ seconds. If the translated message echoes back across the other radio interface, the match is detected and suppressed.
