# Documented Deviations from V2X Standards

This document records **every deviation** from the referenced standards,
with rationale and impact assessment.

> [!IMPORTANT]
> These deviations are intentional and documented. No deviation is silent.
> Code that deviates from a standard includes a `# DEVIATION: Lx` comment
> referencing the entry in this table.

## Deviation Table

| ID | Standard | Clause | Deviation | Rationale | Impact |
|----|---------|--------|-----------|-----------|--------|
| **L1** | IEEE 802.11p | §17 (PHY) | PHY implemented as a statistical MCS→SINR→PDR lookup table, not waveform simulation | Waveform simulation requires MATLAB/Simulink or ns-3; Python cannot model OFDM waveforms at speed | No RF fidelity; simulation only |
| **L2** | SAE J2735-2020 | §7 (BSM) | BSM ASN.1 is a hand-crafted BSM Part I subset — 14 mandatory fields only; no Part II optional extension | Full J2735 ASN.1 file requires SAE membership purchase; not freely distributable | No Part II (optional safety extension); no other J2735 message types |
| **L3** | IEEE 1609.2-2016 | §6 (Certificates) | Certificate keys are locally generated; not enrolled through a real SCMS | USDOT SCMS requires real infrastructure + hardware security module | Not interoperable with real WAVE deployments; simulation use only |
| **L4** | 3GPP TS 36.321 | §5.14 (Mode 4) | LTE-V2X Mode 4 resource selection is a statistical model — no actual HARQ retransmission timing, no precise sub-frame collision modelling | Full Mode 4 requires ns-3 LTE module or MATLAB sidelink; Python DES cannot model 1 ms sub-frame timing | No precise PHY-layer collision granularity |
| **L5** | IEEE 1609.2-2016 | §6.4 (Implicit certs) | Only explicit certificates implemented; ECQV implicit certificates are stubbed | ECQV reconstruction requires elliptic curve point arithmetic not exposed by PyCA at a convenient API level; implementable but deferred | Slightly larger SPDU sizes vs. real high-density deployment |
| **L6** | IEEE 1609.2 / SCMS | Misbehavior detection | Not implemented | Out of scope for this simulation phase | Safety gap; not applicable to simulation |
| **L7** | IEEE 1609.2-2016 | §8 (CRL) | Certificate revocation check is stubbed — always returns `NOT_REVOKED` | No live CRL endpoint; would require SCMS integration | Revoked pseudonym certificates will not be detected |
| **L8** | IEEE 1609.2-2016 | §7.4.2 (Replay) | Replay window is ±1,000 ms (tighter than standard's allowable ±20 minutes) | A ±20-minute window is for real deployments with potential GPS/NTP clock drift; simulation clock is perfect, so ±1 s is appropriate and more secure | May reject messages in edge-case test scenarios with large simulated clock deltas |
| **L9** | IEEE 1609.4 | §6.3 (Channel switching) | Channel switching is simulated as a periodic time-division event in SimPy; no actual radio re-tuning | No physical radio present | No actual guard-interval power ramp-down; purely logical |
| **L10** | 3GPP TS 36.212 | §8.4.1 (SCI) | SCI Format 1 "Timing Advance" field excluded — not a standard SCI Format 1 field | Research found this is a misattribution in some secondary sources; TS 36.212 §8.4.1 defines 6 fields without TA | Correct per standard; some secondary-source readers may expect TA field |

## Code Annotation Convention

Each deviation is marked in source code:

```python
# DEVIATION L2: Hand-crafted BSM Part I ASN.1 subset — not full J2735.
# See docs/deviations.md for rationale.
```

## Future Work (to reduce deviations)

- **L1**: Replace statistical PHY with ns-3 Python bindings (ns3gym) for more accurate PHY simulation
- **L2**: Replace with full J2735 ASN.1 if SAE license obtained
- **L5**: Implement ECQV using PyCA EC point arithmetic
- **L7**: Integrate with a CRL distribution simulation using local revocation lists

