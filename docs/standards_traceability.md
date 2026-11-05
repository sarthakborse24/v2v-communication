# Standards-to-Code Traceability Matrix

This document maps all standards clauses referenced in the implementation to the corresponding source modules and automated verification tests.

---

## Traceability Table

| Standard | Clause / Section | Specification Requirement | Source File | Automated Test File | Status |
|:---|:---|:---|:---|:---|:---:|
| **SAE J2735-2020** | §7.1 | BasicSafetyMessage (BSM) Part I mandatory core data (14 fields) | `src/common/bsm_codec.py` | `tests/unit/test_bsm_codec.py` | ✅ Fully Grounded |
| **ITU-T X.691** | Section 10-26 | Unaligned Packed Encoding Rules (UPER) bit-level packing | `src/common/bsm_codec.py` | `tests/unit/test_bsm_codec.py` | ✅ Fully Grounded |
| **IEEE 1609.2-2016** | §6.3 | Explicit Certificate Structure (TBSCertificate, Issuer, Signature) | `src/common/ieee1609_2/certificates.py` | `tests/unit/test_1609_2_security.py` | ✅ Fully Grounded |
| **IEEE 1609.2-2016** | §5.2 | ECDSA-P256 signature generation and verification with SHA-256 | `src/common/ieee1609_2/crypto.py` | `tests/unit/test_1609_2_security.py` | ✅ Fully Grounded |
| **IEEE 1609.2-2016** | §7.1 | `Ieee1609Dot2Data` SPDU framing and `SignedData` serialization | `src/common/ieee1609_2/spdu.py` | `tests/unit/test_1609_2_security.py` | ✅ Fully Grounded |
| **IEEE 1609.2-2016** | §7.4.2 | Replay protection via `generationTime` window (±1000 ms) | `src/common/ieee1609_2/security_engine.py` | `tests/unit/test_1609_2_security.py` | ✅ Fully Grounded |
| **IEEE 1609.2-2016** | §5.3.5 | AES-128-CCM symmetric authenticated encryption for unicast | `src/common/ieee1609_2/crypto.py` | `tests/unit/test_1609_2_security.py` | ✅ Fully Grounded |
| **IEEE 1609.3-2016** | §8.1.3 | WAVE Short Message Protocol (WSMP-N/T), variable-length PSID | `src/dsrc/wave/wsmp.py` | `tests/unit/test_wsmp.py` | ✅ Fully Grounded |
| **IEEE 802.11p-2010** | §17.3 | 10 MHz channel OFDM framing, OCB mode, EtherType `0x88DC` | `src/dsrc/wave/wave_frame.py` | `tests/unit/test_wave_frame.py` | ✅ Fully Grounded |
| **IEEE 802.11-2016** | §9.2.4.8 | 32-bit CRC Frame Check Sequence (FCS) verification | `src/dsrc/wave/wave_frame.py` | `tests/unit/test_wave_frame.py` | ✅ Fully Grounded |
| **IEEE 1609.4-2016** | §6.2-6.3 | CCH/SCH multi-channel 100 ms sync cycle and 4-queue EDCA QoS | `src/dsrc/mac/wave_mac.py` | `tests/unit/test_dsrc_mac_phy.py` | ✅ Fully Grounded |
| **IEEE 802.11p-2010** | Table 18-14 | Sensitivity, PLCP preamble, and data rates for MCS 0..7 | `src/dsrc/phy/dsrc_phy.py` | `tests/unit/test_dsrc_mac_phy.py` | [SIMULATION MODEL] |
| **3GPP TS 36.212** | §8.4.1 | SCI Format 1 fields (Priority, RRI, Freq Res, Time Gap, MCS, Retx) | `src/cv2x/pc5/sidelink.py` | `tests/unit/test_pc5_sidelink.py` | ✅ Fully Grounded |
| **3GPP TS 36.212** | §5.1.1 | 24-bit CRC-24A polynomial `0x1864CFB` on SL-SCH Transport Block | `src/cv2x/pc5/sidelink.py` | `tests/unit/test_pc5_sidelink.py` | ✅ Fully Grounded |
| **3GPP TS 36.213** | §14.1 | Mode 4 Sensing-Based Autonomous Sidelink Resource Selection | `src/cv2x/pc5/resource_pool.py` | `tests/unit/test_cv2x_mac_phy.py` | ✅ Fully Grounded |
| **3GPP TS 36.321** | §5.14 | SL-SCH MAC prioritization and transmission scheduling | `src/cv2x/mac/lte_mac.py` | `tests/unit/test_cv2x_mac_phy.py` | ✅ Fully Grounded |
| **3GPP TS 36.211** | §9.3 | Subframe duration 1.0 ms, 14 SC-FDMA symbols, PRB layout | `src/cv2x/phy/lte_phy.py` | `tests/unit/test_cv2x_mac_phy.py` | [SIMULATION MODEL] |
| **ETSI TS 102 890-1** | §5.3 | V2X Gateway loop prevention, multi-hop filter, deduplication | `src/gateway/` | `tests/unit/test_loop_prevention.py` | ✅ Fully Grounded |
| **3GPP TR 36.885** | Table A.1-2 | Dual-slope Highway LOS, Urban LOS, and Urban NLOS path loss | `src/simulation/channel/path_loss.py` | `tests/unit/test_channel_models.py` | [SIMULATION MODEL] |
| **ITU-R M.1225** | §1.2 | Rayleigh multipath fading, Rician LOS fading, log-normal shadowing | `src/simulation/channel/fading.py` | `tests/unit/test_channel_models.py` | [SIMULATION MODEL] |

---

## Integrity Notes
- Modules marked **✅ Fully Grounded** implement the exact bit-level encoding, mathematical formulas, or state machines required by the standard.
- Modules marked **[SIMULATION MODEL]** implement validated statistical models representing physical layer behavior (e.g., link budget, SINR, and BLER) without claiming live RF waveform modulation.
