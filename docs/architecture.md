# V2X Gateway Simulator — Technical Architecture

This document describes the software architecture, protocol layering, and data pipelines of the bidirectional **DSRC (IEEE 802.11p/1609) ↔ LTE-C-V2X (3GPP Release 14 PC5)** communication simulator.

---

## 1. System Overview

The simulator models two independent V2X protocol stacks interconnected by an intelligent, security-aware Roadside Gateway. The gateway bridges communication between vehicles equipped exclusively with DSRC and vehicles equipped exclusively with LTE-C-V2X, providing cross-technology interoperability while upholding strict cryptographic integrity and loop prevention guarantees.

```
+----------------------------------------------------------------------------------------------------+
|                                    APPLICATION LAYER (SAE J2735)                                    |
|                             Basic Safety Message (BSM) Part I - 14 Fields                           |
+-------------------------------------------------+--------------------------------------------------+
|               DSRC STACK (WAVE)                 |             LTE-C-V2X STACK (PC5)                |
|  IEEE 1609.2 Security: ECDSA-P256 SignedData    |  IEEE 1609.2 Security: ECDSA-P256 SignedData     |
|  IEEE 1609.3 Networking: WSMP (PSID 0x20)       |  3GPP TS 36.321: MAC SL-SCH Transport Block     |
|  IEEE 1609.4 Multi-Channel: 100ms Sync CCH/SCH  |  3GPP TS 36.213: Mode 4 Autonomous Sensing Pool  |
|  IEEE 802.11p: 10 MHz OFDM, OCB Mode, 5.9 GHz   |  3GPP TS 36.212: SCI Format 1, SC-FDMA, 1ms SF   |
+-------------------------------------------------+--------------------------------------------------+
                                        ▲                                 ▲
                                        │                                 │
                                        ▼                                 ▼
                     +-------------------------------------------------------+
                     |         BIDIRECTIONAL V2X PROTOCOL GATEWAY            |
                     |  - Ingress Demultiplexer & Frame Dissection           |
                     |  - Structural Syntax & ASN.1 UPER Validation          |
                     |  - IEEE 1609.2 Verification (Original Sender Trust)   |
                     |  - Loop Prevention & Egress Digest Echo Filter        |
                     |  - Sliding-Window Deduplication (sourceID, msgCnt)    |
                     |  - Verbatim BSM Preservation & Gateway Re-Signing     |
                     |  - Destination Stack Translation & Scheduled Egress   |
                     +-------------------------------------------------------+
```

---

## 2. Protocol Stacks

### 2.1 DSRC Protocol Stack (US WAVE)
- **Application (`src/dsrc/application/`)**: Generates SAE J2735 Basic Safety Messages at 10 Hz with sequence counter tracking ($0..127$).
- **Security (`src/dsrc/security/`)**: Wraps UPER BSM payloads in IEEE 1609.2 `SignedData` SPDUs with ECDSA-P256 signatures, `generationTime` in microseconds, and HashedId8 signer certificate digests.
- **Networking (`src/dsrc/wave/wsmp.py`)**: Encapsulates SPDU into IEEE 1609.3 WAVE Short Message Protocol (WSMP-N/T), variable-length PSID encoding ($0x20$ for BSM).
- **LLC / MAC (`src/dsrc/wave/wave_frame.py` & `src/dsrc/mac/wave_mac.py`)**:
  - IEEE 802.11p OCB (Outside the Context of a BSS) frame with EtherType $0x88DC$.
  - 32-bit CRC-32 Frame Check Sequence (FCS).
  - IEEE 1609.4 synchronized multi-channel operation: 100 ms sync cycle (50 ms CCH, 50 ms SCH, 4 ms guard band).
  - 4-queue EDCA QoS prioritization (Voice/Safety category AC_VO).
- **Physical Model (`src/dsrc/phy/dsrc_phy.py`)**:
  - 10 MHz OFDM channel at 5.890 GHz (Channel 178).
  - MCS 0..7 (3 Mbps to 27 Mbps); PLCP preamble (40 µs); sensitivity thresholds per IEEE 802.11p Table 18-14.

### 2.2 LTE-C-V2X Protocol Stack (3GPP Release 14/15 PC5)
- **Application (`src/cv2x/application/`)**: Generates SAE J2735 BSMs with V2X priority tagging ($0..7$, default priority 3).
- **Security (`src/cv2x/security/`)**: IEEE 1609.2 security profile identical to DSRC to guarantee cross-technology trust interoperability.
- **Sidelink Protocols (`src/cv2x/pc5/sidelink.py`)**:
  - Sidelink Control Information (SCI) Format 1 per 3GPP TS 36.212 Section 8.4.1 (Priority 3 bits, Resource Reservation Interval 4 bits, Frequency Resource Location 5 bits, Time Gap 4 bits, MCS 5 bits, Retransmission Index 1 bit).
  - Sidelink Shared Channel (SL-SCH) Transport Block with 24-bit CRC-24A polynomial $0x1864CFB$.
- **Resource Allocation (`src/cv2x/pc5/resource_pool.py`)**:
  - Mode 4 Autonomous Sensing-Based Resource Selection per 3GPP TS 36.213 Section 14.
  - 100 ms sensing window tracking S-RSSI across sub-channels.
  - Candidate single-subframe resource selection window ($T_1 \le 4\text{ ms}$, $T_2 \le 100\text{ ms}$).
  - Candidate exclusion based on SCI reservation and RSRP threshold.
  - Semi-Persistent Scheduling (SPS) counter randomized in range $[5, 15]$.
- **MAC & PHY Model (`src/cv2x/mac/lte_mac.py` & `src/cv2x/phy/lte_phy.py`)**:
  - 1.0 ms subframe duration (14 SC-FDMA symbols with extended cyclic prefix).
  - PSCCH occupies 2 PRBs per sub-channel; PSSCH carries data TB.
  - Turbo-coded BLER vs SINR performance curve.

---

## 3. Bidirectional Protocol Gateway

The Gateway operates at the boundary between DSRC and C-V2X:

### 3.1 Pipeline Stages
1. **Receiver Demux (`receiver.py`)**: Ingests raw radio units, strips L1/L2 envelopes, and validates transport CRCs.
2. **Validator (`validator.py`)**: Performs structural sanity checks, extracts the SPDU, decodes UPER BSM, and checks value boundaries.
3. **Loop Prevention (`loop_prevention.py`)**:
   - Detects if the signer is a known gateway certificate (rejects multi-hop loops).
   - Prunes and checks the recent egress SHA-256 payload cache (rejects echoing recently translated payloads).
4. **Duplicate Handler (`duplicate_handler.py`)**: Maintains a sliding-window cache of $(vehicle\_id, msg\_cnt)$ tuples with a 2.0-second TTL to filter retransmissions.
5. **Security Handler (`security_handler.py`)**:
   - Verifies the inbound sender's ECDSA-P256 signature and PKI certificate trust chain.
   - Enforces replay protection window ($|generationTime - now| \le 1000\text{ ms}$).
   - Preserves the verified raw BSM UPER payload bytes **verbatim** without tampering.
   - Re-signs the payload into a new IEEE 1609.2 SPDU using the Gateway's own private key and certificate.
6. **Translator (`translator.py`)**:
   - **DSRC $\to$ C-V2X**: Translates WSMP to SL-SCH Transport Block and generates SCI Format 1.
   - **C-V2X $\to$ DSRC**: Translates SL-SCH to WSMP packet and constructs IEEE 802.11p OCB frame with FCS.
7. **Forwarder (`forwarder.py`)**: Records transit latency, logs audit metrics, and enqueues to the destination interface.

---

## 4. Discrete-Event Simulation Engine

- **Framework**: SimPy process-based discrete-event simulation scheduler (`src/simulation/engine.py`).
- **Channel Models (`src/simulation/channel/`)**:
  - Free Space Path Loss (Friis): calibrated at 100 m @ 5.9 GHz to 87.86 dB.
  - 3GPP TR 36.885 / WINNER+ Highway LOS dual-slope path loss with breakpoint distance $d_{BP}'$.
  - 3GPP TR 36.885 Urban LOS and Urban NLOS models with corner building diffraction attenuation.
  - Rayleigh (NLOS) and Rician (LOS, $K=6\text{ dB}$) fast fading.
  - Log-normal slow fading (shadowing, $\sigma = 3\text{ dB}$ LOS, $6\text{ dB}$ NLOS).
  - Thermal noise power floor: $N_0 = -97.0\text{ dBm}$ (10 MHz, 7 dB NF).
  - Co-channel interference summation and SINR calculation.
  - Sigmoid Packet Delivery Ratio (PDR) mapping calibrated to IEEE 802.11p and LTE-V2X turbo coding.
- **Mobility (`src/vehicles/mobility_model.py`)**:
  - `LinearMobilityModel` (constant velocity / lane acceleration).
  - `WaypointMobilityModel` (timed waypoint interpolation).
  - `IntersectionMobilityModel` (4-way crossroad approach, junction deceleration, departure).
  - Geodetic WGS-84 to local Cartesian coordinate conversions.
- **Fleet Coordination (`src/vehicles/vehicle_manager.py`)**: NumPy-vectorized pairwise distance matrices.
- **Metrics & Reporting (`src/simulation/metrics/`)**: Distance-binned PDR, latency percentiles (P50, P95, P99), gateway transit duration, CSV exports, and Matplotlib publication figures.
