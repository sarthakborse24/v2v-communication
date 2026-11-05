# Hardware Radio Interface & Physical Deployment Guide

This document describes the hardware abstraction layer (`src/common/hardware_interface.py`) and provides integration instructions for connecting physical V2X transceivers (Dedicated OBUs/RSUs or Software-Defined Radios).

---

## 1. Hardware Abstraction Overview

The simulator architecture cleanly separates the upper protocol layers (Application, Security, WSMP, Sidelink, MAC) from the physical transport. The `BaseV2XRadioDevice` interface provides standard hooks for:
- Device lifecycle (`connect()`, `disconnect()`)
- RF parameter tuning (`configure(frequency_hz, bandwidth_hz, tx_power_dbm)`)
- Frame transmission (`transmit_raw_frame(frame_bytes)`)
- Frame reception (`receive_raw_frame(timeout_ms)`)

```
+-----------------------------------------------------------------+
|               V2X Stack / Gateway Translation Logic             |
+-----------------------------------------------------------------+
                                │
                                ▼
+-----------------------------------------------------------------+
|             BaseV2XRadioDevice (Abstract Interface)             |
+-----------------------------------------------------------------+
               │                                   │
               ▼                                   ▼
+-----------------------------+     +-----------------------------+
|       DSCRadioDevice        |     |       CV2XRadioDevice       |
|    (IEEE 802.11p WAVE)      |     |  (3GPP Rel 14/15 PC5 Mode 4)|
+-----------------------------+     +-----------------------------+
               │                                   │
               ▼                                   ▼
+-----------------------------+     +-----------------------------+
| Physical Hardware / Drivers |     | Physical Hardware / Drivers |
| - Cohda Wireless MK5 / MK6  |     | - Qualcomm 9150 C-V2X Chip  |
| - Commsignia OBU / RSU      |     | - Autotalks Secton / CRATON2|
| - Ettus USRP B210 (SDR)     |     | - srsRAN PC5 Sidelink (SDR) |
+-----------------------------+     +-----------------------------+
```

---

## 2. Supported Hardware Targets

### 2.1 IEEE 802.11p DSRC Hardware
1. **Cohda Wireless MK5 / MK6**:
   - Interface: Ethernet / IEEE 802.3 raw socket or Cohda LLC API.
   - Channel: US WAVE Channel 172 to 184 (5.850 to 5.925 GHz).
2. **Commsignia Unex OBU / RSU**:
   - Interface: UDP/V2X API or Linux OCB kernel driver (`iw set type ocb`).
3. **Software-Defined Radio (USRP B210 / X310)**:
   - Toolchain: GNU Radio with `gr-ieee802-11` (Bastian Bloessl) configured for 10 MHz channel bandwidth.

### 2.2 3GPP LTE-C-V2X PC5 Hardware
1. **Qualcomm 9150 C-V2X Chipset**:
   - Interface: Qualcomm Telematics SDK (`ITelematicsManager`, `ICV2XRadio`).
   - Operation: Band 47 PC5 sidelink direct communication.
2. **Autotalks CRATON2 / PLUTON2**:
   - Interface: V2X Communication Processor Host API.
3. **SDR LTE PC5 (OpenAirInterface / srsRAN)**:
   - Experimental sidelink PC5 PHY/MAC transceivers.

---

## 3. Integration Instructions

To bind a physical hardware driver:
1. Subclass `DSCRadioDevice` or `CV2XRadioDevice`.
2. Override `connect()` to establish connection with the hardware SDK or serial/ethernet socket.
3. Implement `transmit_raw_frame(frame_bytes)` to inject bytes directly into the hardware transmission queue.
4. Implement `receive_raw_frame(timeout_ms)` to poll the device hardware ring buffer.

### Example Driver Implementation Skeleton
```python
from common.hardware_interface import DSCRadioDevice, RadioDeviceState

class CohdaMK5RadioDriver(DSCRadioDevice):
    def __init__(self, ip_address: str = "192.168.1.100"):
        super().__init__(device_id="cohda_mk5_0", channel_number=178)
        self.ip_address = ip_address
        self._socket = None

    def connect(self) -> bool:
        import socket
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.connect((self.ip_address, 4400))
        self.state = RadioDeviceState.READY
        return True

    def transmit_raw_frame(self, frame_bytes: bytes) -> int:
        return self._socket.send(frame_bytes)

    def receive_raw_frame(self, timeout_ms: int = 100) -> bytes:
        return self._socket.recv(4096)
```

---

## 4. Regulatory & Safety Notice

> [!WARNING]
> **RF Transmission Warning**:
> Operating in the 5.9 GHz ITS frequency band (5.850–5.925 GHz) requires:
> 1. Type-approved FCC Part 90/95 or ETSI EN 302 571 radio equipment.
> 2. An experimental or operational license from regulatory authorities (FCC in the United States, ETSI/national regulators in Europe).
> 3. RF power amplifiers, bandpass filters, and tuned 5.9 GHz vehicular antennas.
>
> **The default software-only simulation environment operates without RF hardware and does not emit electromagnetic radiation.**
