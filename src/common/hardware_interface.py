"""
V2X Gateway Simulator — Hardware Radio Interface Abstraction
=============================================================
Extensible hardware driver interfaces for future integration with real physical
V2X radio hardware (SDR, dedicated OBUs/RSUs):
  - DSRC (IEEE 802.11p): Cohda Wireless MK5/MK6, Commsignia OBU, Ettus USRP SDR
  - LTE-C-V2X (3GPP PC5): Qualcomm 9150 C-V2X, Autotalks Secton/CRATON2

WARNING & INTEGRITY NOTICE:
  This simulator is a software protocol and channel simulator.
  Physical radio transmission requires compatible RF front-ends, baseband hardware,
  and regulatory transmission licenses in the 5.9 GHz ITS band (5.850-5.925 GHz).
  Any attempt to invoke live RF operations on these hardware stubs raises
  HardwareInterfaceNotImplementedError.

Standards References:
  - IEEE 802.11p-2010 / IEEE 1609.4
  - 3GPP TS 36.101 (E-UTRA Band 47 PC5 Sidelink)
  - FCC 47 CFR Part 95 Subpart L (DSRC) / FCC 20-164 (5.9 GHz Band)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional

from common.exceptions import V2XError
from monitoring.logger import get_logger

log = get_logger("common.hardware_interface")


class HardwareInterfaceError(V2XError):
    """Base exception for hardware radio interface operations."""


class HardwareInterfaceNotImplementedError(HardwareInterfaceError):
    """Raised when hardware transmission or reception is invoked without compatible RF hardware attached."""


class RadioDeviceState(str, Enum):
    """Operational state of a physical radio device."""
    DISCONNECTED = "DISCONNECTED"
    INITIALIZING = "INITIALIZING"
    READY = "READY"
    TRANSMITTING = "TRANSMITTING"
    RECEIVING = "RECEIVING"
    ERROR = "ERROR"


class BaseV2XRadioDevice(ABC):
    """Abstract Base Class for physical V2X radio transceivers."""

    def __init__(
        self,
        device_name: str,
        device_id: str,
        frequency_hz: float = 5.890e9,
        bandwidth_hz: float = 10e6,
        tx_power_dbm: float = 20.0,
    ):
        self.device_name = device_name
        self.device_id = device_id
        self.frequency_hz = frequency_hz
        self.bandwidth_hz = bandwidth_hz
        self.tx_power_dbm = tx_power_dbm
        self.state: RadioDeviceState = RadioDeviceState.DISCONNECTED
        self._rx_callback = None

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection with the radio hardware via USB, Ethernet, or PCI."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Safely shut down RF amplifiers and release hardware handles."""
        pass

    @abstractmethod
    def configure(
        self,
        frequency_hz: Optional[float] = None,
        bandwidth_hz: Optional[float] = None,
        tx_power_dbm: Optional[float] = None,
    ) -> None:
        """Reconfigure transceiver center frequency, channel bandwidth, and RF output power."""
        pass

    @abstractmethod
    def transmit_raw_frame(self, frame_bytes: bytes) -> int:
        """Transmit raw MAC frame or sidelink transport block over the air."""
        pass

    @abstractmethod
    def receive_raw_frame(self, timeout_ms: int = 100) -> Optional[bytes]:
        """Poll for an inbound raw frame from the radio receive buffer."""
        pass

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic health and status metrics."""
        return {
            "device_name": self.device_name,
            "device_id": self.device_id,
            "state": self.state.value,
            "frequency_ghz": self.frequency_hz / 1e9,
            "bandwidth_mhz": self.bandwidth_hz / 1e6,
            "tx_power_dbm": self.tx_power_dbm,
        }


class DSCRadioDevice(BaseV2XRadioDevice):
    """[HARDWARE INTERFACE STUB] Driver stub for IEEE 802.11p WAVE radio transceivers.

    Target hardware:
      - Cohda Wireless MK5 / MK6 OBU & RSU
      - Commsignia OBU / RSU
      - Software-Defined Radio (USRP B210 / X310 with gr-ieee802-11)
    """

    def __init__(
        self,
        device_id: str = "dsrc_radio_0",
        channel_number: int = 178,  # 5.890 GHz (CCH)
        tx_power_dbm: float = 20.0,
    ):
        super().__init__(
            device_name="DSRC-802.11p-Radio-Stub",
            device_id=device_id,
            frequency_hz=5.850e9 + (channel_number - 170) * 0.005e9,
            bandwidth_hz=10e6,
            tx_power_dbm=tx_power_dbm,
        )
        self.channel_number = channel_number

    def connect(self) -> bool:
        log.warning(
            f"[STUB] Physical DSRC hardware connection requested for {self.device_id}. "
            "No compatible IEEE 802.11p radio device detected."
        )
        self.state = RadioDeviceState.ERROR
        raise HardwareInterfaceNotImplementedError(
            f"Physical IEEE 802.11p hardware device '{self.device_id}' is not connected. "
            "Install vendor drivers (Cohda/Commsignia/UHD) and configure hardware interface. "
            "See docs/hardware_interface.md."
        )

    def disconnect(self) -> None:
        self.state = RadioDeviceState.DISCONNECTED
        log.info(f"DSRC radio device {self.device_id} disconnected")

    def configure(
        self,
        frequency_hz: Optional[float] = None,
        bandwidth_hz: Optional[float] = None,
        tx_power_dbm: Optional[float] = None,
    ) -> None:
        if frequency_hz is not None:
            self.frequency_hz = frequency_hz
        if bandwidth_hz is not None:
            self.bandwidth_hz = bandwidth_hz
        if tx_power_dbm is not None:
            self.tx_power_dbm = tx_power_dbm

    def transmit_raw_frame(self, frame_bytes: bytes) -> int:
        raise HardwareInterfaceNotImplementedError(
            "Live RF transmission over DSRC IEEE 802.11p requires physical radio hardware."
        )

    def receive_raw_frame(self, timeout_ms: int = 100) -> Optional[bytes]:
        raise HardwareInterfaceNotImplementedError(
            "Live RF reception over DSRC IEEE 802.11p requires physical radio hardware."
        )


class CV2XRadioDevice(BaseV2XRadioDevice):
    """[HARDWARE INTERFACE STUB] Driver stub for 3GPP LTE-V2X Release 14/15 PC5 transceivers.

    Target hardware:
      - Qualcomm 9150 C-V2X direct chipset
      - Autotalks Secton / CRATON2 V2X communication processor
      - SDR LTE PC5 Sidelink Transceiver (srsRAN / OpenAirInterface)
    """

    def __init__(
        self,
        device_id: str = "cv2x_radio_0",
        frequency_hz: float = 5.890e9,  # Band 47 (5.855-5.925 GHz)
        tx_power_dbm: float = 23.0,
    ):
        super().__init__(
            device_name="LTE-C-V2X-PC5-Radio-Stub",
            device_id=device_id,
            frequency_hz=frequency_hz,
            bandwidth_hz=10e6,
            tx_power_dbm=tx_power_dbm,
        )

    def connect(self) -> bool:
        log.warning(
            f"[STUB] Physical C-V2X hardware connection requested for {self.device_id}. "
            "No compatible 3GPP PC5 sidelink device detected."
        )
        self.state = RadioDeviceState.ERROR
        raise HardwareInterfaceNotImplementedError(
            f"Physical LTE-C-V2X PC5 hardware device '{self.device_id}' is not connected. "
            "Install Qualcomm 9150 / Autotalks / SDR PC5 driver stack. "
            "See docs/hardware_interface.md."
        )

    def disconnect(self) -> None:
        self.state = RadioDeviceState.DISCONNECTED
        log.info(f"C-V2X radio device {self.device_id} disconnected")

    def configure(
        self,
        frequency_hz: Optional[float] = None,
        bandwidth_hz: Optional[float] = None,
        tx_power_dbm: Optional[float] = None,
    ) -> None:
        if frequency_hz is not None:
            self.frequency_hz = frequency_hz
        if bandwidth_hz is not None:
            self.bandwidth_hz = bandwidth_hz
        if tx_power_dbm is not None:
            self.tx_power_dbm = tx_power_dbm

    def transmit_raw_frame(self, frame_bytes: bytes) -> int:
        raise HardwareInterfaceNotImplementedError(
            "Live RF transmission over LTE-C-V2X PC5 requires physical sidelink radio hardware."
        )

    def receive_raw_frame(self, timeout_ms: int = 100) -> Optional[bytes]:
        raise HardwareInterfaceNotImplementedError(
            "Live RF reception over LTE-C-V2X PC5 requires physical sidelink radio hardware."
        )
