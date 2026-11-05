"""
Unit Tests for V2X Hardware Interface Stubs
===========================================
Validates:
  - RadioDeviceState enumeration
  - BaseV2XRadioDevice properties and status dictionary
  - DSCRadioDevice configuration and stub errors
  - CV2XRadioDevice configuration and stub errors
  - Explicit HardwareInterfaceNotImplementedError raising on RF attempts
"""

import pytest

from common.hardware_interface import (
    CV2XRadioDevice,
    DSCRadioDevice,
    HardwareInterfaceError,
    HardwareInterfaceNotImplementedError,
    RadioDeviceState,
)


class TestHardwareInterfaceStubs:
    """Ensure hardware stubs do not claim live RF operation and raise proper exceptions."""

    def test_dsrc_stub_status_and_config(self):
        radio = DSCRadioDevice(device_id="dsrc_0", channel_number=178, tx_power_dbm=20.0)
        assert radio.state == RadioDeviceState.DISCONNECTED

        status = radio.get_status()
        assert status["device_id"] == "dsrc_0"
        assert status["frequency_ghz"] == 5.890
        assert status["bandwidth_mhz"] == 10.0
        assert status["tx_power_dbm"] == 20.0

        radio.configure(tx_power_dbm=23.0)
        assert radio.tx_power_dbm == 23.0

    def test_dsrc_stub_connect_raises(self):
        radio = DSCRadioDevice(device_id="dsrc_0")
        with pytest.raises(HardwareInterfaceNotImplementedError) as exc_info:
            radio.connect()
        assert "not connected" in str(exc_info.value)
        assert radio.state == RadioDeviceState.ERROR

    def test_dsrc_stub_transmit_receive_raises(self):
        radio = DSCRadioDevice(device_id="dsrc_0")
        with pytest.raises(HardwareInterfaceNotImplementedError):
            radio.transmit_raw_frame(b"\x00" * 50)
        with pytest.raises(HardwareInterfaceNotImplementedError):
            radio.receive_raw_frame()

    def test_cv2x_stub_status_and_config(self):
        radio = CV2XRadioDevice(device_id="cv2x_0", frequency_hz=5.890e9, tx_power_dbm=23.0)
        assert radio.state == RadioDeviceState.DISCONNECTED

        status = radio.get_status()
        assert status["device_id"] == "cv2x_0"
        assert status["frequency_ghz"] == 5.890
        assert status["tx_power_dbm"] == 23.0

    def test_cv2x_stub_connect_raises(self):
        radio = CV2XRadioDevice(device_id="cv2x_0")
        with pytest.raises(HardwareInterfaceNotImplementedError) as exc_info:
            radio.connect()
        assert "not connected" in str(exc_info.value)
        assert radio.state == RadioDeviceState.ERROR

    def test_cv2x_stub_transmit_receive_raises(self):
        radio = CV2XRadioDevice(device_id="cv2x_0")
        with pytest.raises(HardwareInterfaceNotImplementedError):
            radio.transmit_raw_frame(b"\x00" * 50)
        with pytest.raises(HardwareInterfaceNotImplementedError):
            radio.receive_raw_frame()

