"""
V2X Gateway Simulator — IEEE 802.11p PHY Simulation Model
==========================================================
DEVIATION L1:
  This is a statistical simulation model, NOT an actual RF waveform generator.
  It calculates airtime, receiver sensitivity thresholds, and SINR-to-PDR
  probabilities per IEEE 802.11p Section 17 specifications.

Standards References:
  - IEEE 802.11p-2010: Section 17 (10 MHz OFDM PHY for 5.9 GHz)
  - IEEE 802.11-2016: Receiver sensitivity & timing parameters
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Dict, Optional, Tuple

from scipy.special import erfc

from common.message_types import (
    BSM_DEFAULT_CHANNEL,
    WAVEChannel,
)


# ---------------------------------------------------------------------------
# IEEE 802.11p 10 MHz MCS Parameters (IEEE 802.11p §17.3.2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MCSParameters:
    """Modulation and Coding Scheme parameters for 10 MHz WAVE channel."""
    index: int
    modulation: str
    coding_rate_str: str
    coding_rate: float
    data_rate_mbps: float
    n_dbps: int             # Data bits per OFDM symbol (52 data subcarriers)
    sensitivity_dbm: float  # Standard minimum receiver sensitivity (dBm)


# 802.11p 10 MHz MCS Table (half of 802.11a 20 MHz rates)
# Source: IEEE 802.11p-2010 Table 17-4
DSRC_MCS_TABLE: Dict[int, MCSParameters] = {
    0: MCSParameters(0, "BPSK",   "1/2", 0.500, 3.0,   24, -85.0),
    1: MCSParameters(1, "BPSK",   "3/4", 0.750, 4.5,   36, -84.0),
    2: MCSParameters(2, "QPSK",   "1/2", 0.500, 6.0,   48, -82.0),
    3: MCSParameters(3, "QPSK",   "3/4", 0.750, 9.0,   72, -80.0),  # Typical default for BSM
    4: MCSParameters(4, "16-QAM", "1/2", 0.500, 12.0,  96, -77.0),
    5: MCSParameters(5, "16-QAM", "3/4", 0.750, 18.0, 144, -73.0),
    6: MCSParameters(6, "64-QAM", "2/3", 0.667, 24.0, 192, -69.0),
    7: MCSParameters(7, "64-QAM", "3/4", 0.750, 27.0, 216, -68.0),
}

# Timing constants for 10 MHz channel (IEEE 802.11p §17.3.3)
PREAMBLE_DURATION_US = 32.0   # 10 short + 2 long training symbols
SIGNAL_DURATION_US   = 8.0    # 1 OFDM symbol (BPSK-1/2)
PLCP_OVERHEAD_US     = 40.0   # Preamble + SIGNAL (32 + 8 µs)
OFDM_SYMBOL_US       = 8.0    # 6.4 µs FFT + 1.6 µs Guard Interval
SERVICE_BITS         = 16
TAIL_BITS            = 6


class DSRCPhyModel:
    """[SIMULATION MODEL] Models IEEE 802.11p radio transmission and packet delivery."""

    def __init__(
        self,
        default_mcs: int = 3,
        tx_power_dbm: float = 20.0,
        antenna_gain_dbi: float = 0.0,
        noise_figure_db: float = 7.0,
        channel_bw_hz: float = 10e6,
    ):
        if default_mcs not in DSRC_MCS_TABLE:
            raise ValueError(f"Invalid MCS index {default_mcs}; must be 0..7")

        self.default_mcs = default_mcs
        self.tx_power_dbm = tx_power_dbm
        self.antenna_gain_dbi = antenna_gain_dbi
        self.noise_figure_db = noise_figure_db
        self.channel_bw_hz = channel_bw_hz

        # Thermal noise floor at 290K: N = k * T * B * NF
        # N = -174 dBm/Hz + 10*log10(10 MHz) + NF = -174 + 70 + NF = -104 + NF
        self.noise_floor_dbm = -174.0 + 10.0 * math.log10(self.channel_bw_hz) + self.noise_figure_db

    def calculate_transmission_time_us(
        self,
        payload_bytes: int,
        mcs_index: Optional[int] = None,
    ) -> float:
        """Compute over-the-air transmission duration in microseconds.

        Formula (IEEE 802.11p §17.3.5.4):
          N_sym = ceil((8 * payload_bytes + 16 + 6) / N_dbps)
          T_tx = T_preamble + T_signal + N_sym * T_sym
        """
        mcs = DSRC_MCS_TABLE[mcs_index if mcs_index is not None else self.default_mcs]
        total_bits = (payload_bytes * 8) + SERVICE_BITS + TAIL_BITS
        num_symbols = math.ceil(total_bits / mcs.n_dbps)
        return PLCP_OVERHEAD_US + (num_symbols * OFDM_SYMBOL_US)

    def calculate_sinr_db(
        self,
        rx_power_dbm: float,
        interference_power_dbm: Optional[float] = None,
    ) -> float:
        """Compute Signal-to-Interference-plus-Noise Ratio (SINR) in dB."""
        noise_mw = 10.0 ** (self.noise_floor_dbm / 10.0)
        interference_mw = 10.0 ** (interference_power_dbm / 10.0) if interference_power_dbm is not None else 0.0
        signal_mw = 10.0 ** (rx_power_dbm / 10.0)

        total_noise_mw = noise_mw + interference_mw
        if total_noise_mw <= 0:
            return 100.0
        sinr_linear = signal_mw / total_noise_mw
        return 10.0 * math.log10(max(1e-10, sinr_linear))

    def calculate_pdr(
        self,
        rx_power_dbm: float,
        payload_bytes: int,
        mcs_index: Optional[int] = None,
        interference_power_dbm: Optional[float] = None,
    ) -> float:
        """Calculate Packet Delivery Ratio (PDR ∈ [0.0, 1.0]) for a received frame.

        Uses analytical BER approximations for digital modulation under AWGN/fading:
          - BPSK: BER = 0.5 * erfc(sqrt(Eb/N0))
          - QPSK: BER = 0.5 * erfc(sqrt(Eb/N0))
          - 16-QAM: BER ≈ (3/8) * erfc(sqrt(Eb/N0 / 2.5))
          - 64-QAM: BER ≈ (7/24) * erfc(sqrt(Eb/N0 / 7))
          PDR = (1 - BER) ** (8 * payload_bytes)
        """
        mcs = DSRC_MCS_TABLE[mcs_index if mcs_index is not None else self.default_mcs]

        # Fast path: below receiver sensitivity -> frame cannot be decoded
        if rx_power_dbm < mcs.sensitivity_dbm:
            return 0.0

        sinr_db = self.calculate_sinr_db(rx_power_dbm, interference_power_dbm)
        sinr_linear = 10.0 ** (sinr_db / 10.0)

        # Eb/N0 = SINR * (Bandwidth / BitRate)
        bit_rate_bps = mcs.data_rate_mbps * 1e6
        eb_n0 = sinr_linear * (self.channel_bw_hz / bit_rate_bps)

        if eb_n0 <= 0:
            return 0.0

        # Modulation-specific BER calculation
        mod = mcs.modulation
        if mod in ("BPSK", "QPSK"):
            ber = 0.5 * erfc(math.sqrt(max(0.0, eb_n0)))
        elif mod == "16-QAM":
            ber = (3.0 / 8.0) * erfc(math.sqrt(max(0.0, eb_n0 / 2.5)))
        elif mod == "64-QAM":
            ber = (7.0 / 24.0) * erfc(math.sqrt(max(0.0, eb_n0 / 7.0)))
        else:
            ber = 0.5 * erfc(math.sqrt(eb_n0))

        # Clamp BER
        ber = min(0.5, max(1e-12, ber))

        # Packet error rate over total frame bits
        total_bits = (payload_bytes * 8) + SERVICE_BITS + TAIL_BITS
        # Incorporate forward error correction coding gain
        effective_ber = ber ** (1.0 + mcs.coding_rate)
        pdr = (1.0 - effective_ber) ** total_bits
        return max(0.0, min(1.0, float(pdr)))

    def simulate_reception(
        self,
        rx_power_dbm: float,
        payload_bytes: int,
        mcs_index: Optional[int] = None,
        interference_power_dbm: Optional[float] = None,
        rng: Optional[random.Random] = None,
    ) -> bool:
        """Stochastic reception decision: True if frame decoded successfully."""
        pdr = self.calculate_pdr(
            rx_power_dbm=rx_power_dbm,
            payload_bytes=payload_bytes,
            mcs_index=mcs_index,
            interference_power_dbm=interference_power_dbm,
        )
        threshold = rng.random() if rng else random.random()
        return threshold < pdr
