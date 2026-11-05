"""
V2X Gateway Simulator — 3GPP LTE-V2X Release 14 PHY Simulation Model
=====================================================================
DEVIATION L4:
  Statistical simulation model of 3GPP Release 14 PC5 sidelink physical layer.
  Models 1.0 ms subframe duration, PSCCH (2 PRB) + PSSCH multiplexing,
  receiver sensitivity, and SINR-to-BLER/PDR mapping.

Standards References:
  - 3GPP TS 36.211 Release 14: Section 9 (Sidelink)
  - 3GPP TS 36.213 Release 14: Section 14 (Sidelink procedures)
  - 3GPP TR 36.885: Study on LTE-based V2X Services
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class LTEMCSParameters:
    """LTE Sidelink PSSCH Modulation and Coding Scheme parameters."""
    index: int
    modulation: str
    modulation_order: int   # Qm: 2 for QPSK, 4 for 16-QAM, 6 for 64-QAM
    target_code_rate: float
    snr_threshold_db: float  # SNR threshold for 10% BLER
    sensitivity_dbm: float   # Minimum receiver sensitivity (dBm)


# 3GPP TS 36.213 Table 14.1.1-1: Representative LTE-V2X MCS parameters
LTE_V2X_MCS_TABLE: Dict[int, LTEMCSParameters] = {
    0:  LTEMCSParameters(0,  "QPSK",   2, 0.15, -4.5, -94.0),
    2:  LTEMCSParameters(2,  "QPSK",   2, 0.23, -2.5, -93.0),
    4:  LTEMCSParameters(4,  "QPSK",   2, 0.38,  0.5, -92.0),
    6:  LTEMCSParameters(6,  "QPSK",   2, 0.50,  2.5, -91.0),
    8:  LTEMCSParameters(8,  "QPSK",   2, 0.60,  4.5, -90.0),
    10: LTEMCSParameters(10, "16-QAM", 4, 0.37,  6.0, -89.0),  # Typical BSM default
    12: LTEMCSParameters(12, "16-QAM", 4, 0.48,  8.5, -87.0),
    14: LTEMCSParameters(14, "16-QAM", 4, 0.60, 11.0, -85.0),
    16: LTEMCSParameters(16, "16-QAM", 4, 0.74, 14.0, -82.0),
    18: LTEMCSParameters(18, "64-QAM", 6, 0.60, 16.5, -79.0),
    20: LTEMCSParameters(20, "64-QAM", 6, 0.75, 20.0, -75.0),
}

# Subframe duration per 3GPP TS 36.211 (1.0 ms)
SUBFRAME_DURATION_MS = 1.0

# PSCCH fixed allocation per TS 36.213 §14.2.4 (2 PRBs, QPSK rate 1/6)
PSCCH_PRBS = 2
PSCCH_SENSITIVITY_DBM = -96.0  # Extremely robust control channel


class LTEPhyModel:
    """[SIMULATION MODEL] Statistical physical layer model for LTE PC5 sidelink."""

    def __init__(
        self,
        default_mcs: int = 10,
        tx_power_dbm: float = 23.0,  # 23 dBm = 200 mW (3GPP standard UE power)
        antenna_gain_dbi: float = 0.0,
        noise_figure_db: float = 7.0,
        channel_bw_hz: float = 10e6,
    ):
        if default_mcs not in LTE_V2X_MCS_TABLE:
            # Fallback to closest known MCS
            default_mcs = 10
        self.default_mcs = default_mcs
        self.tx_power_dbm = tx_power_dbm
        self.antenna_gain_dbi = antenna_gain_dbi
        self.noise_figure_db = noise_figure_db
        self.channel_bw_hz = channel_bw_hz

        # Thermal noise floor at 290 K for 10 MHz: -174 + 70 + NF = -104 + NF
        self.noise_floor_dbm = -174.0 + 10.0 * math.log10(self.channel_bw_hz) + self.noise_figure_db

    @property
    def subframe_duration_ms(self) -> float:
        return SUBFRAME_DURATION_MS

    def calculate_sinr_db(
        self,
        rx_power_dbm: float,
        interference_power_dbm: Optional[float] = None,
    ) -> float:
        """Calculate SINR in dB."""
        noise_mw = 10.0 ** (self.noise_floor_dbm / 10.0)
        interf_mw = 10.0 ** (interference_power_dbm / 10.0) if interference_power_dbm is not None else 0.0
        signal_mw = 10.0 ** (rx_power_dbm / 10.0)

        total_noise_mw = noise_mw + interf_mw
        if total_noise_mw <= 0:
            return 100.0
        return 10.0 * math.log10(max(1e-10, signal_mw / total_noise_mw))

    def calculate_pdr(
        self,
        rx_power_dbm: float,
        mcs_index: Optional[int] = None,
        interference_power_dbm: Optional[float] = None,
    ) -> float:
        """Calculate Sidelink Packet Delivery Ratio (PDR ∈ [0.0, 1.0]).

        Uses standard 3GPP TR 36.885 sigmoid BLER model for LTE turbo codes:
          BLER(SINR) = 1 / (1 + exp(alpha * (SINR - SNR_thresh)))
          PDR = 1.0 - BLER
        """
        used_mcs = mcs_index if mcs_index is not None else self.default_mcs
        mcs = LTE_V2X_MCS_TABLE.get(used_mcs, LTE_V2X_MCS_TABLE[10])

        # If below receiver sensitivity, drop packet
        if rx_power_dbm < mcs.sensitivity_dbm:
            return 0.0

        sinr_db = self.calculate_sinr_db(rx_power_dbm, interference_power_dbm)

        # Sigmoid transition slope (alpha ≈ 1.5 for LTE turbo coding)
        alpha = 1.5
        snr_diff = sinr_db - mcs.snr_threshold_db

        # Prevent exp overflow
        if snr_diff > 15.0:
            bler = 0.0
        elif snr_diff < -15.0:
            bler = 1.0
        else:
            bler = 1.0 / (1.0 + math.exp(alpha * snr_diff))

        return max(0.0, min(1.0, 1.0 - bler))

    def simulate_reception(
        self,
        rx_power_dbm: float,
        mcs_index: Optional[int] = None,
        interference_power_dbm: Optional[float] = None,
        rng: Optional[random.Random] = None,
    ) -> bool:
        """Stochastic reception decision for a subframe."""
        pdr = self.calculate_pdr(
            rx_power_dbm=rx_power_dbm,
            mcs_index=mcs_index,
            interference_power_dbm=interference_power_dbm,
        )
        threshold = rng.random() if rng else random.random()
        return threshold < pdr
