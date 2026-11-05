"""
V2X Simulation Engine — Interference & SINR to PDR Model
=========================================================
[SIMULATION MODEL] Statistical co-channel interference, SINR, and Packet Delivery Ratio:
  - Thermal noise power calculation: N0 = -174 dBm/Hz + 10*log10(B) + NF
  - Received signal power computation: Prx = Ptx + Gtx + Grx - TotalAttenuation
  - Co-channel interference summation in linear domain (mW)
  - SINR = Prx / (N0 + sum(I_k))
  - Technology-dependent PDR mappings calibrated against 802.11p and LTE PC5 curves.

Standards References:
  - IEEE 802.11p-2010 Receiver Minimum Sensitivity (Table 18-14)
  - 3GPP TS 36.101 Annex G: Sidelink radio performance requirements
"""

from __future__ import annotations

import math
from typing import List, Optional, Tuple, Union
import numpy as np

# Boltzmann constant * 290K reference noise spectral density in dBm/Hz
THERMAL_NOISE_DENSITY_DBM_PER_HZ: float = -174.0

# Calibrated SINR threshold (dB) for 50% PDR on 802.11p (10 MHz OFDM, convolutional code)
DSRC_MCS_SINR_THRESHOLD_DB: dict[int, float] = {
    0: 2.0,   # BPSK 1/2, 3 Mbps
    1: 3.5,   # BPSK 3/4, 4.5 Mbps
    2: 5.0,   # QPSK 1/2, 6 Mbps
    3: 7.0,   # QPSK 3/4, 9 Mbps (default safety broadcast)
    4: 10.0,  # 16-QAM 1/2, 12 Mbps
    5: 14.0,  # 16-QAM 3/4, 18 Mbps
    6: 18.0,  # 64-QAM 2/3, 24 Mbps
    7: 20.0,  # 64-QAM 3/4, 27 Mbps
}

# Calibrated SINR threshold (dB) for 50% PDR on LTE-V2X PC5 (10 MHz SC-FDMA, Turbo code)
# Turbo coding offers ~2-3 dB advantage over convolutional coding.
CV2X_MCS_SINR_THRESHOLD_DB: dict[int, float] = {
    0: -2.0,  # QPSK 1/6
    2: 0.0,   # QPSK 1/3
    4: 1.5,   # QPSK 1/2
    6: 3.0,   # QPSK 2/3
    8: 4.0,   # QPSK 3/4
    10: 4.5,  # 16-QAM 1/2 (typical default)
    12: 7.0,  # 16-QAM 2/3
    14: 9.5,  # 16-QAM 3/4
    16: 12.0, # 16-QAM 5/6
    18: 14.0, # 64-QAM 2/3
    20: 16.5, # 64-QAM 3/4
}


def dbm_to_mw(dbm: float) -> float:
    """Convert power in dBm to milliwatts (mW)."""
    return 10.0 ** (dbm / 10.0)


def mw_to_dbm(mw: float) -> float:
    """Convert milliwatts (mW) to dBm."""
    if mw <= 0.0:
        return -150.0
    return 10.0 * math.log10(mw)


def compute_thermal_noise_power_dbm(
    bandwidth_hz: float = 10e6,
    noise_figure_db: float = 7.0,
) -> float:
    """Compute thermal noise power floor in dBm:
        N0 = -174 dBm/Hz + 10*log10(B) + NF

    For 10 MHz BW and 7 dB NF:
        N0 = -174 + 70 + 7 = -97.0 dBm
    """
    bw_db = 10.0 * math.log10(bandwidth_hz)
    return THERMAL_NOISE_DENSITY_DBM_PER_HZ + bw_db + noise_figure_db


class ChannelInterferenceModel:
    """Computes SINR and statistical Packet Delivery Ratio (PDR).

    [SIMULATION MODEL]
    """

    def __init__(
        self,
        bandwidth_hz: float = 10e6,
        noise_figure_db: float = 7.0,
        tx_antenna_gain_dbi: float = 0.0,
        rx_antenna_gain_dbi: float = 0.0,
    ):
        self.bandwidth_hz = bandwidth_hz
        self.noise_figure_db = noise_figure_db
        self.tx_antenna_gain_dbi = tx_antenna_gain_dbi
        self.rx_antenna_gain_dbi = rx_antenna_gain_dbi
        self.noise_floor_dbm = compute_thermal_noise_power_dbm(
            bandwidth_hz=bandwidth_hz,
            noise_figure_db=noise_figure_db,
        )
        self.noise_floor_mw = dbm_to_mw(self.noise_floor_dbm)

    def compute_received_power_dbm(
        self,
        tx_power_dbm: float,
        attenuation_db: float,
    ) -> float:
        """Calculate received signal power in dBm:
            Prx = Ptx + Gtx + Grx - Attenuation
        """
        return tx_power_dbm + self.tx_antenna_gain_dbi + self.rx_antenna_gain_dbi - attenuation_db

    def compute_sinr_db(
        self,
        rx_power_dbm: float,
        interferers_rx_power_dbm: Optional[List[float]] = None,
    ) -> float:
        """Compute Signal-to-Interference-plus-Noise Ratio (SINR) in dB:
            SINR_lin = Prx / (N0 + sum(I_k))
        """
        prx_mw = dbm_to_mw(rx_power_dbm)
        interference_mw = 0.0
        if interferers_rx_power_dbm:
            for i_dbm in interferers_rx_power_dbm:
                interference_mw += dbm_to_mw(i_dbm)

        total_noise_plus_interference = self.noise_floor_mw + interference_mw
        sinr_lin = prx_mw / total_noise_plus_interference
        if sinr_lin <= 0.0:
            return -50.0
        return 10.0 * math.log10(sinr_lin)

    def compute_pdr(
        self,
        sinr_db: float,
        technology: str = "DSRC",
        mcs_index: int = 3,
    ) -> float:
        """Calculate Packet Delivery Ratio (PDR ∈ [0.0, 1.0]) from SINR using sigmoid model.

        [SIMULATION MODEL]
            PDR(SINR) = 1 / (1 + exp(-slope * (SINR - threshold)))
        """
        tech_upper = technology.upper()
        if "DSRC" in tech_upper or "80211" in tech_upper:
            # DSRC curve
            threshold = DSRC_MCS_SINR_THRESHOLD_DB.get(mcs_index, 7.0)
            slope = 1.2
        else:
            # LTE-C-V2X curve (turbo coder provides steeper roll-off and lower threshold)
            # Find closest MCS entry
            closest_mcs = min(CV2X_MCS_SINR_THRESHOLD_DB.keys(), key=lambda k: abs(k - mcs_index))
            threshold = CV2X_MCS_SINR_THRESHOLD_DB[closest_mcs]
            slope = 1.5

        delta = slope * (sinr_db - threshold)
        # Numerical guard against overflow in exp
        if delta > 30.0:
            return 1.0
        if delta < -30.0:
            return 0.0

        pdr = 1.0 / (1.0 + math.exp(-delta))
        return float(min(max(pdr, 0.0), 1.0))

    def is_packet_delivered(
        self,
        sinr_db: float,
        technology: str = "DSRC",
        mcs_index: int = 3,
        rng: Optional[np.random.Generator] = None,
    ) -> Tuple[bool, float]:
        """Determine whether packet is successfully decoded based on statistical PDR.

        Returns:
            (is_delivered: bool, pdr: float)
        """
        pdr = self.compute_pdr(sinr_db, technology=technology, mcs_index=mcs_index)
        generator = rng if rng is not None else np.random.default_rng()
        rand_val = generator.uniform(0.0, 1.0)
        delivered = rand_val < pdr
        return delivered, pdr

