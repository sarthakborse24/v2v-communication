"""
V2X Simulation Engine — Path Loss Models
========================================
[SIMULATION MODEL] Statistical propagation path loss models for V2X:
  - Free Space Path Loss (FSPL / Friis)
  - 3GPP TR 36.885 / WINNER+ V2V Channel Models:
      * Highway LOS (dual-slope model with breakpoint)
      * Urban LOS (microcellular / street canyon)
      * Urban NLOS (building diffraction / corner)

Standards References:
  - 3GPP TR 36.885 v14.0.0 (2016-06) Table A.1-2: V2V channel models for 5.9 GHz
  - WINNER+ D5.3: Channel models for 4G and Beyond
  - IEEE 802.11p-2010 Channel Modelling
"""

from __future__ import annotations

from enum import Enum
import math
from typing import Union
import numpy as np

# Speed of light in vacuum (m/s)
C_LIGHT: float = 299792458.0

# Default V2X carrier frequency: 5.9 GHz (IEEE 802.11p / 3GPP Band 47)
DEFAULT_FC_HZ: float = 5.9e9
DEFAULT_FC_GHZ: float = 5.9


class PathLossType(str, Enum):
    """Path loss model variants."""
    FREE_SPACE = "free_space"
    HIGHWAY_LOS = "highway_los"
    URBAN_LOS = "urban_los"
    URBAN_NLOS = "urban_nlos"


def free_space_path_loss(
    distance_m: Union[float, np.ndarray],
    fc_hz: float = DEFAULT_FC_HZ,
) -> Union[float, np.ndarray]:
    """Calculate Free Space Path Loss (FSPL) in dB.

    [SIMULATION MODEL] Friis transmission formula:
        PL(d) = 20 * log10(d) + 20 * log10(fc) + 20 * log10(4 * pi / c)

    At 5.9 GHz:
        At d = 1 m  -> PL ≈ 47.86 dB
        At d = 100 m -> PL ≈ 87.86 dB
    """
    # Guard against distance <= 0
    d = np.maximum(distance_m, 0.1)
    wavelength = C_LIGHT / fc_hz
    fspl_const = 20.0 * np.log10(4.0 * np.pi / wavelength)
    pl_db = 20.0 * np.log10(d) + fspl_const

    if isinstance(distance_m, (int, float)):
        return float(pl_db)
    return pl_db


def highway_los_path_loss(
    distance_m: Union[float, np.ndarray],
    fc_ghz: float = DEFAULT_FC_GHZ,
    h_tx: float = 1.5,
    h_rx: float = 1.5,
) -> Union[float, np.ndarray]:
    """Calculate 3GPP TR 36.885 / WINNER+ Highway LOS path loss (dual-slope) in dB.

    [SIMULATION MODEL]
    Effective antenna heights:
        h'_tx = h_tx - 1.0 (min 0.5 m)
        h'_rx = h_rx - 1.0 (min 0.5 m)
    Breakpoint distance:
        d'_BP = 4 * h'_tx * h'_rx / lambda

    Before breakpoint (d < d'_BP):
        PL(d) = 32.4 + 20*log10(fc_ghz) + 20*log10(d)
    After breakpoint (d >= d'_BP):
        PL(d) = 32.4 + 20*log10(fc_ghz) + 40*log10(d / d'_BP) + 20*log10(d'_BP)
    """
    d = np.maximum(distance_m, 1.0)
    fc_hz = fc_ghz * 1e9
    wavelength = C_LIGHT / fc_hz

    h_tx_eff = max(h_tx - 1.0, 0.5)
    h_rx_eff = max(h_rx - 1.0, 0.5)
    d_bp = (4.0 * h_tx_eff * h_rx_eff) / wavelength

    pl_const = 32.4 + 20.0 * np.log10(fc_ghz)

    if isinstance(d, np.ndarray):
        pl_db = np.zeros_like(d, dtype=float)
        before_mask = d < d_bp
        after_mask = ~before_mask

        pl_db[before_mask] = pl_const + 20.0 * np.log10(d[before_mask])
        pl_db[after_mask] = (
            pl_const
            + 40.0 * np.log10(d[after_mask] / d_bp)
            + 20.0 * np.log10(d_bp)
        )
        return pl_db
    else:
        if d < d_bp:
            return float(pl_const + 20.0 * np.log10(d))
        else:
            return float(
                pl_const
                + 40.0 * np.log10(d / d_bp)
                + 20.0 * np.log10(d_bp)
            )


def urban_los_path_loss(
    distance_m: Union[float, np.ndarray],
    fc_ghz: float = DEFAULT_FC_GHZ,
) -> Union[float, np.ndarray]:
    """Calculate 3GPP TR 36.885 Urban LOS path loss in dB.

    [SIMULATION MODEL]
        PL(d) = 38.77 + 16.7 * log10(d) + 18.2 * log10(fc_ghz)
    """
    d = np.maximum(distance_m, 1.0)
    pl_db = 38.77 + 16.7 * np.log10(d) + 18.2 * np.log10(fc_ghz)
    if isinstance(distance_m, (int, float)):
        return float(pl_db)
    return pl_db


def urban_nlos_path_loss(
    distance_m: Union[float, np.ndarray],
    fc_ghz: float = DEFAULT_FC_GHZ,
) -> Union[float, np.ndarray]:
    """Calculate 3GPP TR 36.885 Urban NLOS path loss in dB.

    [SIMULATION MODEL]
        PL(d) = 36.85 + 30.0 * log10(d) + 18.9 * log10(fc_ghz)
    """
    d = np.maximum(distance_m, 1.0)
    pl_db = 36.85 + 30.0 * np.log10(d) + 18.9 * np.log10(fc_ghz)
    if isinstance(distance_m, (int, float)):
        return float(pl_db)
    return pl_db


class PathLossCalculator:
    """Configurable path loss calculator dispatching to the selected model."""

    def __init__(
        self,
        model_type: Union[PathLossType, str] = PathLossType.HIGHWAY_LOS,
        fc_hz: float = DEFAULT_FC_HZ,
        antenna_height_tx_m: float = 1.5,
        antenna_height_rx_m: float = 1.5,
    ):
        if isinstance(model_type, str):
            model_type = PathLossType(model_type)
        self.model_type = model_type
        self.fc_hz = fc_hz
        self.fc_ghz = fc_hz / 1e9
        self.antenna_height_tx_m = antenna_height_tx_m
        self.antenna_height_rx_m = antenna_height_rx_m

    def compute_path_loss_db(
        self,
        distance_m: Union[float, np.ndarray],
    ) -> Union[float, np.ndarray]:
        """Compute path loss in dB for given distance(s)."""
        if self.model_type == PathLossType.FREE_SPACE:
            return free_space_path_loss(distance_m, self.fc_hz)
        elif self.model_type == PathLossType.HIGHWAY_LOS:
            return highway_los_path_loss(
                distance_m,
                self.fc_ghz,
                self.antenna_height_tx_m,
                self.antenna_height_rx_m,
            )
        elif self.model_type == PathLossType.URBAN_LOS:
            return urban_los_path_loss(distance_m, self.fc_ghz)
        elif self.model_type == PathLossType.URBAN_NLOS:
            return urban_nlos_path_loss(distance_m, self.fc_ghz)
        else:
            raise ValueError(f"Unknown path loss model type: {self.model_type}")

