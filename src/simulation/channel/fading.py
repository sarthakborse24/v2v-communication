"""
V2X Simulation Engine — Fast and Slow Fading Models
===================================================
[SIMULATION MODEL] Statistical wireless channel fading:
  - Rayleigh fast fading (multipath envelope, Exp(1) power gain)
  - Rician fast fading (specular LOS component + multipath diffuse, K-factor)
  - Log-normal shadowing (slow fading, standard deviation sigma in dB)

Standards References:
  - 3GPP TR 36.885 v14.0.0 Table A.1-2 (Shadow fading std dev: 3 dB LOS, 6-8 dB NLOS)
  - ITU-R M.1225: Guidelines for evaluation of radio transmission technologies
"""

from __future__ import annotations

from enum import Enum
import math
from typing import Optional, Union
import numpy as np
from scipy import stats


class FadingType(str, Enum):
    """Fast fading distribution."""
    NONE = "none"
    RAYLEIGH = "rayleigh"
    RICIAN = "rician"


class ChannelFadingSimulator:
    """Simulates statistical small-scale fading and large-scale shadowing.

    [SIMULATION MODEL]
    """

    def __init__(
        self,
        fading_type: Union[FadingType, str] = FadingType.RAYLEIGH,
        rician_k_db: float = 6.0,
        shadowing_enabled: bool = True,
        shadowing_std_db: float = 3.0,
        seed: Optional[int] = None,
    ):
        if isinstance(fading_type, str):
            fading_type = FadingType(fading_type)
        self.fading_type = fading_type
        self.rician_k_db = rician_k_db
        # Linear K factor: K_lin = 10^(K_db / 10)
        self.rician_k_lin = 10.0 ** (rician_k_db / 10.0)
        self.shadowing_enabled = shadowing_enabled
        self.shadowing_std_db = shadowing_std_db
        self.rng = np.random.default_rng(seed)

    def sample_fast_fading_gain_db(self, count: int = 1) -> Union[float, np.ndarray]:
        """Sample fast fading power gain in dB (can be positive or negative).

        Power gain = 10 * log10(|h|^2).
        For Rayleigh: |h|^2 ~ Exponential(scale=1.0).
        For Rician: |h| ~ Rice(b = sqrt(2*K)), normalized so E[|h|^2] = 1.0.
        """
        if self.fading_type == FadingType.NONE:
            return 0.0 if count == 1 else np.zeros(count, dtype=float)

        if self.fading_type == FadingType.RAYLEIGH:
            # Exponential distribution with mean = 1.0
            power_lin = self.rng.exponential(scale=1.0, size=count)
            # Clip very small values to prevent log10(0)
            power_lin = np.maximum(power_lin, 1e-12)
            gain_db = 10.0 * np.log10(power_lin)
            return float(gain_db[0]) if count == 1 else gain_db

        elif self.fading_type == FadingType.RICIAN:
            # Non-central chi distribution with 2 degrees of freedom
            # Parameter b for scipy.stats.rice is sqrt(2 * K)
            b = np.sqrt(2.0 * self.rician_k_lin)
            scale = 1.0 / np.sqrt(2.0 * (self.rician_k_lin + 1.0))
            envelope = stats.rice.rvs(b=b, scale=scale, size=count, random_state=self.rng)
            power_lin = np.maximum(envelope ** 2, 1e-12)
            gain_db = 10.0 * np.log10(power_lin)
            return float(gain_db[0]) if count == 1 else gain_db

        raise ValueError(f"Unknown fading type: {self.fading_type}")

    def sample_shadowing_loss_db(self, count: int = 1) -> Union[float, np.ndarray]:
        """Sample log-normal shadowing loss in dB (positive adds loss, negative reduces loss).

        Shadowing ~ Normal(0, sigma_shadow^2).
        """
        if not self.shadowing_enabled or self.shadowing_std_db <= 0.0:
            return 0.0 if count == 1 else np.zeros(count, dtype=float)

        loss_db = self.rng.normal(0.0, self.shadowing_std_db, size=count)
        return float(loss_db[0]) if count == 1 else loss_db

    def compute_total_attenuation_db(
        self,
        path_loss_db: Union[float, np.ndarray],
    ) -> Union[float, np.ndarray]:
        """Compute total attenuation = path_loss + shadowing - fast_fading_gain.

        Returns attenuation in dB (higher means weaker signal).
        """
        if isinstance(path_loss_db, (int, float)):
            fast_gain = self.sample_fast_fading_gain_db(count=1)
            shadow_loss = self.sample_shadowing_loss_db(count=1)
            return float(path_loss_db + shadow_loss - fast_gain)
        else:
            n = len(path_loss_db)
            fast_gain = self.sample_fast_fading_gain_db(count=n)
            shadow_loss = self.sample_shadowing_loss_db(count=n)
            return path_loss_db + shadow_loss - fast_gain
