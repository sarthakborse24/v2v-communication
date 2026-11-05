"""
Unit Tests for V2X Channel Models
==================================
Tests:
  - Free Space Path Loss (FSPL) calibration (100 m @ 5.9 GHz ≈ 87.86 dB)
  - WINNER+ / 3GPP Highway LOS, Urban LOS, and Urban NLOS models
  - Monotonic path loss growth with distance
  - Fast fading (Rayleigh, Rician) gain distributions
  - Log-normal slow fading (shadowing)
  - Thermal noise power calculation (-97.0 dBm for 10 MHz BW, 7 dB NF)
  - Co-channel interference and SINR calculation
  - PDR sigmoid calculation and monotonicity with SINR
"""

import math
import numpy as np
import pytest

from simulation.channel.path_loss import (
    PathLossCalculator,
    PathLossType,
    free_space_path_loss,
    highway_los_path_loss,
    urban_los_path_loss,
    urban_nlos_path_loss,
)
from simulation.channel.fading import (
    ChannelFadingSimulator,
    FadingType,
)
from simulation.channel.interference import (
    ChannelInterferenceModel,
    compute_thermal_noise_power_dbm,
    dbm_to_mw,
    mw_to_dbm,
)


class TestPathLossModels:
    """Validate path loss formulas against known analytical points."""

    def test_fspl_at_100m_calibrated(self):
        """Standard assertion: FSPL at 100 m @ 5.9 GHz ≈ 87.86 dB."""
        pl = free_space_path_loss(100.0, fc_hz=5.9e9)
        assert pytest.approx(87.86, abs=0.1) == pl

    def test_fspl_at_1m(self):
        """At 1m, FSPL should be approx 47.86 dB."""
        pl = free_space_path_loss(1.0, fc_hz=5.9e9)
        assert pytest.approx(47.86, abs=0.1) == pl

    def test_fspl_monotonicity(self):
        """Path loss must strictly increase with distance."""
        distances = np.array([10.0, 50.0, 100.0, 200.0, 500.0])
        pl_values = free_space_path_loss(distances, fc_hz=5.9e9)
        assert np.all(np.diff(pl_values) > 0.0)

    def test_highway_los_dual_slope(self):
        """Highway LOS model should exhibit higher slope after breakpoint."""
        calc = PathLossCalculator(model_type=PathLossType.HIGHWAY_LOS)
        pl_50m = calc.compute_path_loss_db(50.0)
        pl_100m = calc.compute_path_loss_db(100.0)
        pl_300m = calc.compute_path_loss_db(300.0)
        assert pl_50m < pl_100m < pl_300m

    def test_urban_nlos_higher_loss_than_los(self):
        """Urban NLOS must exhibit greater attenuation than Urban LOS at same distance."""
        d = 150.0
        pl_los = urban_los_path_loss(d)
        pl_nlos = urban_nlos_path_loss(d)
        assert pl_nlos > pl_los


class TestFadingModels:
    """Validate fast and slow fading statistical properties."""

    def test_rayleigh_fading_mean_power(self):
        """Rayleigh fading power linear mean should be close to 1.0."""
        fader = ChannelFadingSimulator(fading_type=FadingType.RAYLEIGH, seed=42)
        # Sample 10,000 values
        gains_db = fader.sample_fast_fading_gain_db(count=10000)
        gains_lin = 10.0 ** (gains_db / 10.0)
        assert pytest.approx(1.0, abs=0.05) == float(np.mean(gains_lin))

    def test_rician_fading_variance_lower_than_rayleigh(self):
        """Rician fading (with dominant LOS path) has lower power variance than Rayleigh."""
        fader_rician = ChannelFadingSimulator(
            fading_type=FadingType.RICIAN, rician_k_db=9.0, seed=42
        )
        fader_rayleigh = ChannelFadingSimulator(
            fading_type=FadingType.RAYLEIGH, seed=42
        )
        r_rician = fader_rician.sample_fast_fading_gain_db(count=5000)
        r_rayleigh = fader_rayleigh.sample_fast_fading_gain_db(count=5000)
        assert np.var(r_rician) < np.var(r_rayleigh)

    def test_shadowing_std_dev(self):
        """Log-normal shadowing samples should reflect configured standard deviation."""
        fader = ChannelFadingSimulator(shadowing_std_db=4.0, seed=123)
        shadow_samples = fader.sample_shadowing_loss_db(count=10000)
        assert pytest.approx(4.0, abs=0.2) == float(np.std(shadow_samples))
        assert pytest.approx(0.0, abs=0.2) == float(np.mean(shadow_samples))


class TestInterferenceAndPDR:
    """Validate SINR calculations and PDR mapping."""

    def test_thermal_noise_power(self):
        """Thermal noise for 10 MHz BW & 7 dB NF must equal -97.0 dBm."""
        noise_dbm = compute_thermal_noise_power_dbm(bandwidth_hz=10e6, noise_figure_db=7.0)
        assert pytest.approx(-97.0, abs=0.05) == noise_dbm

    def test_mw_dbm_conversions(self):
        """0 dBm is 1 mW; 30 dBm is 1000 mW."""
        assert pytest.approx(1.0, abs=1e-5) == dbm_to_mw(0.0)
        assert pytest.approx(1000.0, abs=1e-3) == dbm_to_mw(30.0)
        assert pytest.approx(0.0, abs=1e-5) == mw_to_dbm(1.0)
        assert pytest.approx(30.0, abs=1e-5) == mw_to_dbm(1000.0)

    def test_sinr_calculation_without_interference(self):
        """Without interference, SINR = Prx - N0."""
        model = ChannelInterferenceModel(bandwidth_hz=10e6, noise_figure_db=7.0)
        # N0 is -97 dBm. If Prx is -80 dBm, SINR should be +17 dB
        sinr = model.compute_sinr_db(rx_power_dbm=-80.0, interferers_rx_power_dbm=[])
        assert pytest.approx(17.0, abs=0.1) == sinr

    def test_sinr_calculation_with_interferers(self):
        """Interference raises the noise floor, dropping SINR."""
        model = ChannelInterferenceModel(bandwidth_hz=10e6, noise_figure_db=7.0)
        sinr_no_intf = model.compute_sinr_db(rx_power_dbm=-80.0)
        sinr_with_intf = model.compute_sinr_db(
            rx_power_dbm=-80.0, interferers_rx_power_dbm=[-85.0, -88.0]
        )
        assert sinr_with_intf < sinr_no_intf

    def test_pdr_monotonicity_with_sinr(self):
        """PDR must monotonically increase as SINR improves."""
        model = ChannelInterferenceModel()
        sinr_values = [-10.0, 0.0, 5.0, 10.0, 15.0, 25.0]
        pdrs = [model.compute_pdr(s, technology="DSRC", mcs_index=3) for s in sinr_values]
        assert np.all(np.diff(pdrs) >= 0.0)
        assert pdrs[0] < 0.01
        assert pdrs[-1] > 0.99

    def test_cv2x_turbo_coding_advantage(self):
        """LTE-C-V2X (with turbo coding) should achieve higher PDR at low SINR (e.g. 5 dB) than DSRC."""
        model = ChannelInterferenceModel()
        # At SINR = 5 dB:
        # DSRC MCS 3 (threshold 7 dB) is below threshold -> PDR < 0.5
        # LTE MCS 10 (threshold 4.5 dB) is above threshold -> PDR > 0.5
        pdr_dsrc = model.compute_pdr(5.0, technology="DSRC", mcs_index=3)
        pdr_cv2x = model.compute_pdr(5.0, technology="CV2X", mcs_index=10)
        assert pdr_cv2x > pdr_dsrc

