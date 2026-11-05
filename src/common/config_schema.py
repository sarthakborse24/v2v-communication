"""
V2X Gateway Simulator — Default Configuration Schema
=====================================================
Loaded at startup by main.py.  Validated via Pydantic v2.
Override with environment-specific YAML files in configs/.
"""

from __future__ import annotations
from typing import Literal, Optional
from pydantic import BaseModel, Field, field_validator


class DSRCConfig(BaseModel):
    """DSRC (IEEE 802.11p / 1609.x) stack configuration."""

    # Channel (IEEE 1609.4)
    channel: int = Field(178, description="WAVE channel number; 178 = CCH (5.890 GHz)")
    tx_power_dbm: float = Field(20.0, ge=-30.0, le=33.0,
                                description="Transmit power in dBm (max 33 dBm per FCC Part 95)")
    mcs_index: int = Field(3, ge=0, le=7,
                           description="802.11p MCS index (0=BPSK-1/2 3Mbps, 7=64QAM-3/4 27Mbps)")

    # MAC (IEEE 1609.4)
    sync_interval_ms: int = Field(100, description="CCH+SCH sync interval in ms (IEEE 1609.4 §6.3)")
    cch_interval_ms: int = Field(50, description="CCH dwell time in ms")
    guard_interval_ms: float = Field(4.0, description="Guard interval at CCH/SCH boundary in ms")

    # PHY (IEEE 802.11p) — simulation model
    antenna_gain_dbi: float = Field(0.0, description="Antenna gain in dBi")
    noise_figure_db: float = Field(7.0, description="Receiver noise figure in dB")


class CV2XConfig(BaseModel):
    """LTE-C-V2X (3GPP R14 PC5) stack configuration."""

    # Resource pool (Mode 4)
    num_subchannels: int = Field(4, ge=1, le=25,
                                 description="Number of sub-channels in the resource pool")
    subchannel_prbs: int = Field(10, description="PRBs per sub-channel")
    sensing_window_ms: int = Field(100, description="Mode 4 sensing window in ms (TS 36.213 §14)")
    mcs_index: int = Field(10, ge=0, le=28,
                           description="LTE MCS index for PSSCH (0=QPSK, 28≈64QAM)")

    # PHY — simulation model
    tx_power_dbm: float = Field(23.0, ge=-30.0, le=33.0,
                                description="Transmit power in dBm")
    antenna_gain_dbi: float = Field(0.0)
    noise_figure_db: float = Field(7.0)


class SecurityConfig(BaseModel):
    """IEEE 1609.2 security configuration."""

    # Signing
    signature_algorithm: Literal["ecdsa-p256"] = "ecdsa-p256"  # Only P-256 supported

    # Replay protection (documented deviation L8: tighter than standard's ±20 min)
    replay_window_ms: int = Field(1_000, description="Max |generationTime - now| to accept (ms)")
    dedup_window_seconds: float = Field(2.0,
                                        description="Sliding window for (sourceID, msgCnt) dedup")

    # Pseudonym certificate pool
    pseudonym_pool_size: int = Field(20, ge=1,
                                     description="Number of pseudonym certs pre-provisioned per vehicle")
    pseudonym_rotation_interval_s: float = Field(300.0,
                                                 description="Seconds between pseudonym cert rotations")

    # Stubs (not implemented in this simulator)
    enable_revocation_check: bool = Field(False,
                                          description="STUB: CRL check not implemented; always NOT_REVOKED")
    enable_misbehavior_detection: bool = Field(False,
                                               description="STUB: Misbehavior detection not implemented")


class ChannelConfig(BaseModel):
    """Wireless channel model configuration."""

    model: Literal["winner_plus", "free_space", "two_ray"] = "winner_plus"
    environment: Literal["highway", "urban_intersection", "suburban"] = "highway"
    enable_fading: bool = Field(True, description="Enable Rayleigh fast fading")
    enable_interference: bool = Field(True, description="Enable co-channel interference model")
    carrier_frequency_hz: float = Field(5.9e9, description="Carrier frequency in Hz")
    temperature_kelvin: float = Field(293.15, description="Ambient temperature for thermal noise")


class SimulationConfig(BaseModel):
    """Simulation engine configuration."""

    duration_seconds: float = Field(30.0, ge=1.0,
                                    description="Total simulation time in seconds")
    seed: int = Field(42, description="Random seed for reproducibility")
    bsm_rate_hz: float = Field(10.0, ge=0.1, le=100.0,
                               description="BSM transmission rate per vehicle in Hz")
    real_time: bool = Field(False,
                            description="Run SimPy in real-time mode (slower; for demos)")


class GatewayConfig(BaseModel):
    """Bidirectional gateway configuration."""

    enable_dsrc_to_cv2x: bool = True
    enable_cv2x_to_dsrc: bool = True
    max_gateway_latency_ms: float = Field(5.0,
                                          description="Warn if gateway processing exceeds this")
    log_every_message: bool = Field(True,
                                    description="Log each gateway translation event (verbose)")


class V2XSimConfig(BaseModel):
    """Root configuration model — loaded from YAML and validated by Pydantic."""

    scenario: str = Field("highway", description="Scenario name (highway|intersection|mixed_stack)")
    num_dsrc_vehicles: int = Field(5, ge=0, le=200)
    num_cv2x_vehicles: int = Field(5, ge=0, le=200)

    dsrc: DSRCConfig = Field(default_factory=DSRCConfig)
    cv2x: CV2XConfig = Field(default_factory=CV2XConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    channel: ChannelConfig = Field(default_factory=ChannelConfig)
    simulation: SimulationConfig = Field(default_factory=SimulationConfig)
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)

    results_dir: str = Field("results", description="Directory for metrics CSV and plots")
    log_level: str = Field("INFO", description="Logging level: DEBUG|INFO|WARNING|ERROR")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v.upper()

