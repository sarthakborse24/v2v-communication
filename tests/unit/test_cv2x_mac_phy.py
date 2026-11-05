"""
Unit Tests for LTE-C-V2X MAC (Mode 4) & PHY Simulation Models
==============================================================
Standards References:
  - 3GPP TS 36.213 Release 14: Section 14.1.1.6 (Mode 4 Sensing)
  - 3GPP TS 36.211 Release 14: Section 9 (Sidelink PHY)
"""

import random
import pytest

from common.message_types import V2XPriority
from cv2x.mac.lte_mac import LTEMAC
from cv2x.pc5.resource_pool import Mode4ResourcePool
from cv2x.pc5.sidelink import SCIFormat1
from cv2x.phy.lte_phy import (
    LTE_V2X_MCS_TABLE,
    LTEPhyModel,
    SUBFRAME_DURATION_MS,
)


class TestMode4ResourcePool:
    """Tests for 3GPP TS 36.213 §14.1.1.6 Mode 4 sensing-based selection."""

    def test_initial_selection_without_sensing(self):
        pool = Mode4ResourcePool(num_subchannels=4, selection_window_ms=100)
        rng = random.Random(42)

        subframe, subch, sps_cnt = pool.select_resource(
            current_subframe=1000,
            rng=rng,
        )
        assert 1004 <= subframe <= 1100  # Within selection window [n+4, n+100]
        assert 0 <= subch <= 3           # Within 4 subchannels
        assert 5 <= sps_cnt <= 15        # Standard SPS counter range

    def test_sps_counter_decrements_on_retention(self):
        pool = Mode4ResourcePool(num_subchannels=4, default_rri_ms=100)
        rng = random.Random(42)

        # Initial selection
        sf1, ch1, cnt1 = pool.select_resource(current_subframe=1000, rng=rng)

        # Second selection with active SPS reservation
        sf2, ch2, cnt2 = pool.select_resource(current_subframe=sf1, rng=rng)
        assert ch2 == ch1                # Retained same subchannel
        assert sf2 == sf1 + 100          # Advanced by 1 RRI period (100 ms)
        assert cnt2 == cnt1 - 1          # Counter decremented by 1

    def test_sensing_exclusion_avoids_busy_subchannel(self):
        pool = Mode4ResourcePool(num_subchannels=2, selection_window_ms=20)
        rng = random.Random(42)

        # Sensed high interference on subchannel 0 at future periodic intervals
        sci_peer = SCIFormat1(
            priority=1,
            resource_reservation=3,  # RRI = 100 ms
            freq_resource_location=0,
        )
        # Peer transmitted with high power on subchannel 0 projecting onto candidates
        for sf_offset in range(4, 21):
            pool.record_sensed_transmission(
                subframe_index=1000 + sf_offset - 100,
                subchannel_index=0,
                sci=sci_peer,
                measured_rssi_dbm=-60.0,  # High power above -95 dBm threshold
            )

        # Selection at subframe 1000
        sf, subch, _ = pool.select_resource(current_subframe=1000, rng=rng)
        # Subchannel 1 must be chosen because subchannel 0 has high sensed energy
        assert subch == 1


class TestLTEMAC:
    """Tests for LTE Sidelink MAC layer."""

    def test_prepare_transmission(self):
        mac = LTEMAC(
            source_l2_id=b"\x01\x02\x03",
            default_mcs=10,
        )
        payload = b"SPDU-TEST-PAYLOAD"

        unit = mac.prepare_transmission(
            payload=payload,
            priority=V2XPriority.SAFETY_CRITICAL,
            current_subframe=500,
        )

        assert unit.sci.priority == int(V2XPriority.SAFETY_CRITICAL)
        assert unit.sci.mcs == 10
        assert unit.transport_block.source_l2_id == b"\x01\x02\x03"
        assert unit.transport_block.payload == payload
        assert unit.scheduled_subframe >= 504
        assert len(unit.raw_sci_bytes) == 4
        assert len(unit.raw_tb_bytes) == len(payload) + 11


class TestLTEPhyModel:
    """Tests for LTE PC5 physical layer simulation model."""

    def test_subframe_duration(self):
        phy = LTEPhyModel()
        assert phy.subframe_duration_ms == 1.0

    def test_pdr_high_snr(self):
        """High signal strength (-60 dBm, well above sensitivity) should yield PDR > 0.99."""
        phy = LTEPhyModel(default_mcs=10)
        pdr = phy.calculate_pdr(rx_power_dbm=-60.0)
        assert pdr > 0.99

    def test_pdr_below_sensitivity(self):
        """Signal strength below sensitivity threshold should yield PDR = 0.0."""
        phy = LTEPhyModel(default_mcs=10)  # MCS 10 sensitivity is -89 dBm
        pdr = phy.calculate_pdr(rx_power_dbm=-95.0)
        assert pdr == 0.0

    def test_interference_degrades_pdr(self):
        phy = LTEPhyModel(default_mcs=10)
        pdr_clean = phy.calculate_pdr(rx_power_dbm=-82.0)
        pdr_interf = phy.calculate_pdr(rx_power_dbm=-82.0, interference_power_dbm=-80.0)
        assert pdr_interf < pdr_clean
