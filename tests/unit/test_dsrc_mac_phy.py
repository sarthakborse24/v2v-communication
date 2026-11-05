"""
Unit Tests for IEEE 1609.4 MAC & IEEE 802.11p PHY Simulation Models
===================================================================
Standards References:
  - IEEE 1609.4-2016: Multi-channel intervals
  - IEEE 802.11p-2010: Section 17 (10 MHz OFDM PHY)
"""

import math
import random
import pytest

from common.message_types import (
    BSM_EDCA_CATEGORY,
    EDCACategory,
    WAVEChannel,
)
from dsrc.mac.wave_mac import (
    ChannelAccessMode,
    ChannelInterval,
    WAVEMAC,
)
from dsrc.phy.dsrc_phy import (
    DSRC_MCS_TABLE,
    DSRCPhyModel,
    OFDM_SYMBOL_US,
    PLCP_OVERHEAD_US,
)
from dsrc.wave.wave_frame import WAVEFrame


class TestWAVEMAC:
    """Tests for IEEE 1609.4 multi-channel operation and 802.11e EDCA."""

    def test_alternating_access_timing(self):
        """Verify 100 ms sync cycle phases:
        0..4 ms -> GUARD, 4..50 ms -> CCH, 50..54 ms -> GUARD, 54..100 ms -> SCH.
        """
        mac = WAVEMAC(
            access_mode=ChannelAccessMode.ALTERNATING,
            sync_interval_ms=100.0,
            cch_interval_ms=50.0,
            guard_interval_ms=4.0,
        )

        # 2.0 ms: inside first guard interval
        interval, chan = mac.get_current_interval(2.0)
        assert interval == ChannelInterval.GUARD_INTERVAL

        # 20.0 ms: inside CCH interval
        interval, chan = mac.get_current_interval(20.0)
        assert interval == ChannelInterval.CCH_INTERVAL
        assert chan == WAVEChannel.CCH_178

        # 52.0 ms: inside second guard interval
        interval, chan = mac.get_current_interval(52.0)
        assert interval == ChannelInterval.GUARD_INTERVAL

        # 75.0 ms: inside SCH interval
        interval, chan = mac.get_current_interval(75.0)
        assert interval == ChannelInterval.SCH_INTERVAL
        assert chan == WAVEChannel.SCH_172

        # 120.0 ms: wraps to next cycle (offset 20 ms -> CCH)
        interval, chan = mac.get_current_interval(120.0)
        assert interval == ChannelInterval.CCH_INTERVAL

    def test_continuous_cch_access(self):
        """Dedicated safety radio should remain permanently on CCH with 0 wait time."""
        mac = WAVEMAC(access_mode=ChannelAccessMode.CONTINUOUS_CCH)
        interval, chan = mac.get_current_interval(75.0)
        assert interval == ChannelInterval.CCH_INTERVAL
        assert chan == WAVEChannel.CCH_178
        assert mac.time_until_channel_ready_ms(WAVEChannel.CCH_178, 75.0) == 0.0

    def test_edca_priority_queuing(self):
        """AC_VO frames must be dequeued strictly before AC_BE and AC_BK."""
        mac = WAVEMAC()

        frame_bk = WAVEFrame(payload=b"BK", edca_category=EDCACategory.AC_BK)
        frame_be = WAVEFrame(payload=b"BE", edca_category=EDCACategory.AC_BE)
        frame_vo = WAVEFrame(payload=b"VO", edca_category=EDCACategory.AC_VO)

        # Enqueue in reverse priority order
        mac.enqueue_frame(frame_bk)
        mac.enqueue_frame(frame_be)
        mac.enqueue_frame(frame_vo)

        # Dequeue must return AC_VO first
        first = mac.dequeue_next_frame()
        assert first is not None
        assert first.payload == b"VO"
        assert first.edca_category == EDCACategory.AC_VO

        # Then AC_BE
        second = mac.dequeue_next_frame()
        assert second is not None
        assert second.payload == b"BE"

        # Then AC_BK
        third = mac.dequeue_next_frame()
        assert third is not None
        assert third.payload == b"BK"

    def test_edca_backoff_ordering(self):
        """AC_VO should have smaller average backoff than AC_BK."""
        mac = WAVEMAC()
        rng = random.Random(42)

        vo_delays = [mac.calculate_edca_backoff_us(EDCACategory.AC_VO, rng=rng) for _ in range(100)]
        bk_delays = [mac.calculate_edca_backoff_us(EDCACategory.AC_BK, rng=rng) for _ in range(100)]

        avg_vo = sum(vo_delays) / len(vo_delays)
        avg_bk = sum(bk_delays) / len(bk_delays)

        assert avg_vo < avg_bk, f"Expected AC_VO delay ({avg_vo}) < AC_BK delay ({avg_bk})"


class TestDSRCPhyModel:
    """Tests for IEEE 802.11p PHY simulation model."""

    def test_transmission_airtime_formula(self):
        phy = DSRCPhyModel(default_mcs=3)  # QPSK-3/4 -> 72 bits/symbol
        payload_bytes = 100

        # Total bits = 100*8 + 16 (service) + 6 (tail) = 822 bits
        # Num symbols = ceil(822 / 72) = 12 symbols
        # Airtime = 40 µs + 12 * 8 µs = 136 µs
        airtime = phy.calculate_transmission_time_us(payload_bytes, mcs_index=3)
        assert airtime == 136.0

    def test_higher_mcs_reduces_airtime(self):
        phy = DSRCPhyModel()
        payload = 200
        time_mcs0 = phy.calculate_transmission_time_us(payload, mcs_index=0)  # 3 Mbps
        time_mcs7 = phy.calculate_transmission_time_us(payload, mcs_index=7)  # 27 Mbps
        assert time_mcs7 < time_mcs0

    def test_pdr_high_snr(self):
        """Under high signal strength (-50 dBm, well above -80 dBm sensitivity), PDR should be ~1.0."""
        phy = DSRCPhyModel(default_mcs=3)
        pdr = phy.calculate_pdr(rx_power_dbm=-50.0, payload_bytes=100)
        assert pdr > 0.99

    def test_pdr_below_sensitivity(self):
        """Under signal strength below sensitivity threshold (-95 dBm < -80 dBm), PDR must be 0.0."""
        phy = DSRCPhyModel(default_mcs=3)
        pdr = phy.calculate_pdr(rx_power_dbm=-95.0, payload_bytes=100)
        assert pdr == 0.0

    def test_pdr_decreases_with_interference(self):
        phy = DSRCPhyModel(default_mcs=3)
        pdr_clean = phy.calculate_pdr(rx_power_dbm=-70.0, payload_bytes=100)
        pdr_interfered = phy.calculate_pdr(
            rx_power_dbm=-70.0,
            payload_bytes=100,
            interference_power_dbm=-65.0,
        )
        assert pdr_interfered < pdr_clean

