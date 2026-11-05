"""
V2X Gateway Simulator — 3GPP Release 14 Mode 4 Autonomous Resource Pool
========================================================================
Implements Mode 4 Autonomous Sensing-Based Resource Selection:
  - 100 ms Sensing Window & S-RSSI measurement recording
  - Candidate Resource exclusion based on decoded SCI reservations
  - Semi-Persistent Scheduling (SPS) counter & reselection

Standards References:
  - 3GPP TS 36.213 Release 14: Section 14.1.1.6 (UE autonomous resource selection)
  - 3GPP TS 36.331 Release 14: Sidelink pre-configuration

DEVIATION L4:
  Statistical model of Mode 4 sensing and SPS; sub-frame collisions are modeled
  statistically without full HARQ turbo-decoder processing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import random
from typing import Dict, List, Optional, Set, Tuple

from common.exceptions import ResourcePoolError
from cv2x.pc5.sidelink import SCIFormat1
from monitoring.logger import get_logger

log = get_logger("cv2x.mode4")


@dataclass
class CandidateResource:
    """Represents a candidate transmission resource in time and frequency."""
    subframe_index: int       # Subframe index (ms)
    subchannel_index: int     # Sub-channel index in frequency pool
    s_rssi_dbm: float = -110.0  # Measured energy on this resource


class Mode4ResourcePool:
    """Manages the C-V2X Mode 4 resource pool and sensing-based selection."""

    def __init__(
        self,
        num_subchannels: int = 4,
        subchannel_size_prbs: int = 10,
        sensing_window_ms: int = 100,
        selection_window_ms: int = 100,
        default_rri_ms: int = 100,
        s_rssi_threshold_dbm: float = -95.0,
        prob_resource_keep: float = 0.4,
    ):
        self.num_subchannels = num_subchannels
        self.subchannel_size_prbs = subchannel_size_prbs
        self.sensing_window_ms = sensing_window_ms
        self.selection_window_ms = selection_window_ms
        self.default_rri_ms = default_rri_ms
        self.s_rssi_threshold_dbm = s_rssi_threshold_dbm
        self.prob_resource_keep = prob_resource_keep

        # Sensing history: maps (subframe_index, subchannel_index) -> (s_rssi_dbm, reservation_rri_ms)
        self._sensing_history: Dict[Tuple[int, int], Tuple[float, int]] = {}

        # SPS state for this UE: (subchannel, subframe_offset, reselection_counter)
        self._current_reservation: Optional[Tuple[int, int]] = None
        self._sps_counter: int = 0

    @property
    def has_active_sps_reservation(self) -> bool:
        return self._current_reservation is not None and self._sps_counter > 0

    def record_sensed_transmission(
        self,
        subframe_index: int,
        subchannel_index: int,
        sci: SCIFormat1,
        measured_rssi_dbm: float,
    ) -> None:
        """Record an observed peer transmission from PSCCH decoding into the sensing window."""
        rri = sci.reservation_interval_ms
        self._sensing_history[(subframe_index, subchannel_index)] = (measured_rssi_dbm, rri)

    def prune_sensing_window(self, current_subframe: int) -> None:
        """Remove observations older than sensing_window_ms."""
        cutoff = current_subframe - self.sensing_window_ms
        expired = [k for k in self._sensing_history if k[0] < cutoff]
        for k in expired:
            del self._sensing_history[k]

    def select_resource(
        self,
        current_subframe: int,
        priority: int = 1,
        rng: Optional[random.Random] = None,
    ) -> Tuple[int, int, int]:
        """Execute 3GPP TS 36.213 §14.1.1.6 Mode 4 sensing-based resource selection.

        Steps:
          1. Check if active SPS reservation can be retained (reselection counter > 0).
          2. Generate Candidate Single-Subframe Resources (CSR) in selection window [n+T1, n+T2].
          3. Exclude CSRs that conflict with future reservations of sensed peers with S-RSSI > threshold.
          4. Ensure at least 20% of candidates remain (adjust threshold if necessary).
          5. Select randomly from the lowest-energy 20% candidate subset.
          6. Draw new SPS reselection counter in [5, 15].

        Returns:
            Tuple of (scheduled_subframe, subchannel_index, sps_reselection_counter).
        """
        r = rng if rng is not None else random

        # 1. Semi-Persistent Scheduling (SPS) retention
        if self._current_reservation is not None and self._sps_counter > 0:
            self._sps_counter -= 1
            subchannel, prev_subframe = self._current_reservation
            # Next periodic allocation at current_subframe + RRI
            scheduled_subframe = current_subframe + self.default_rri_ms
            self._current_reservation = (subchannel, scheduled_subframe)

            # If counter expired, probabilistically decide whether to keep or re-sense
            if self._sps_counter == 0 and r.random() < self.prob_resource_keep:
                self._sps_counter = r.randint(5, 15)
                return scheduled_subframe, subchannel, self._sps_counter
            elif self._sps_counter > 0:
                return scheduled_subframe, subchannel, self._sps_counter

        # 2. Generate Candidate Single-Subframe Resources (CSR) in selection window
        # Selection window: [n + 4, n + 100] ms per TS 36.213
        t1 = 4
        t2 = min(100, self.selection_window_ms)
        all_candidates: List[CandidateResource] = []

        for sf_offset in range(t1, t2 + 1):
            sf = current_subframe + sf_offset
            for subch in range(self.num_subchannels):
                all_candidates.append(CandidateResource(subframe_index=sf, subchannel_index=subch))

        total_candidates = len(all_candidates)
        if total_candidates == 0:
            raise ResourcePoolError("Mode 4 resource pool selection window is empty")

        # 3. Resource Exclusion
        self.prune_sensing_window(current_subframe)

        # Map each candidate to expected interference based on periodic reservations
        threshold_dbm = self.s_rssi_threshold_dbm
        eligible_candidates: List[CandidateResource] = []

        for cand in all_candidates:
            # Check past sensing history for periodic reservations that project onto this candidate
            projected_rssi = -115.0  # Background thermal noise baseline
            for (hist_sf, hist_subch), (s_rssi, rri) in self._sensing_history.items():
                if hist_subch == cand.subchannel_index and rri > 0:
                    # Check if periodic repetition aligns with cand.subframe_index
                    diff = cand.subframe_index - hist_sf
                    if diff > 0 and (diff % rri) == 0:
                        projected_rssi = max(projected_rssi, s_rssi)

            cand.s_rssi_dbm = projected_rssi
            if projected_rssi < threshold_dbm:
                eligible_candidates.append(cand)

        # 4. 20% candidate availability check (TS 36.213 §14.1.1.6)
        min_candidates = max(1, int(0.20 * total_candidates))
        while len(eligible_candidates) < min_candidates and threshold_dbm < -50.0:
            threshold_dbm += 3.0  # Increment by 3 dB
            eligible_candidates = [c for c in all_candidates if c.s_rssi_dbm < threshold_dbm]

        if not eligible_candidates:
            eligible_candidates = all_candidates

        # 5. Sort by energy and take best 20%
        eligible_candidates.sort(key=lambda c: c.s_rssi_dbm)
        top_slice_count = max(1, int(0.20 * len(eligible_candidates)))
        best_candidates = eligible_candidates[:top_slice_count]

        # Randomly select one candidate from the best subset
        chosen = r.choice(best_candidates)

        # 6. Initialize new SPS counter between 5 and 15 (TS 36.321 §5.14.1.1)
        self._sps_counter = r.randint(5, 15)
        self._current_reservation = (chosen.subchannel_index, chosen.subframe_index)

        log.debug(
            f"Mode 4 selected resource: subchannel={chosen.subchannel_index}, "
            f"subframe={chosen.subframe_index} (in {chosen.subframe_index - current_subframe}ms), "
            f"sps_counter={self._sps_counter}"
        )

        return chosen.subframe_index, chosen.subchannel_index, self._sps_counter
