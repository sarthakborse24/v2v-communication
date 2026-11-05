"""
V2X Simulation — Mixed-Stack Interoperability Benchmark
========================================================
Comparative scenario:
  - Runs fleet without gateway (isolated DSRC and C-V2X networks)
  - Runs fleet with bidirectional gateway enabled
  - Quantifies cross-technology awareness improvement and gateway transit overhead.
"""

from __future__ import annotations

from typing import Dict, Any, Tuple
from monitoring.logger import get_logger
from simulation.scenarios.highway import create_highway_scenario

log = get_logger("scenario.mixed_stack")


def run_comparative_benchmark(
    num_vehicles: int = 10,
    duration_s: float = 4.0,
    seed: int = 42,
) -> Dict[str, Any]:
    """Run A/B benchmark (Gateway OFF vs Gateway ON) and compare results."""
    log.info("Starting Mixed-Stack A/B Interoperability Benchmark...")

    # Run A: Without Gateway
    _, metrics_no_gw = create_highway_scenario(
        num_vehicles=num_vehicles,
        enable_gateway=False,
        duration_s=duration_s,
        seed=seed,
    )

    # Run B: With Gateway
    _, metrics_with_gw = create_highway_scenario(
        num_vehicles=num_vehicles,
        enable_gateway=True,
        duration_s=duration_s,
        seed=seed,
    )

    pdr_no_gw = metrics_no_gw.get_overall_pdr()
    pdr_with_gw = metrics_with_gw.get_overall_pdr()
    delivered_no_gw = metrics_no_gw.get_total_delivered_count()
    delivered_with_gw = metrics_with_gw.get_total_delivered_count()
    gw_summary = metrics_with_gw.get_gateway_summary()

    gain_percent = ((delivered_with_gw - delivered_no_gw) / max(1, delivered_no_gw)) * 100.0

    results = {
        "without_gateway": {
            "delivered": delivered_no_gw,
            "overall_pdr": pdr_no_gw,
        },
        "with_gateway": {
            "delivered": delivered_with_gw,
            "overall_pdr": pdr_with_gw,
            "gateway_forwarded": gw_summary["forwarded"],
            "gateway_dropped": gw_summary["dropped"],
            "mean_transit_ms": gw_summary["mean_transit_ms"],
        },
        "interoperability_gain_percent": gain_percent,
    }

    log.info(f"Benchmark finished. Cross-technology delivery gain: +{gain_percent:.1f}%")
    return results
