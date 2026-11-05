"""
V2X Simulation — 4-Way Urban Intersection Scenario
===================================================
Simulates a dense urban crossroad:
  - 4-way intersection centered at (0, 0)
  - Approaches from North, South, East, West
  - Buildings on street corners inducing NLOS obstruction and high attenuation
  - Roadside Gateway RSU mounted atop traffic signal mast at (0, 0, 8m)
  - 3GPP TR 36.885 Urban NLOS / LOS path loss + Rayleigh multipath fading
"""

from __future__ import annotations

from typing import Optional, Tuple
from certificates.generate_pki import build_simulated_pki
from cv2x.stack import CV2XStack
from dsrc.stack import DSRCStack
from gateway.gateway import V2XGateway
from monitoring.logger import get_logger
from simulation.channel.fading import FadingType
from simulation.channel.path_loss import PathLossType
from simulation.engine import SimulationEngine
from simulation.metrics.collector import MetricsCollector
from vehicles.mobility_model import IntersectionMobilityModel
from vehicles.vehicle import Vehicle, VehicleTechnology
from vehicles.vehicle_manager import VehicleManager

log = get_logger("scenario.intersection")


def create_intersection_scenario(
    num_vehicles: int = 8,
    enable_gateway: bool = True,
    duration_s: float = 5.0,
    seed: int = 42,
) -> Tuple[SimulationEngine, MetricsCollector]:
    """Build and execute urban intersection simulation."""
    log.info(f"Setting up Urban Intersection Scenario: {num_vehicles} vehicles (Gateway={'ON' if enable_gateway else 'OFF'})")

    pki = build_simulated_pki(num_vehicles=num_vehicles, certs_per_vehicle=2)
    vm = VehicleManager()

    directions = ["west", "east", "south", "north"]

    for i in range(1, num_vehicles + 1):
        v_name = f"Vehicle-{i}"
        dir_idx = (i - 1) % len(directions)
        approach_dir = directions[dir_idx]
        offset_dist = 120.0 + ((i - 1) // 4) * 40.0

        is_dsrc = (i % 2 == 1)
        tech = VehicleTechnology.DSRC if is_dsrc else VehicleTechnology.CV2X

        mobility = IntersectionMobilityModel(
            approach_from=approach_dir,
            approach_distance_m=offset_dist,
            cruise_speed_mps=14.0,  # ~50 km/h
            slow_speed_mps=6.0,     # ~20 km/h through junction
        )

        dsrc_stack = DSRCStack(vehicle_name=v_name, cert_store=pki) if is_dsrc else None
        cv2x_stack = CV2XStack(vehicle_name=v_name, cert_store=pki) if not is_dsrc else None

        vehicle = Vehicle(
            vehicle_id=f"veh_int_{i:02d}",
            station_id=2000 + i,
            technology=tech,
            mobility_model=mobility,
            dsrc_stack=dsrc_stack,
            cv2x_stack=cv2x_stack,
        )
        vm.add_vehicle(vehicle)

    gateway = None
    if enable_gateway:
        gw_cert = next(c for c in pki.entity_certs.values() if "Gateway" in c.to_be_signed.cert_id)
        gw_digest = gw_cert.compute_digest8()
        gw_priv = pki.get_private_key(gw_digest)

        gateway = V2XGateway(
            gateway_cert=gw_cert,
            gateway_private_key=gw_priv,
            cert_store=pki,
            dedup_window_seconds=2.0,
            replay_window_ms=1000,
        )

    engine = SimulationEngine(
        vehicle_manager=vm,
        gateway=gateway,
        gateway_position=(0.0, 0.0, 8.0),
        gateway_tx_power_dbm=23.0,
        gateway_range_m=300.0,
        channel_model=PathLossType.URBAN_NLOS,
        fading_type=FadingType.RAYLEIGH,
        tx_power_dbm=20.0,
        seed=seed,
    )

    metrics = engine.run(duration_seconds=duration_s)
    return engine, metrics

