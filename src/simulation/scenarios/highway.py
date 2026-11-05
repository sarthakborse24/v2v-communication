"""
V2X Simulation — Highway Scenario
=================================
Simulates a multi-lane highway environment:
  - 3-lane straight highway segment (e.g. 1.2 km)
  - Fleet of vehicles traveling eastbound at 25-33 m/s (~90-120 km/h)
  - Heterogeneous mix: 50% DSRC, 50% LTE-C-V2X
  - Roadside Gateway RSU placed mid-segment at (x=600m, y=-6m, z=6m)
  - 3GPP TR 36.885 Highway LOS path loss + Rayleigh/Rician fast fading
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
from vehicles.mobility_model import LinearMobilityModel
from vehicles.vehicle import Vehicle, VehicleTechnology
from vehicles.vehicle_manager import VehicleManager

log = get_logger("scenario.highway")


def create_highway_scenario(
    num_vehicles: int = 12,
    highway_length_m: float = 1200.0,
    enable_gateway: bool = True,
    duration_s: float = 5.0,
    seed: int = 42,
) -> Tuple[SimulationEngine, MetricsCollector]:
    """Build and execute the highway simulation scenario."""
    log.info(f"Setting up Highway Scenario with {num_vehicles} vehicles (Gateway={'ON' if enable_gateway else 'OFF'})")

    # 1. Generate PKI certificates
    pki = build_simulated_pki(num_vehicles=num_vehicles, certs_per_vehicle=2)

    # 2. Setup Vehicle Manager
    vm = VehicleManager()
    lanes_y = [0.0, 4.0, 8.0]
    speeds = [25.0, 28.0, 32.0]

    spacing_m = (highway_length_m * 0.75) / max(1, num_vehicles // 3)

    for i in range(1, num_vehicles + 1):
        v_name = f"Vehicle-{i}"
        lane_idx = (i - 1) % len(lanes_y)
        lane_y = lanes_y[lane_idx]
        speed = speeds[lane_idx]
        start_x = ((i - 1) // len(lanes_y)) * spacing_m

        # Alternate between DSRC and C-V2X
        is_dsrc = (i % 2 == 1)
        tech = VehicleTechnology.DSRC if is_dsrc else VehicleTechnology.CV2X

        mobility = LinearMobilityModel(
            start_x=start_x,
            start_y=lane_y,
            start_z=1.5,
            initial_speed_mps=speed,
            heading_deg=90.0,  # Eastbound (+x)
        )

        dsrc_stack = DSRCStack(vehicle_name=v_name, cert_store=pki) if is_dsrc else None
        cv2x_stack = CV2XStack(vehicle_name=v_name, cert_store=pki) if not is_dsrc else None

        vehicle = Vehicle(
            vehicle_id=f"veh_{i:02d}",
            station_id=1000 + i,
            technology=tech,
            mobility_model=mobility,
            dsrc_stack=dsrc_stack,
            cv2x_stack=cv2x_stack,
        )
        vm.add_vehicle(vehicle)

    # 3. Setup Gateway
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

    # 4. Initialize Simulation Engine
    engine = SimulationEngine(
        vehicle_manager=vm,
        gateway=gateway,
        gateway_position=(highway_length_m / 2.0, -6.0, 6.0),
        gateway_tx_power_dbm=23.0,
        gateway_range_m=500.0,
        channel_model=PathLossType.HIGHWAY_LOS,
        fading_type=FadingType.RICIAN,
        tx_power_dbm=20.0,
        seed=seed,
    )

    metrics = engine.run(duration_seconds=duration_s)
    return engine, metrics
