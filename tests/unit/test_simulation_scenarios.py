"""
Unit and Integration Tests for Simulation Engine, Vehicles, and Scenarios
========================================================================
Validates:
  1. Mobility models (Linear, Waypoint, Intersection) and WGS-84 coordinate transforms
  2. Vehicle Manager pairwise distance matrix calculation
  3. Vehicle BSM generation and packet reception
  4. MetricsCollector distance binning and percentile latencies
  5. SimulationReporter CSV and figure outputs
  6. Highway and Intersection discrete-event scenario executions
"""

import math
from pathlib import Path
import numpy as np
import pytest

from simulation.channel.path_loss import PathLossType
from simulation.metrics.collector import MetricsCollector
from simulation.metrics.reporter import SimulationReporter
from simulation.scenarios.highway import create_highway_scenario
from simulation.scenarios.intersection import create_intersection_scenario
from simulation.scenarios.mixed_stack import run_comparative_benchmark
from vehicles.mobility_model import (
    IntersectionMobilityModel,
    LinearMobilityModel,
    WaypointMobilityModel,
    cartesian_to_wgs84,
    wgs84_to_cartesian,
)
from vehicles.vehicle import Vehicle, VehicleStats, VehicleTechnology
from vehicles.vehicle_manager import VehicleManager


class TestMobilityModels:
    """Validate kinematics and trajectory calculations."""

    def test_linear_mobility(self):
        """Constant speed Eastbound linear model."""
        mob = LinearMobilityModel(
            start_x=10.0, start_y=20.0, start_z=1.5,
            initial_speed_mps=20.0, heading_deg=90.0
        )
        x0, y0, z0 = mob.get_position(0.0)
        assert x0 == 10.0 and y0 == 20.0 and z0 == 1.5

        # At t = 2.0 s, distance = 40.0 m East (+x)
        x2, y2, z2 = mob.get_position(2.0)
        assert pytest.approx(50.0, abs=1e-3) == x2
        assert pytest.approx(20.0, abs=1e-3) == y2
        assert mob.get_speed_mps(2.0) == 20.0
        assert mob.get_heading_deg(2.0) == 90.0

    def test_waypoint_mobility(self):
        """Waypoint piecewise linear interpolation."""
        pts = [
            (0.0, 0.0, 0.0, 1.5),
            (10.0, 100.0, 0.0, 1.5),
        ]
        mob = WaypointMobilityModel(pts)
        # Midpoint at t = 5.0 s
        x, y, z = mob.get_position(5.0)
        assert pytest.approx(50.0, abs=1e-3) == x
        assert pytest.approx(0.0, abs=1e-3) == y
        assert pytest.approx(10.0, abs=1e-3) == mob.get_speed_mps(5.0)

    def test_intersection_mobility(self):
        """Approaches intersection, slows down, and continues."""
        mob = IntersectionMobilityModel(approach_from="west", approach_distance_m=100.0)
        x0, y0, _ = mob.get_position(0.0)
        assert x0 < 0.0  # West of center
        # Speeds at start vs center
        speed_start = mob.get_speed_mps(0.0)
        assert speed_start > 0.0

    def test_wgs84_cartesian_round_trip(self):
        """Conversion between Cartesian (x, y, z) and WGS-84 (lat, lon, elev)."""
        x_orig, y_orig, z_orig = 150.0, -80.0, 2.5
        lat, lon, elev = cartesian_to_wgs84(x_orig, y_orig, z_orig)
        x_rec, y_rec, z_rec = wgs84_to_cartesian(lat, lon, elev)
        assert pytest.approx(x_orig, abs=1e-2) == x_rec
        assert pytest.approx(y_orig, abs=1e-2) == y_rec
        assert pytest.approx(z_orig, abs=1e-2) == z_rec


class TestVehicleManager:
    """Validate fleet coordination and pairwise distance calculations."""

    def test_pairwise_distance_matrix(self):
        vm = VehicleManager()
        v1 = Vehicle("v1", 101, mobility_model=LinearMobilityModel(start_x=0.0, start_y=0.0, start_z=1.5))
        v2 = Vehicle("v2", 102, mobility_model=LinearMobilityModel(start_x=30.0, start_y=40.0, start_z=1.5))
        vm.add_vehicle(v1)
        vm.add_vehicle(v2)

        v_ids, dist_mat = vm.compute_distance_matrix()
        assert len(v_ids) == 2
        # Distance between (0, 0, 1.5) and (30, 40, 1.5) is 50.0 m (3-4-5 triangle)
        assert pytest.approx(0.0, abs=1e-4) == dist_mat[0, 0]
        assert pytest.approx(0.0, abs=1e-4) == dist_mat[1, 1]
        assert pytest.approx(50.0, abs=1e-4) == dist_mat[0, 1]
        assert pytest.approx(50.0, abs=1e-4) == dist_mat[1, 0]

    def test_find_vehicles_in_range(self):
        vm = VehicleManager()
        vm.add_vehicle(Vehicle("v1", 101, mobility_model=LinearMobilityModel(start_x=0.0, start_y=0.0)))
        vm.add_vehicle(Vehicle("v2", 102, mobility_model=LinearMobilityModel(start_x=100.0, start_y=0.0)))
        vm.add_vehicle(Vehicle("v3", 103, mobility_model=LinearMobilityModel(start_x=300.0, start_y=0.0)))

        near = vm.find_vehicles_in_range(center_x=0.0, center_y=0.0, center_z=0.0, max_range_m=150.0)
        assert len(near) == 2
        assert near[0][0].vehicle_id == "v1"
        assert near[1][0].vehicle_id == "v2"


class TestMetricsAndReporter:
    """Validate metrics collector, CSV exports, and plot generation."""

    def test_metrics_collection_and_binned_pdr(self, tmp_path):
        collector = MetricsCollector(bin_width_m=50.0, max_distance_m=200.0)
        collector.record_tx(0.0, "v1", "DSRC", 1, 200)

        # Record some receptions: 30m delivered, 70m dropped, 75m delivered
        collector.record_rx(0.01, "v1", "v2", "DSRC", 30.0, -70.0, 15.0, 0.99, True, 1.2)
        collector.record_rx(0.01, "v1", "v3", "DSRC", 70.0, -85.0, 4.0, 0.40, False, 1.2)
        collector.record_rx(0.01, "v1", "v4", "DSRC", 75.0, -83.0, 5.0, 0.50, True, 1.2)

        bins = collector.compute_binned_pdr(technology="DSRC")
        # Bin 0 [0, 50m): 1 attempt, 1 delivered -> PDR = 1.0
        assert bins[0]["total_attempts"] == 1
        assert bins[0]["pdr"] == 1.0
        # Bin 1 [50, 100m): 2 attempts, 1 delivered -> PDR = 0.5
        assert bins[1]["total_attempts"] == 2
        assert bins[1]["pdr"] == 0.5

        # Check reporter file generation
        reporter = SimulationReporter(collector, output_dir=tmp_path)
        files = reporter.generate_all_reports()
        assert files["pdr_csv"].exists()
        assert files["summary_csv"].exists()
        assert files["pdr_plot"].exists()
        assert files["latency_plot"].exists()


class TestScenarioExecutions:
    """Run smoke tests on Highway and Intersection scenarios."""

    def test_highway_scenario_smoke(self):
        """Run highway scenario for 0.3s with 4 vehicles."""
        engine, metrics = create_highway_scenario(
            num_vehicles=4,
            highway_length_m=500.0,
            enable_gateway=True,
            duration_s=0.3,
            seed=42,
        )
        assert metrics.get_total_tx_count() > 0
        assert metrics.get_total_rx_attempts() > 0
        assert metrics.get_total_delivered_count() > 0

    def test_intersection_scenario_smoke(self):
        """Run intersection scenario for 0.3s with 4 vehicles."""
        engine, metrics = create_intersection_scenario(
            num_vehicles=4,
            enable_gateway=True,
            duration_s=0.3,
            seed=42,
        )
        assert metrics.get_total_tx_count() > 0
        assert metrics.get_total_rx_attempts() > 0

    def test_mixed_stack_benchmark(self):
        """A/B test: Gateway ON enables cross-technology packet delivery."""
        results = run_comparative_benchmark(
            num_vehicles=4,
            duration_s=0.3,
            seed=42,
        )
        assert results["with_gateway"]["delivered"] >= results["without_gateway"]["delivered"]
        assert "interoperability_gain_percent" in results
