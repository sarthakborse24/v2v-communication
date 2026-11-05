"""
V2X Simulation Engine — Vehicle Mobility Models
================================================
Defines kinematic mobility models for vehicles in V2X simulations:
  - Base MobilityModel interface: get_position(t), get_velocity(t), get_heading(t)
  - LinearMobilityModel: Highway constant or accelerating lane mobility
  - WaypointMobilityModel: Trajectory interpolation across discrete waypoints
  - IntersectionMobilityModel: 4-way urban intersection approach and turn

Coordinates:
  - Local Cartesian (x, y, z) in meters (z = antenna height above ground)
  - Convert to/from WGS-84 (lat, lon, elev) relative to a reference origin.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import math
from typing import List, Optional, Tuple


# WGS-84 reference conversion constants
# 1 degree of latitude ≈ 111,139 meters
METERS_PER_DEG_LAT: float = 111139.0


def cartesian_to_wgs84(
    x_m: float,
    y_m: float,
    z_m: float,
    ref_lat: float = 37.7749,
    ref_lon: float = -122.4194,
    ref_elev_m: float = 10.0,
) -> Tuple[float, float, float]:
    """Convert local Cartesian (x=East, y=North, z=Up in meters) to WGS-84 (lat, lon, elev)."""
    lat = ref_lat + (y_m / METERS_PER_DEG_LAT)
    meters_per_deg_lon = METERS_PER_DEG_LAT * math.cos(math.radians(ref_lat))
    lon = ref_lon + (x_m / meters_per_deg_lon)
    elev = ref_elev_m + z_m
    return lat, lon, elev


def wgs84_to_cartesian(
    lat: float,
    lon: float,
    elev: float,
    ref_lat: float = 37.7749,
    ref_lon: float = -122.4194,
    ref_elev_m: float = 10.0,
) -> Tuple[float, float, float]:
    """Convert WGS-84 (lat, lon, elev) to local Cartesian (x=East, y=North, z=Up in meters)."""
    y_m = (lat - ref_lat) * METERS_PER_DEG_LAT
    meters_per_deg_lon = METERS_PER_DEG_LAT * math.cos(math.radians(ref_lat))
    x_m = (lon - ref_lon) * meters_per_deg_lon
    z_m = elev - ref_elev_m
    return x_m, y_m, z_m


class MobilityModel(ABC):
    """Abstract base class for all vehicle mobility trajectories."""

    @abstractmethod
    def get_position(self, t_seconds: float) -> Tuple[float, float, float]:
        """Return (x, y, z) position in meters at time t."""
        pass

    @abstractmethod
    def get_speed_mps(self, t_seconds: float) -> float:
        """Return scalar speed in meters/second at time t."""
        pass

    @abstractmethod
    def get_heading_deg(self, t_seconds: float) -> float:
        """Return heading in degrees clockwise from North [0.0, 360.0)."""
        pass


class LinearMobilityModel(MobilityModel):
    """Straight-line motion along a highway lane with optional constant acceleration.

    Parameters:
        start_x, start_y, start_z: Initial coordinates (m)
        initial_speed_mps: Initial velocity (m/s)
        acceleration_mps2: Constant acceleration (m/s^2)
        heading_deg: Heading angle (degrees from North)
    """

    def __init__(
        self,
        start_x: float = 0.0,
        start_y: float = 0.0,
        start_z: float = 1.5,
        initial_speed_mps: float = 30.0,  # ~108 km/h
        acceleration_mps2: float = 0.0,
        heading_deg: float = 90.0,         # Eastbound by default
    ):
        self.start_x = start_x
        self.start_y = start_y
        self.start_z = start_z
        self.initial_speed_mps = initial_speed_mps
        self.acceleration_mps2 = acceleration_mps2
        self.heading_deg = heading_deg % 360.0

        # Precompute direction unit vector (heading 0 = North = +y, 90 = East = +x)
        rad = math.radians(self.heading_deg)
        self.dir_x = math.sin(rad)
        self.dir_y = math.cos(rad)

    def get_speed_mps(self, t_seconds: float) -> float:
        speed = self.initial_speed_mps + self.acceleration_mps2 * t_seconds
        return max(0.0, speed)

    def get_heading_deg(self, t_seconds: float) -> float:
        return self.heading_deg

    def get_position(self, t_seconds: float) -> Tuple[float, float, float]:
        distance = (
            self.initial_speed_mps * t_seconds
            + 0.5 * self.acceleration_mps2 * (t_seconds ** 2)
        )
        x = self.start_x + distance * self.dir_x
        y = self.start_y + distance * self.dir_y
        z = self.start_z
        return x, y, z


class WaypointMobilityModel(MobilityModel):
    """Piecewise linear interpolation through a sequence of timed waypoints (t, x, y, z)."""

    def __init__(
        self,
        waypoints: List[Tuple[float, float, float, float]],
    ):
        if len(waypoints) < 2:
            raise ValueError("At least 2 waypoints are required")
        # Ensure waypoints are sorted by time
        self.waypoints = sorted(waypoints, key=lambda wp: wp[0])

    def get_position(self, t_seconds: float) -> Tuple[float, float, float]:
        if t_seconds <= self.waypoints[0][0]:
            wp = self.waypoints[0]
            return wp[1], wp[2], wp[3]
        if t_seconds >= self.waypoints[-1][0]:
            wp = self.waypoints[-1]
            return wp[1], wp[2], wp[3]

        for i in range(len(self.waypoints) - 1):
            t0, x0, y0, z0 = self.waypoints[i]
            t1, x1, y1, z1 = self.waypoints[i + 1]
            if t0 <= t_seconds <= t1:
                dt = t1 - t0
                if dt <= 0.0:
                    return x0, y0, z0
                alpha = (t_seconds - t0) / dt
                return (
                    x0 + alpha * (x1 - x0),
                    y0 + alpha * (y1 - y0),
                    z0 + alpha * (z1 - z0),
                )
        return self.waypoints[-1][1], self.waypoints[-1][2], self.waypoints[-1][3]

    def get_speed_mps(self, t_seconds: float) -> float:
        for i in range(len(self.waypoints) - 1):
            t0, x0, y0, z0 = self.waypoints[i]
            t1, x1, y1, z1 = self.waypoints[i + 1]
            if t0 <= t_seconds <= t1:
                dt = t1 - t0
                if dt <= 0.0:
                    return 0.0
                dist = math.sqrt((x1 - x0) ** 2 + (y1 - y0) ** 2 + (z1 - z0) ** 2)
                return dist / dt
        return 0.0

    def get_heading_deg(self, t_seconds: float) -> float:
        for i in range(len(self.waypoints) - 1):
            t0, x0, y0, _ = self.waypoints[i]
            t1, x1, y1, _ = self.waypoints[i + 1]
            if t0 <= t_seconds <= t1:
                dx = x1 - x0
                dy = y1 - y0
                deg = math.degrees(math.atan2(dx, dy))
                return deg % 360.0
        return 0.0


class IntersectionMobilityModel(MobilityModel):
    """Models a vehicle approaching a 4-way intersection (origin (0,0)), slowing, and departing.

    Approach directions: 'north', 'south', 'east', 'west'.
    """

    def __init__(
        self,
        approach_from: str = "west",
        approach_distance_m: float = 200.0,
        cruise_speed_mps: float = 15.0,  # ~54 km/h
        slow_speed_mps: float = 5.0,     # at junction
        turn: str = "straight",           # 'straight', 'right', 'left'
        antenna_height_m: float = 1.5,
    ):
        self.antenna_height_m = antenna_height_m
        self.cruise_speed_mps = cruise_speed_mps
        self.approach_from = approach_from.lower()
        self.turn = turn.lower()

        # Build timed waypoints automatically
        # Phase 1: cruise from -approach_distance to -50m
        # Phase 2: decelerate to junction
        # Phase 3: cross/turn junction
        # Phase 4: accelerate to +approach_distance
        t = 0.0
        d_start = -approach_distance_m
        d_slow = -40.0
        d_stop = 0.0
        d_accel = 40.0
        d_end = approach_distance_m

        # Time intervals
        t1 = (d_slow - d_start) / cruise_speed_mps
        t2 = t1 + (d_stop - d_slow) / ((cruise_speed_mps + slow_speed_mps) / 2.0)
        t3 = t2 + (d_accel - d_stop) / slow_speed_mps
        t4 = t3 + (d_end - d_accel) / ((cruise_speed_mps + slow_speed_mps) / 2.0)

        # Map 1D along-track distance to 2D (x, y) based on approach direction
        pts = []
        for time_pt, dist in [(0.0, d_start), (t1, d_slow), (t2, d_stop), (t3, d_accel), (t4, d_end)]:
            if self.approach_from == "west":
                # Moving along x axis towards East (+x)
                pts.append((time_pt, dist, 0.0, antenna_height_m))
            elif self.approach_from == "east":
                pts.append((time_pt, -dist, 0.0, antenna_height_m))
            elif self.approach_from == "south":
                pts.append((time_pt, 0.0, dist, antenna_height_m))
            else:  # north
                pts.append((time_pt, 0.0, -dist, antenna_height_m))

        self._interpolator = WaypointMobilityModel(pts)

    def get_position(self, t_seconds: float) -> Tuple[float, float, float]:
        return self._interpolator.get_position(t_seconds)

    def get_speed_mps(self, t_seconds: float) -> float:
        return self._interpolator.get_speed_mps(t_seconds)

    def get_heading_deg(self, t_seconds: float) -> float:
        return self._interpolator.get_heading_deg(t_seconds)

