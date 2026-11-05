"""
V2X Simulation Engine — Fleet Vehicle Manager
=============================================
Manages all simulated vehicles:
  - Fleet registration and lifecycle
  - Synchronized kinematic state updates
  - Vectorized pairwise Euclidean distance calculation (NumPy)
  - Geographic neighborhood queries (e.g., vehicles within range of gateway)
"""

from __future__ import annotations

import math
from typing import Dict, Iterator, List, Optional, Tuple
import numpy as np

from monitoring.logger import get_logger
from vehicles.vehicle import Vehicle, VehicleTechnology

log = get_logger("vehicles.manager")


class VehicleManager:
    """Fleet coordinator managing all simulated vehicles."""

    def __init__(self):
        self._vehicles: Dict[str, Vehicle] = {}

    def add_vehicle(self, vehicle: Vehicle) -> None:
        """Add vehicle to fleet."""
        if vehicle.vehicle_id in self._vehicles:
            raise ValueError(f"Vehicle with id {vehicle.vehicle_id} already exists")
        self._vehicles[vehicle.vehicle_id] = vehicle

    def get_vehicle(self, vehicle_id: str) -> Optional[Vehicle]:
        return self._vehicles.get(vehicle_id)

    def remove_vehicle(self, vehicle_id: str) -> None:
        if vehicle_id in self._vehicles:
            del self._vehicles[vehicle_id]

    def all_vehicles(self) -> List[Vehicle]:
        return list(self._vehicles.values())

    def __iter__(self) -> Iterator[Vehicle]:
        return iter(self._vehicles.values())

    def __len__(self) -> int:
        return len(self._vehicles)

    def get_by_technology(self, technology: VehicleTechnology) -> List[Vehicle]:
        """Filter vehicles by communication technology."""
        return [v for v in self._vehicles.values() if v.technology == technology]

    def update_all(self, t_seconds: float) -> None:
        """Advance kinematic positions of all vehicles at time t."""
        for v in self._vehicles.values():
            v.update_state(t_seconds)

    def get_positions_array(self) -> Tuple[List[str], np.ndarray]:
        """Return list of vehicle IDs and an (N, 3) NumPy array of (x, y, z) coordinates."""
        v_ids = list(self._vehicles.keys())
        coords = np.array([[self._vehicles[vid].x, self._vehicles[vid].y, self._vehicles[vid].z] for vid in v_ids], dtype=float)
        return v_ids, coords

    def compute_distance_matrix(self) -> Tuple[List[str], np.ndarray]:
        """Compute (N, N) pairwise Euclidean distance matrix using NumPy vectorization."""
        v_ids, coords = self.get_positions_array()
        if len(v_ids) == 0:
            return [], np.zeros((0, 0))

        # Vectorized Euclidean distance: diff is (N, 1, 3) - (1, N, 3) -> (N, N, 3)
        diff = coords[:, np.newaxis, :] - coords[np.newaxis, :, :]
        dist_matrix = np.sqrt(np.sum(diff ** 2, axis=-1))
        return v_ids, dist_matrix

    def get_distance_between(self, v1_id: str, v2_id: str) -> float:
        """Compute Euclidean distance between two vehicles."""
        v1 = self._vehicles.get(v1_id)
        v2 = self._vehicles.get(v2_id)
        if not v1 or not v2:
            raise KeyError("Vehicle ID not found")
        return math.sqrt((v1.x - v2.x) ** 2 + (v1.y - v2.y) ** 2 + (v1.z - v2.z) ** 2)

    def find_vehicles_in_range(
        self,
        center_x: float,
        center_y: float,
        center_z: float,
        max_range_m: float,
    ) -> List[Tuple[Vehicle, float]]:
        """Find all vehicles within max_range_m of a reference point (e.g. gateway RSU).

        Returns list of (Vehicle, distance_m) sorted by distance.
        """
        results = []
        for v in self._vehicles.values():
            dist = math.sqrt((v.x - center_x) ** 2 + (v.y - center_y) ** 2 + (v.z - center_z) ** 2)
            if dist <= max_range_m:
                results.append((v, dist))
        results.sort(key=lambda item: item[1])
        return results

