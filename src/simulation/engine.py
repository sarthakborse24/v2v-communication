"""
V2X Simulation Engine — Discrete-Event Core (SimPy)
===================================================
Coordinates time progression, vehicle mobility, wireless channel propagation,
packet transmissions at 10 Hz, gateway bridging, and metrics collection.

Standards References:
  - IEEE 802.11p-2010 (10 MHz, 5.9 GHz)
  - 3GPP Rel-14 PC5 Mode 4 (10 MHz, Sidelink)
  - SAE J2735: 100 ms (10 Hz) periodic BSM generation
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple, Union
import numpy as np
import simpy

from common.config_schema import SimulationConfig
from gateway.gateway import V2XGateway
from monitoring.logger import get_logger
from simulation.channel.fading import ChannelFadingSimulator, FadingType
from simulation.channel.interference import ChannelInterferenceModel
from simulation.channel.path_loss import PathLossCalculator, PathLossType
from simulation.metrics.collector import MetricsCollector
from vehicles.vehicle import Vehicle, VehicleTechnology
from vehicles.vehicle_manager import VehicleManager

log = get_logger("simulation.engine")


class SimulationEngine:
    """SimPy-driven discrete-event simulation engine for V2X networks."""

    def __init__(
        self,
        vehicle_manager: VehicleManager,
        gateway: Optional[V2XGateway] = None,
        gateway_position: Tuple[float, float, float] = (0.0, 0.0, 5.0),
        gateway_tx_power_dbm: float = 23.0,
        gateway_range_m: float = 400.0,
        channel_model: Union[PathLossType, str] = PathLossType.HIGHWAY_LOS,
        fading_type: Union[FadingType, str] = FadingType.RAYLEIGH,
        shadowing_enabled: bool = True,
        tx_power_dbm: float = 20.0,
        seed: Optional[int] = 42,
    ):
        self.env = simpy.Environment()
        self.vehicle_manager = vehicle_manager
        self.gateway = gateway
        self.gateway_x, self.gateway_y, self.gateway_z = gateway_position
        self.gateway_tx_power_dbm = gateway_tx_power_dbm
        self.gateway_range_m = gateway_range_m
        self.tx_power_dbm = tx_power_dbm

        self.rng = np.random.default_rng(seed)

        # Channel components
        self.path_loss = PathLossCalculator(model_type=channel_model)
        self.fader = ChannelFadingSimulator(
            fading_type=fading_type,
            shadowing_enabled=shadowing_enabled,
            seed=seed,
        )
        self.interference = ChannelInterferenceModel()

        # Telemetry
        self.metrics = MetricsCollector()

    def run(self, duration_seconds: float = 10.0) -> MetricsCollector:
        """Execute simulation for specified duration in seconds."""
        log.info(f"Starting V2X simulation run: duration={duration_seconds:.1f}s, vehicles={len(self.vehicle_manager)}")

        # Start periodic mobility updater (every 50 ms)
        self.env.process(self._mobility_process(step_interval_s=0.05))

        # Start periodic BSM broadcast process for each vehicle
        for vehicle in self.vehicle_manager:
            self.env.process(self._vehicle_broadcast_process(vehicle))

        self.env.run(until=duration_seconds)
        log.info(f"Simulation run complete. Total TX={self.metrics.get_total_tx_count()}, Delivered={self.metrics.get_total_delivered_count()}")
        return self.metrics

    def _mobility_process(self, step_interval_s: float = 0.05):
        """Periodically advance kinematic positions of all vehicles."""
        while True:
            self.vehicle_manager.update_all(self.env.now)
            yield self.env.timeout(step_interval_s)

    def _vehicle_broadcast_process(self, vehicle: Vehicle):
        """Generate and broadcast BSM every 100 ms (10 Hz) with initial random phase jitter."""
        # Initial jitter U[0, 100ms] to avoid lockstep
        initial_jitter = self.rng.uniform(0.0, 0.1)
        yield self.env.timeout(initial_jitter)

        period_s = 0.1  # 10 Hz
        while True:
            now_s = self.env.now
            try:
                frame = vehicle.generate_bsm_payload(now_s)
                # Compute payload byte size
                if isinstance(frame, bytes):
                    payload_bytes = len(frame)
                elif hasattr(frame, "raw_tb_bytes"):
                    payload_bytes = len(frame.raw_tb_bytes)
                elif hasattr(frame, "transport_block") and hasattr(frame.transport_block, "data"):
                    payload_bytes = len(frame.transport_block.data)
                else:
                    payload_bytes = 200

                self.metrics.record_tx(
                    tx_time_s=now_s,
                    sender_id=vehicle.vehicle_id,
                    technology=vehicle.technology.value,
                    msg_cnt=vehicle.stats.tx_bsm_count % 128,
                    payload_bytes=payload_bytes,
                )

                # Direct vehicle-to-vehicle propagation (same technology)
                self._propagate_v2v(vehicle, frame, now_s)

                # If gateway is present, propagate to gateway
                if self.gateway is not None:
                    self._propagate_to_gateway(vehicle, frame, now_s)

            except Exception as e:
                log.error(f"Error in broadcast process for {vehicle.vehicle_id}: {e}")

            # Sleep until next 10 Hz interval
            yield self.env.timeout(period_s)

    def _propagate_v2v(self, sender: Vehicle, frame: Any, now_s: float):
        """Evaluate direct V2V channel to all peer vehicles."""
        for receiver in self.vehicle_manager:
            if receiver.vehicle_id == sender.vehicle_id:
                continue

            # Only direct peers of matching technology can receive directly
            if receiver.technology != sender.technology and receiver.technology != VehicleTechnology.DUAL_STACK:
                continue

            dist_m = math.sqrt(
                (sender.x - receiver.x) ** 2
                + (sender.y - receiver.y) ** 2
                + (sender.z - receiver.z) ** 2
            )

            # Compute channel propagation
            pl_db = self.path_loss.compute_path_loss_db(dist_m)
            total_atten_db = self.fader.compute_total_attenuation_db(pl_db)
            prx_dbm = self.interference.compute_received_power_dbm(self.tx_power_dbm, total_atten_db)
            sinr_db = self.interference.compute_sinr_db(prx_dbm)

            tech_str = sender.technology.value
            delivered, pdr = self.interference.is_packet_delivered(
                sinr_db=sinr_db,
                technology=tech_str,
                mcs_index=3 if "DSRC" in tech_str else 10,
                rng=self.rng,
            )

            # Air interface transmission delay (0.5 to 2.0 ms)
            air_delay_ms = 1.0 + self.rng.uniform(-0.3, 0.3)

            if delivered:
                receiver.receive_frame(frame, rx_power_dbm=prx_dbm, sinr_db=sinr_db, current_time_s=now_s)

            self.metrics.record_rx(
                rx_time_s=now_s,
                sender_id=sender.vehicle_id,
                receiver_id=receiver.vehicle_id,
                technology=tech_str,
                distance_m=dist_m,
                prx_dbm=prx_dbm,
                sinr_db=sinr_db,
                modeled_pdr=pdr,
                delivered=delivered,
                latency_ms=air_delay_ms,
                is_gateway_bridged=False,
            )

    def _propagate_to_gateway(self, sender: Vehicle, frame: Any, now_s: float):
        """Propagate vehicle broadcast to Roadside Gateway."""
        dist_to_gw = math.sqrt(
            (sender.x - self.gateway_x) ** 2
            + (sender.y - self.gateway_y) ** 2
            + (sender.z - self.gateway_z) ** 2
        )
        if dist_to_gw > self.gateway_range_m:
            return  # Beyond radio range of gateway

        pl_db = self.path_loss.compute_path_loss_db(dist_to_gw)
        atten_db = self.fader.compute_total_attenuation_db(pl_db)
        prx_dbm = self.interference.compute_received_power_dbm(self.tx_power_dbm, atten_db)
        sinr_db = self.interference.compute_sinr_db(prx_dbm)

        delivered, _ = self.interference.is_packet_delivered(
            sinr_db=sinr_db,
            technology=sender.technology.value,
            rng=self.rng,
        )
        if not delivered:
            return

        # Gateway ingress and translation process
        self.env.process(self._gateway_translation_process(sender, frame, dist_to_gw, now_s))

    def _gateway_translation_process(
        self,
        sender: Vehicle,
        frame: Any,
        ingress_distance_m: float,
        ingress_time_s: float,
    ):
        """Process ingress through Gateway, wait transit time, and re-broadcast to opposite technology."""
        if self.gateway is None:
            return

        is_dsrc_sender = sender.technology == VehicleTechnology.DSRC
        egress_frame = None
        transit_latency_ms = 0.0
        dropped = False
        drop_reason = None

        now_ms = int(self.env.now * 1000.0)
        try:
            if is_dsrc_sender:
                frame_bytes = frame if isinstance(frame, bytes) else frame.serialize(compute_fcs=True)
                egress_frame = self.gateway.ingress_dsrc(frame_bytes, current_time_ms=now_ms)
            else:
                egress_frame = self.gateway.ingress_cv2x(
                    sci_bytes=frame.raw_sci_bytes,
                    tb_bytes=frame.raw_tb_bytes,
                    current_time_ms=now_ms,
                )

            if egress_frame is None:
                dropped = True
                drop_reason = "Filtered by Gateway (dedup/loop)"
        except Exception as e:
            dropped = True
            drop_reason = str(e)

        # Simulate gateway internal processing pipeline latency (e.g. 5-10 ms)
        transit_delay_s = self.rng.uniform(0.005, 0.010)
        yield self.env.timeout(transit_delay_s)
        transit_latency_ms = transit_delay_s * 1000.0

        self.metrics.record_gateway_event(
            timestamp_s=self.env.now,
            ingress_tech="DSRC" if is_dsrc_sender else "CV2X",
            egress_tech="CV2X" if is_dsrc_sender else "DSRC",
            transit_latency_ms=transit_latency_ms,
            dropped=dropped,
            drop_reason=drop_reason,
        )

        if dropped or egress_frame is None:
            return

        # Gateway re-broadcasts on the other interface from gateway location
        target_tech = VehicleTechnology.CV2X if is_dsrc_sender else VehicleTechnology.DSRC

        for receiver in self.vehicle_manager:
            if receiver.technology != target_tech and receiver.technology != VehicleTechnology.DUAL_STACK:
                continue

            dist_from_gw = math.sqrt(
                (self.gateway_x - receiver.x) ** 2
                + (self.gateway_y - receiver.y) ** 2
                + (self.gateway_z - receiver.z) ** 2
            )

            pl_db = self.path_loss.compute_path_loss_db(dist_from_gw)
            atten_db = self.fader.compute_total_attenuation_db(pl_db)
            prx_dbm = self.interference.compute_received_power_dbm(self.gateway_tx_power_dbm, atten_db)
            sinr_db = self.interference.compute_sinr_db(prx_dbm)

            out_tech_str = target_tech.value
            delivered, pdr = self.interference.is_packet_delivered(
                sinr_db=sinr_db,
                technology=out_tech_str,
                mcs_index=10 if "CV2X" in out_tech_str else 3,
                rng=self.rng,
            )

            total_e2e_latency_ms = transit_latency_ms + 2.0  # includes air interface delay

            if delivered:
                receiver.receive_frame(egress_frame, rx_power_dbm=prx_dbm, sinr_db=sinr_db, current_time_s=self.env.now)

            # Total distance from original sender to receiver
            total_dist_m = math.sqrt(
                (sender.x - receiver.x) ** 2
                + (sender.y - receiver.y) ** 2
                + (sender.z - receiver.z) ** 2
            )

            self.metrics.record_rx(
                rx_time_s=self.env.now,
                sender_id=sender.vehicle_id,
                receiver_id=receiver.vehicle_id,
                technology=out_tech_str,
                distance_m=total_dist_m,
                prx_dbm=prx_dbm,
                sinr_db=sinr_db,
                modeled_pdr=pdr,
                delivered=delivered,
                latency_ms=total_e2e_latency_ms,
                is_gateway_bridged=True,
            )
