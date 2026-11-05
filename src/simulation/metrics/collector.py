"""
V2X Simulation Engine — Metrics Collector
=========================================
Aggregates telemetry and performance measurements during simulation runs:
  - Packet delivery events (distance, Prx, SINR, PDR, delivery outcome)
  - Latency samples (air interface + gateway transit)
  - Throughput tracking over time
  - Gateway translation metrics (ingress, egress, deduplicated, loop dropped)
  - Distance-binned PDR statistics
"""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class PacketTxRecord:
    tx_time_s: float
    sender_id: str
    technology: str
    msg_cnt: int
    payload_bytes: int


@dataclass
class PacketRxRecord:
    rx_time_s: float
    sender_id: str
    receiver_id: str
    technology: str
    distance_m: float
    prx_dbm: float
    sinr_db: float
    modeled_pdr: float
    delivered: bool
    latency_ms: float
    is_gateway_bridged: bool = False


@dataclass
class GatewayEventRecord:
    timestamp_s: float
    ingress_tech: str
    egress_tech: str
    transit_latency_ms: float
    dropped: bool
    drop_reason: Optional[str] = None


class MetricsCollector:
    """Collects and analyzes simulation metrics."""

    def __init__(self, bin_width_m: float = 50.0, max_distance_m: float = 1000.0):
        self.bin_width_m = bin_width_m
        self.max_distance_m = max_distance_m

        self.tx_records: List[PacketTxRecord] = []
        self.rx_records: List[PacketRxRecord] = []
        self.gateway_records: List[GatewayEventRecord] = []

    def record_tx(
        self,
        tx_time_s: float,
        sender_id: str,
        technology: str,
        msg_cnt: int,
        payload_bytes: int,
    ) -> None:
        self.tx_records.append(
            PacketTxRecord(
                tx_time_s=tx_time_s,
                sender_id=sender_id,
                technology=technology,
                msg_cnt=msg_cnt,
                payload_bytes=payload_bytes,
            )
        )

    def record_rx(
        self,
        rx_time_s: float,
        sender_id: str,
        receiver_id: str,
        technology: str,
        distance_m: float,
        prx_dbm: float,
        sinr_db: float,
        modeled_pdr: float,
        delivered: bool,
        latency_ms: float,
        is_gateway_bridged: bool = False,
    ) -> None:
        self.rx_records.append(
            PacketRxRecord(
                rx_time_s=rx_time_s,
                sender_id=sender_id,
                receiver_id=receiver_id,
                technology=technology,
                distance_m=distance_m,
                prx_dbm=prx_dbm,
                sinr_db=sinr_db,
                modeled_pdr=modeled_pdr,
                delivered=delivered,
                latency_ms=latency_ms,
                is_gateway_bridged=is_gateway_bridged,
            )
        )

    def record_gateway_event(
        self,
        timestamp_s: float,
        ingress_tech: str,
        egress_tech: str,
        transit_latency_ms: float,
        dropped: bool,
        drop_reason: Optional[str] = None,
    ) -> None:
        self.gateway_records.append(
            GatewayEventRecord(
                timestamp_s=timestamp_s,
                ingress_tech=ingress_tech,
                egress_tech=egress_tech,
                transit_latency_ms=transit_latency_ms,
                dropped=dropped,
                drop_reason=drop_reason,
            )
        )

    def get_total_tx_count(self) -> int:
        return len(self.tx_records)

    def get_total_rx_attempts(self) -> int:
        return len(self.rx_records)

    def get_total_delivered_count(self) -> int:
        return sum(1 for r in self.rx_records if r.delivered)

    def get_overall_pdr(self) -> float:
        total = len(self.rx_records)
        if total == 0:
            return 0.0
        return self.get_total_delivered_count() / total

    def compute_binned_pdr(
        self,
        technology: Optional[str] = None,
        only_gateway_bridged: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """Compute PDR partitioned into distance intervals [0, 50), [50, 100), etc."""
        num_bins = int(self.max_distance_m / self.bin_width_m)
        bin_edges = [i * self.bin_width_m for i in range(num_bins + 1)]

        bins_data = [
            {
                "bin_start_m": bin_edges[i],
                "bin_end_m": bin_edges[i + 1],
                "bin_center_m": (bin_edges[i] + bin_edges[i + 1]) / 2.0,
                "total_attempts": 0,
                "delivered": 0,
                "pdr": 0.0,
            }
            for i in range(num_bins)
        ]

        for r in self.rx_records:
            if technology is not None and r.technology.upper() != technology.upper():
                continue
            if only_gateway_bridged is not None and r.is_gateway_bridged != only_gateway_bridged:
                continue

            bin_idx = int(r.distance_m // self.bin_width_m)
            if 0 <= bin_idx < num_bins:
                bins_data[bin_idx]["total_attempts"] += 1
                if r.delivered:
                    bins_data[bin_idx]["delivered"] += 1

        for b in bins_data:
            if b["total_attempts"] > 0:
                b["pdr"] = b["delivered"] / b["total_attempts"]
            else:
                b["pdr"] = 0.0

        return bins_data

    def get_latency_percentiles(self) -> Dict[str, float]:
        """Compute latency percentiles (mean, min, 50th, 90th, 95th, 99th, max) in ms."""
        delivered_latencies = [r.latency_ms for r in self.rx_records if r.delivered and r.latency_ms > 0.0]
        if not delivered_latencies:
            return {
                "count": 0,
                "mean_ms": 0.0,
                "p50_ms": 0.0,
                "p90_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "max_ms": 0.0,
            }
        arr = np.array(delivered_latencies)
        return {
            "count": len(arr),
            "mean_ms": float(np.mean(arr)),
            "p50_ms": float(np.percentile(arr, 50)),
            "p90_ms": float(np.percentile(arr, 90)),
            "p95_ms": float(np.percentile(arr, 95)),
            "p99_ms": float(np.percentile(arr, 99)),
            "max_ms": float(np.max(arr)),
        }

    def get_gateway_summary(self) -> Dict[str, Any]:
        """Summary of gateway translation performance."""
        total = len(self.gateway_records)
        if total == 0:
            return {"total_ingress": 0, "forwarded": 0, "dropped": 0, "mean_transit_ms": 0.0}

        forwarded = [r for r in self.gateway_records if not r.dropped]
        dropped = [r for r in self.gateway_records if r.dropped]
        latencies = [r.transit_latency_ms for r in forwarded]

        return {
            "total_ingress": total,
            "forwarded": len(forwarded),
            "dropped": len(dropped),
            "mean_transit_ms": float(np.mean(latencies)) if latencies else 0.0,
            "p95_transit_ms": float(np.percentile(latencies, 95)) if latencies else 0.0,
        }
