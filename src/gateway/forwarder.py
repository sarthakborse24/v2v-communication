"""
V2X Gateway Simulator — Gateway Egress Forwarder
=================================================
Manages outbound queues, measures gateway transit latency,
maintains performance metrics, and dispatches to destination stacks.

Performance Requirements:
  - Gateway processing latency < 5.0 ms
  - Zero payload corruption
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Dict, List, Optional, Tuple

from common.message_types import (
    GatewayDirection,
    StackType,
)
from cv2x.mac.lte_mac import SidelinkTransmissionUnit
from dsrc.wave.wave_frame import WAVEFrame
from monitoring.logger import get_logger

log = get_logger("gateway.forwarder")


@dataclass
class GatewayMetrics:
    """Cumulative operational metrics for the gateway."""
    ingress_dsrc_count: int = 0
    ingress_cv2x_count: int = 0
    forwarded_dsrc_to_cv2x: int = 0
    forwarded_cv2x_to_dsrc: int = 0
    dropped_validation: int = 0
    dropped_duplicate: int = 0
    dropped_security: int = 0
    dropped_loop: int = 0
    latencies_ms: List[float] = field(default_factory=list)

    @property
    def total_ingress(self) -> int:
        return self.ingress_dsrc_count + self.ingress_cv2x_count

    @property
    def total_forwarded(self) -> int:
        return self.forwarded_dsrc_to_cv2x + self.forwarded_cv2x_to_dsrc

    @property
    def total_dropped(self) -> int:
        return (
            self.dropped_validation
            + self.dropped_duplicate
            + self.dropped_security
            + self.dropped_loop
        )

    @property
    def avg_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return sum(self.latencies_ms) / len(self.latencies_ms)

    @property
    def max_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return max(self.latencies_ms)


class GatewayForwarder:
    """Manages egress queues and tracks transit metrics."""

    def __init__(self, warn_latency_threshold_ms: float = 5.0):
        self.warn_latency_threshold_ms = warn_latency_threshold_ms
        self.metrics = GatewayMetrics()

        # Egress output queues
        self.outbound_cv2x_queue: List[Tuple[SidelinkTransmissionUnit, float]] = []
        self.outbound_dsrc_queue: List[Tuple[WAVEFrame, float]] = []

    def record_forwarded(
        self,
        direction: GatewayDirection,
        ingress_timestamp_ms: int,
        current_time_ms: Optional[int] = None,
    ) -> float:
        """Record transit latency and update metrics.

        Returns:
            Calculated transit latency in milliseconds.
        """
        now_ms = current_time_ms if current_time_ms is not None else int(time.time() * 1000)
        latency_ms = max(0.0, float(now_ms - ingress_timestamp_ms))

        self.metrics.latencies_ms.append(latency_ms)

        if direction == GatewayDirection.DSRC_TO_CV2X:
            self.metrics.forwarded_dsrc_to_cv2x += 1
        else:
            self.metrics.forwarded_cv2x_to_dsrc += 1

        if latency_ms > self.warn_latency_threshold_ms:
            log.warning(
                f"Gateway transit latency ({latency_ms:.2f}ms) exceeded threshold ({self.warn_latency_threshold_ms}ms)"
            )
        else:
            log.debug(f"Gateway forwarded [{direction.name}] in {latency_ms:.2f}ms")

        return latency_ms

    def enqueue_cv2x(self, tx_unit: SidelinkTransmissionUnit, latency_ms: float) -> None:
        self.outbound_cv2x_queue.append((tx_unit, latency_ms))

    def enqueue_dsrc(self, wave_frame: WAVEFrame, latency_ms: float) -> None:
        self.outbound_dsrc_queue.append((wave_frame, latency_ms))

    def pop_next_cv2x(self) -> Optional[Tuple[SidelinkTransmissionUnit, float]]:
        return self.outbound_cv2x_queue.pop(0) if self.outbound_cv2x_queue else None

    def pop_next_dsrc(self) -> Optional[Tuple[WAVEFrame, float]]:
        return self.outbound_dsrc_queue.pop(0) if self.outbound_dsrc_queue else None
