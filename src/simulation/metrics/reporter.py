"""
V2X Simulation Engine — Simulation Reporter & Plotter
=====================================================
Generates publication-quality performance reports and plots:
  - CSV reports (distance-binned PDR, gateway transit latency, summary metrics)
  - Matplotlib plots (PDR vs Distance, Latency CDF, Throughput Timeline)
  - Markdown summary report
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np

# Use non-interactive backend for headless execution
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from monitoring.logger import get_logger
from simulation.metrics.collector import MetricsCollector

log = get_logger("simulation.reporter")


class SimulationReporter:
    """Exports metrics to CSV, Markdown, and Matplotlib figures."""

    def __init__(
        self,
        collector: MetricsCollector,
        output_dir: Union[Path, str] = "results",
    ):
        self.collector = collector
        self.output_dir = Path(output_dir)
        self.reports_dir = self.output_dir / "reports"
        self.plots_dir = self.output_dir / "plots"

        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.plots_dir.mkdir(parents=True, exist_ok=True)

    def export_pdr_csv(self, filename: str = "pdr_by_distance.csv") -> Path:
        """Export distance-binned PDR to CSV."""
        filepath = self.reports_dir / filename
        bins_all = self.collector.compute_binned_pdr()
        bins_dsrc = self.collector.compute_binned_pdr(technology="DSRC")
        bins_cv2x = self.collector.compute_binned_pdr(technology="CV2X")

        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Distance_Start_m", "Distance_End_m", "Distance_Center_m",
                "Total_Attempts", "Total_Delivered", "Overall_PDR",
                "DSRC_Attempts", "DSRC_Delivered", "DSRC_PDR",
                "CV2X_Attempts", "CV2X_Delivered", "CV2X_PDR",
            ])
            for i in range(len(bins_all)):
                ba = bins_all[i]
                bd = bins_dsrc[i]
                bc = bins_cv2x[i]
                writer.writerow([
                    ba["bin_start_m"], ba["bin_end_m"], ba["bin_center_m"],
                    ba["total_attempts"], ba["delivered"], f"{ba['pdr']:.4f}",
                    bd["total_attempts"], bd["delivered"], f"{bd['pdr']:.4f}",
                    bc["total_attempts"], bc["delivered"], f"{bc['pdr']:.4f}",
                ])
        log.info(f"Exported PDR CSV to {filepath}")
        return filepath

    def export_summary_json_or_csv(self, filename: str = "summary_metrics.csv") -> Path:
        """Export high-level summary KPIs to CSV."""
        filepath = self.reports_dir / filename
        lat = self.collector.get_latency_percentiles()
        gw = self.collector.get_gateway_summary()

        with open(filepath, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value", "Unit"])
            writer.writerow(["Total_BSM_Transmitted", self.collector.get_total_tx_count(), "packets"])
            writer.writerow(["Total_Rx_Attempts", self.collector.get_total_rx_attempts(), "packets"])
            writer.writerow(["Total_Delivered", self.collector.get_total_delivered_count(), "packets"])
            writer.writerow(["Overall_PDR", f"{self.collector.get_overall_pdr() * 100:.2f}", "%"])
            writer.writerow(["Mean_Latency", f"{lat['mean_ms']:.2f}", "ms"])
            writer.writerow(["P50_Latency", f"{lat['p50_ms']:.2f}", "ms"])
            writer.writerow(["P95_Latency", f"{lat['p95_ms']:.2f}", "ms"])
            writer.writerow(["P99_Latency", f"{lat['p99_ms']:.2f}", "ms"])
            writer.writerow(["Gateway_Ingress", gw["total_ingress"], "packets"])
            writer.writerow(["Gateway_Forwarded", gw["forwarded"], "packets"])
            writer.writerow(["Gateway_Dropped", gw["dropped"], "packets"])
            writer.writerow(["Gateway_Mean_Transit", f"{gw['mean_transit_ms']:.2f}", "ms"])

        log.info(f"Exported summary KPIs to {filepath}")
        return filepath

    def plot_pdr_vs_distance(self, filename: str = "pdr_vs_distance.png") -> Path:
        """Plot Packet Delivery Ratio (PDR) vs Distance for DSRC, C-V2X, and Bridged."""
        filepath = self.plots_dir / filename
        bins_all = self.collector.compute_binned_pdr()
        bins_dsrc = self.collector.compute_binned_pdr(technology="DSRC")
        bins_cv2x = self.collector.compute_binned_pdr(technology="CV2X")

        dist_centers = [b["bin_center_m"] for b in bins_all]
        pdr_all = [b["pdr"] for b in bins_all]
        pdr_dsrc = [b["pdr"] for b in bins_dsrc]
        pdr_cv2x = [b["pdr"] for b in bins_cv2x]

        plt.figure(figsize=(9, 5.5))
        plt.plot(dist_centers, pdr_all, "o-", label="Combined / Overall", color="#2c3e50", linewidth=2)
        if any(b["total_attempts"] > 0 for b in bins_dsrc):
            plt.plot(dist_centers, pdr_dsrc, "s--", label="DSRC (802.11p)", color="#e74c3c", linewidth=1.5)
        if any(b["total_attempts"] > 0 for b in bins_cv2x):
            plt.plot(dist_centers, pdr_cv2x, "^--", label="C-V2X (PC5 Mode 4)", color="#2980b9", linewidth=1.5)

        plt.title("V2X Packet Delivery Ratio (PDR) vs Distance", fontsize=14, fontweight="bold")
        plt.xlabel("Distance (meters)", fontsize=12)
        plt.ylabel("Packet Delivery Ratio (PDR)", fontsize=12)
        plt.ylim(-0.05, 1.05)
        plt.grid(True, linestyle="--", alpha=0.6)
        plt.legend(fontsize=11)
        plt.tight_layout()
        plt.savefig(filepath, dpi=300)
        plt.close()

        log.info(f"Generated PDR vs Distance plot at {filepath}")
        return filepath

    def plot_latency_cdf(self, filename: str = "latency_cdf.png") -> Path:
        """Plot empirical Cumulative Distribution Function (CDF) of latency."""
        filepath = self.plots_dir / filename
        delivered_latencies = [r.latency_ms for r in self.collector.rx_records if r.delivered and r.latency_ms > 0.0]

        plt.figure(figsize=(8, 5))
        if delivered_latencies:
            sorted_lat = np.sort(delivered_latencies)
            cdf = np.arange(1, len(sorted_lat) + 1) / len(sorted_lat)
            plt.plot(sorted_lat, cdf, color="#16a085", linewidth=2, label="End-to-End Latency")
            plt.axvline(np.percentile(sorted_lat, 95), color="#e67e22", linestyle=":", label="95th Percentile")

        plt.title("V2X End-to-End Latency Cumulative Distribution (CDF)", fontsize=13, fontweight="bold")
        plt.xlabel("Latency (ms)", fontsize=11)
        plt.ylabel("Cumulative Probability", fontsize=11)
        plt.ylim(0.0, 1.05)
        plt.grid(True, linestyle="--", alpha=0.6)
        plt.legend(fontsize=10)
        plt.tight_layout()
        plt.savefig(filepath, dpi=300)
        plt.close()

        log.info(f"Generated Latency CDF plot at {filepath}")
        return filepath

    def generate_all_reports(self) -> Dict[str, Path]:
        """Convenience method to generate all outputs."""
        return {
            "pdr_csv": self.export_pdr_csv(),
            "summary_csv": self.export_summary_json_or_csv(),
            "pdr_plot": self.plot_pdr_vs_distance(),
            "latency_plot": self.plot_latency_cdf(),
        }

