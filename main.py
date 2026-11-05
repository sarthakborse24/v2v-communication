"""
V2X Gateway Simulator — Main Entry Point
=========================================
CLI Orchestrator for DSRC ↔ LTE-C-V2X Communication Simulation.

Runs full simulation scenarios, prints real-time and summary metrics,
and writes CSV performance reports and publication-grade Matplotlib plots.

Usage:
    python main.py --scenario highway --duration 5.0 --vehicles 12 --generate-plots
    python main.py --scenario intersection --duration 5.0 --vehicles 8 --generate-plots
    python main.py --scenario mixed_stack --duration 4.0 --vehicles 10
    python main.py --list-scenarios
    python main.py --generate-pki

Standards References:
  - IEEE 802.11p / IEEE 1609.2 / IEEE 1609.3 / IEEE 1609.4
  - SAE J2735: Basic Safety Message (BSM) Part I
  - 3GPP LTE-V2X Release 14/15 PC5 Sidelink Mode 4
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import time

# Ensure src/ is on PYTHONPATH when running from project root
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import yaml
from pydantic import ValidationError

from common.config_schema import V2XSimConfig
from monitoring.logger import configure_logging, get_logger
from simulation.metrics.reporter import SimulationReporter
from simulation.scenarios.highway import create_highway_scenario
from simulation.scenarios.intersection import create_intersection_scenario
from simulation.scenarios.mixed_stack import run_comparative_benchmark

SCENARIOS = {
    "highway": "Multi-lane highway (3GPP TR 36.885 Highway LOS + Rician fading)",
    "intersection": "4-way urban crossroad (3GPP TR 36.885 Urban NLOS + Rayleigh fading)",
    "mixed_stack": "Comparative benchmark: Gateway OFF vs Gateway ON interoperability gain",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="v2x-gateway",
        description="DSRC ↔ LTE-C-V2X Communication Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scenario highway --duration 5.0 --vehicles 12 --generate-plots
  python main.py --scenario intersection --duration 5.0 --vehicles 8 --generate-plots
  python main.py --scenario mixed_stack --duration 4.0 --vehicles 10
  python main.py --list-scenarios
  python main.py --generate-pki
        """,
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()),
        default="highway",
        help="Named simulation scenario (default: highway)",
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=5.0,
        help="Simulation duration in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--vehicles", "-v",
        type=int,
        default=10,
        help="Total number of vehicles in simulation (default: 10)",
    )
    parser.add_argument(
        "--no-gateway",
        action="store_true",
        help="Disable Roadside Gateway (isolate DSRC and C-V2X networks)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="results",
        help="Output directory for reports and plots (default: results)",
    )
    parser.add_argument(
        "--generate-plots",
        action="store_true",
        help="Generate Matplotlib PDR and Latency CDF plots",
    )
    parser.add_argument(
        "--log-level", "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity level (default: INFO)",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List available scenarios and exit",
    )
    parser.add_argument(
        "--generate-pki",
        action="store_true",
        help="Generate simulated PKI certificate hierarchy and exit",
    )
    return parser.parse_args()


def print_banner():
    print(r"""
========================================================================
   ____  ____  ____   ____    __  __  _   _   ___   ____  ____  ____ 
  |  _ \/ ___||  _ \ / ___|  |  \/  || | | | / _ \ / ___||  _ \|  _ \
  | | | \___ \| |_) | |      | |\/| || | | || | | | |    | |_) | |_) |
  | |_| |___) |  _ <| |___   | |  | || |_| || |_| | |___ |  _ <|  _ <
  |____/|____/|_| \_\\____|  |_|  |_| \___/  \___/ \____||_| \_\_| \_\
  
     DSRC (IEEE 802.11p) <---> LTE-C-V2X (3GPP Rel-14 PC5 Mode 4)
             Standards-Grounded Bidirectional Protocol Gateway
========================================================================
""")


def print_summary_table(scenario_name: str, duration: float, collector):
    total_tx = collector.get_total_tx_count()
    total_rx = collector.get_total_rx_attempts()
    total_deliv = collector.get_total_delivered_count()
    overall_pdr = collector.get_overall_pdr() * 100.0
    lat = collector.get_latency_percentiles()
    gw = collector.get_gateway_summary()

    print("\n" + "=" * 72)
    print(f" SIMULATION RUN SUMMARY: {scenario_name.upper()} ({duration:.1f}s)")
    print("=" * 72)
    print(f"  Total BSM Broadcasts Transmitted:   {total_tx:>8} packets")
    print(f"  Total Wireless Reception Attempts:  {total_rx:>8} packets")
    print(f"  Total Packets Successfully Decoded: {total_deliv:>8} packets")
    print(f"  Overall Packet Delivery Ratio:      {overall_pdr:>8.2f} %")
    print("-" * 72)
    print(f"  Mean End-to-End Latency:            {lat['mean_ms']:>8.2f} ms")
    print(f"  Median (P50) Latency:               {lat['p50_ms']:>8.2f} ms")
    print(f"  95th Percentile Latency:            {lat['p95_ms']:>8.2f} ms")
    print(f"  99th Percentile Latency:            {lat['p99_ms']:>8.2f} ms")
    print("-" * 72)
    print(f"  Gateway Ingress Packets:            {gw['total_ingress']:>8} packets")
    print(f"  Gateway Successfully Forwarded:     {gw['forwarded']:>8} packets")
    print(f"  Gateway Dropped (Dedup/Loop/Sec):   {gw['dropped']:>8} packets")
    print(f"  Gateway Mean Transit Pipeline:      {gw['mean_transit_ms']:>8.2f} ms")
    print("=" * 72 + "\n")


def main() -> None:
    args = parse_args()

    if args.list_scenarios:
        print("\nAvailable V2X Simulation Scenarios:")
        for name, desc in SCENARIOS.items():
            print(f"  - {name:<15} : {desc}")
        print()
        return

    output_dir = Path(args.output_dir)
    configure_logging(
        log_level=args.log_level,
        log_dir=output_dir / "logs",
        enable_file=True,
    )
    log = get_logger("main")

    if args.generate_pki:
        log.info("Generating simulated IEEE 1609.2 PKI hierarchy...")
        from certificates.generate_pki import build_simulated_pki
        build_simulated_pki(num_vehicles=args.vehicles, certs_per_vehicle=5)
        print("\n✅ Simulated PKI certificates generated successfully in certificates/.\n")
        return

    print_banner()

    start_wall_time = time.time()
    enable_gw = not args.no_gateway

    if args.scenario == "highway":
        log.info(f"Running Highway Scenario: vehicles={args.vehicles}, duration={args.duration}s, gateway={enable_gw}")
        engine, collector = create_highway_scenario(
            num_vehicles=args.vehicles,
            enable_gateway=enable_gw,
            duration_s=args.duration,
        )
        print_summary_table("Highway", args.duration, collector)

    elif args.scenario == "intersection":
        log.info(f"Running Intersection Scenario: vehicles={args.vehicles}, duration={args.duration}s, gateway={enable_gw}")
        engine, collector = create_intersection_scenario(
            num_vehicles=args.vehicles,
            enable_gateway=enable_gw,
            duration_s=args.duration,
        )
        print_summary_table("Intersection", args.duration, collector)

    elif args.scenario == "mixed_stack":
        log.info(f"Running Mixed-Stack A/B Interoperability Benchmark: vehicles={args.vehicles}, duration={args.duration}s")
        results = run_comparative_benchmark(
            num_vehicles=args.vehicles,
            duration_s=args.duration,
        )
        print("\n" + "=" * 72)
        print(" MIXED-STACK INTEROPERABILITY A/B BENCHMARK RESULTS")
        print("=" * 72)
        print(f"  WITHOUT GATEWAY (Isolated Stacks):")
        print(f"    - Delivered Packets:             {results['without_gateway']['delivered']:>8}")
        print(f"    - Overall PDR:                   {results['without_gateway']['overall_pdr']*100:>8.2f} %")
        print(f"  WITH GATEWAY (Bidirectional Translation):")
        print(f"    - Delivered Packets:             {results['with_gateway']['delivered']:>8}")
        print(f"    - Overall PDR:                   {results['with_gateway']['overall_pdr']*100:>8.2f} %")
        print(f"    - Gateway Forwarded:             {results['with_gateway']['gateway_forwarded']:>8}")
        print(f"    - Gateway Transit Pipeline:      {results['with_gateway']['mean_transit_ms']:>8.2f} ms")
        print("-" * 72)
        print(f"  INTEROPERABILITY RECEPTION GAIN:   +{results['interoperability_gain_percent']:>7.1f} %")
        print("=" * 72 + "\n")
        return

    # Export CSVs & Plots
    reporter = SimulationReporter(collector, output_dir=output_dir)
    pdr_csv = reporter.export_pdr_csv()
    summary_csv = reporter.export_summary_json_or_csv()
    print(f"📊 Exported CSV Reports:\n   - {pdr_csv}\n   - {summary_csv}")

    if args.generate_plots:
        print("\n📈 Generating publication plots with Matplotlib...")
        pdr_fig = reporter.plot_pdr_vs_distance()
        lat_fig = reporter.plot_latency_cdf()
        print(f"   - {pdr_fig}\n   - {lat_fig}")

    elapsed = time.time() - start_wall_time
    print(f"\nExecution finished in {elapsed:.2f} seconds.\n")


if __name__ == "__main__":
    main()
