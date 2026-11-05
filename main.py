"""
V2X Gateway Simulator — Main Entry Point
=========================================
CLI orchestrator.  Loads config, initialises stacks, runs simulation.

Usage:
    python main.py --scenario highway
    python main.py --scenario intersection --duration 60
    python main.py --config configs/my_scenario.yaml --log-level DEBUG
    python main.py --list-scenarios

NOTE: This file is the Phase 6 final orchestrator stub.
      Scenario and simulation modules are wired in during Phase 5/6.
      At Phase 0 this file validates that the project skeleton loads correctly.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure src/ is on PYTHONPATH when running from project root
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import yaml
from pydantic import ValidationError

from common.config_schema import V2XSimConfig
from monitoring.logger import configure_logging, get_logger


SCENARIOS = {
    "highway":      "configs/highway_scenario.yaml",
    "intersection": "configs/intersection_scenario.yaml",
    "mixed_stack":  "configs/default.yaml",
}


def load_config(config_path: str) -> V2XSimConfig:
    """Load and validate a YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        print(f"ERROR: Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    try:
        return V2XSimConfig(**raw)
    except ValidationError as exc:
        print(f"ERROR: Invalid configuration:\n{exc}", file=sys.stderr)
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="v2x-gateway",
        description="DSRC ↔ LTE-C-V2X Communication Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --scenario highway
  python main.py --scenario intersection --duration 60
  python main.py --config configs/my_scenario.yaml --log-level DEBUG
  python main.py --list-scenarios
        """,
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()),
        default="highway",
        help="Named simulation scenario (default: highway)",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to custom YAML config file (overrides --scenario)",
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=None,
        help="Override simulation duration in seconds",
    )
    parser.add_argument(
        "--log-level", "-l",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override log level from config",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List available scenarios and exit",
    )
    parser.add_argument(
        "--generate-pki",
        action="store_true",
        help="Generate simulated PKI certificates and exit",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_scenarios:
        print("\nAvailable scenarios:")
        for name, cfg in SCENARIOS.items():
            print(f"  {name:<20} → {cfg}")
        print()
        return

    # --- Load configuration ---
    config_path = args.config if args.config else SCENARIOS[args.scenario]
    config = load_config(config_path)

    # Apply CLI overrides
    if args.duration is not None:
        config.simulation.duration_seconds = args.duration
    if args.log_level is not None:
        config.log_level = args.log_level

    # --- Logging ---
    results_dir = Path(config.results_dir)
    configure_logging(
        log_level=config.log_level,
        log_dir=results_dir / "logs",
        enable_file=True,
    )
    log = get_logger("main")

    log.info(
        f"V2X Gateway Simulator starting | scenario={config.scenario} "
        f"| dsrc_vehicles={config.num_dsrc_vehicles} "
        f"| cv2x_vehicles={config.num_cv2x_vehicles} "
        f"| duration={config.simulation.duration_seconds}s"
    )

    if args.generate_pki:
        log.info("PKI generation requested — running generate_pki.py")
        import subprocess
        result = subprocess.run(
            [sys.executable, "certificates/generate_pki.py"],
            capture_output=False,
        )
        sys.exit(result.returncode)

    # --- Phase gate: simulation engine wired in Phase 5 ---
    log.warning(
        "Simulation engine not yet wired (Phase 5 not yet implemented). "
        "Project skeleton validated successfully."
    )
    print(
        "\n✅ Phase 0 complete — project skeleton loaded and config validated.\n"
        "   Run: pytest tests/ to verify all stubs pass collection.\n"
        "   Next: Phase 1 (BSM codec + IEEE 1609.2 security core).\n"
    )


if __name__ == "__main__":
    main()

