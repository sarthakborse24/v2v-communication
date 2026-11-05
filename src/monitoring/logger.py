"""
V2X Gateway Simulator — Structured Logger
==========================================
Wraps Loguru with per-layer structured output format.

Usage:
    from src.monitoring.logger import get_logger
    log = get_logger("dsrc.security")
    log.info("BSM signed", psid=0x20, cert_digest="ab12...")
"""

import sys
from pathlib import Path
from loguru import logger


# Default log file location (overridable via config)
_DEFAULT_LOG_DIR = Path(__file__).resolve().parents[2] / "results" / "logs"

_CONFIGURED = False


def configure_logging(
    log_level: str = "DEBUG",
    log_dir: Path = _DEFAULT_LOG_DIR,
    enable_file: bool = True,
    rotation: str = "10 MB",
    retention: str = "7 days",
) -> None:
    """Configure global Loguru settings.  Call once at startup from main.py."""
    global _CONFIGURED

    # Remove default handler
    logger.remove()

    # --- Console handler: human-readable ---
    logger.add(
        sys.stderr,
        level=log_level,
        format=(
            "<green>{time:HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{extra[subsystem]: <20}</cyan> | "
            "{message}"
        ),
        colorize=True,
    )

    if enable_file:
        log_dir.mkdir(parents=True, exist_ok=True)
        # --- File handler: structured JSON for post-processing ---
        logger.add(
            log_dir / "v2x_gateway_{time:YYYYMMDD}.log",
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {extra[subsystem]} | {message}",
            rotation=rotation,
            retention=retention,
            encoding="utf-8",
        )
        # --- Security-specific log file ---
        logger.add(
            log_dir / "security_{time:YYYYMMDD}.log",
            level="DEBUG",
            filter=lambda record: record["extra"].get("subsystem", "").startswith("security")
                                  or record["extra"].get("subsystem", "").startswith("gateway.security"),
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {extra} | {message}",
            rotation=rotation,
            retention=retention,
            encoding="utf-8",
        )

    _CONFIGURED = True


def get_logger(subsystem: str):
    """Return a Loguru logger bound to a specific subsystem name.

    Args:
        subsystem: Dot-separated subsystem path, e.g. "dsrc.security",
                   "gateway.validator", "simulation.channel".

    Returns:
        A Loguru logger with the subsystem bound in its extra context.
    """
    if not _CONFIGURED:
        # Auto-configure with defaults if not yet set up (useful in tests)
        configure_logging(enable_file=False)
    return logger.bind(subsystem=subsystem)

