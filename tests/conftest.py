"""
Global pytest configuration and fixtures.
Ensures src/ is on sys.path for all tests.
"""

import sys
from pathlib import Path

# Add src to sys.path
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

