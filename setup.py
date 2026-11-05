"""
V2X Gateway Simulator — setup.py
Allows: pip install -e .  (editable install; adds src/ to PYTHONPATH)
"""

from setuptools import setup, find_packages

setup(
    name="v2x-gateway-simulator",
    version="0.1.0",
    description="DSRC ↔ LTE-C-V2X Communication Simulator (Python, Windows)",
    author="V2X Research",
    python_requires=">=3.11",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "cryptography>=42.0.0",
        "asn1tools>=0.166.0",
        "simpy>=4.1.1",
        "numpy>=1.26.0",
        "scipy>=1.12.0",
        "scapy>=2.5.0",
        "matplotlib>=3.8.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0.0",
        "loguru>=0.7.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0.0", "pytest-cov>=4.0.0", "pytest-mock>=3.12.0", "black>=24.0.0"],
    },
    entry_points={
        "console_scripts": [
            "v2x-gateway=main:main",
        ],
    },
)

