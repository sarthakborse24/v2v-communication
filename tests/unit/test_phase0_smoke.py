"""
Phase 0 Smoke Tests — Project Skeleton Validation
==================================================
Verifies that:
1. All critical library imports succeed
2. PSID constants are correct per IEEE 1609.3
3. Exception hierarchy is importable
4. Config schema validates correctly
5. Logger initialises without errors
6. ASN.1 schema file exists and is parseable by asn1tools

Run: pytest tests/unit/test_phase0_smoke.py -v
"""

import sys
from pathlib import Path
import pytest

# Ensure src is on path
_SRC = Path(__file__).resolve().parents[2] / "src"
sys.path.insert(0, str(_SRC))


# ---------------------------------------------------------------------------
# 1. Library Import Tests
# ---------------------------------------------------------------------------

class TestLibraryImports:
    """All project dependencies must import cleanly on Windows."""

    def test_simpy_import(self):
        import simpy
        assert hasattr(simpy, "Environment")

    def test_numpy_import(self):
        import numpy as np
        assert np.__version__

    def test_scipy_import(self):
        import scipy
        assert scipy.__version__

    def test_cryptography_ecdsa_p256(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        assert key is not None

    def test_cryptography_aes_ccm(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESCCM
        import os
        key = AESCCM.generate_key(bit_length=128)
        assert len(key) == 16

    def test_asn1tools_import(self):
        import asn1tools
        assert hasattr(asn1tools, "compile_files")

    def test_scapy_import(self):
        import scapy
        assert scapy.__version__

    def test_matplotlib_import(self):
        import matplotlib
        matplotlib.use("Agg")  # Non-interactive backend for CI
        assert matplotlib.__version__

    def test_loguru_import(self):
        from loguru import logger
        assert logger is not None

    def test_pydantic_import(self):
        import pydantic
        assert pydantic.__version__.startswith("2.")

    def test_yaml_import(self):
        import yaml
        assert hasattr(yaml, "safe_load")


# ---------------------------------------------------------------------------
# 2. PSID Constant Tests
# Source: IEEE 1609.3 Annex; confirmed in research
# ---------------------------------------------------------------------------

class TestPSIDConstants:
    """PSID values must match IEEE 1609.3 Annex allocations."""

    def test_bsm_psid(self):
        from common.message_types import PSID
        assert PSID.BSM == 0x0020, "BSM PSID must be 0x20 per IEEE 1609.3"

    def test_map_psid(self):
        from common.message_types import PSID
        assert PSID.MAP == 0x0022

    def test_spat_psid(self):
        from common.message_types import PSID
        assert PSID.SPAT == 0x0023

    def test_ethertype_wsmp(self):
        from common.message_types import ETHERTYPE_WSMP
        assert ETHERTYPE_WSMP == 0x88DC

    def test_bsm_edca_category(self):
        """BSMs must use AC_VO (highest priority EDCA queue)."""
        from common.message_types import BSM_EDCA_CATEGORY, EDCACategory
        assert BSM_EDCA_CATEGORY == EDCACategory.AC_VO

    def test_psid_encoded_length_1_byte(self):
        """PSID 0x20 (BSM) fits in 1 byte."""
        from common.message_types import psid_encoded_length
        assert psid_encoded_length(0x20) == 1

    def test_psid_encoded_length_2_bytes(self):
        """PSID 0x0080 requires 2 bytes."""
        from common.message_types import psid_encoded_length
        assert psid_encoded_length(0x0080) == 2

    def test_psid_encoded_length_3_bytes(self):
        from common.message_types import psid_encoded_length
        assert psid_encoded_length(0x4000) == 3

    def test_psid_encoded_length_4_bytes(self):
        from common.message_types import psid_encoded_length
        assert psid_encoded_length(0x200000) == 4

    def test_psid_too_large_raises(self):
        from common.message_types import psid_encoded_length
        with pytest.raises(ValueError):
            psid_encoded_length(0x20000000)

    def test_cch_channel_frequency(self):
        """CCH_178 must be at 5.890 GHz."""
        from common.message_types import WAVEChannel
        freq = WAVEChannel.CCH_178.frequency_hz
        assert abs(freq - 5.890e9) < 1e6, f"CCH frequency wrong: {freq}"


# ---------------------------------------------------------------------------
# 3. Exception Hierarchy Tests
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    """All domain exceptions must derive from V2XError."""

    def test_v2x_error_base(self):
        from common.exceptions import V2XError
        assert issubclass(V2XError, Exception)

    def test_security_exceptions(self):
        from common.exceptions import (
            SecurityError, SignatureVerificationError,
            ReplayDetectedError, CertificateChainError,
            PSIDPermissionError, V2XError
        )
        for exc in [SecurityError, SignatureVerificationError,
                    ReplayDetectedError, CertificateChainError,
                    PSIDPermissionError]:
            assert issubclass(exc, V2XError), f"{exc.__name__} must extend V2XError"

    def test_codec_exceptions(self):
        from common.exceptions import CodecError, BSMEncodeError, BSMDecodeError, V2XError
        for exc in [CodecError, BSMEncodeError, BSMDecodeError]:
            assert issubclass(exc, V2XError)

    def test_wsmp_exceptions(self):
        from common.exceptions import WSMPError, WSMPVersionError, WSMPLengthError, V2XError
        for exc in [WSMPError, WSMPVersionError, WSMPLengthError]:
            assert issubclass(exc, V2XError)

    def test_gateway_exceptions(self):
        from common.exceptions import (
            GatewayError, ValidationError, TranslationError,
            DuplicateMessageError, LoopDetectedError, V2XError
        )
        for exc in [GatewayError, ValidationError, TranslationError,
                    DuplicateMessageError, LoopDetectedError]:
            assert issubclass(exc, V2XError)

    def test_not_implemented_stubs(self):
        from common.exceptions import (
            SCMSNotImplementedError,
            RevocationNotImplementedError,
            HardwareInterfaceNotImplementedError,
        )
        for exc in [SCMSNotImplementedError, RevocationNotImplementedError,
                    HardwareInterfaceNotImplementedError]:
            assert issubclass(exc, NotImplementedError)

    def test_exceptions_are_raiseable(self):
        from common.exceptions import SignatureVerificationError
        with pytest.raises(SignatureVerificationError):
            raise SignatureVerificationError("test")


# ---------------------------------------------------------------------------
# 4. Configuration Schema Tests
# ---------------------------------------------------------------------------

class TestConfigSchema:
    """Pydantic V2XSimConfig must validate YAML configs correctly."""

    def test_default_config_loads(self):
        from common.config_schema import V2XSimConfig
        cfg = V2XSimConfig()
        assert cfg.scenario == "highway"
        assert cfg.num_dsrc_vehicles == 5

    def test_dsrc_cch_channel(self):
        from common.config_schema import V2XSimConfig
        cfg = V2XSimConfig()
        assert cfg.dsrc.channel == 178

    def test_bsm_rate_hz(self):
        from common.config_schema import V2XSimConfig
        cfg = V2XSimConfig()
        assert cfg.simulation.bsm_rate_hz == 10.0

    def test_security_algorithm(self):
        from common.config_schema import V2XSimConfig
        cfg = V2XSimConfig()
        assert cfg.security.signature_algorithm == "ecdsa-p256"

    def test_replay_window_default(self):
        from common.config_schema import V2XSimConfig
        cfg = V2XSimConfig()
        assert cfg.security.replay_window_ms == 1000

    def test_invalid_log_level_rejected(self):
        from common.config_schema import V2XSimConfig
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            V2XSimConfig(log_level="VERBOSE")

    def test_yaml_config_file_loads(self):
        """The default.yaml config file must load and validate."""
        import yaml
        from common.config_schema import V2XSimConfig
        config_path = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"
        assert config_path.exists(), "configs/default.yaml missing"
        with config_path.open() as fh:
            raw = yaml.safe_load(fh)
        cfg = V2XSimConfig(**raw)
        assert cfg.scenario == "highway"

    def test_highway_scenario_config_loads(self):
        import yaml
        from common.config_schema import V2XSimConfig
        path = Path(__file__).resolve().parents[2] / "configs" / "highway_scenario.yaml"
        with path.open() as fh:
            raw = yaml.safe_load(fh)
        cfg = V2XSimConfig(**raw)
        assert cfg.num_dsrc_vehicles == 10

    def test_intersection_scenario_config_loads(self):
        import yaml
        from common.config_schema import V2XSimConfig
        path = Path(__file__).resolve().parents[2] / "configs" / "intersection_scenario.yaml"
        with path.open() as fh:
            raw = yaml.safe_load(fh)
        cfg = V2XSimConfig(**raw)
        assert cfg.num_dsrc_vehicles == 4
        assert cfg.num_cv2x_vehicles == 4


# ---------------------------------------------------------------------------
# 5. Logger Tests
# ---------------------------------------------------------------------------

class TestLogger:
    """Logger must initialise without errors."""

    def test_get_logger(self):
        from monitoring.logger import get_logger
        log = get_logger("test.phase0")
        assert log is not None

    def test_logger_subsystems(self):
        from monitoring.logger import get_logger
        for subsystem in ["dsrc.security", "gateway.validator", "simulation.channel"]:
            log = get_logger(subsystem)
            assert log is not None


# ---------------------------------------------------------------------------
# 6. ASN.1 Schema File Tests
# ---------------------------------------------------------------------------

class TestASN1Schema:
    """BSM ASN.1 schema file must exist and compile with asn1tools."""

    def test_schema_file_exists(self):
        schema_path = Path(__file__).resolve().parents[2] / "asn1" / "BSM_PartI_Subset_v1.asn"
        assert schema_path.exists(), "ASN.1 schema file missing"
        assert schema_path.stat().st_size > 100, "ASN.1 schema file appears empty"

    def test_schema_compiles(self):
        """asn1tools must compile the BSM schema without errors."""
        import asn1tools
        schema_path = Path(__file__).resolve().parents[2] / "asn1" / "BSM_PartI_Subset_v1.asn"
        db = asn1tools.compile_files(str(schema_path), codec="uper")
        assert "BSM-PartI-Subset" in db.modules

    def test_schema_has_bsm_type(self):
        import asn1tools
        schema_path = Path(__file__).resolve().parents[2] / "asn1" / "BSM_PartI_Subset_v1.asn"
        db = asn1tools.compile_files(str(schema_path), codec="uper")
        types = db.modules["BSM-PartI-Subset"]
        assert "BasicSafetyMessage" in types
        assert "BSMcoreData" in types

    def test_schema_key_types_present(self):
        import asn1tools
        schema_path = Path(__file__).resolve().parents[2] / "asn1" / "BSM_PartI_Subset_v1.asn"
        db = asn1tools.compile_files(str(schema_path), codec="uper")
        types = db.modules["BSM-PartI-Subset"]
        expected = [
            "MsgCount", "TemporaryID", "DSecond", "Latitude", "Longitude",
            "Elevation", "Speed", "Heading", "VehicleSize", "BrakeSystemStatus",
        ]
        for t in expected:
            assert t in types, f"ASN.1 type '{t}' missing from schema"

