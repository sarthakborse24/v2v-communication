# V2X Gateway Simulator
# =====================

A research-grade Python simulation of a bidirectional **DSRC ↔ LTE-C-V2X** protocol gateway,
implementing standards-grounded communication stacks with IEEE 1609.2 security processing.

> **This is a software simulation only.** No actual RF transmission occurs.
> All PHY/MAC models are labelled as simulation models. See [docs/deviations.md](docs/deviations.md).

---

## Standards Implemented

| Stack | Standards |
|-------|-----------|
| DSRC | IEEE 802.11p, IEEE 1609.2, IEEE 1609.3, IEEE 1609.4, SAE J2735 BSM Part I |
| LTE-C-V2X | 3GPP Release 14 PC5 (Mode 4), IEEE 1609.2, SAE J2735 BSM Part I |
| Security | IEEE 1609.2 ECDSA-P256, explicit certificates, simulated PKI |

## Quick Start (Windows)

```powershell
# 1. Clone / open project in VS Code
cd c:\sarthak\code\project\V2V

# 2. Run setup (creates venv, installs deps, verifies imports)
.\setup.ps1

# 3. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Generate simulated PKI
python certificates\generate_pki.py

# 5. Run tests
pytest

# 6. Run a simulation scenario
python main.py --scenario highway
python main.py --scenario intersection --duration 60
```

## Project Structure

```
V2V-Gateway/
├── src/
│   ├── dsrc/           IEEE 802.11p / 1609.x DSRC stack
│   ├── cv2x/           3GPP LTE-V2X PC5 stack
│   ├── gateway/        Bidirectional DSRC ↔ C-V2X gateway
│   ├── common/         Shared BSM codec, 1609.2 security, config
│   ├── vehicles/       Vehicle mobility models
│   ├── simulation/     SimPy DES engine, channel models, scenarios
│   └── monitoring/     Structured logging
├── tests/              pytest unit + integration tests
├── configs/            YAML scenario configurations
├── certificates/       Simulated PKI (not real SCMS)
├── asn1/               BSM Part I ASN.1 schema
├── docs/               Architecture, traceability, security design
├── results/            Generated logs, CSVs, plots
├── requirements.txt
├── setup.ps1           Windows setup script
└── main.py
```

## Implementation Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | ✅ Complete | Project skeleton, deps, config, exceptions, logging, ASN.1 schema |
| 1 | ✅ Complete | BSM codec (UPER), IEEE 1609.2 security core, simulated PKI |
| 2 | ✅ Complete | DSRC stack (WSMP, 802.11p frames, 1609.4 MAC, PHY simulation) |
| 3 | ✅ Complete | LTE-C-V2X stack (PC5 SCI-1, Mode 4, LTE MAC, PHY simulation) |
| 4 | 🔄 Next | Bidirectional gateway (validation, translation, dedup, loop prevention) |
| 4 | ⏳ Pending | Bidirectional gateway (validation, translation, dedup) |
| 5 | ⏳ Pending | Simulation engine (SimPy, channel models, vehicles, metrics) |
| 6 | ⏳ Pending | Integration, documentation, hardware interface stubs |

## Key Design Decisions

- **IEEE 1609.2 security**: BSMs are **signed** (ECDSA-P256), not encrypted. Only unicast messages use AES-128-CCM encryption. This is correct per the standard.
- **No silent fallback**: If a standard feature cannot be fully implemented, it is explicitly stubbed with `NotImplemented` markers in the code and documented in [docs/deviations.md](docs/deviations.md).
- **Vanetza is NOT used**: Vanetza implements ETSI ITS (European CAM/DENM), not IEEE 1609 WAVE. See [docs/deviations.md](docs/deviations.md).
- **ASN.1**: Uses a hand-crafted BSM Part I subset (the full J2735 schema requires SAE membership).

## Running Tests

```powershell
# All tests
pytest

# Phase 0 smoke tests only
pytest tests/unit/test_phase0_smoke.py -v

# With coverage
pytest --cov=src --cov-report=term-missing

# By marker
pytest -m security
pytest -m dsrc
pytest -m gateway
```

## Configuration

Edit `configs/default.yaml` or pass a custom config:

```powershell
python main.py --config configs/my_scenario.yaml
```

Key settings:
- `simulation.bsm_rate_hz`: BSM transmission rate (10 Hz per SAE J2735)
- `security.replay_window_ms`: Replay detection window (1000 ms, see deviations.md)
- `channel.model`: Path loss model (`winner_plus`, `free_space`, `two_ray`)

## Known Limitations

See [docs/deviations.md](docs/deviations.md) for the full list. Key ones:

1. **PHY is a statistical model** — no actual RF waveform simulation
2. **BSM ASN.1 is a subset** — J2735 Part I only (14 fields)
3. **Local PKI only** — not interoperable with real SCMS infrastructure
4. **CRL stubbed** — revoked certificates are not detected

## License

Research / educational use. See individual library licenses in requirements.txt.

## Standards References

- IEEE 802.11p-2010
- IEEE 1609.2-2016 (Security)
- IEEE 1609.3-2016 (Networking)
- IEEE 1609.4-2016 (MAC)
- SAE J2735-2020 (Message Set)
- 3GPP TS 36.212 Release 14 (SCI Format 1)
- 3GPP TS 36.213 Release 14 (Mode 4)
- 3GPP TS 36.321 Release 14 (MAC)

