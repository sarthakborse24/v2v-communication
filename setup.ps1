# =============================================================================
# V2X Gateway Simulator — Windows PowerShell Setup Script
# Compatible: Windows 10/11, PowerShell 5.1+, Python 3.11+
# Usage: Right-click PowerShell → Run as Administrator (only for first run)
#        Or: cd <project root>; .\setup.ps1
# =============================================================================

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  V2X Gateway Simulator — Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# --- 1. Check Python version ---
Write-Host "[1/6] Checking Python version..." -ForegroundColor Yellow
try {
    $pyVersion = python --version 2>&1
    Write-Host "      Found: $pyVersion" -ForegroundColor Green
    $versionNum = ($pyVersion -replace "Python ", "").Split(".")
    if ([int]$versionNum[0] -lt 3 -or ([int]$versionNum[0] -eq 3 -and [int]$versionNum[1] -lt 11)) {
        Write-Host "      WARNING: Python 3.11+ recommended. Found $pyVersion" -ForegroundColor Yellow
    }
} catch {
    Write-Host "      ERROR: Python not found. Install from https://python.org" -ForegroundColor Red
    exit 1
}

# --- 2. Create virtual environment ---
Write-Host "[2/6] Creating virtual environment (.venv)..." -ForegroundColor Yellow
if (Test-Path ".venv") {
    Write-Host "      .venv already exists — skipping creation." -ForegroundColor Gray
} else {
    python -m venv .venv
    Write-Host "      .venv created." -ForegroundColor Green
}

# --- 3. Activate venv ---
Write-Host "[3/6] Activating virtual environment..." -ForegroundColor Yellow
$activateScript = ".venv\Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Host "      ERROR: Activation script not found at $activateScript" -ForegroundColor Red
    exit 1
}
& $activateScript
Write-Host "      Activated." -ForegroundColor Green

# --- 4. Upgrade pip and install dependencies ---
Write-Host "[4/6] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
Write-Host "      Dependencies installed." -ForegroundColor Green

# --- 5. Install project in editable mode ---
Write-Host "[5/6] Installing project in editable mode..." -ForegroundColor Yellow
if (Test-Path "setup.py") {
    pip install -e . --quiet
    Write-Host "      Project installed (editable)." -ForegroundColor Green
} else {
    # Add src to PYTHONPATH for development
    $env:PYTHONPATH = "$ProjectRoot\src;$env:PYTHONPATH"
    Write-Host "      PYTHONPATH set to include src\." -ForegroundColor Green
}

# --- 6. Verify imports ---
Write-Host "[6/6] Verifying critical imports..." -ForegroundColor Yellow
$imports = @(
    "import simpy; print(f'  simpy {simpy.__version__} OK')",
    "import numpy; print(f'  numpy {numpy.__version__} OK')",
    "import scipy; print(f'  scipy {scipy.__version__} OK')",
    "from cryptography.hazmat.primitives.asymmetric import ec; print('  cryptography (ECDSA P-256) OK')",
    "from cryptography.hazmat.primitives.ciphers.aead import AESCCM; print('  cryptography (AES-CCM) OK')",
    "import asn1tools; print(f'  asn1tools {asn1tools.__version__} OK')",
    "import scapy; print(f'  scapy {scapy.__version__} OK')",
    "import matplotlib; print(f'  matplotlib {matplotlib.__version__} OK')",
    "import loguru; print('  loguru OK')",
    "import pydantic; print(f'  pydantic {pydantic.__version__} OK')"
)
$allOk = $true
foreach ($imp in $imports) {
    try {
        python -c $imp
    } catch {
        Write-Host "  FAILED: $imp" -ForegroundColor Red
        $allOk = $false
    }
}

Write-Host ""
if ($allOk) {
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  Setup complete! All imports verified." -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  Activate venv : .\.venv\Scripts\Activate.ps1"
    Write-Host "  Run tests     : pytest"
    Write-Host "  Run simulator : python main.py --scenario highway"
    Write-Host "  Generate PKI  : python certificates\generate_pki.py"
} else {
    Write-Host "============================================" -ForegroundColor Red
    Write-Host "  Setup completed with errors. Check above." -ForegroundColor Red
    Write-Host "============================================" -ForegroundColor Red
    exit 1
}

