"""
V2X Gateway Simulator — Simulated PKI Generator
================================================
Generates a complete IEEE 1609.2-compliant simulated PKI hierarchy:
  - Root CA (Self-Signed)
  - Enrollment CA (ECA)
  - Pseudonym CA (PCA)
  - Gateway Certificate
  - Vehicle Pseudonym Certificate Pools

Standards References:
  - IEEE 1609.2-2016: Certificate format & signing
  - CAMP SCMS Architecture: PKI entity roles
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is on sys.path when executed directly
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import time
from typing import Dict, List, Optional, Tuple

from common.ieee1609_2.certificates import (
    Certificate,
    CertificateStore,
    CertificateType,
    IssuerChoice,
    ToBeSignedCertificate,
    ValidityPeriod,
)
from common.ieee1609_2.crypto import (
    generate_keypair,
    public_key_to_uncompressed_bytes,
    sign_ecdsa_p256,
)
from common.ieee1609_2.spdu import EcdsaP256Signature
from common.message_types import PSID
from monitoring.logger import get_logger

log = get_logger("security.pki_generator")


def issue_certificate(
    cert_id: str,
    subject_public_key_bytes: bytes,
    issuer_cert: Optional[Certificate],
    issuer_private_key,
    app_permissions: List[int],
    duration_seconds: int = 86400 * 365,
    crl_series: int = 1,
) -> Certificate:
    """Issue a new certificate signed by an issuer CA (or self-signed if issuer_cert is None)."""
    now_ms = int(time.time() * 1000)
    validity = ValidityPeriod(
        start_time_ms=now_ms - 60_000,  # 1 minute clock skew allowance
        duration_seconds=duration_seconds,
    )

    tbsc = ToBeSignedCertificate(
        cert_id=cert_id,
        craca_id=b"\x00\x00\x01",
        crl_series=crl_series,
        validity_period=validity,
        app_permissions=app_permissions,
        public_key_bytes=subject_public_key_bytes,
    )

    tbs_bytes = tbsc.serialize()
    r, s = sign_ecdsa_p256(issuer_private_key, tbs_bytes)
    signature = EcdsaP256Signature(r=r, s=s)

    if issuer_cert is None:
        # Self-signed root
        cert = Certificate(
            version=3,
            cert_type=CertificateType.EXPLICIT,
            issuer_choice=IssuerChoice.SELF_SIGNED,
            issuer_digest=None,
            to_be_signed=tbsc,
            signature=signature,
        )
    else:
        issuer_digest = issuer_cert.compute_digest8()
        cert = Certificate(
            version=3,
            cert_type=CertificateType.EXPLICIT,
            issuer_choice=IssuerChoice.SHA256_DIGEST,
            issuer_digest=issuer_digest,
            to_be_signed=tbsc,
            signature=signature,
        )

    return cert


def build_simulated_pki(
    num_vehicles: int = 5,
    certs_per_vehicle: int = 3,
    save_dir: Optional[Path] = None,
) -> CertificateStore:
    """Generate in-memory (and optionally on-disk) simulated PKI.

    Returns:
        Configured CertificateStore with all root, intermediate, gateway, and
        pseudonym certificates installed.
    """
    store = CertificateStore()

    # 1. Root CA
    root_priv, root_pub = generate_keypair()
    root_pub_bytes = public_key_to_uncompressed_bytes(root_pub)
    root_cert = issue_certificate(
        cert_id="Root-CA",
        subject_public_key_bytes=root_pub_bytes,
        issuer_cert=None,
        issuer_private_key=root_priv,
        app_permissions=[PSID.BSM, PSID.MAP, PSID.SPAT, PSID.TIM],
        duration_seconds=86400 * 365 * 10,  # 10 years
    )
    store.add_root_ca(root_cert, root_priv)
    log.info(f"Generated Root CA [digest: {root_cert.compute_digest8().hex()}]")

    # 2. Enrollment CA (ECA)
    eca_priv, eca_pub = generate_keypair()
    eca_cert = issue_certificate(
        cert_id="Enrollment-CA",
        subject_public_key_bytes=public_key_to_uncompressed_bytes(eca_pub),
        issuer_cert=root_cert,
        issuer_private_key=root_priv,
        app_permissions=[PSID.BSM, PSID.MAP, PSID.SPAT, PSID.TIM],
        duration_seconds=86400 * 365 * 5,
    )
    store.add_intermediate_ca(eca_cert, eca_priv)

    # 3. Pseudonym CA (PCA)
    pca_priv, pca_pub = generate_keypair()
    pca_cert = issue_certificate(
        cert_id="Pseudonym-CA",
        subject_public_key_bytes=public_key_to_uncompressed_bytes(pca_pub),
        issuer_cert=root_cert,
        issuer_private_key=root_priv,
        app_permissions=[PSID.BSM],
        duration_seconds=86400 * 365 * 3,
    )
    store.add_intermediate_ca(pca_cert, pca_priv)
    log.info(f"Generated Pseudonym CA [digest: {pca_cert.compute_digest8().hex()}]")

    # 4. Gateway Certificate
    gw_priv, gw_pub = generate_keypair()
    gw_cert = issue_certificate(
        cert_id="V2X-Gateway",
        subject_public_key_bytes=public_key_to_uncompressed_bytes(gw_pub),
        issuer_cert=root_cert,
        issuer_private_key=root_priv,
        app_permissions=[PSID.BSM, PSID.MAP, PSID.SPAT, PSID.TIM],
        duration_seconds=86400 * 365 * 2,
    )
    store.add_entity_cert(gw_cert, gw_priv)
    log.info(f"Generated Gateway cert [digest: {gw_cert.compute_digest8().hex()}]")

    # 5. Vehicle Pseudonym Certificates
    for v_idx in range(1, num_vehicles + 1):
        for c_idx in range(certs_per_vehicle):
            v_priv, v_pub = generate_keypair()
            cert_id = f"Vehicle-{v_idx}-Pseudo-{c_idx}"
            v_cert = issue_certificate(
                cert_id=cert_id,
                subject_public_key_bytes=public_key_to_uncompressed_bytes(v_pub),
                issuer_cert=pca_cert,
                issuer_private_key=pca_priv,
                app_permissions=[PSID.BSM],
                duration_seconds=86400 * 7,  # 7-day pseudonym lifetime
            )
            store.add_entity_cert(v_cert, v_priv)

    log.info(
        f"Simulated PKI ready: 1 Root CA, 2 Intermediate CAs, 1 Gateway Cert, "
        f"{num_vehicles * certs_per_vehicle} Vehicle Pseudonym Certs."
    )

    # Optionally persist to disk
    if save_dir:
        save_dir.mkdir(parents=True, exist_ok=True)
        root_dir = save_dir / "root_ca"
        root_dir.mkdir(parents=True, exist_ok=True)
        (root_dir / "root.cert").write_bytes(root_cert.serialize())

        pca_dir = save_dir / "pseudonym_ca"
        pca_dir.mkdir(parents=True, exist_ok=True)
        (pca_dir / "pca.cert").write_bytes(pca_cert.serialize())

        gw_dir = save_dir / "gateway"
        gw_dir.mkdir(parents=True, exist_ok=True)
        (gw_dir / "gateway.cert").write_bytes(gw_cert.serialize())

    return store


if __name__ == "__main__":
    import sys
    base_dir = Path(__file__).resolve().parent
    build_simulated_pki(num_vehicles=5, certs_per_vehicle=3, save_dir=base_dir)
    print("Simulated PKI generated successfully in certificates/")
