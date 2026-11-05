"""
V2X Gateway Simulator — Message Types, Constants & Enumerations
===============================================================
All protocol constants are sourced from published standards.
References are cited per constant.

Standards References:
  - IEEE 1609.3 Annex: PSID allocations
  - IEEE 1609.2 §7:    Protocol version, algorithm identifiers
  - SAE J2735 §7:      Message type IDs
  - 3GPP TS 36.212 §8.4.1: SCI Format 1 priority values
"""

from enum import IntEnum, IntFlag, auto


# ---------------------------------------------------------------------------
# PSID (Provider Service Identifier) Constants
# Source: IEEE 1609.3 Annex; IEEE Registration Authority allocations
# ---------------------------------------------------------------------------

class PSID(IntEnum):
    """US WAVE PSID allocations.

    PSIDs are variable-length encoded in WSMP headers (1–4 bytes).
    Leading bits determine the byte count:
      0xxxxxxx              = 1 byte  (0x00–0x7F)
      10xxxxxx xxxxxxxx     = 2 bytes (0x0080–0x3FFF)
      110xxxxx xxxxxxxx...  = 3 bytes (0x4000–0x1FFFFF)
      1110xxxx xxxxxxxx...  = 4 bytes (0x200000–0x1FFFFFFF)

    Source: IEEE 1609.3 §8.1.3
    """
    BSM         = 0x0020   # Basic Safety Message (SAE J2735) — US DSRC safety
    MAP         = 0x0022   # MAP Data (intersection geometry)
    SPAT        = 0x0023   # Signal Phase and Timing
    TIM         = 0x004A   # Traveller Information Message
    RSA         = 0x0027   # Road Side Alert
    PDM         = 0x0028   # Probe Data Management
    SRM         = 0x001E   # Signal Request Message
    SSM         = 0x001F   # Signal Status Message
    RTCM        = 0x0085   # RTCM corrections


PSID_BYTE_LENGTHS = {
    # Map PSID ranges to their WSMP encoding byte count
    # Source: IEEE 1609.3 §8.1.3
    (0x00, 0x7F):           1,
    (0x80, 0x3FFF):         2,
    (0x4000, 0x1FFFFF):     3,
    (0x200000, 0x1FFFFFFF): 4,
}


def psid_encoded_length(psid: int) -> int:
    """Return the number of bytes required to encode a PSID per IEEE 1609.3 §8.1.3."""
    if psid <= 0x7F:
        return 1
    elif psid <= 0x3FFF:
        return 2
    elif psid <= 0x1FFFFF:
        return 3
    elif psid <= 0x1FFFFFFF:
        return 4
    raise ValueError(f"PSID value 0x{psid:08X} exceeds maximum (0x1FFFFFFF)")


# ---------------------------------------------------------------------------
# WAVE Channel Numbers
# Source: IEEE 1609.4 §6.1; FCC 47 CFR Part 90 Subpart M
# ---------------------------------------------------------------------------

class WAVEChannel(IntEnum):
    """DSRC channel numbers in the 5.9 GHz band.

    Channel numbering follows 802.11 convention: CH_N at 5.000 + N*5 MHz.
    All channels are 10 MHz wide in DSRC (not 20 MHz as in standard 802.11).
    """
    SCH_172 = 172   # 5.860 GHz — Service Channel
    SCH_174 = 174   # 5.870 GHz — Service Channel
    SCH_176 = 176   # 5.880 GHz — Service Channel
    CCH_178 = 178   # 5.890 GHz — Control Channel (safety / BSMs)
    SCH_180 = 180   # 5.900 GHz — Service Channel
    SCH_182 = 182   # 5.910 GHz — Service Channel
    SCH_184 = 184   # 5.920 GHz — Service Channel

    @property
    def frequency_hz(self) -> float:
        """Centre frequency in Hz."""
        return (5.000e9 + self.value * 5.0e6)

CCH_CHANNEL = WAVEChannel.CCH_178
BSM_DEFAULT_CHANNEL = WAVEChannel.CCH_178


# ---------------------------------------------------------------------------
# WAVE EDCA Access Categories
# Source: IEEE 1609.4 §6.2.6; IEEE 802.11e §9.19.2
# ---------------------------------------------------------------------------

class EDCACategory(IntEnum):
    """802.11e / WAVE EDCA Access Category priorities.

    Lower AC number = higher priority queue.
    Safety messages (BSMs) use AC_VO for lowest latency.
    """
    AC_BK = 0   # Background
    AC_BE = 1   # Best Effort
    AC_VI = 2   # Video
    AC_VO = 3   # Voice / Safety (BSMs use this)

BSM_EDCA_CATEGORY = EDCACategory.AC_VO


# ---------------------------------------------------------------------------
# IEEE 1609.2 Security Constants
# Source: IEEE 1609.2-2016 §7
# ---------------------------------------------------------------------------

class HashAlgorithm(IntEnum):
    """Hash algorithm identifiers.  Source: IEEE 1609.2 §6.3.3."""
    SHA256   = 0
    SHA384   = 1   # For P-384; not used in this simulator
    SM3      = 2   # Chinese standard; not used

class SymmetricAlgorithm(IntEnum):
    """Symmetric cipher identifiers.  Source: IEEE 1609.2 §6.3.5."""
    AES_128_CCM = 0

class SignatureAlgorithm(IntEnum):
    """Signature algorithm identifiers.  Source: IEEE 1609.2 §6.3.4."""
    ECDSA_NISTP256_WITH_SHA256         = 0
    ECDSA_BRAINPOOLP256R1_WITH_SHA256  = 1  # ETSI profile; NOT used (unreliable in PyCA)
    ECDSA_NISTP384_WITH_SHA384         = 2  # Not used in this simulator
    SM2_WITH_SM3                       = 4  # Chinese standard; not used

# Active signature algorithm for this simulator
ACTIVE_SIG_ALGORITHM = SignatureAlgorithm.ECDSA_NISTP256_WITH_SHA256

# IEEE 1609.2 protocol version
IEEE1609_2_PROTOCOL_VERSION = 3

# Replay window: messages with |generationTime - now| > this value are rejected.
# Standard allows up to ±20 minutes; simulator uses ±1 second (documented deviation L8).
# Units: milliseconds
REPLAY_WINDOW_MS = 1_000

# Sliding dedup window for (sourceID, msgCnt) pairs
# Source: Gateway duplicate_handler.py
DEDUP_WINDOW_SECONDS = 2.0

# AES-CCM tag length (bytes) for IEEE 1609.2 EncryptedData
# Source: IEEE 1609.2 §7.3.5
AES_CCM_TAG_LENGTH = 16
AES_CCM_KEY_LENGTH = 16  # 128 bits


# ---------------------------------------------------------------------------
# SAE J2735 BSM Constants
# Source: SAE J2735-2020 data dictionary
# ---------------------------------------------------------------------------

class J2735MessageID(IntEnum):
    """SAE J2735 message type identifiers."""
    BSM   = 20   # BasicSafetyMessage (Part I + optional Part II)
    MAP   = 18   # MapData
    SPAT  = 19   # SPATIntersectionState
    TIM   = 31   # TravelerInformation

# BSM Part I field constraints (for constraint checking before UPER encode)
BSM_MSG_CNT_MAX   = 127
BSM_MSG_CNT_MIN   = 0
BSM_LAT_MAX       = 900_000_000     # 1/10 microdegree units; +90.0°
BSM_LAT_MIN       = -900_000_000    # -90.0°
BSM_LON_MAX       = 1_800_000_000   # +180.0°
BSM_LON_MIN       = -1_800_000_000  # -180.0°
BSM_ELEV_MAX      = 61_439          # 0.1 m units; +6143.9 m
BSM_ELEV_MIN      = -4_096          # -409.6 m (special: 0xF000 = unknown)
BSM_ELEV_UNKNOWN  = 0xF000
BSM_SPEED_MAX     = 8_191           # 0.02 m/s units; 8191 = unavailable
BSM_SPEED_MIN     = 0
BSM_HEADING_MAX   = 28_800          # 0.0125° units; 28800 = unavailable
BSM_HEADING_MIN   = 0
BSM_WIDTH_MAX     = 1_023           # cm
BSM_LENGTH_MAX    = 4_095           # cm
BSM_TEMP_ID_LENGTH = 4              # bytes; TemporaryID


# ---------------------------------------------------------------------------
# LTE-V2X PC5 Constants
# Source: 3GPP TS 36.212 §8.4.1; 3GPP TS 36.213 §14
# ---------------------------------------------------------------------------

class V2XPriority(IntEnum):
    """V2X message priority levels.  Source: 3GPP TS 36.321 §5.14.1.
    Maps to SCI Format 1 Priority field (3 bits: 0=highest, 7=lowest).
    """
    SAFETY_CRITICAL  = 0   # Emergency brake, FCW
    SAFETY_HIGH      = 1   # BSM / CAM periodic safety
    SAFETY_MEDIUM    = 2   # Road hazard
    TRAFFIC_HIGH     = 3   # Traffic efficiency
    TRAFFIC_MEDIUM   = 4   # Infotainment priority
    TRAFFIC_LOW      = 5
    BEST_EFFORT_HIGH = 6
    BEST_EFFORT_LOW  = 7

BSM_DEFAULT_V2X_PRIORITY = V2XPriority.SAFETY_HIGH

# SCI Format 1 field ranges (Source: 3GPP TS 36.212 §8.4.1)
SCI1_PRIORITY_BITS          = 3    # 0–7
SCI1_RESOURCE_RESERVATION_BITS = 4  # 0=no reservation; 1–15 = period
SCI1_TIME_GAP_BITS          = 4    # subframe gap to retransmission
SCI1_MCS_BITS               = 5    # 0–31 MCS index
SCI1_RETX_INDEX_BITS        = 1    # 0=initial, 1=retransmission

# Mode 4 sensing window duration
# Source: 3GPP TS 36.213 §14.1.1.6
MODE4_SENSING_WINDOW_MS = 100

# LTE subframe duration
LTE_SUBFRAME_MS = 1

# C-V2X centre frequency (5.9 GHz band, same DSRC band in US)
CV2X_CENTRE_FREQ_HZ = 5.9e9


# ---------------------------------------------------------------------------
# Stack Type Identifiers
# ---------------------------------------------------------------------------

class StackType(IntEnum):
    """Communication stack type for a vehicle or gateway port."""
    DSRC  = 1   # IEEE 802.11p / 1609.x
    CV2X  = 2   # 3GPP LTE-V2X PC5

class GatewayDirection(IntEnum):
    """Direction of a gateway translation."""
    DSRC_TO_CV2X = 1
    CV2X_TO_DSRC = 2


# ---------------------------------------------------------------------------
# Convenience: EtherType constants
# ---------------------------------------------------------------------------

ETHERTYPE_WSMP = 0x88DC   # IEEE 1609.3 WSMP; Source: IEEE 1609.3 §8.1
ETHERTYPE_IPV6 = 0x86DD   # IPv6 on WAVE service channels

