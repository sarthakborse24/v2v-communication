"""
V2X Gateway Simulator — Gateway Bidirectional Message Translator
=================================================================
Performs bidirectional protocol and header translation:
  - DSRC (IEEE 1609.3 WSMP / 802.11p) -> LTE-C-V2X (3GPP PC5 SL-SCH / SCI-1)
  - LTE-C-V2X (3GPP PC5 SL-SCH / SCI-1) -> DSRC (IEEE 1609.3 WSMP / 802.11p)

CRITICAL RULE:
  Preserves the underlying SAE J2735 BSM UPER payload bytes verbatim.
  Maps network and QoS attributes appropriately between stacks.
"""

from __future__ import annotations

from typing import Optional, Tuple

from common.exceptions import TranslationError
from common.ieee1609_2.spdu import Ieee1609Dot2Data
from common.message_types import (
    BSM_DEFAULT_CHANNEL,
    BSM_DEFAULT_V2X_PRIORITY,
    BSM_EDCA_CATEGORY,
    EDCACategory,
    ETHERTYPE_WSMP,
    PSID,
    V2XPriority,
    WAVEChannel,
)
from cv2x.pc5.sidelink import (
    SCIFormat1,
    SidelinkTransportBlock,
    V2X_BROADCAST_L2_ID,
)
from dsrc.wave.wave_frame import (
    BROADCAST_MAC,
    WAVEFrame,
)
from dsrc.wave.wsmp import WSMPacket
from gateway.receiver import IngressPacket
from monitoring.logger import get_logger

log = get_logger("gateway.translator")


class GatewayTranslator:
    """Translates protocol envelopes between DSRC WAVE and LTE-V2X PC5."""

    def __init__(
        self,
        gateway_mac_address: bytes = b"\x00\xaa\xbb\xcc\xdd\x01",
        gateway_l2_id: bytes = b"\xaa\xbb\x01",
        default_cv2x_mcs: int = 10,
    ):
        self.gateway_mac_address = gateway_mac_address
        self.gateway_l2_id = gateway_l2_id
        self.default_cv2x_mcs = default_cv2x_mcs

    def translate_dsrc_to_cv2x(
        self,
        inbound_packet: IngressPacket,
        re_signed_spdu: Ieee1609Dot2Data,
        allocated_subchannel: int = 0,
    ) -> Tuple[SCIFormat1, SidelinkTransportBlock]:
        """Translate DSRC WSMP packet into C-V2X PC5 SL-SCH TB + SCI Format 1.

        Mapping:
          - EDCA AC_VO -> V2XPriority.SAFETY_HIGH (1)
          - Broadcast Destination -> V2X_BROADCAST_L2_ID (0xFFFFFF)
          - SPDU -> PSSCH Transport Block payload
          - Channel 178 -> Sidelink Resource Pool Subchannel
        """
        spdu_bytes = re_signed_spdu.to_bytes()

        # Map 802.11e EDCA category to 3GPP V2X Priority
        edca_cat = inbound_packet.metadata.get("edca_category", BSM_EDCA_CATEGORY)
        if edca_cat == EDCACategory.AC_VO:
            v2x_prio = V2XPriority.SAFETY_HIGH
        else:
            v2x_prio = V2XPriority.TRAFFIC_HIGH

        # Construct SCI Format 1
        sci = SCIFormat1(
            priority=int(v2x_prio),
            resource_reservation=3,  # 100 ms SPS period
            freq_resource_location=allocated_subchannel,
            time_gap=0,
            mcs=self.default_cv2x_mcs,
            retx_index=0,
        )

        # Construct Transport Block
        tb = SidelinkTransportBlock(
            payload=spdu_bytes,
            source_l2_id=self.gateway_l2_id,
            dest_l2_id=V2X_BROADCAST_L2_ID,
        )

        log.debug(
            f"Translated DSRC -> C-V2X: l2_src={self.gateway_l2_id.hex()} "
            f"prio={sci.priority} mcs={sci.mcs} subch={allocated_subchannel}"
        )
        return sci, tb

    def translate_cv2x_to_dsrc(
        self,
        inbound_packet: IngressPacket,
        re_signed_spdu: Ieee1609Dot2Data,
    ) -> Tuple[WAVEFrame, WSMPacket]:
        """Translate C-V2X PC5 Transport Block into DSRC 802.11p OCB WAVE frame.

        Mapping:
          - V2XPriority.SAFETY_CRITICAL / SAFETY_HIGH -> EDCA AC_VO (TID 6)
          - Sidelink Payload -> WSMP payload with PSID 0x20
          - SL-SCH -> Channel 178 (CCH)
          - Broadcast -> Destination MAC FF:FF:FF:FF:FF:FF
        """
        spdu_bytes = re_signed_spdu.to_bytes()

        # Map 3GPP V2X Priority to 802.11e EDCA category
        prio_val = inbound_packet.metadata.get("priority", 1)
        if prio_val in (0, 1):
            edca_cat = EDCACategory.AC_VO
        elif prio_val in (2, 3):
            edca_cat = EDCACategory.AC_VI
        else:
            edca_cat = EDCACategory.AC_BE

        # Construct WSMPacket
        wsm = WSMPacket(
            payload=spdu_bytes,
            psid=PSID.BSM,
            channel_number=WAVEChannel.CCH_178,
            tx_power_dbm=20,
        )
        wsm_bytes = wsm.serialize()

        # Construct 802.11p WAVE frame
        wave_frame = WAVEFrame(
            payload=wsm_bytes,
            source_mac=self.gateway_mac_address,
            dest_mac=BROADCAST_MAC,
            edca_category=edca_cat,
            ethertype=ETHERTYPE_WSMP,
        )

        log.debug(
            f"Translated C-V2X -> DSRC: src_mac={self.gateway_mac_address.hex()} "
            f"edca={edca_cat.name} psid=0x{wsm.psid:04X}"
        )
        return wave_frame, wsm
