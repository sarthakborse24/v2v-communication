"""
Unit Tests for Gateway Duplicate Message Handler
=================================================
Standards References:
  - IEEE 1609.2-2016: Section 7.4.2
"""

import pytest

from common.exceptions import DuplicateMessageError
from gateway.duplicate_handler import DuplicateHandler


class TestDuplicateHandler:
    """Tests for sliding-window deduplication."""

    def test_novel_message_accepted(self):
        handler = DuplicateHandler(window_seconds=2.0)
        source = b"\x12\x34\x56\x78"

        # Novel message must succeed
        handler.check_and_record(source_id=source, msg_cnt=1, current_time_s=100.0)
        assert handler.is_duplicate(source_id=source, msg_cnt=1, current_time_s=100.5) is True

    def test_duplicate_within_window_rejected(self):
        handler = DuplicateHandler(window_seconds=2.0)
        source = b"\x12\x34\x56\x78"

        handler.check_and_record(source_id=source, msg_cnt=42, current_time_s=100.0)

        # Re-submitting identical (source, msg_cnt) within 2.0s must raise DuplicateMessageError
        with pytest.raises(DuplicateMessageError):
            handler.check_and_record(source_id=source, msg_cnt=42, current_time_s=101.5)

    def test_different_msg_cnt_accepted(self):
        handler = DuplicateHandler(window_seconds=2.0)
        source = b"\x12\x34\x56\x78"

        handler.check_and_record(source_id=source, msg_cnt=1, current_time_s=100.0)
        # Next sequence number from same vehicle must be accepted
        handler.check_and_record(source_id=source, msg_cnt=2, current_time_s=100.1)

    def test_duplicate_after_window_expiration_accepted(self):
        handler = DuplicateHandler(window_seconds=2.0)
        source = b"\x12\x34\x56\x78"

        handler.check_and_record(source_id=source, msg_cnt=5, current_time_s=100.0)

        # After 2.5 seconds (past window_seconds = 2.0), entry is pruned and accepted
        handler.check_and_record(source_id=source, msg_cnt=5, current_time_s=102.5)
