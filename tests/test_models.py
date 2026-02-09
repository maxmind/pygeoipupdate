"""Tests for pygeoipupdate data models."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pygeoipupdate.models import UpdateResult


class TestUpdateResultValidation:
    """Tests for UpdateResult __post_init__ validation."""

    def test_naive_modified_at_rejected(self) -> None:
        with pytest.raises(ValueError, match="modified_at must be timezone-aware"):
            UpdateResult(
                edition_id="GeoLite2-City",
                old_hash="aaa",
                new_hash="bbb",
                modified_at=datetime(2024, 1, 15, 12, 0, 0),  # noqa: DTZ001
            )

    def test_naive_checked_at_rejected(self) -> None:
        with pytest.raises(ValueError, match="checked_at must be timezone-aware"):
            UpdateResult(
                edition_id="GeoLite2-City",
                old_hash="aaa",
                new_hash="bbb",
                checked_at=datetime(2024, 1, 15, 12, 0, 0),  # noqa: DTZ001
            )

    def test_aware_datetimes_accepted(self) -> None:
        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="bbb",
            modified_at=datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC),
            checked_at=datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC),
        )
        assert result.modified_at is not None
        assert result.checked_at is not None

    def test_none_datetimes_accepted(self) -> None:
        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="bbb",
        )
        assert result.modified_at is None
        assert result.checked_at is None


class TestUpdateResultToDict:
    """Tests for UpdateResult.to_dict()."""

    def test_timestamps_are_unix_epoch_integers(self) -> None:
        modified = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        checked = datetime(2024, 6, 1, 8, 30, 0, tzinfo=UTC)

        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="bbb",
            modified_at=modified,
            checked_at=checked,
        ).to_dict()

        assert result["modified_at"] == 1705320000
        assert result["checked_at"] == 1717230600
        assert isinstance(result["modified_at"], int)
        assert isinstance(result["checked_at"], int)

    def test_none_timestamps_omitted(self) -> None:
        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="aaa",
        ).to_dict()

        assert "modified_at" not in result
        assert "checked_at" not in result

    def test_partial_timestamps(self) -> None:
        checked = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="aaa",
            checked_at=checked,
        ).to_dict()

        assert "modified_at" not in result
        assert result["checked_at"] == 1705320000

    def test_base_fields_always_present(self) -> None:
        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="bbb",
        ).to_dict()

        assert result["edition_id"] == "GeoLite2-City"
        assert result["old_hash"] == "aaa"
        assert result["new_hash"] == "bbb"


class TestWasUpdated:
    """Tests for UpdateResult.was_updated property."""

    def test_was_updated_true(self) -> None:
        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="bbb",
        )
        assert result.was_updated is True

    def test_was_updated_false(self) -> None:
        result = UpdateResult(
            edition_id="GeoLite2-City",
            old_hash="aaa",
            new_hash="aaa",
        )
        assert result.was_updated is False
