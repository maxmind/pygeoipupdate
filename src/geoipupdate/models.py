"""Data models for geoipupdate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Metadata:
    """Database metadata from the MaxMind update service.

    Attributes:
        edition_id: The database edition ID.
        date: The database date in YYYY-MM-DD format.
        md5: The MD5 hash of the database file.

    """

    edition_id: str
    date: str
    md5: str


@dataclass(frozen=True)
class UpdateResult:
    """Result of updating a single database edition.

    Attributes:
        edition_id: The database edition ID.
        old_hash: MD5 hash of the database before update.
        new_hash: MD5 hash of the database after update.
        modified_at: Timestamp when the database was last modified on the server.
        checked_at: Timestamp when the update check was performed.

    """

    edition_id: str
    old_hash: str
    new_hash: str
    modified_at: datetime | None = None
    checked_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization.

        Returns:
            Dictionary representation suitable for JSON output.

        """
        result: dict[str, Any] = {
            "edition_id": self.edition_id,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
        }
        if self.modified_at:
            result["modified_at"] = self.modified_at.isoformat()
        if self.checked_at:
            result["checked_at"] = self.checked_at.isoformat()
        return result

    @property
    def was_updated(self) -> bool:
        """Return True if the database was updated.

        Returns:
            True if old_hash differs from new_hash.

        """
        return self.old_hash != self.new_hash
