"""File writer for pygeoipupdate databases."""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path

from pygeoipupdate.errors import HashMismatchError

logger = logging.getLogger(__name__)

ZERO_MD5 = "00000000000000000000000000000000"


class LocalFileWriter:
    """Writes database files atomically with MD5 verification.

    Databases are written to a temporary file first, then atomically
    renamed to their final location after hash verification.
    """

    def __init__(
        self,
        database_dir: Path,
        *,
        preserve_file_times: bool = False,
        verbose: bool = False,
    ) -> None:
        """Initialize the file writer.

        Args:
            database_dir: Directory to store database files.
            preserve_file_times: Whether to preserve file modification times.
            verbose: Enable verbose logging.

        """
        self._dir = database_dir
        self._preserve_file_times = preserve_file_times
        self._verbose = verbose

        # Ensure database directory exists
        self._dir.mkdir(parents=True, exist_ok=True)

    def get_hash(self, edition_id: str) -> str:
        """Get the MD5 hash of an existing database file.

        Args:
            edition_id: The database edition ID.

        Returns:
            The MD5 hash as a hex string, or ZERO_MD5 if the file doesn't exist.

        """
        file_path = self._get_file_path(edition_id)

        if not file_path.exists():
            if self._verbose:
                logger.info("Database does not exist, returning zeroed hash")
            return ZERO_MD5

        md5_hash = hashlib.md5()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)

        result = md5_hash.hexdigest()
        if self._verbose:
            logger.info("Calculated MD5 sum for %s: %s", file_path, result)

        return result

    def write(
        self,
        edition_id: str,
        data: bytes,
        expected_md5: str,
        last_modified: datetime | None = None,
    ) -> None:
        """Write database data to a file atomically.

        Args:
            edition_id: The database edition ID.
            data: The database file contents.
            expected_md5: Expected MD5 hash of the data.
            last_modified: Optional timestamp to set as the file's mtime.

        Raises:
            HashMismatchError: If the data hash doesn't match expected_md5.
            OSError: If file operations fail.

        """
        final_path = self._get_file_path(edition_id)

        # Verify hash of data before writing
        actual_md5 = hashlib.md5(data).hexdigest()

        if actual_md5.lower() != expected_md5.lower():
            msg = (
                f"MD5 of new database ({actual_md5}) "
                f"does not match expected MD5 ({expected_md5})"
            )
            raise HashMismatchError(msg, expected=expected_md5, actual=actual_md5)

        # Write to temporary file in the same directory for atomic rename
        fd, temp_path = tempfile.mkstemp(
            suffix=".temporary",
            prefix=f"{edition_id}_",
            dir=self._dir,
        )

        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o644)
            os.write(fd, data)
            os.fsync(fd)
        except Exception:
            os.close(fd)
            try:
                os.unlink(temp_path)
            except OSError:
                logger.warning(
                    "Failed to clean up temp file: %s", temp_path, exc_info=True
                )
            raise
        os.close(fd)

        try:
            os.replace(temp_path, final_path)
        except Exception:
            try:
                os.unlink(temp_path)
            except OSError:
                logger.warning(
                    "Failed to clean up temp file: %s", temp_path, exc_info=True
                )
            raise

        # After the atomic rename, the database is correctly placed.
        # Failures in sync/utime are non-fatal.
        self._sync_dir(self._dir)

        if self._preserve_file_times and last_modified:
            try:
                timestamp = last_modified.timestamp()
                os.utime(final_path, (timestamp, timestamp))
            except OSError:
                logger.warning(
                    "Failed to set modification time for %s",
                    final_path,
                    exc_info=True,
                )

        if self._verbose:
            logger.info(
                "Database %s successfully updated: %s", edition_id, expected_md5
            )

    def _get_file_path(self, edition_id: str) -> Path:
        """Get the file path for a database edition.

        Args:
            edition_id: The database edition ID.

        Returns:
            Path to the database file.

        Raises:
            ValueError: If edition_id contains path traversal characters.

        """
        if "/" in edition_id or "\\" in edition_id or ".." in edition_id:
            msg = f"Invalid edition_id: {edition_id}"
            raise ValueError(msg)
        return self._dir / f"{edition_id}.mmdb"

    def _sync_dir(self, path: Path) -> None:
        """Sync directory to ensure rename is persisted.

        Args:
            path: Directory path to sync.

        """
        if not hasattr(os, "O_DIRECTORY"):
            return
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            # Some filesystems don't support directory fsync
            logger.warning("Failed to sync directory %s", path, exc_info=True)
