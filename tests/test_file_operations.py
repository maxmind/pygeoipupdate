"""Tests for file operations modules."""

from __future__ import annotations

import gzip
import hashlib
import io
import stat
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from pygeoipupdate._file_lock import FileLock
from pygeoipupdate._file_writer import ZERO_MD5, LocalFileWriter
from pygeoipupdate.errors import DownloadError, HashMismatchError
from tests.conftest import create_test_tar_gz_file


class TestFileLock:
    """Tests for FileLock."""

    def test_acquire_and_release(self, tmp_path: Path) -> None:
        lock_path = tmp_path / ".geoipupdate.lock"
        lock = FileLock(lock_path)

        lock.acquire()
        assert lock_path.exists()
        lock.release()

    def test_context_manager(self, tmp_path: Path) -> None:
        lock_path = tmp_path / ".geoipupdate.lock"

        with FileLock(lock_path):
            assert lock_path.exists()

    def test_double_acquire_same_process(self, tmp_path: Path) -> None:
        lock_path = tmp_path / ".geoipupdate.lock"
        lock = FileLock(lock_path)

        # Same process can acquire the same lock multiple times
        lock.acquire()
        lock.acquire()  # Should not block
        lock.release()
        lock.release()

    def test_timeout(self, tmp_path: Path) -> None:
        lock_path = tmp_path / ".geoipupdate.lock"

        # Create a lock file manually to simulate another process
        # Note: This test is limited because filelock allows re-entry from same process
        # A proper test would require multiprocessing
        with FileLock(lock_path):
            # Lock is held, but same process can re-enter
            pass


class TestLocalFileWriter:
    """Tests for LocalFileWriter."""

    def test_creates_directory(self, tmp_path: Path) -> None:
        db_dir = tmp_path / "nested" / "geoip"
        writer = LocalFileWriter(db_dir)

        assert db_dir.exists()

    def test_get_hash_nonexistent_file(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)

        result = writer.get_hash("GeoLite2-City")

        assert result == ZERO_MD5

    def test_get_hash_permission_error(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)
        file_path = tmp_path / "GeoLite2-City.mmdb"
        file_path.write_bytes(b"test content")
        file_path.chmod(0o000)

        try:
            result = writer.get_hash("GeoLite2-City")
            assert result == ZERO_MD5
        finally:
            file_path.chmod(0o644)

    def test_get_hash_file_deleted_during_read(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)

        with patch.object(Path, "open", side_effect=FileNotFoundError("deleted")):
            result = writer.get_hash("GeoLite2-City")

        assert result == ZERO_MD5

    def test_get_hash_existing_file(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)
        content = b"test mmdb content"
        expected_hash = hashlib.md5(content).hexdigest()

        # Write file directly
        (tmp_path / "GeoLite2-City.mmdb").write_bytes(content)

        result = writer.get_hash("GeoLite2-City")

        assert result == expected_hash

    def test_write_success(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)
        content = b"test mmdb content"
        md5_hash = hashlib.md5(content).hexdigest()
        compressed_path = create_test_tar_gz_file(tmp_path, content)

        writer.write("GeoLite2-City", compressed_path, md5_hash)

        file_path = tmp_path / "GeoLite2-City.mmdb"
        assert file_path.exists()
        assert file_path.read_bytes() == content

    def test_write_sets_644_permissions(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)
        content = b"test mmdb content"
        md5_hash = hashlib.md5(content).hexdigest()
        compressed_path = create_test_tar_gz_file(tmp_path, content)

        writer.write("GeoLite2-City", compressed_path, md5_hash)

        file_path = tmp_path / "GeoLite2-City.mmdb"
        mode = stat.S_IMODE(file_path.stat().st_mode)
        assert mode == 0o644

    def test_write_hash_mismatch(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)
        content = b"test mmdb content"
        compressed_path = create_test_tar_gz_file(tmp_path, content)

        with pytest.raises(HashMismatchError) as exc_info:
            writer.write("GeoLite2-City", compressed_path, "wronghash")

        assert exc_info.value.expected == "wronghash"
        assert exc_info.value.actual == hashlib.md5(content).hexdigest()

        # File should not exist after failed write
        assert not (tmp_path / "GeoLite2-City.mmdb").exists()

    def test_write_overwrites_existing(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)

        # Write initial content
        old_content = b"old content"
        old_hash = hashlib.md5(old_content).hexdigest()
        writer.write(
            "GeoLite2-City", create_test_tar_gz_file(tmp_path, old_content), old_hash
        )

        # Overwrite with new content
        new_content = b"new content"
        new_hash = hashlib.md5(new_content).hexdigest()
        writer.write(
            "GeoLite2-City", create_test_tar_gz_file(tmp_path, new_content), new_hash
        )

        file_path = tmp_path / "GeoLite2-City.mmdb"
        assert file_path.read_bytes() == new_content

    def test_write_preserves_file_times(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path, preserve_file_times=True)
        content = b"test mmdb content"
        md5_hash = hashlib.md5(content).hexdigest()
        last_modified = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        writer.write(
            "GeoLite2-City",
            create_test_tar_gz_file(tmp_path, content),
            md5_hash,
            last_modified,
        )

        file_path = tmp_path / "GeoLite2-City.mmdb"
        mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=UTC)

        # Compare timestamps (allowing small difference for filesystem precision)
        assert abs((mtime - last_modified).total_seconds()) < 2

    def test_write_atomic(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)

        # Write initial content
        old_content = b"old content"
        old_hash = hashlib.md5(old_content).hexdigest()
        writer.write(
            "GeoLite2-City", create_test_tar_gz_file(tmp_path, old_content), old_hash
        )

        # Try to write with wrong hash - should fail atomically
        new_content = b"new content"
        with pytest.raises(HashMismatchError):
            writer.write(
                "GeoLite2-City",
                create_test_tar_gz_file(tmp_path, new_content),
                "wronghash",
            )

        # Original file should still have old content
        file_path = tmp_path / "GeoLite2-City.mmdb"
        assert file_path.read_bytes() == old_content

    def test_get_file_path(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)

        path = writer._get_file_path("GeoLite2-City")

        assert path == tmp_path / "GeoLite2-City.mmdb"

    @pytest.mark.parametrize(
        "edition_id",
        ["../etc/passwd", "foo/bar", "foo\\bar", ".."],
    )
    def test_path_traversal_rejected(self, tmp_path: Path, edition_id: str) -> None:
        writer = LocalFileWriter(tmp_path)

        with pytest.raises(ValueError, match="Invalid edition_id"):
            writer._get_file_path(edition_id)

    def test_verbose_logging(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        writer = LocalFileWriter(tmp_path, verbose=True)
        content = b"test content"
        md5_hash = hashlib.md5(content).hexdigest()

        import logging

        with caplog.at_level(logging.INFO):
            writer.write(
                "GeoLite2-City", create_test_tar_gz_file(tmp_path, content), md5_hash
            )

        assert "successfully updated" in caplog.text

    def test_write_failure_closes_fd(self, tmp_path: Path) -> None:
        """Verify os.close is called when os.write raises."""
        writer = LocalFileWriter(tmp_path)
        content = b"test content"
        md5_hash = hashlib.md5(content).hexdigest()

        with (
            patch(
                "pygeoipupdate._file_writer.os.write", side_effect=OSError("disk full")
            ),
            patch("pygeoipupdate._file_writer.os.close") as mock_close,
        ):
            with pytest.raises(OSError, match="disk full"):
                writer.write(
                    "GeoLite2-City",
                    create_test_tar_gz_file(tmp_path, content),
                    md5_hash,
                )

            mock_close.assert_called_once()

        # Verify no temp files remain
        temp_files = list(tmp_path.glob("*.temporary"))
        assert temp_files == []

    def test_hash_mismatch_no_temp_files(self, tmp_path: Path) -> None:
        """Verify no orphaned .temporary files remain after a HashMismatchError."""
        writer = LocalFileWriter(tmp_path)
        content = b"test mmdb content"

        with pytest.raises(HashMismatchError):
            writer.write(
                "GeoLite2-City",
                create_test_tar_gz_file(tmp_path, content),
                "wrong_hash",
            )

        temp_files = list(tmp_path.glob("*.temporary"))
        assert temp_files == []


class TestExtractAndWrite:
    """Tests for tar.gz extraction in LocalFileWriter."""

    def test_no_mmdb_file(self, tmp_path: Path) -> None:
        """Archive without .mmdb should raise DownloadError."""
        writer = LocalFileWriter(tmp_path)

        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            info = tarfile.TarInfo(name="README.txt")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"test"))

        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_buffer.getvalue())

        gz_path = tmp_path / "no_mmdb.tar.gz"
        gz_path.write_bytes(gz_buffer.getvalue())

        with pytest.raises(DownloadError, match="does not contain an mmdb file"):
            writer.write("GeoLite2-City", gz_path, "somehash")

    def test_mmdb_symlink_not_extractable(self, tmp_path: Path) -> None:
        """A symlink .mmdb entry should give a specific error."""
        writer = LocalFileWriter(tmp_path)

        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            info = tarfile.TarInfo(name="GeoLite2-City/GeoLite2-City.mmdb")
            info.type = tarfile.SYMTYPE
            info.linkname = "nonexistent"
            tar.addfile(info)

        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_buffer.getvalue())

        gz_path = tmp_path / "symlink.tar.gz"
        gz_path.write_bytes(gz_buffer.getvalue())

        with pytest.raises(DownloadError, match="Failed to extract"):
            writer.write("GeoLite2-City", gz_path, "somehash")

    def test_invalid_gzip(self, tmp_path: Path) -> None:
        writer = LocalFileWriter(tmp_path)
        bad_gz_path = tmp_path / "bad.tar.gz"
        bad_gz_path.write_bytes(b"not valid gzip data")

        with pytest.raises(DownloadError, match="Failed to extract"):
            writer.write("GeoLite2-City", bad_gz_path, "somehash")
