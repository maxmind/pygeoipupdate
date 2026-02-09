"""Shared test helpers for pygeoipupdate tests."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path


def create_test_tar_gz(
    mmdb_content: bytes = b"test mmdb content",
    filename: str = "GeoLite2-City_20240101/GeoLite2-City.mmdb",
) -> bytes:
    """Create a test tar.gz archive containing an mmdb file."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        mmdb_info = tarfile.TarInfo(name=filename)
        mmdb_info.size = len(mmdb_content)
        tar.addfile(mmdb_info, io.BytesIO(mmdb_content))

    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
        gz.write(tar_buffer.getvalue())

    return gz_buffer.getvalue()


def create_test_tar_gz_file(
    tmp_path: Path,
    mmdb_content: bytes = b"test mmdb content",
    filename: str = "GeoLite2-City_20240101/GeoLite2-City.mmdb",
) -> Path:
    """Create a test tar.gz file on disk and return its path."""
    data = create_test_tar_gz(mmdb_content, filename)
    tar_gz_path = tmp_path / "test_download.tar.gz"
    tar_gz_path.write_bytes(data)
    return tar_gz_path
