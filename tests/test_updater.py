"""Tests for the Updater class."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pytest_httpserver import HTTPServer

from geoipupdate.config import Config
from geoipupdate.updater import Updater


def create_test_tar_gz(mmdb_content: bytes = b"test mmdb content") -> bytes:
    """Create a test tar.gz archive containing an mmdb file."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        mmdb_info = tarfile.TarInfo(name="GeoLite2-City_20240101/GeoLite2-City.mmdb")
        mmdb_info.size = len(mmdb_content)
        tar.addfile(mmdb_info, io.BytesIO(mmdb_content))

    tar_data = tar_buffer.getvalue()

    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
        gz.write(tar_data)

    return gz_buffer.getvalue()


class TestUpdater:
    """Tests for Updater class."""

    @pytest.mark.asyncio
    async def test_download_new_database(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"new mmdb data here"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=GeoLite2-City",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )

        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(
            tar_gz_data,
            content_type="application/gzip",
            headers={"Last-Modified": "Mon, 15 Jan 2024 12:00:00 GMT"},
        )

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=["GeoLite2-City"],
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
        )

        async with Updater(config) as updater:
            results = await updater.run()

        assert len(results) == 1
        assert results[0].edition_id == "GeoLite2-City"
        assert results[0].was_updated
        assert results[0].new_hash == mmdb_hash

        # Verify file was written
        db_file = tmp_path / "GeoLite2-City.mmdb"
        assert db_file.exists()
        assert db_file.read_bytes() == mmdb_content

    @pytest.mark.asyncio
    async def test_no_update_needed(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"existing mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()

        # Write existing database
        db_file = tmp_path / "GeoLite2-City.mmdb"
        db_file.write_bytes(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=["GeoLite2-City"],
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
        )

        async with Updater(config) as updater:
            results = await updater.run()

        assert len(results) == 1
        assert results[0].edition_id == "GeoLite2-City"
        assert not results[0].was_updated
        assert results[0].old_hash == results[0].new_hash

    @pytest.mark.asyncio
    async def test_multiple_editions(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        city_content = b"city mmdb data"
        city_hash = hashlib.md5(city_content).hexdigest()
        city_tar_gz = create_test_tar_gz(city_content)

        country_content = b"country mmdb data"
        country_hash = hashlib.md5(country_content).hexdigest()

        # Create country tar.gz
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
            info = tarfile.TarInfo(name="GeoLite2-Country/GeoLite2-Country.mmdb")
            info.size = len(country_content)
            tar.addfile(info, io.BytesIO(country_content))
        gz_buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
            gz.write(tar_buffer.getvalue())
        country_tar_gz = gz_buffer.getvalue()

        # City metadata and download
        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=GeoLite2-City",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": city_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(city_tar_gz, content_type="application/gzip")

        # Country metadata and download
        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=GeoLite2-Country",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-Country",
                        "date": "2024-01-15",
                        "md5": country_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-Country/download",
        ).respond_with_data(country_tar_gz, content_type="application/gzip")

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=["GeoLite2-City", "GeoLite2-Country"],
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
        )

        async with Updater(config) as updater:
            results = await updater.run()

        assert len(results) == 2

        # Verify both files were written
        assert (tmp_path / "GeoLite2-City.mmdb").exists()
        assert (tmp_path / "GeoLite2-Country.mmdb").exists()

    @pytest.mark.asyncio
    async def test_parallel_downloads(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        editions = ["Edition1", "Edition2", "Edition3"]

        for edition in editions:
            content = f"{edition} data".encode()
            md5_hash = hashlib.md5(content).hexdigest()

            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
                info = tarfile.TarInfo(name=f"{edition}/{edition}.mmdb")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            gz_buffer = io.BytesIO()
            with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
                gz.write(tar_buffer.getvalue())
            tar_gz = gz_buffer.getvalue()

            httpserver.expect_request(
                "/geoip/updates/metadata",
                query_string=f"edition_id={edition}",
            ).respond_with_json(
                {
                    "databases": [
                        {"edition_id": edition, "date": "2024-01-15", "md5": md5_hash}
                    ]
                }
            )
            httpserver.expect_request(
                f"/geoip/databases/{edition}/download",
            ).respond_with_data(tar_gz, content_type="application/gzip")

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=editions,
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
            parallelism=3,
        )

        async with Updater(config) as updater:
            results = await updater.run()

        assert len(results) == 3
        for edition in editions:
            assert (tmp_path / f"{edition}.mmdb").exists()

    @pytest.mark.asyncio
    async def test_requires_context_manager(self, tmp_path: Path) -> None:
        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=["GeoLite2-City"],
            database_directory=tmp_path,
        )

        updater = Updater(config)

        with pytest.raises(RuntimeError, match="must be used as async context manager"):
            await updater.run()

    @pytest.mark.asyncio
    async def test_file_locking(self, httpserver: HTTPServer, tmp_path: Path) -> None:
        mmdb_content = b"test data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        lock_file = tmp_path / ".geoipupdate.lock"

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=["GeoLite2-City"],
            database_directory=tmp_path,
            lock_file=lock_file,
            host=httpserver.url_for("/"),
        )

        async with Updater(config) as updater:
            # Lock file should exist during run
            await updater.run()

        # Lock should be released after context manager exits

    @pytest.mark.asyncio
    async def test_aenter_failure_cleans_up(self, tmp_path: Path) -> None:
        """If Client.__aenter__ raises, __aexit__ should not produce a secondary error."""
        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=["GeoLite2-City"],
            database_directory=tmp_path,
        )

        updater = Updater(config)
        with (
            patch(
                "geoipupdate.updater.Client.__aenter__",
                side_effect=RuntimeError("connection failed"),
            ),
            pytest.raises(RuntimeError, match="connection failed"),
        ):
            await updater.__aenter__()

        # __aexit__ should not raise even though __aenter__ failed
        await updater.__aexit__(None, None, None)
