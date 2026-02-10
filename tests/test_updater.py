"""Tests for the Updater class."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import aiohttp
import pytest
from pytest_httpserver import HTTPServer
from werkzeug import Request, Response

from pygeoipupdate.config import Config
from pygeoipupdate.errors import (
    AuthenticationError,
    DownloadError,
    HashMismatchError,
    HTTPError,
)
from pygeoipupdate.updater import Updater, _is_retryable_error
from tests.conftest import create_test_tar_gz


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
            edition_ids=("GeoLite2-City",),
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

        # Verify no .download temp files remain
        assert list(tmp_path.glob("*.download")) == []

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
            edition_ids=("GeoLite2-City",),
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
            edition_ids=("GeoLite2-City", "GeoLite2-Country"),
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
        editions = ("Edition1", "Edition2", "Edition3")

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
    async def test_parallel_error_cancels_siblings(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        """When one parallel download fails, sibling tasks should be cancelled."""
        # Edition1 succeeds
        e1_content = b"edition1 data"
        e1_hash = hashlib.md5(e1_content).hexdigest()
        e1_tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=e1_tar_buffer, mode="w") as tar:
            info = tarfile.TarInfo(name="Edition1/Edition1.mmdb")
            info.size = len(e1_content)
            tar.addfile(info, io.BytesIO(e1_content))
        e1_gz = io.BytesIO()
        with gzip.GzipFile(fileobj=e1_gz, mode="wb") as gz:
            gz.write(e1_tar_buffer.getvalue())

        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=Edition1",
        ).respond_with_json(
            {
                "databases": [
                    {"edition_id": "Edition1", "date": "2024-01-15", "md5": e1_hash}
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/Edition1/download",
        ).respond_with_data(e1_gz.getvalue(), content_type="application/gzip")

        # Edition2 returns 401 (non-retryable, should cause immediate failure)
        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=Edition2",
        ).respond_with_json({"error": "Invalid license key"}, status=401)

        # Edition3 succeeds
        e3_content = b"edition3 data"
        e3_hash = hashlib.md5(e3_content).hexdigest()
        e3_tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=e3_tar_buffer, mode="w") as tar:
            info = tarfile.TarInfo(name="Edition3/Edition3.mmdb")
            info.size = len(e3_content)
            tar.addfile(info, io.BytesIO(e3_content))
        e3_gz = io.BytesIO()
        with gzip.GzipFile(fileobj=e3_gz, mode="wb") as gz:
            gz.write(e3_tar_buffer.getvalue())

        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=Edition3",
        ).respond_with_json(
            {
                "databases": [
                    {"edition_id": "Edition3", "date": "2024-01-15", "md5": e3_hash}
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/Edition3/download",
        ).respond_with_data(e3_gz.getvalue(), content_type="application/gzip")

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=("Edition1", "Edition2", "Edition3"),
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
            parallelism=3,
        )

        with pytest.raises(ExceptionGroup) as exc_info:
            async with Updater(config) as updater:
                await updater.run()

        # The ExceptionGroup should contain the AuthenticationError
        auth_errors = exc_info.group_contains(AuthenticationError)
        assert auth_errors

    @pytest.mark.asyncio
    async def test_requires_context_manager(self, tmp_path: Path) -> None:
        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=("GeoLite2-City",),
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
            edition_ids=("GeoLite2-City",),
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
            edition_ids=("GeoLite2-City",),
            database_directory=tmp_path,
        )

        updater = Updater(config)
        with (
            patch(
                "pygeoipupdate.updater.Client.__aenter__",
                side_effect=RuntimeError("connection failed"),
            ),
            pytest.raises(RuntimeError, match="connection failed"),
        ):
            await updater.__aenter__()

        # __aexit__ should not raise even though __aenter__ failed
        await updater.__aexit__(None, None, None)

    @pytest.mark.asyncio
    async def test_download_without_retry(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        """With retry_for=0, _download_edition_once is called directly."""
        mmdb_content = b"no retry mmdb data"
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
        )

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=("GeoLite2-City",),
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
            retry_for=timedelta(0),
        )

        async with Updater(config) as updater:
            results = await updater.run()

        assert len(results) == 1
        assert results[0].was_updated
        assert results[0].new_hash == mmdb_hash

    @pytest.mark.asyncio
    async def test_retries_on_transient_500(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        """A transient 500 on metadata should be retried and succeed."""
        mmdb_content = b"new mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)
        call_count = 0

        def metadata_handler(_request: Request) -> Response:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Response(
                    json.dumps({"error": "transient"}),
                    status=500,
                    content_type="application/json",
                )
            return Response(
                json.dumps(
                    {
                        "databases": [
                            {
                                "edition_id": "GeoLite2-City",
                                "date": "2024-01-15",
                                "md5": mmdb_hash,
                            }
                        ]
                    }
                ),
                status=200,
                content_type="application/json",
            )

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_handler(metadata_handler)

        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        config = Config(
            account_id=12345,
            license_key="test_key",
            edition_ids=("GeoLite2-City",),
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
            retry_for=timedelta(seconds=30),
        )

        async with Updater(config) as updater:
            results = await updater.run()

        assert len(results) == 1
        assert results[0].was_updated
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_auth_error_not_retried_despite_retry_for(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        """AuthenticationError should not be retried even with retry_for set."""
        call_count = 0

        def metadata_handler(_request: Request) -> Response:
            nonlocal call_count
            call_count += 1
            return Response(
                json.dumps({"error": "Invalid license key"}),
                status=401,
                content_type="application/json",
            )

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_handler(metadata_handler)

        config = Config(
            account_id=12345,
            license_key="bad_key",
            edition_ids=("GeoLite2-City",),
            database_directory=tmp_path,
            host=httpserver.url_for("/"),
            retry_for=timedelta(seconds=30),
        )

        with pytest.raises(AuthenticationError):
            async with Updater(config) as updater:
                await updater.run()

        assert call_count == 1


class TestIsRetryableError:
    """Tests for _is_retryable_error."""

    def test_auth_error_not_retryable(self) -> None:
        assert _is_retryable_error(AuthenticationError("bad key")) is False

    def test_http_500_retryable(self) -> None:
        assert _is_retryable_error(HTTPError("fail", status_code=500, body="")) is True

    def test_http_404_not_retryable(self) -> None:
        assert _is_retryable_error(HTTPError("fail", status_code=404, body="")) is False

    def test_client_error_retryable(self) -> None:
        assert _is_retryable_error(aiohttp.ClientError("conn")) is True

    def test_timeout_retryable(self) -> None:
        assert _is_retryable_error(TimeoutError()) is True

    def test_download_error_without_cause_not_retryable(self) -> None:
        assert _is_retryable_error(DownloadError("no mmdb")) is False

    def test_download_error_with_client_cause_retryable(self) -> None:
        err = DownloadError("parse failed")
        err.__cause__ = aiohttp.ClientError()
        assert _is_retryable_error(err) is True

    def test_hash_mismatch_retryable(self) -> None:
        assert _is_retryable_error(HashMismatchError("mismatch", "a", "b")) is True

    def test_connection_error_retryable(self) -> None:
        assert _is_retryable_error(ConnectionError("reset")) is True

    def test_os_error_not_retryable(self) -> None:
        assert _is_retryable_error(OSError("disk full")) is False

    def test_permission_error_not_retryable(self) -> None:
        assert _is_retryable_error(PermissionError("denied")) is False

    def test_http_403_not_retryable(self) -> None:
        assert (
            _is_retryable_error(HTTPError("forbidden", status_code=403, body=""))
            is False
        )

    def test_http_429_not_retryable(self) -> None:
        assert (
            _is_retryable_error(HTTPError("rate limited", status_code=429, body=""))
            is False
        )

    def test_unrelated_error_not_retryable(self) -> None:
        assert _is_retryable_error(ValueError("bad")) is False
