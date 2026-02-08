"""Tests for pygeoipupdate HTTP client."""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest
from pytest_httpserver import HTTPServer

from pygeoipupdate.client import (
    Client,
    NoUpdateAvailable,
    UpdateAvailable,
)
from pygeoipupdate.errors import AuthenticationError, DownloadError, HTTPError


def create_test_tar_gz(mmdb_content: bytes = b"test mmdb content") -> bytes:
    """Create a test tar.gz archive containing an mmdb file."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        # Add the mmdb file
        mmdb_info = tarfile.TarInfo(name="GeoLite2-City_20240101/GeoLite2-City.mmdb")
        mmdb_info.size = len(mmdb_content)
        tar.addfile(mmdb_info, io.BytesIO(mmdb_content))

    tar_data = tar_buffer.getvalue()

    # Compress with gzip
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
        gz.write(tar_data)

    return gz_buffer.getvalue()


class TestClient:
    """Tests for Client class."""

    @pytest.mark.asyncio
    async def test_get_metadata(self, httpserver: HTTPServer) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
            query_string="edition_id=GeoLite2-City",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": "abc123def456",
                    }
                ]
            }
        )

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            metadata = await client.get_metadata("GeoLite2-City")

            assert metadata.edition_id == "GeoLite2-City"
            assert metadata.date == "2024-01-15"
            assert metadata.md5 == "abc123def456"

    @pytest.mark.asyncio
    async def test_get_metadata_auth_error(self, httpserver: HTTPServer) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {"error": "Invalid license key"},
            status=401,
        )

        async with Client(
            account_id=12345,
            license_key="bad_key",
            host=httpserver.url_for("/"),
        ) as client:
            with pytest.raises(AuthenticationError):
                await client.get_metadata("GeoLite2-City")

    @pytest.mark.asyncio
    async def test_get_metadata_http_error(self, httpserver: HTTPServer) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {"error": "Server error"},
            status=500,
        )

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            with pytest.raises(HTTPError) as exc_info:
                await client.get_metadata("GeoLite2-City")

            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_get_metadata_empty_response(self, httpserver: HTTPServer) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({"databases": []})

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            with pytest.raises(DownloadError, match="does not contain edition"):
                await client.get_metadata("GeoLite2-City")

    @pytest.mark.asyncio
    async def test_download_no_update_needed(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": "current_hash",
                    }
                ]
            }
        )

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            response = await client.download("GeoLite2-City", "current_hash", tmp_path)

            assert isinstance(response, NoUpdateAvailable)
            assert response.md5 == "current_hash"

    @pytest.mark.asyncio
    async def test_download_with_update(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"new mmdb data here"
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": "new_hash",
                    }
                ]
            }
        )

        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
            query_string="date=20240115&suffix=tar.gz",
        ).respond_with_data(
            tar_gz_data,
            content_type="application/gzip",
            headers={"Last-Modified": "Mon, 15 Jan 2024 12:00:00 GMT"},
        )

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            response = await client.download("GeoLite2-City", "old_hash", tmp_path)

            assert isinstance(response, UpdateAvailable)
            assert response.compressed_path.read_bytes() == tar_gz_data
            assert response.md5 == "new_hash"
            assert response.last_modified is not None

    @pytest.mark.asyncio
    async def test_download_auth_error(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": "new_hash",
                    }
                ]
            }
        )

        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_json(
            {"error": "Invalid license"},
            status=401,
        )

        async with Client(
            account_id=12345,
            license_key="bad_key",
            host=httpserver.url_for("/"),
        ) as client:
            with pytest.raises(AuthenticationError):
                await client.download("GeoLite2-City", "old_hash", tmp_path)

    @pytest.mark.asyncio
    async def test_download_malformed_last_modified(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"test mmdb data"
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": "new_hash",
                    }
                ]
            }
        )

        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(
            tar_gz_data,
            content_type="application/gzip",
            headers={"Last-Modified": "not a valid date"},
        )

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            result = await client.download("GeoLite2-City", "old_hash", tmp_path)
            assert isinstance(result, UpdateAvailable)
            assert result.last_modified is None

    @pytest.mark.asyncio
    async def test_get_metadata_non_json_content_type(
        self, httpserver: HTTPServer
    ) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_data(
            "<html>Bad Gateway</html>",
            status=200,
            content_type="text/html",
        )

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            with pytest.raises(DownloadError, match="parse metadata"):
                await client.get_metadata("GeoLite2-City")

    @pytest.mark.asyncio
    async def test_get_metadata_malformed_json(self, httpserver: HTTPServer) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({"databases": [{"edition_id": "Foo"}]})

        async with Client(
            account_id=12345,
            license_key="test_key",
            host=httpserver.url_for("/"),
        ) as client:
            with pytest.raises(DownloadError, match="Malformed metadata"):
                await client.get_metadata("GeoLite2-City")

    @pytest.mark.asyncio
    async def test_client_requires_context_manager(self) -> None:
        client = Client(account_id=12345, license_key="test_key")

        with pytest.raises(RuntimeError, match="must be used as async context manager"):
            await client.get_metadata("GeoLite2-City")
