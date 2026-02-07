"""HTTP client for MaxMind GeoIP update service."""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Self
from urllib.parse import quote, urlencode

import aiohttp
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_delay,
    wait_exponential,
)

from pygeoipupdate import __version__
from pygeoipupdate.errors import AuthenticationError, DownloadError, HTTPError
from pygeoipupdate.models import Metadata

if TYPE_CHECKING:
    from datetime import timedelta

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NoUpdateAvailable:
    """Returned when the local database is already up to date.

    Attributes:
        md5: The MD5 hash of the current database.

    """

    md5: str


@dataclass(frozen=True)
class UpdateAvailable:
    """Returned when a newer database was downloaded.

    Attributes:
        compressed_path: Path to the downloaded tar.gz temp file.
        md5: Expected MD5 hash from the metadata response, used to verify
            the downloaded database.
        last_modified: The last modified timestamp from the server.

    """

    compressed_path: Path
    md5: str
    last_modified: datetime | None


DownloadResponse = NoUpdateAvailable | UpdateAvailable


def _is_retryable_error(exception: BaseException) -> bool:
    """Determine if an exception is retryable.

    Args:
        exception: The exception to check.

    Returns:
        True if the exception should trigger a retry.

    """
    if isinstance(exception, HTTPError):
        # Only 5xx (server) errors are retryable
        return exception.status_code >= 500
    if isinstance(exception, AuthenticationError):
        return False
    # Network errors, timeouts, etc. are retryable
    return isinstance(exception, (aiohttp.ClientError, TimeoutError, OSError))


class Client:
    """Async HTTP client for MaxMind GeoIP update service.

    Example:
        async with Client(account_id=12345, license_key="key") as client:
            metadata = await client.get_metadata("GeoLite2-City")
            response = await client.download("GeoLite2-City", "")

    """

    def __init__(
        self,
        account_id: int,
        license_key: str,
        *,
        host: str = "https://updates.maxmind.com",
        proxy: str | None = None,
        retry_for: timedelta | None = None,
    ) -> None:
        """Initialize the client.

        Args:
            account_id: MaxMind account ID.
            license_key: MaxMind license key.
            host: Update server URL.
            proxy: Proxy URL (http, https, or socks5).
            retry_for: Duration to retry failed requests.

        """
        self._account_id = account_id
        self._license_key = license_key
        self._host = host.rstrip("/")
        self._proxy = proxy
        self._retry_for = retry_for
        self._session: aiohttp.ClientSession | None = None
        self._auth: aiohttp.BasicAuth | None = None

    async def __aenter__(self) -> Self:
        """Enter async context manager."""
        self._auth = aiohttp.BasicAuth(str(self._account_id), self._license_key)
        headers = {"User-Agent": f"pygeoipupdate/{__version__}"}
        self._session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit async context manager."""
        if self._session:
            await self._session.close()
            self._session = None

    async def get_metadata(self, edition_id: str) -> Metadata:
        """Get metadata for a database edition.

        Args:
            edition_id: The database edition ID (e.g., "GeoLite2-City").

        Returns:
            Metadata for the database.

        Raises:
            AuthenticationError: If authentication fails.
            HTTPError: If the server returns an error status.
            DownloadError: If the request fails.

        """
        if self._retry_for:
            return await self._get_metadata_with_retry(edition_id)
        return await self._get_metadata(edition_id)

    async def _get_metadata_with_retry(self, edition_id: str) -> Metadata:
        """Get metadata with retry logic."""

        @retry(
            stop=stop_after_delay(self._retry_for.total_seconds()),
            wait=wait_exponential(multiplier=1, min=1, max=60),
            retry=retry_if_exception(_is_retryable_error),
            reraise=True,
        )
        async def _retry_wrapper() -> Metadata:
            return await self._get_metadata(edition_id)

        return await _retry_wrapper()

    async def _get_metadata(self, edition_id: str) -> Metadata:
        """Get metadata without retry."""
        if not self._session:
            msg = "Client must be used as async context manager"
            raise RuntimeError(msg)

        params = urlencode({"edition_id": edition_id})
        url = f"{self._host}/geoip/updates/metadata?{params}"

        try:
            async with self._session.get(
                url, proxy=self._proxy, auth=self._auth
            ) as response:
                body = await response.text()

                if response.status == 401:
                    msg = "Invalid account ID or license key"
                    raise AuthenticationError(msg)

                if response.status != 200:
                    raise HTTPError(
                        f"Unexpected HTTP status code: {response.status}",
                        status_code=response.status,
                        body=body[:256],
                    )

                data = await response.json()
                databases = data.get("databases", [])
                if not databases:
                    msg = f"Response does not contain edition {edition_id}"
                    raise DownloadError(msg)

                db = databases[0]
                return Metadata(
                    edition_id=db["edition_id"],
                    date=db["date"],
                    md5=db["md5"],
                )
        except aiohttp.ClientError as e:
            msg = f"Failed to fetch metadata: {e}"
            raise DownloadError(msg) from e

    async def download(
        self,
        edition_id: str,
        current_md5: str,
        temp_dir: Path,
    ) -> DownloadResponse:
        """Download a database edition.

        Args:
            edition_id: The database edition ID (e.g., "GeoLite2-City").
            current_md5: MD5 hash of the current local database. Any value
                that does not match the server's hash triggers a download.
            temp_dir: Directory in which to create the download temp file.

        Returns:
            Download response with the database data.

        Raises:
            AuthenticationError: If authentication fails.
            HTTPError: If the server returns an error status.
            DownloadError: If the request fails.

        """
        if self._retry_for:
            return await self._download_with_retry(
                edition_id, current_md5, temp_dir
            )
        return await self._download(edition_id, current_md5, temp_dir)

    async def _download_with_retry(
        self,
        edition_id: str,
        current_md5: str,
        temp_dir: Path,
    ) -> DownloadResponse:
        """Download with retry logic."""

        @retry(
            stop=stop_after_delay(self._retry_for.total_seconds()),
            wait=wait_exponential(multiplier=1, min=1, max=60),
            retry=retry_if_exception(_is_retryable_error),
            reraise=True,
        )
        async def _retry_wrapper() -> DownloadResponse:
            return await self._download(edition_id, current_md5, temp_dir)

        return await _retry_wrapper()

    async def _download(
        self,
        edition_id: str,
        current_md5: str,
        temp_dir: Path,
    ) -> DownloadResponse:
        """Download without retry."""
        # First get metadata to check if update is needed
        metadata = await self._get_metadata(edition_id)

        if metadata.md5 == current_md5:
            return NoUpdateAvailable(md5=current_md5)

        # Download the database
        compressed_path, last_modified = await self._fetch_database(
            edition_id, metadata.date, temp_dir
        )

        return UpdateAvailable(
            compressed_path=compressed_path,
            md5=metadata.md5,
            last_modified=last_modified,
        )

    async def _fetch_database(
        self,
        edition_id: str,
        date: str,
        temp_dir: Path,
    ) -> tuple[Path, datetime | None]:
        """Fetch the database file, streaming to a temp file.

        Args:
            edition_id: The database edition ID.
            date: The database date in YYYY-MM-DD format.
            temp_dir: Directory in which to create the download temp file.

        Returns:
            Tuple of (path to temp file containing compressed tar.gz, last
            modified timestamp).

        """
        if not self._session:
            msg = "Client must be used as async context manager"
            raise RuntimeError(msg)

        # Convert date format from YYYY-MM-DD to YYYYMMDD
        date_param = date.replace("-", "")

        params = urlencode({"date": date_param, "suffix": "tar.gz"})
        escaped_edition = quote(edition_id, safe="")
        url = f"{self._host}/geoip/databases/{escaped_edition}/download?{params}"

        try:
            async with self._session.get(
                url, proxy=self._proxy, auth=self._auth
            ) as response:
                if response.status == 401:
                    msg = "Invalid account ID or license key"
                    raise AuthenticationError(msg)

                if response.status != 200:
                    body = await response.text()
                    raise HTTPError(
                        f"Unexpected HTTP status code: {response.status}",
                        status_code=response.status,
                        body=body[:256],
                    )

                # Parse Last-Modified header
                last_modified: datetime | None = None
                if lm_header := response.headers.get("Last-Modified"):
                    try:
                        last_modified = parsedate_to_datetime(lm_header)
                    except (ValueError, TypeError):
                        logger.warning(
                            "Failed to parse Last-Modified header: %s",
                            lm_header,
                        )

                # Stream response body to a temp file
                fd, temp_path = tempfile.mkstemp(
                    suffix=".download",
                    prefix=f"{edition_id}_",
                    dir=temp_dir,
                )
                try:
                    async for chunk in response.content.iter_chunked(
                        64 * 1024,
                    ):
                        os.write(fd, chunk)
                    os.fsync(fd)
                except BaseException:
                    os.close(fd)
                    _cleanup_temp_file(temp_path)
                    raise
                os.close(fd)

                return Path(temp_path), last_modified

        except aiohttp.ClientError as e:
            msg = f"Failed to download database: {e}"
            raise DownloadError(msg) from e


def _cleanup_temp_file(temp_path: str) -> None:
    try:
        os.unlink(temp_path)
    except OSError:
        logger.warning("Failed to clean up temp file: %s", temp_path, exc_info=True)
