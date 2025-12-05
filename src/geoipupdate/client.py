"""HTTP client for MaxMind GeoIP update service."""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Self
from urllib.parse import quote, urlencode

import aiohttp
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_delay,
    wait_exponential,
)

from geoipupdate import __version__
from geoipupdate.errors import AuthenticationError, DownloadError, HTTPError
from geoipupdate.models import Metadata

if TYPE_CHECKING:
    from datetime import timedelta


@dataclass
class DownloadResponse:
    """Response from a download request.

    Attributes:
        update_available: True if an update is available.
        data: The MMDB file data (only set if update_available is True).
        md5: The MD5 hash of the downloaded file.
        last_modified: The last modified timestamp from the server.

    """

    update_available: bool
    data: bytes
    md5: str
    last_modified: datetime | None


def _is_retryable_error(exception: BaseException) -> bool:
    """Determine if an exception is retryable.

    Args:
        exception: The exception to check.

    Returns:
        True if the exception should trigger a retry.

    """
    if isinstance(exception, HTTPError):
        # 4xx errors are not retryable (permanent errors)
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

    async def __aenter__(self) -> Self:
        """Enter async context manager."""
        auth = aiohttp.BasicAuth(str(self._account_id), self._license_key)
        headers = {"User-Agent": f"geoipupdate-python/{__version__}"}
        self._session = aiohttp.ClientSession(auth=auth, headers=headers)
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
            async with self._session.get(url, proxy=self._proxy) as response:
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
    ) -> DownloadResponse:
        """Download a database edition.

        Args:
            edition_id: The database edition ID (e.g., "GeoLite2-City").
            current_md5: MD5 hash of the current local database, or "" if none.

        Returns:
            Download response with the database data.

        Raises:
            AuthenticationError: If authentication fails.
            HTTPError: If the server returns an error status.
            DownloadError: If the request fails.

        """
        if self._retry_for:
            return await self._download_with_retry(edition_id, current_md5)
        return await self._download(edition_id, current_md5)

    async def _download_with_retry(
        self,
        edition_id: str,
        current_md5: str,
    ) -> DownloadResponse:
        """Download with retry logic."""

        @retry(
            stop=stop_after_delay(self._retry_for.total_seconds()),
            wait=wait_exponential(multiplier=1, min=1, max=60),
            retry=retry_if_exception(_is_retryable_error),
            reraise=True,
        )
        async def _retry_wrapper() -> DownloadResponse:
            return await self._download(edition_id, current_md5)

        return await _retry_wrapper()

    async def _download(
        self,
        edition_id: str,
        current_md5: str,
    ) -> DownloadResponse:
        """Download without retry."""
        # First get metadata to check if update is needed
        metadata = await self._get_metadata(edition_id)

        if metadata.md5 == current_md5:
            return DownloadResponse(
                update_available=False,
                data=b"",
                md5=current_md5,
                last_modified=None,
            )

        # Download the database
        data, last_modified = await self._fetch_database(edition_id, metadata.date)

        return DownloadResponse(
            update_available=True,
            data=data,
            md5=metadata.md5,
            last_modified=last_modified,
        )

    async def _fetch_database(
        self,
        edition_id: str,
        date: str,
    ) -> tuple[bytes, datetime | None]:
        """Fetch the database file.

        Args:
            edition_id: The database edition ID.
            date: The database date in YYYY-MM-DD format.

        Returns:
            Tuple of (mmdb file data, last modified timestamp).

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
            async with self._session.get(url, proxy=self._proxy) as response:
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
                        pass

                # Read and extract the tar.gz
                compressed_data = await response.read()
                mmdb_data = _extract_mmdb_from_tar_gz(compressed_data)

                return mmdb_data, last_modified

        except aiohttp.ClientError as e:
            msg = f"Failed to download database: {e}"
            raise DownloadError(msg) from e


def _extract_mmdb_from_tar_gz(data: bytes) -> bytes:
    """Extract the .mmdb file from a tar.gz archive.

    Args:
        data: The compressed tar.gz data.

    Returns:
        The extracted MMDB file data.

    Raises:
        DownloadError: If no .mmdb file is found in the archive.

    """
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            with tarfile.open(fileobj=gz, mode="r|") as tar:
                for member in tar:
                    if member.name.endswith(".mmdb"):
                        extracted = tar.extractfile(member)
                        if extracted:
                            return extracted.read()
    except (gzip.BadGzipFile, tarfile.TarError) as e:
        msg = f"Failed to extract database from archive: {e}"
        raise DownloadError(msg) from e

    msg = "tar archive does not contain an mmdb file"
    raise DownloadError(msg)
