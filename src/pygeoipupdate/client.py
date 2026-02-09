"""HTTP client for MaxMind GeoIP update service."""

from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Self
from urllib.parse import quote, urlencode

import aiohttp

from pygeoipupdate import __version__
from pygeoipupdate.errors import AuthenticationError, DownloadError, HTTPError
from pygeoipupdate.models import Metadata

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
    ) -> None:
        """Initialize the client.

        Args:
            account_id: MaxMind account ID.
            license_key: MaxMind license key.
            host: Update server URL.
            proxy: Proxy URL (http, https, or socks5).

        """
        self._account_id = account_id
        self._license_key = license_key
        self._host = host.rstrip("/")
        self._proxy = proxy
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
        if not self._session:
            msg = "Client must be used as async context manager"
            raise RuntimeError(msg)

        params = urlencode({"edition_id": edition_id})
        url = f"{self._host}/geoip/updates/metadata?{params}"

        try:
            async with self._session.get(
                url, proxy=self._proxy, auth=self._auth
            ) as response:
                if response.status == 401:
                    msg = "Invalid account ID or license key"
                    raise AuthenticationError(msg)

                if response.status != 200:
                    body_text = await response.text()
                    body = body_text[:256]
                    if len(body_text) > 256:
                        body += f"... ({len(body_text)} bytes total)"
                    raise HTTPError(
                        f"Unexpected HTTP status code: {response.status}",
                        status_code=response.status,
                        body=body,
                    )

                data = await response.json()
                databases = data.get("databases", [])
                if not databases:
                    msg = f"Response does not contain edition {edition_id}"
                    raise DownloadError(msg)

                try:
                    db = databases[0]
                    return Metadata(
                        edition_id=db["edition_id"],
                        date=db["date"],
                        md5=db["md5"],
                    )
                except (KeyError, IndexError) as e:
                    msg = f"Malformed metadata response: missing field {e}"
                    raise DownloadError(msg) from e
        except aiohttp.ContentTypeError as e:
            msg = f"Failed to parse metadata response as JSON: {e}"
            raise DownloadError(msg) from e
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
        # First get metadata to check if update is needed
        metadata = await self.get_metadata(edition_id)

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
                    body_text = await response.text()
                    body = body_text[:256]
                    if len(body_text) > 256:
                        body += f"... ({len(body_text)} bytes total)"
                    raise HTTPError(
                        f"Unexpected HTTP status code: {response.status}",
                        status_code=response.status,
                        body=body,
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
                    with os.fdopen(fd, "wb") as f:
                        async for chunk in response.content.iter_chunked(
                            64 * 1024,
                        ):
                            f.write(chunk)
                        f.flush()
                        os.fsync(f.fileno())
                except BaseException:
                    _cleanup_temp_file(temp_path)
                    raise

                return Path(temp_path), last_modified

        except aiohttp.ClientError as e:
            msg = f"Failed to download database: {e}"
            raise DownloadError(msg) from e


def _cleanup_temp_file(temp_path: str) -> None:
    try:
        os.unlink(temp_path)
    except OSError:
        logger.warning("Failed to clean up temp file: %s", temp_path, exc_info=True)
