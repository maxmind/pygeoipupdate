"""Update orchestration for pygeoipupdate."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Self

import aiohttp
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception,
    stop_after_delay,
    wait_exponential,
)

from pygeoipupdate._file_lock import FileLock
from pygeoipupdate._file_writer import LocalFileWriter
from pygeoipupdate.client import Client, NoUpdateAvailable
from pygeoipupdate.errors import (
    AuthenticationError,
    DownloadError,
    HashMismatchError,
    HTTPError,
)
from pygeoipupdate.models import UpdateResult

if TYPE_CHECKING:
    from pygeoipupdate.config import Config

logger = logging.getLogger(__name__)


def _cleanup_temp_file(temp_path: str) -> None:
    try:
        os.unlink(temp_path)
    except OSError:
        logger.warning("Failed to clean up temp file: %s", temp_path, exc_info=True)


def _is_retryable_error(exception: BaseException) -> bool:
    """Determine if an exception is retryable.

    Args:
        exception: The exception to check.

    Returns:
        True if the exception should trigger a retry.

    """
    if isinstance(exception, HashMismatchError):
        return True
    # HTTPError and AuthenticationError are DownloadError subclasses;
    # check them before the generic DownloadError catch-all.
    if isinstance(exception, HTTPError):
        # Only 5xx (server) errors are retryable
        return exception.status_code >= 500
    if isinstance(exception, AuthenticationError):
        return False
    # Subclasses (HTTPError, AuthenticationError) are checked above.
    # Remaining DownloadErrors are retryable only if caused by a transient
    # network issue (e.g., ContentTypeError from a load balancer returning HTML).
    if isinstance(exception, DownloadError):
        return isinstance(exception.__cause__, aiohttp.ClientError)
    # Network errors, timeouts, etc. are retryable.
    # ConnectionError (not the broader OSError) covers network-related failures
    # without retrying on disk full, permission denied, etc.
    return isinstance(exception, (aiohttp.ClientError, TimeoutError, ConnectionError))


class Updater:
    """Orchestrates GeoIP database updates.

    This class coordinates the download and update process for multiple
    database editions, handling parallelism, file locking, and atomic writes.

    Example:
        config = Config(
            account_id=12345,
            license_key="your_key",
            edition_ids=["GeoLite2-City"],
            database_directory=Path("/var/lib/GeoIP"),
        )

        async with Updater(config) as updater:
            results = await updater.run()

    """

    def __init__(self, config: Config) -> None:
        """Initialize the updater.

        Args:
            config: Configuration for the updater.

        """
        self._config = config
        self._client: Client | None = None
        self._writer: LocalFileWriter | None = None
        self._lock: FileLock | None = None
        self._exit_stack: contextlib.AsyncExitStack | None = None

    async def __aenter__(self) -> Self:
        """Enter async context manager."""
        self._exit_stack = contextlib.AsyncExitStack()
        try:
            client = Client(
                account_id=self._config.account_id,
                license_key=self._config.license_key,
                host=self._config.host,
                proxy=self._config.proxy,
            )
            self._client = await self._exit_stack.enter_async_context(client)

            self._writer = LocalFileWriter(
                self._config.database_directory,
                preserve_file_times=self._config.preserve_file_times,
                verbose=self._config.verbose,
            )
        except BaseException:
            await self._exit_stack.aclose()
            raise

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit async context manager."""
        if self._exit_stack:
            await self._exit_stack.aclose()
            self._exit_stack = None

    async def run(self) -> list[UpdateResult]:
        """Run the update process for all configured editions.

        Returns:
            List of update results for each edition.

        Raises:
            LockError: If the lock cannot be acquired.
            DownloadError: If a download fails.
            HashMismatchError: If a downloaded file fails hash verification.

        """
        if not self._client or not self._writer:
            msg = "Updater must be used as async context manager"
            raise RuntimeError(msg)

        # Acquire file lock
        if self._config.lock_file:
            self._lock = FileLock(self._config.lock_file, verbose=self._config.verbose)
            self._lock.acquire()

        try:
            results = await self._run_updates()
            return results
        finally:
            if self._lock:
                self._lock.release()
                self._lock = None

    async def _run_updates(self) -> list[UpdateResult]:
        """Run updates for all editions with configured parallelism.

        Returns:
            List of update results.

        """
        edition_ids = self._config.edition_ids
        parallelism = self._config.parallelism

        if parallelism <= 1 or len(edition_ids) <= 1:
            # Sequential execution
            results = []
            for edition_id in edition_ids:
                result = await self._download_edition(edition_id)
                results.append(result)
            return results

        # Parallel execution with limited concurrency.
        # TaskGroup cancels all remaining tasks if any one raises,
        # matching Go's errgroup cancel-on-first-error semantics.
        semaphore = asyncio.Semaphore(parallelism)

        async def download_with_semaphore(edition_id: str) -> UpdateResult:
            async with semaphore:
                return await self._download_edition(edition_id)

        task_handles: list[asyncio.Task[UpdateResult]] = []
        async with asyncio.TaskGroup() as tg:
            task_handles.extend(
                tg.create_task(download_with_semaphore(eid)) for eid in edition_ids
            )

        return [t.result() for t in task_handles]

    async def _download_edition(self, edition_id: str) -> UpdateResult:
        """Download a single database edition with retry.

        Args:
            edition_id: The database edition ID.

        Returns:
            Update result for the edition.

        """
        retry_for = self._config.retry_for
        if retry_for and retry_for.total_seconds() > 0:
            return await self._download_edition_with_retry(
                edition_id, retry_for.total_seconds()
            )
        return await self._download_edition_once(edition_id)

    async def _download_edition_with_retry(
        self, edition_id: str, retry_seconds: float
    ) -> UpdateResult:
        """Download with retry wrapping the entire operation."""

        @retry(
            stop=stop_after_delay(retry_seconds),
            wait=wait_exponential(multiplier=1, min=1, max=60),
            retry=retry_if_exception(_is_retryable_error),
            before_sleep=before_sleep_log(logger, logging.WARNING),
            reraise=True,
        )
        async def _retry_wrapper() -> UpdateResult:
            return await self._download_edition_once(edition_id)

        return await _retry_wrapper()

    async def _download_edition_once(self, edition_id: str) -> UpdateResult:
        """Download a single database edition (one attempt).

        Args:
            edition_id: The database edition ID.

        Returns:
            Update result for the edition.

        """
        if not self._client or not self._writer:
            msg = "Updater not initialized"
            raise RuntimeError(msg)

        # Get current hash
        old_hash = self._writer.get_hash(edition_id)

        # Download
        response = await self._client.download(
            edition_id, old_hash, self._config.database_directory
        )

        checked_at = datetime.now(timezone.utc)

        if isinstance(response, NoUpdateAvailable):
            if self._config.verbose:
                logger.info("No new updates available for %s", edition_id)
                logger.info("Database %s up to date", edition_id)

            return UpdateResult(
                edition_id=edition_id,
                old_hash=old_hash,
                new_hash=old_hash,
                checked_at=checked_at,
            )

        if self._config.verbose:
            logger.info("Updates available for %s", edition_id)

        # Write the database, cleaning up the download temp file afterward
        try:
            self._writer.write(
                edition_id,
                response.compressed_path,
                response.md5,
                response.last_modified,
            )
        finally:
            _cleanup_temp_file(str(response.compressed_path))

        return UpdateResult(
            edition_id=edition_id,
            old_hash=old_hash,
            new_hash=response.md5,
            modified_at=response.last_modified,
            checked_at=checked_at,
        )
