"""Update orchestration for geoipupdate."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Self

from geoipupdate._file_lock import FileLock
from geoipupdate._file_writer import LocalFileWriter
from geoipupdate.client import Client, NoUpdateAvailable
from geoipupdate.models import UpdateResult

if TYPE_CHECKING:
    from geoipupdate.config import Config

logger = logging.getLogger(__name__)


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
                retry_for=self._config.retry_for,
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

            # Output JSON if requested
            if self._config.output:
                output = [r.to_dict() for r in results]
                print(json.dumps(output))  # noqa: T201

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

        # Parallel execution with limited concurrency
        semaphore = asyncio.Semaphore(parallelism)

        async def download_with_semaphore(edition_id: str) -> UpdateResult:
            async with semaphore:
                return await self._download_edition(edition_id)

        tasks = [download_with_semaphore(eid) for eid in edition_ids]
        results = await asyncio.gather(*tasks)

        return list(results)

    async def _download_edition(self, edition_id: str) -> UpdateResult:
        """Download a single database edition.

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

        # Download (client handles retry internally)
        response = await self._client.download(edition_id, old_hash)

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

        # Write the database
        self._writer.write(
            edition_id,
            response.data,
            response.md5,
            response.last_modified,
        )

        return UpdateResult(
            edition_id=edition_id,
            old_hash=old_hash,
            new_hash=response.md5,
            modified_at=response.last_modified,
            checked_at=checked_at,
        )
