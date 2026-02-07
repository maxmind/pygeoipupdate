"""File locking for pygeoipupdate."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Self

from filelock import FileLock as BaseFileLock
from filelock import Timeout

from pygeoipupdate.errors import LockError

logger = logging.getLogger(__name__)


class FileLock:
    """Cross-platform file lock for process coordination.

    This ensures only one pygeoipupdate process runs at a time.

    Example:
        with FileLock(Path("/var/lib/GeoIP/.geoipupdate.lock")) as lock:
            # Do work while holding lock
            pass

    """

    def __init__(self, path: Path, *, verbose: bool = False) -> None:
        """Initialize the file lock.

        Args:
            path: Path to the lock file.
            verbose: Enable verbose logging.

        """
        self._path = path
        self._verbose = verbose
        self._lock = BaseFileLock(str(path))

    def acquire(self, timeout: float = 0) -> None:
        """Acquire the lock.

        Args:
            timeout: Timeout in seconds. 0 means fail immediately if held.

        Raises:
            LockError: If the lock cannot be acquired.

        """
        try:
            if self._verbose:
                logger.info("Initializing file lock at %s", self._path)
            self._lock.acquire(timeout=timeout)
            if self._verbose:
                logger.info("Acquired lock: %s", self._path)
        except Timeout as e:
            msg = f"Could not acquire lock on {self._path}: another process may be running"
            raise LockError(msg) from e

    def release(self) -> None:
        """Release the lock."""
        self._lock.release()
        if self._verbose:
            logger.info("Released lock: %s", self._path)

    def __enter__(self) -> Self:
        """Enter context manager and acquire lock."""
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Exit context manager and release lock."""
        self.release()
