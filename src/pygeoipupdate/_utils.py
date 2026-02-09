"""Internal utilities for pygeoipupdate."""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def cleanup_temp_file(temp_path: str) -> None:
    """Remove a temporary file, logging a warning on failure.

    Args:
        temp_path: Path to the temporary file.

    """
    try:
        os.unlink(temp_path)
    except OSError:
        logger.warning("Failed to clean up temp file: %s", temp_path, exc_info=True)
