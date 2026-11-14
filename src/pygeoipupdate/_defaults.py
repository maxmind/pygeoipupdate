"""Platform-specific default paths for pygeoipupdate."""

from __future__ import annotations

import os
import platform
from pathlib import Path


def get_default_config_file() -> Path:
    """Get the platform-specific default configuration file path.

    Returns:
        Path to the default configuration file.

    """
    if platform.system() == "Windows":
        system_drive = os.environ.get("SYSTEMDRIVE", "C:")
        return Path(system_drive) / "ProgramData/MaxMind/GeoIPUpdate/GeoIP.conf"
    return Path("/usr/local/etc/GeoIP.conf")


def find_default_config_file() -> Path | None:
    """Get the default configuration file path if the file exists.

    Returns:
        Path to the default configuration file, or None if it does not exist.

    """
    path = get_default_config_file()
    if path.exists():
        return path
    return None


def get_default_database_directory() -> Path:
    """Get the platform-specific default database directory path.

    Returns:
        Path to the default database directory.

    """
    if platform.system() == "Windows":
        system_drive = os.environ.get("SYSTEMDRIVE", "C:")
        return Path(system_drive) / "ProgramData/MaxMind/GeoIPUpdate/GeoIP"
    return Path("/usr/local/share/GeoIP")
