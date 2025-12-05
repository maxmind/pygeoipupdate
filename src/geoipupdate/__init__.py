"""MaxMind GeoIP database updater."""

from __future__ import annotations

__version__ = "1.0.0"

from geoipupdate.client import Client
from geoipupdate.config import Config
from geoipupdate.errors import (
    AuthenticationError,
    ConfigError,
    DownloadError,
    GeoIPUpdateError,
    HashMismatchError,
    HTTPError,
    LockError,
)
from geoipupdate.models import Metadata, UpdateResult
from geoipupdate.updater import Updater

__all__ = [
    "AuthenticationError",
    "Client",
    "Config",
    "ConfigError",
    "DownloadError",
    "GeoIPUpdateError",
    "HTTPError",
    "HashMismatchError",
    "LockError",
    "Metadata",
    "UpdateResult",
    "Updater",
    "__version__",
]
