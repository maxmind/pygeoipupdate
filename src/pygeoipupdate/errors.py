"""Exception classes for pygeoipupdate."""

from __future__ import annotations


class GeoIPUpdateError(Exception):
    """Base exception for pygeoipupdate errors."""


class ConfigError(GeoIPUpdateError):
    """Configuration is invalid or incomplete."""


class DownloadError(GeoIPUpdateError):
    """Error downloading a database."""


class AuthenticationError(DownloadError):
    """Authentication with MaxMind failed (invalid account ID or license key)."""


class HTTPError(DownloadError):
    """HTTP request failed with an error status code."""

    def __init__(self, message: str, status_code: int, body: str = "") -> None:
        """Initialize HTTPError.

        Args:
            message: Error message.
            status_code: HTTP status code.
            body: Response body, if available.

        """
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class LockError(GeoIPUpdateError):
    """Could not acquire file lock."""


class HashMismatchError(GeoIPUpdateError):
    """Downloaded file hash does not match expected hash."""

    def __init__(self, message: str, expected: str, actual: str) -> None:
        """Initialize HashMismatchError.

        Args:
            message: Error message.
            expected: Expected MD5 hash.
            actual: Actual MD5 hash.

        """
        super().__init__(message)
        self.expected = expected
        self.actual = actual
