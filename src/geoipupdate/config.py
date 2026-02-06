"""Configuration management for geoipupdate."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Self
from urllib.parse import urlparse, urlunparse

from geoipupdate._defaults import (
    get_default_config_file,
    get_default_database_directory,
)
from geoipupdate.errors import ConfigError

_SCHEME_RE = re.compile(r"(?i)\A([a-z][a-z0-9+\-.]*)://")


@dataclass(frozen=True)
class Config:
    """Configuration for geoipupdate.

    Attributes:
        account_id: MaxMind account ID.
        license_key: MaxMind license key.
        edition_ids: List of database edition IDs to download.
        database_directory: Directory to store database files.
        host: MaxMind update server URL.
        proxy: Proxy URL (http, https, or socks5).
        preserve_file_times: Whether to preserve file modification times.
        lock_file: Path to lock file for preventing concurrent runs.
        retry_for: Duration to retry failed downloads.
        parallelism: Number of parallel downloads.
        verbose: Enable verbose output.
        output: Enable JSON output.

    """

    account_id: int
    license_key: str
    edition_ids: list[str]
    database_directory: Path = field(default_factory=get_default_database_directory)
    host: str = "https://updates.maxmind.com"
    proxy: str | None = None
    preserve_file_times: bool = False
    lock_file: Path | None = None
    retry_for: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    parallelism: int = 1
    verbose: bool = False
    output: bool = False

    def __post_init__(self) -> None:
        """Validate and set derived values after initialization."""
        if self.lock_file is None:
            object.__setattr__(
                self, "lock_file", self.database_directory / ".geoipupdate.lock"
            )
        if self.account_id < 1:
            raise ConfigError("account_id must be a positive integer")
        if not self.edition_ids:
            raise ConfigError("the `EditionIDs` option is required")
        if not self.license_key:
            raise ConfigError("the `LicenseKey` option is required")
        if self.parallelism < 1:
            msg = f"parallelism should be greater than 0, got '{self.parallelism}'"
            raise ConfigError(msg)

    @classmethod
    def from_file(
        cls,
        config_file: Path | None = None,
        *,
        database_directory: Path | None = None,
        parallelism: int | None = None,
        verbose: bool = False,
        output: bool = False,
    ) -> Self:
        """Load configuration with precedence: defaults < file < env < args.

        Args:
            config_file: Path to configuration file. If None, uses default.
            database_directory: Override for database directory.
            parallelism: Override for parallelism.
            verbose: Enable verbose output.
            output: Enable JSON output.

        Returns:
            Loaded configuration.

        Raises:
            ConfigError: If configuration is invalid or incomplete.

        """
        # Start with defaults
        config_data: dict[str, object] = {
            "host": "https://updates.maxmind.com",
            "database_directory": get_default_database_directory(),
            "retry_for": timedelta(minutes=5),
            "parallelism": 1,
            "preserve_file_times": False,
            "verbose": False,
            "output": False,
        }

        # Load from config file if it exists
        if config_file is None:
            default_file = get_default_config_file()
            if default_file.exists():
                config_file = default_file

        if config_file is not None:
            file_config = _parse_config_file(config_file)
            config_data.update(file_config)

        # Override with environment variables
        env_config = _parse_environment()
        config_data.update(env_config)

        # Override with CLI arguments
        if database_directory is not None:
            config_data["database_directory"] = database_directory
        if parallelism is not None and parallelism > 0:
            config_data["parallelism"] = parallelism
        if verbose:
            config_data["verbose"] = True
        if output:
            config_data["output"] = True

        # Validate required fields
        _validate_config(config_data)

        # Build proxy URL if needed
        proxy = _build_proxy_url(
            config_data.get("_proxy_url"),
            config_data.get("_proxy_user_password"),
        )
        if proxy:
            config_data["proxy"] = proxy

        # Remove internal keys
        config_data.pop("_proxy_url", None)
        config_data.pop("_proxy_user_password", None)

        return cls(
            account_id=int(config_data["account_id"]),  # type: ignore[arg-type]
            license_key=str(config_data["license_key"]),
            edition_ids=list(config_data["edition_ids"]),  # type: ignore[arg-type]
            database_directory=Path(config_data["database_directory"]),  # type: ignore[arg-type]
            host=str(config_data["host"]),
            proxy=config_data.get("proxy"),  # type: ignore[arg-type]
            preserve_file_times=bool(config_data.get("preserve_file_times", False)),
            lock_file=Path(config_data["lock_file"])
            if config_data.get("lock_file")
            else None,  # type: ignore[arg-type]
            retry_for=config_data["retry_for"],  # type: ignore[arg-type]
            parallelism=int(config_data["parallelism"]),  # type: ignore[arg-type]
            verbose=bool(config_data.get("verbose", False)),
            output=bool(config_data.get("output", False)),
        )


def _parse_config_file(path: Path) -> dict[str, object]:
    """Parse a GeoIP.conf configuration file.

    Args:
        path: Path to the configuration file.

    Returns:
        Dictionary of configuration values.

    Raises:
        ConfigError: If the file cannot be parsed.

    """
    config: dict[str, object] = {}
    keys_seen: set[str] = set()

    try:
        with path.open() as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(None, 1)
                if len(parts) < 2:
                    msg = f"invalid format on line {line_num}"
                    raise ConfigError(msg)

                key, value = parts[0], parts[1]

                if key in keys_seen:
                    msg = f"`{key}' is in the config multiple times"
                    raise ConfigError(msg)
                keys_seen.add(key)

                _set_config_value(config, keys_seen, key, value, line_num)
    except OSError as e:
        msg = f"error opening file: {e}"
        raise ConfigError(msg) from e

    return config


def _set_config_value(
    config: dict[str, object],
    keys_seen: set[str],
    key: str,
    value: str,
    line_num: int,
) -> None:
    """Set a configuration value from a parsed key-value pair.

    Args:
        config: Configuration dictionary to update.
        keys_seen: Set of keys already seen.
        key: Configuration key.
        value: Configuration value.
        line_num: Line number for error messages.

    Raises:
        ConfigError: If the value is invalid.

    """
    if key in ("AccountID", "UserId"):
        try:
            config["account_id"] = int(value)
        except ValueError as e:
            msg = "invalid account ID format"
            raise ConfigError(msg) from e
        keys_seen.add("AccountID")
        keys_seen.add("UserId")

    elif key == "DatabaseDirectory":
        config["database_directory"] = Path(value)

    elif key in ("EditionIDs", "ProductIds"):
        config["edition_ids"] = value.split()
        keys_seen.add("EditionIDs")
        keys_seen.add("ProductIds")

    elif key == "Host":
        config["host"] = _parse_host(value)

    elif key == "LicenseKey":
        config["license_key"] = value

    elif key == "LockFile":
        config["lock_file"] = Path(value)

    elif key == "PreserveFileTimes":
        if value not in ("0", "1"):
            msg = "`PreserveFileTimes' must be 0 or 1"
            raise ConfigError(msg)
        config["preserve_file_times"] = value == "1"

    elif key == "Proxy":
        config["_proxy_url"] = value

    elif key == "ProxyUserPassword":
        config["_proxy_user_password"] = value

    elif key in ("Protocol", "SkipHostnameVerification", "SkipPeerVerification"):
        # Deprecated options, ignore
        pass

    elif key == "RetryFor":
        config["retry_for"] = _parse_duration(value)

    elif key == "Parallelism":
        try:
            parallelism = int(value)
        except ValueError as e:
            msg = f"'{value}' is not a valid parallelism value"
            raise ConfigError(msg) from e
        if parallelism <= 0:
            msg = f"parallelism should be greater than 0, got '{parallelism}'"
            raise ConfigError(msg)
        config["parallelism"] = parallelism

    else:
        msg = f"unknown option on line {line_num}"
        raise ConfigError(msg)


def _parse_host(value: str) -> str:
    """Parse a host value, adding https scheme if missing.

    Args:
        value: Host value from configuration.

    Returns:
        Full URL with scheme.

    Raises:
        ConfigError: If the URL cannot be parsed.

    """
    try:
        parsed = urlparse(value)
        if not parsed.scheme:
            parsed = urlparse(f"https://{value}")
        return urlunparse(parsed)
    except Exception as e:
        msg = f"failed to parse Host: {e}"
        raise ConfigError(msg) from e


def _parse_duration(value: str) -> timedelta:
    """Parse a Go-style duration string.

    Supports formats like "5m", "1h30m", "2h", "300s".

    Args:
        value: Duration string.

    Returns:
        Parsed timedelta.

    Raises:
        ConfigError: If the duration cannot be parsed.

    """
    pattern = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
    match = pattern.match(value)

    if not match or not any(match.groups()):
        msg = f"'{value}' is not a valid duration"
        raise ConfigError(msg)

    hours = int(match.group(1) or 0)
    minutes = int(match.group(2) or 0)
    seconds = int(match.group(3) or 0)

    duration = timedelta(hours=hours, minutes=minutes, seconds=seconds)
    if duration < timedelta(0):
        msg = f"'{value}' is not a valid duration"
        raise ConfigError(msg)

    return duration


def _parse_environment() -> dict[str, object]:
    """Parse configuration from environment variables.

    Returns:
        Dictionary of configuration values from environment.

    Raises:
        ConfigError: If environment values are invalid.

    """
    config: dict[str, object] = {}

    # Account ID
    if value := os.environ.get("GEOIPUPDATE_ACCOUNT_ID"):
        try:
            config["account_id"] = int(value)
        except ValueError as e:
            msg = "invalid account ID format"
            raise ConfigError(msg) from e

    if file_path := os.environ.get("GEOIPUPDATE_ACCOUNT_ID_FILE"):
        try:
            content = Path(file_path).read_text().strip()
            config["account_id"] = int(content)
        except OSError as e:
            msg = f"failed to open GEOIPUPDATE_ACCOUNT_ID_FILE: {e}"
            raise ConfigError(msg) from e
        except ValueError as e:
            msg = "invalid account ID format"
            raise ConfigError(msg) from e

    # License Key
    if value := os.environ.get("GEOIPUPDATE_LICENSE_KEY"):
        config["license_key"] = value

    if file_path := os.environ.get("GEOIPUPDATE_LICENSE_KEY_FILE"):
        try:
            config["license_key"] = Path(file_path).read_text().strip()
        except OSError as e:
            msg = f"failed to open GEOIPUPDATE_LICENSE_KEY_FILE: {e}"
            raise ConfigError(msg) from e

    # Database directory
    if value := os.environ.get("GEOIPUPDATE_DB_DIR"):
        config["database_directory"] = Path(value)

    # Edition IDs
    if value := os.environ.get("GEOIPUPDATE_EDITION_IDS"):
        config["edition_ids"] = value.split()

    # Host
    if value := os.environ.get("GEOIPUPDATE_HOST"):
        config["host"] = _parse_host(value)

    # Lock file
    if value := os.environ.get("GEOIPUPDATE_LOCK_FILE"):
        config["lock_file"] = Path(value)

    # Parallelism
    if value := os.environ.get("GEOIPUPDATE_PARALLELISM"):
        try:
            parallelism = int(value)
        except ValueError as e:
            msg = f"'{value}' is not a valid parallelism value"
            raise ConfigError(msg) from e
        if parallelism <= 0:
            msg = f"parallelism should be greater than 0, got '{parallelism}'"
            raise ConfigError(msg)
        config["parallelism"] = parallelism

    # Preserve file times
    if value := os.environ.get("GEOIPUPDATE_PRESERVE_FILE_TIMES"):
        if value not in ("0", "1"):
            msg = "`GEOIPUPDATE_PRESERVE_FILE_TIMES' must be 0 or 1"
            raise ConfigError(msg)
        config["preserve_file_times"] = value == "1"

    # Proxy
    if value := os.environ.get("GEOIPUPDATE_PROXY"):
        config["_proxy_url"] = value

    if value := os.environ.get("GEOIPUPDATE_PROXY_USER_PASSWORD"):
        config["_proxy_user_password"] = value

    # Retry for
    if value := os.environ.get("GEOIPUPDATE_RETRY_FOR"):
        config["retry_for"] = _parse_duration(value)

    # Verbose
    if value := os.environ.get("GEOIPUPDATE_VERBOSE"):
        if value not in ("0", "1"):
            msg = "`GEOIPUPDATE_VERBOSE' must be 0 or 1"
            raise ConfigError(msg)
        config["verbose"] = value == "1"

    return config


def _validate_config(config: dict[str, object]) -> None:
    """Validate that required configuration values are present.

    Args:
        config: Configuration dictionary.

    Raises:
        ConfigError: If required values are missing or invalid.

    """
    # Check for invalid placeholder credentials
    account_id = config.get("account_id", 0)
    license_key = config.get("license_key", "")

    if (account_id in (0, 999999)) and license_key == "000000000000":
        msg = "geoipupdate requires a valid AccountID and LicenseKey combination"
        raise ConfigError(msg)

    if not config.get("edition_ids"):
        msg = "the `EditionIDs` option is required"
        raise ConfigError(msg)

    if not account_id:
        msg = "the `AccountID` option is required"
        raise ConfigError(msg)

    if not license_key:
        msg = "the `LicenseKey` option is required"
        raise ConfigError(msg)


def _build_proxy_url(
    proxy_url: str | None,
    proxy_user_password: str | None,
) -> str | None:
    """Build a complete proxy URL from components.

    Args:
        proxy_url: Proxy host/URL.
        proxy_user_password: Proxy credentials in "user:password" format.

    Returns:
        Complete proxy URL or None.

    Raises:
        ConfigError: If proxy configuration is invalid.

    """
    if not proxy_url:
        return None

    # Add scheme if missing
    match = _SCHEME_RE.match(proxy_url)
    if not match:
        proxy_url = f"http://{proxy_url}"
    else:
        scheme = match.group(1).lower()
        if scheme not in ("http", "https", "socks5"):
            msg = f"unsupported proxy type: {scheme}"
            raise ConfigError(msg)

    try:
        parsed = urlparse(proxy_url)
    except Exception as e:
        msg = f"parsing proxy URL: {e}"
        raise ConfigError(msg) from e

    # Add default port if missing
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 1080  # Default from cURL

    netloc = f"{host}:{port}"

    # Add credentials if provided and not already in URL
    if parsed.username is None and proxy_user_password:
        parts = proxy_user_password.split(":", 1)
        if len(parts) != 2:
            msg = "proxy user/password is malformed"
            raise ConfigError(msg)
        username, password = parts
        netloc = f"{username}:{password}@{netloc}"
    elif parsed.username:
        if parsed.password:
            netloc = f"{parsed.username}:{parsed.password}@{netloc}"
        else:
            netloc = f"{parsed.username}@{netloc}"

    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))
