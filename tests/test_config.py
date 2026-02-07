"""Tests for pygeoipupdate configuration."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from pygeoipupdate.config import (
    Config,
    _build_proxy_url,
    _parse_config_file,
    _parse_duration,
    _parse_environment,
)
from pygeoipupdate.errors import ConfigError


class TestParseConfigFile:
    """Tests for _parse_config_file."""

    def test_basic_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""# Comment
AccountID 12345
LicenseKey abc123xyz
EditionIDs GeoLite2-City GeoLite2-Country
DatabaseDirectory /var/lib/GeoIP
""")
        config = _parse_config_file(config_file)

        assert config["account_id"] == 12345
        assert config["license_key"] == "abc123xyz"
        assert config["edition_ids"] == ["GeoLite2-City", "GeoLite2-Country"]
        assert config["database_directory"] == Path("/var/lib/GeoIP")

    def test_legacy_keys(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""UserId 12345
LicenseKey abc123
ProductIds GeoLite2-City
""")
        config = _parse_config_file(config_file)

        assert config["account_id"] == 12345
        assert config["edition_ids"] == ["GeoLite2-City"]

    def test_all_options(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc123
EditionIDs GeoLite2-City
DatabaseDirectory /var/lib/GeoIP
Host updates.example.com
LockFile /var/run/geoipupdate.lock
PreserveFileTimes 1
Proxy proxy.example.com:8080
ProxyUserPassword user:pass
RetryFor 10m
Parallelism 4
""")
        config = _parse_config_file(config_file)

        assert config["account_id"] == 12345
        assert config["license_key"] == "abc123"
        assert config["edition_ids"] == ["GeoLite2-City"]
        assert config["database_directory"] == Path("/var/lib/GeoIP")
        assert config["host"] == "https://updates.example.com"
        assert config["lock_file"] == Path("/var/run/geoipupdate.lock")
        assert config["preserve_file_times"] is True
        assert config["_proxy_url"] == "proxy.example.com:8080"
        assert config["_proxy_user_password"] == "user:pass"
        assert config["retry_for"] == timedelta(minutes=10)
        assert config["parallelism"] == 4

    def test_duplicate_key_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
AccountID 67890
LicenseKey abc
EditionIDs Test
""")

        with pytest.raises(ConfigError, match="is in the config multiple times"):
            _parse_config_file(config_file)

    def test_invalid_format_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID
LicenseKey abc
EditionIDs Test
""")

        with pytest.raises(ConfigError, match="invalid format on line 1"):
            _parse_config_file(config_file)

    def test_unknown_option_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc
EditionIDs Test
UnknownOption value
""")

        with pytest.raises(ConfigError, match="unknown option on line 4"):
            _parse_config_file(config_file)

    def test_invalid_account_id(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID notanumber
LicenseKey abc
EditionIDs Test
""")

        with pytest.raises(ConfigError, match="invalid account ID format"):
            _parse_config_file(config_file)

    def test_invalid_preserve_file_times(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc
EditionIDs Test
PreserveFileTimes yes
""")

        with pytest.raises(ConfigError, match="PreserveFileTimes' must be 0 or 1"):
            _parse_config_file(config_file)

    def test_invalid_parallelism(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc
EditionIDs Test
Parallelism -1
""")

        with pytest.raises(ConfigError, match="parallelism should be greater than 0"):
            _parse_config_file(config_file)

    def test_deprecated_options_ignored(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc
EditionIDs Test
Protocol https
SkipHostnameVerification 1
SkipPeerVerification 1
""")

        # Should not raise
        config = _parse_config_file(config_file)
        assert config["account_id"] == 12345


class TestParseDuration:
    """Tests for _parse_duration."""

    def test_minutes(self) -> None:
        assert _parse_duration("5m") == timedelta(minutes=5)

    def test_hours(self) -> None:
        assert _parse_duration("2h") == timedelta(hours=2)

    def test_seconds(self) -> None:
        assert _parse_duration("30s") == timedelta(seconds=30)

    def test_combined(self) -> None:
        assert _parse_duration("1h30m") == timedelta(hours=1, minutes=30)
        assert _parse_duration("2h15m30s") == timedelta(hours=2, minutes=15, seconds=30)

    def test_invalid(self) -> None:
        with pytest.raises(ConfigError, match="is not a valid duration"):
            _parse_duration("invalid")

    def test_empty(self) -> None:
        with pytest.raises(ConfigError, match="is not a valid duration"):
            _parse_duration("")

    def test_zero_seconds(self) -> None:
        assert _parse_duration("0s") == timedelta(0)

    def test_combined_minutes_seconds(self) -> None:
        assert _parse_duration("1m30s") == timedelta(minutes=1, seconds=30)

    def test_large_values(self) -> None:
        assert _parse_duration("99h99m99s") == timedelta(
            hours=99, minutes=99, seconds=99
        )

    def test_space_invalid(self) -> None:
        with pytest.raises(ConfigError, match="is not a valid duration"):
            _parse_duration("1h 30m")

    def test_wrong_order_accepted(self) -> None:
        # Go's time.ParseDuration accepts any order
        assert _parse_duration("30m5h") == timedelta(hours=5, minutes=30)

    def test_milliseconds(self) -> None:
        assert _parse_duration("300ms") == timedelta(milliseconds=300)

    def test_microseconds(self) -> None:
        assert _parse_duration("100us") == timedelta(microseconds=100)

    def test_microseconds_unicode(self) -> None:
        assert _parse_duration("100µs") == timedelta(microseconds=100)

    def test_nanoseconds(self) -> None:
        assert _parse_duration("1000ns") == timedelta(microseconds=1)

    def test_fractional_seconds(self) -> None:
        assert _parse_duration("1.5s") == timedelta(seconds=1, milliseconds=500)

    def test_fractional_minutes(self) -> None:
        assert _parse_duration("1.5m") == timedelta(seconds=90)

    def test_mixed_subsecond(self) -> None:
        assert _parse_duration("1s500ms") == timedelta(seconds=1, milliseconds=500)

    def test_negative_duration_rejected(self) -> None:
        with pytest.raises(ConfigError, match="not a valid duration"):
            _parse_duration("-5m")


class TestParseEnvironment:
    """Tests for _parse_environment."""

    def test_account_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEOIPUPDATE_ACCOUNT_ID", "12345")
        config = _parse_environment()
        assert config["account_id"] == 12345

    def test_account_id_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        id_file = tmp_path / "account_id"
        id_file.write_text("67890\n")
        monkeypatch.setenv("GEOIPUPDATE_ACCOUNT_ID_FILE", str(id_file))
        config = _parse_environment()
        assert config["account_id"] == 67890

    def test_license_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEOIPUPDATE_LICENSE_KEY", "mykey")
        config = _parse_environment()
        assert config["license_key"] == "mykey"

    def test_license_key_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        key_file = tmp_path / "license_key"
        key_file.write_text("secretkey\n")
        monkeypatch.setenv("GEOIPUPDATE_LICENSE_KEY_FILE", str(key_file))
        config = _parse_environment()
        assert config["license_key"] == "secretkey"

    def test_edition_ids(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEOIPUPDATE_EDITION_IDS", "GeoLite2-City GeoLite2-Country")
        config = _parse_environment()
        assert config["edition_ids"] == ["GeoLite2-City", "GeoLite2-Country"]

    def test_verbose(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEOIPUPDATE_VERBOSE", "1")
        config = _parse_environment()
        assert config["verbose"] is True

    def test_invalid_verbose(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GEOIPUPDATE_VERBOSE", "yes")
        with pytest.raises(ConfigError, match="GEOIPUPDATE_VERBOSE' must be 0 or 1"):
            _parse_environment()


class TestBuildProxyUrl:
    """Tests for _build_proxy_url."""

    def test_none(self) -> None:
        assert _build_proxy_url(None, None) is None

    def test_simple_host(self) -> None:
        result = _build_proxy_url("proxy.example.com", None)
        assert result == "http://proxy.example.com:1080"

    def test_host_with_port(self) -> None:
        result = _build_proxy_url("proxy.example.com:8080", None)
        assert result == "http://proxy.example.com:8080"

    def test_with_scheme(self) -> None:
        result = _build_proxy_url("https://proxy.example.com:8080", None)
        assert result == "https://proxy.example.com:8080"

    def test_socks5(self) -> None:
        result = _build_proxy_url("socks5://proxy.example.com:1080", None)
        assert result == "socks5://proxy.example.com:1080"

    def test_with_credentials(self) -> None:
        result = _build_proxy_url("proxy.example.com:8080", "user:pass")
        assert result == "http://user:pass@proxy.example.com:8080"

    def test_credentials_in_url(self) -> None:
        result = _build_proxy_url("http://user:pass@proxy.example.com:8080", None)
        assert result == "http://user:pass@proxy.example.com:8080"

    def test_invalid_scheme(self) -> None:
        with pytest.raises(ConfigError, match="unsupported proxy type"):
            _build_proxy_url("ftp://proxy.example.com", None)

    def test_malformed_credentials(self) -> None:
        with pytest.raises(ConfigError, match="proxy user/password is malformed"):
            _build_proxy_url("proxy.example.com", "useronly")


class TestConfig:
    """Tests for Config class."""

    def test_from_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc123
EditionIDs GeoLite2-City GeoLite2-Country
DatabaseDirectory /var/lib/GeoIP
""")
        config = Config.from_file(config_file=config_file)

        assert config.account_id == 12345
        assert config.license_key == "abc123"
        assert config.edition_ids == ("GeoLite2-City", "GeoLite2-Country")
        assert config.database_directory == Path("/var/lib/GeoIP")
        assert config.host == "https://updates.maxmind.com"
        assert config.parallelism == 1
        assert config.lock_file == Path("/var/lib/GeoIP/.geoipupdate.lock")

    def test_env_overrides_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc123
EditionIDs GeoLite2-City
""")
        monkeypatch.setenv("GEOIPUPDATE_ACCOUNT_ID", "99999")

        config = Config.from_file(config_file=config_file)
        assert config.account_id == 99999

    def test_cli_overrides_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc123
EditionIDs GeoLite2-City
""")
        monkeypatch.setenv("GEOIPUPDATE_DB_DIR", "/env/path")

        config = Config.from_file(
            config_file=config_file,
            database_directory=Path("/cli/path"),
        )
        assert config.database_directory == Path("/cli/path")

    def test_missing_account_id(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""LicenseKey abc123
EditionIDs GeoLite2-City
""")

        with pytest.raises(ConfigError, match="AccountID.*required"):
            Config.from_file(config_file=config_file)

    def test_missing_license_key(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
EditionIDs GeoLite2-City
""")

        with pytest.raises(ConfigError, match="LicenseKey.*required"):
            Config.from_file(config_file=config_file)

    def test_missing_edition_ids(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey abc123
""")

        with pytest.raises(ConfigError, match="EditionIDs.*required"):
            Config.from_file(config_file=config_file)

    def test_placeholder_credentials(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 999999
LicenseKey 000000000000
EditionIDs GeoLite2-City
""")

        with pytest.raises(ConfigError, match="valid AccountID and LicenseKey"):
            Config.from_file(config_file=config_file)

    def test_direct_instantiation(self) -> None:
        config = Config(
            account_id=12345,
            license_key="abc123",
            edition_ids=["GeoLite2-City"],
            database_directory=Path("/var/lib/GeoIP"),
        )

        assert config.account_id == 12345
        assert config.license_key == "abc123"
        assert config.edition_ids == ("GeoLite2-City",)
        assert config.lock_file == Path("/var/lib/GeoIP/.geoipupdate.lock")

    def test_frozen(self) -> None:
        config = Config(
            account_id=12345,
            license_key="abc123",
            edition_ids=["GeoLite2-City"],
            database_directory=Path("/var/lib/GeoIP"),
        )

        with pytest.raises(AttributeError):
            config.account_id = 99999  # type: ignore[misc]

    def test_empty_license_key_raises(self) -> None:
        with pytest.raises(ConfigError, match="LicenseKey.*required"):
            Config(
                account_id=1,
                license_key="",
                edition_ids=["GeoLite2-City"],
            )

    def test_empty_edition_ids_raises(self) -> None:
        with pytest.raises(ConfigError, match="EditionIDs.*required"):
            Config(
                account_id=1,
                license_key="abc123",
                edition_ids=[],
            )

    def test_invalid_parallelism_raises(self) -> None:
        with pytest.raises(ConfigError, match="parallelism should be greater than 0"):
            Config(
                account_id=1,
                license_key="abc123",
                edition_ids=["GeoLite2-City"],
                parallelism=0,
            )
