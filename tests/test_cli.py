"""Tests for the CLI module."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner
from pytest_httpserver import HTTPServer

from pygeoipupdate import __version__
from pygeoipupdate.cli import main
from tests.conftest import create_test_tar_gz


class TestCLI:
    """Tests for the CLI."""

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])

        assert result.exit_code == 0
        assert "pygeoipupdate" in result.output
        assert __version__ in result.output

    def test_version_short_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-V"])

        assert result.exit_code == 0
        assert "pygeoipupdate" in result.output
        assert __version__ in result.output

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "Update MaxMind GeoIP databases" in result.output
        assert "--config-file" in result.output
        assert "--database-directory" in result.output
        assert "--verbose" in result.output
        assert "--output" in result.output

    def test_help_short_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["-h"])

        assert result.exit_code == 0
        assert "Update MaxMind GeoIP databases" in result.output

    def test_negative_parallelism(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("""AccountID 12345
LicenseKey test_key
EditionIDs GeoLite2-City
""")

        runner = CliRunner()
        result = runner.invoke(main, ["-f", str(config_file), "--parallelism", "-1"])

        assert result.exit_code != 0
        assert "Parallelism must be a positive number" in result.output

    def test_missing_config(self, tmp_path: Path) -> None:
        runner = CliRunner()

        # No config file and no environment variables
        result = runner.invoke(main, ["-d", str(tmp_path)])

        assert result.exit_code == 1
        assert "Configuration error" in result.output

    def test_invalid_config_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text("InvalidOption value\n")

        runner = CliRunner()
        result = runner.invoke(main, ["-f", str(config_file)])

        assert result.exit_code == 1
        assert "Configuration error" in result.output

    def test_successful_update(self, httpserver: HTTPServer, tmp_path: Path) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text(f"""AccountID 12345
LicenseKey test_key
EditionIDs GeoLite2-City
Host {httpserver.url_for("/")}
DatabaseDirectory {tmp_path}
""")

        runner = CliRunner()
        result = runner.invoke(main, ["-f", str(config_file)])

        assert result.exit_code == 0
        assert (tmp_path / "GeoLite2-City.mmdb").exists()

    def test_verbose_output(
        self, httpserver: HTTPServer, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text(f"""AccountID 12345
LicenseKey test_key
EditionIDs GeoLite2-City
Host {httpserver.url_for("/")}
DatabaseDirectory {tmp_path}
""")

        runner = CliRunner()
        with caplog.at_level(logging.INFO):
            result = runner.invoke(main, ["-f", str(config_file), "-v"])

        assert result.exit_code == 0
        # Verbose startup messages should include version, config file, and database directory
        assert "pygeoipupdate version" in caplog.text
        assert str(config_file) in caplog.text
        assert str(tmp_path) in caplog.text

    def test_json_output(self, httpserver: HTTPServer, tmp_path: Path) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text(f"""AccountID 12345
LicenseKey test_key
EditionIDs GeoLite2-City
Host {httpserver.url_for("/")}
DatabaseDirectory {tmp_path}
""")

        runner = CliRunner()
        result = runner.invoke(main, ["-f", str(config_file), "-o"])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert len(output) == 1
        assert output[0]["edition_id"] == "GeoLite2-City"
        assert output[0]["new_hash"] == mmdb_hash
        # Timestamps must be Unix epoch integers, not ISO 8601 strings
        assert isinstance(output[0]["checked_at"], int)
        # No Last-Modified header in mock response, so modified_at should be absent
        assert "modified_at" not in output[0]

    def test_auth_error(self, httpserver: HTTPServer, tmp_path: Path) -> None:
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({"error": "Invalid"}, status=401)

        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text(f"""AccountID 12345
LicenseKey bad_key
EditionIDs GeoLite2-City
Host {httpserver.url_for("/")}
DatabaseDirectory {tmp_path}
""")

        runner = CliRunner()
        result = runner.invoke(main, ["-f", str(config_file)])

        assert result.exit_code == 1
        assert "Authentication error" in result.output

    def test_parallel_auth_error(self, httpserver: HTTPServer, tmp_path: Path) -> None:
        """Parallel errors (ExceptionGroup) should produce clean CLI output."""
        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({"error": "Invalid"}, status=401)

        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text(f"""AccountID 12345
LicenseKey bad_key
EditionIDs GeoLite2-City GeoLite2-Country
Host {httpserver.url_for("/")}
DatabaseDirectory {tmp_path}
Parallelism 2
""")

        runner = CliRunner()
        result = runner.invoke(main, ["-f", str(config_file)])

        assert result.exit_code == 1
        assert "Authentication error" in result.output
        assert "ExceptionGroup" not in result.output
        assert "Traceback" not in result.output

    def test_env_var_config(self, httpserver: HTTPServer, tmp_path: Path) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json(
            {
                "databases": [
                    {
                        "edition_id": "GeoLite2-City",
                        "date": "2024-01-15",
                        "md5": mmdb_hash,
                    }
                ]
            }
        )
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        runner = CliRunner(
            env={
                "GEOIPUPDATE_ACCOUNT_ID": "12345",
                "GEOIPUPDATE_LICENSE_KEY": "test_key",
                "GEOIPUPDATE_EDITION_IDS": "GeoLite2-City",
                "GEOIPUPDATE_HOST": httpserver.url_for("/"),
                "GEOIPUPDATE_DB_DIR": str(tmp_path),
            }
        )
        result = runner.invoke(main, [])

        assert result.exit_code == 0
        assert (tmp_path / "GeoLite2-City.mmdb").exists()

    def test_connection_error_not_labeled_file_operation(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        """ConnectionError should say 'Connection error', not 'File operation error'."""
        config_file = tmp_path / "GeoIP.conf"
        config_file.write_text(f"""AccountID 12345
LicenseKey test_key
EditionIDs GeoLite2-City
Host {httpserver.url_for("/")}
DatabaseDirectory {tmp_path}
""")

        mock_run = AsyncMock(side_effect=ConnectionError("Connection refused"))

        runner = CliRunner()
        with patch("pygeoipupdate.cli._run", mock_run):
            result = runner.invoke(main, ["-f", str(config_file)])

        assert result.exit_code == 1
        assert "Connection error" in result.output
        assert "File operation error" not in result.output
