"""Tests for the CLI module."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
from pathlib import Path

from click.testing import CliRunner
from pytest_httpserver import HTTPServer

from geoipupdate.cli import main


def create_test_tar_gz(mmdb_content: bytes = b"test mmdb content") -> bytes:
    """Create a test tar.gz archive containing an mmdb file."""
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tar:
        mmdb_info = tarfile.TarInfo(name="GeoLite2-City_20240101/GeoLite2-City.mmdb")
        mmdb_info.size = len(mmdb_content)
        tar.addfile(mmdb_info, io.BytesIO(mmdb_content))

    tar_data = tar_buffer.getvalue()

    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
        gz.write(tar_data)

    return gz_buffer.getvalue()


class TestCLI:
    """Tests for the CLI."""

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])

        assert result.exit_code == 0
        assert "geoipupdate" in result.output
        assert "1.0.0" in result.output

    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "Update MaxMind GeoIP databases" in result.output
        assert "--config-file" in result.output
        assert "--database-directory" in result.output
        assert "--verbose" in result.output
        assert "--output" in result.output

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

    def test_successful_update(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({
            "databases": [{
                "edition_id": "GeoLite2-City",
                "date": "2024-01-15",
                "md5": mmdb_hash,
            }]
        })
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
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({
            "databases": [{
                "edition_id": "GeoLite2-City",
                "date": "2024-01-15",
                "md5": mmdb_hash,
            }]
        })
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
        result = runner.invoke(main, ["-f", str(config_file), "-v"])

        assert result.exit_code == 0

    def test_json_output(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({
            "databases": [{
                "edition_id": "GeoLite2-City",
                "date": "2024-01-15",
                "md5": mmdb_hash,
            }]
        })
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
        assert "edition_id" in result.output
        assert "GeoLite2-City" in result.output

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

    def test_env_var_config(
        self, httpserver: HTTPServer, tmp_path: Path
    ) -> None:
        mmdb_content = b"test mmdb data"
        mmdb_hash = hashlib.md5(mmdb_content).hexdigest()
        tar_gz_data = create_test_tar_gz(mmdb_content)

        httpserver.expect_request(
            "/geoip/updates/metadata",
        ).respond_with_json({
            "databases": [{
                "edition_id": "GeoLite2-City",
                "date": "2024-01-15",
                "md5": mmdb_hash,
            }]
        })
        httpserver.expect_request(
            "/geoip/databases/GeoLite2-City/download",
        ).respond_with_data(tar_gz_data, content_type="application/gzip")

        runner = CliRunner(env={
            "GEOIPUPDATE_ACCOUNT_ID": "12345",
            "GEOIPUPDATE_LICENSE_KEY": "test_key",
            "GEOIPUPDATE_EDITION_IDS": "GeoLite2-City",
            "GEOIPUPDATE_HOST": httpserver.url_for("/"),
            "GEOIPUPDATE_DB_DIR": str(tmp_path),
        })
        result = runner.invoke(main, [])

        assert result.exit_code == 0
        assert (tmp_path / "GeoLite2-City.mmdb").exists()
