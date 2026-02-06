# geoipupdate

Python client for updating MaxMind GeoIP2 and GeoLite2 databases.

## Description

`geoipupdate` is a program that downloads and updates GeoIP2 and GeoLite2
binary MMDB databases from MaxMind. This is a Python port of the
[official Go version](https://github.com/maxmind/geoipupdate).

## Installation

```bash
pip install geoipupdate
```

Or with uv:

```bash
uv add geoipupdate
```

## Quick Start

1. Get your Account ID and License Key from your
   [MaxMind account page](https://www.maxmind.com/en/accounts/current/license-key).

2. Create a configuration file or set environment variables:

   ```bash
   export GEOIPUPDATE_ACCOUNT_ID=12345
   export GEOIPUPDATE_LICENSE_KEY=your_license_key
   export GEOIPUPDATE_EDITION_IDS="GeoLite2-City GeoLite2-Country"
   ```

3. Run geoipupdate:

   ```bash
   geoipupdate
   ```

## Usage

### Command Line

```bash
# Using a config file
geoipupdate -f /etc/GeoIP.conf

# Using environment variables
geoipupdate

# Verbose output
geoipupdate -v

# JSON output (for scripting)
geoipupdate -o

# Parallel downloads
geoipupdate --parallelism 4
```

### Python API

```python
import asyncio
from pathlib import Path

from geoipupdate import Config, Updater

config = Config(
    account_id=12345,
    license_key="your_license_key",
    edition_ids=["GeoLite2-City", "GeoLite2-Country"],
    database_directory=Path("/var/lib/GeoIP"),
)

async def main():
    async with Updater(config) as updater:
        results = await updater.run()
        for result in results:
            if result.was_updated:
                print(f"Updated {result.edition_id}")
            else:
                print(f"{result.edition_id} is up to date")

asyncio.run(main())
```

### Loading Configuration from File

```python
from geoipupdate import Config, Updater

config = Config.from_file(config_file=Path("/etc/GeoIP.conf"))

async with Updater(config) as updater:
    await updater.run()
```

## Configuration

Configuration can be provided via (in order of precedence):
1. CLI arguments
2. Environment variables
3. Configuration file
4. Default values

### Configuration File Format

```
# GeoIP.conf

# Your MaxMind account ID
AccountID 12345

# Your MaxMind license key
LicenseKey your_license_key

# Space-separated list of edition IDs to download
EditionIDs GeoLite2-City GeoLite2-Country GeoLite2-ASN

# Directory to store database files
DatabaseDirectory /var/lib/GeoIP

# Optional: Number of parallel downloads (default: 1)
Parallelism 4

# Optional: Preserve file modification times
PreserveFileTimes 1

# Optional: Retry duration for failed requests (default: 5m)
RetryFor 10m
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GEOIPUPDATE_ACCOUNT_ID` | MaxMind account ID |
| `GEOIPUPDATE_LICENSE_KEY` | MaxMind license key |
| `GEOIPUPDATE_ACCOUNT_ID_FILE` | Path to file containing account ID |
| `GEOIPUPDATE_LICENSE_KEY_FILE` | Path to file containing license key |
| `GEOIPUPDATE_EDITION_IDS` | Space-separated list of edition IDs |
| `GEOIPUPDATE_DB_DIR` | Database directory |
| `GEOIPUPDATE_HOST` | Update server URL |
| `GEOIPUPDATE_PROXY` | Proxy URL (http, https, or socks5) |
| `GEOIPUPDATE_PROXY_USER_PASSWORD` | Proxy credentials (user:password) |
| `GEOIPUPDATE_PRESERVE_FILE_TIMES` | Preserve file times (0 or 1) |
| `GEOIPUPDATE_LOCK_FILE` | Lock file path |
| `GEOIPUPDATE_RETRY_FOR` | Retry duration (e.g., "5m", "1h") |
| `GEOIPUPDATE_PARALLELISM` | Number of parallel downloads |
| `GEOIPUPDATE_VERBOSE` | Enable verbose output (0 or 1) |

### CLI Options

```
geoipupdate [OPTIONS]

Options:
  -f, --config-file PATH    Path to the configuration file
  -d, --database-directory PATH
                            Directory to store database files
  -v, --verbose             Enable verbose output
  -o, --output              Output download results as JSON
  --parallelism INTEGER     Number of parallel downloads
  -V, --version             Show the version and exit
  -h, --help                Show this message and exit
```

## Default Paths

### Unix/Linux/macOS
- Configuration file: `/usr/local/etc/GeoIP.conf`
- Database directory: `/usr/local/share/GeoIP`

### Windows
- Configuration file: `%SYSTEMDRIVE%\ProgramData\MaxMind\GeoIPUpdate\GeoIP.conf`
- Database directory: `%SYSTEMDRIVE%\ProgramData\MaxMind\GeoIPUpdate\GeoIP`

## Running as a Cron Job

To keep your databases up to date, we recommend running geoipupdate at least
twice per week. Here's an example cron entry:

```cron
# Run twice a week on Wednesday and Sunday at 3:00 AM
0 3 * * 0,3 /usr/local/bin/geoipupdate
```

## Requirements

- Python 3.10+
- A MaxMind account with a license key

## License

Apache-2.0

## Links

- [MaxMind Developer Portal](https://dev.maxmind.com/)
- [GeoIP2 Database Documentation](https://dev.maxmind.com/geoip/docs/databases)
- [Go version (geoipupdate)](https://github.com/maxmind/geoipupdate)
