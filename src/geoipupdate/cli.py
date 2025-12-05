"""Command-line interface for geoipupdate."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click

from geoipupdate import __version__
from geoipupdate.config import Config
from geoipupdate.errors import (
    AuthenticationError,
    ConfigError,
    DownloadError,
    GeoIPUpdateError,
    LockError,
)
from geoipupdate.updater import Updater


@click.command()
@click.option(
    "--config-file",
    "-f",
    type=click.Path(exists=True, path_type=Path),
    envvar="GEOIPUPDATE_CONF_FILE",
    help="Path to the configuration file.",
)
@click.option(
    "--database-directory",
    "-d",
    type=click.Path(path_type=Path),
    envvar="GEOIPUPDATE_DB_DIR",
    help="Directory to store database files.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    envvar="GEOIPUPDATE_VERBOSE",
    help="Enable verbose output.",
)
@click.option(
    "--output",
    "-o",
    is_flag=True,
    help="Output download results as JSON.",
)
@click.option(
    "--parallelism",
    type=int,
    default=0,
    help="Number of parallel downloads (default: from config or 1).",
)
@click.version_option(version=__version__, prog_name="geoipupdate")
def main(
    config_file: Path | None,
    database_directory: Path | None,
    verbose: bool,
    output: bool,
    parallelism: int,
) -> None:
    """Update MaxMind GeoIP databases.

    Downloads and updates GeoIP2 and GeoLite2 MMDB databases from MaxMind.
    Configuration can be provided via a configuration file, environment
    variables, or command-line options.

    Example usage:

        # Using a configuration file
        geoipupdate -f /etc/GeoIP.conf

        # Using environment variables
        export GEOIPUPDATE_ACCOUNT_ID=12345
        export GEOIPUPDATE_LICENSE_KEY=your_key
        export GEOIPUPDATE_EDITION_IDS="GeoLite2-City GeoLite2-Country"
        geoipupdate

        # Verbose output with JSON results
        geoipupdate -v -o
    """
    # Set up logging
    if verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
        )
    else:
        logging.basicConfig(
            level=logging.WARNING,
            format="%(message)s",
        )

    try:
        config = Config.from_file(
            config_file=config_file,
            database_directory=database_directory,
            parallelism=parallelism if parallelism > 0 else None,
            verbose=verbose,
            output=output,
        )
    except ConfigError as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(1)

    try:
        asyncio.run(_run(config))
    except AuthenticationError as e:
        click.echo(f"Authentication error: {e}", err=True)
        sys.exit(1)
    except LockError as e:
        click.echo(f"Lock error: {e}", err=True)
        sys.exit(1)
    except DownloadError as e:
        click.echo(f"Download error: {e}", err=True)
        sys.exit(1)
    except GeoIPUpdateError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        sys.exit(130)


async def _run(config: Config) -> None:
    """Run the updater with the given configuration.

    Args:
        config: The configuration to use.

    """
    async with Updater(config) as updater:
        await updater.run()


if __name__ == "__main__":
    main()
