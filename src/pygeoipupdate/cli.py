"""Command-line interface for pygeoipupdate."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click

from pygeoipupdate import __version__
from pygeoipupdate.config import Config
from pygeoipupdate.errors import (
    AuthenticationError,
    ConfigError,
    DownloadError,
    GeoIPUpdateError,
    LockError,
)
from pygeoipupdate.updater import Updater


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config-file",
    "-f",
    type=click.Path(exists=True, path_type=Path),
    envvar="GEOIPUPDATE_CONF_FILE",
    help="Configuration file.",
)
@click.option(
    "--database-directory",
    "-d",
    type=click.Path(path_type=Path),
    envvar="GEOIPUPDATE_DB_DIR",
    help="Store databases in this directory (uses config if not specified).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    envvar="GEOIPUPDATE_VERBOSE",
    help="Use verbose output.",
)
@click.option(
    "--output",
    "-o",
    is_flag=True,
    help="Output download/update results in JSON format.",
)
@click.option(
    "--parallelism",
    type=int,
    default=0,
    help="Set the number of parallel database downloads.",
)
@click.version_option(__version__, "-V", "--version", prog_name="pygeoipupdate")
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
        pygeoipupdate -f /etc/GeoIP.conf

        # Using environment variables
        export GEOIPUPDATE_ACCOUNT_ID=12345
        export GEOIPUPDATE_LICENSE_KEY=your_key
        export GEOIPUPDATE_EDITION_IDS="GeoLite2-City GeoLite2-Country"
        pygeoipupdate

        # Verbose output with JSON results
        pygeoipupdate -v -o
    """
    if parallelism < 0:
        raise click.UsageError("Parallelism must be a positive number.")

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

    logger = logging.getLogger(__name__)

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

    if verbose:
        logger.info("pygeoipupdate version %s", __version__)
        if config_file:
            logger.info("Using config file %s", config_file)
        logger.info("Using database directory %s", config.database_directory)

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
