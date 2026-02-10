"""Command-line interface for pygeoipupdate."""

from __future__ import annotations

import asyncio
import json
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

logger = logging.getLogger(__name__)


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
    help="Store databases in this directory (uses config if not specified).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
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
def main(  # noqa: C901, PLR0912
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
    config = _setup(config_file, database_directory, verbose, output, parallelism)

    # except* handles both bare exceptions and ExceptionGroup-wrapped
    # exceptions from asyncio.TaskGroup (parallel downloads). We cannot
    # call sys.exit() inside except* handlers because SystemExit would be
    # wrapped in another ExceptionGroup, so we record the exit code and
    # exit after the try block.
    #
    # The type: ignore[assignment] comments work around a mypy bug where
    # reusing the `eg` variable across except* clauses is flagged as an
    # incompatible assignment (same class of bug as mypy#1045, but for
    # except* instead of except).
    exit_code: int = 0
    try:
        asyncio.run(_run(config))
    except* AuthenticationError as eg:
        for exc in eg.exceptions:
            click.echo(f"Authentication error: {exc}", err=True)
        exit_code = 1
    except* LockError as eg:
        for exc in eg.exceptions:  # type: ignore[assignment]
            click.echo(f"Lock error: {exc}", err=True)
        exit_code = 1
    except* DownloadError as eg:
        for exc in eg.exceptions:  # type: ignore[assignment]
            click.echo(f"Download error: {exc}", err=True)
        exit_code = 1
    except* GeoIPUpdateError as eg:
        for exc in eg.exceptions:  # type: ignore[assignment]
            click.echo(f"Error: {exc}", err=True)
        exit_code = 1
    except* ConnectionError as eg:
        for exc in eg.exceptions:  # type: ignore[assignment]
            click.echo(f"Connection error: {exc}", err=True)
        exit_code = 1
    except* OSError as eg:
        for exc in eg.exceptions:  # type: ignore[assignment]
            click.echo(f"File operation error: {exc}", err=True)
        exit_code = 1
    except* KeyboardInterrupt:
        click.echo("\nInterrupted.", err=True)
        exit_code = 130
    except* Exception as eg:
        for exc in eg.exceptions:  # type: ignore[assignment]
            logger.error("Unexpected error", exc_info=exc)  # noqa: TRY400
            click.echo(f"Unexpected error ({type(exc).__name__}): {exc}", err=True)
        exit_code = 1
    if exit_code:
        sys.exit(exit_code)


def _setup(
    config_file: Path | None,
    database_directory: Path | None,
    verbose: bool,
    output: bool,
    parallelism: int,
) -> Config:
    """Validate CLI args, configure logging, and load configuration."""
    if parallelism < 0:
        raise click.UsageError("Parallelism must be a positive number.")

    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
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

    if verbose:
        logger.info("pygeoipupdate version %s", __version__)
        if config_file:
            logger.info("Using config file %s", config_file)
        logger.info("Using database directory %s", config.database_directory)

    return config


async def _run(config: Config) -> None:
    """Run the updater with the given configuration.

    Args:
        config: The configuration to use.

    """
    async with Updater(config) as updater:
        results = await updater.run()

    if config.output:
        output = [r.to_dict() for r in results]
        print(json.dumps(output))  # noqa: T201


if __name__ == "__main__":
    main()
