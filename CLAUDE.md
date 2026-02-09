# CLAUDE.md

## Commands

```bash
# Run all tests
uv run pytest tests/ -x -q

# Run a single test file
uv run pytest tests/test_client.py -x -q

# Run a single test by name
uv run pytest tests/test_updater.py -x -q -k test_download_new_database

# Lint and format check
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/

# Type check
uv run mypy src tests

# Auto-fix lint errors
uv run ruff check --fix src/ tests/

# Auto-format
uv run ruff format src/ tests/

# Full CI matrix (all Python versions + lint)
uv run tox
```

## Architecture

Python port of the [Go geoipupdate](https://github.com/maxmind/geoipupdate) tool. Downloads MaxMind GeoIP MMDB databases via their REST API.

### Module layout

```
src/pygeoipupdate/
├── cli.py           # Click CLI entry point, except* error handling
├── config.py        # Frozen dataclass, file/env/CLI config cascade
├── client.py        # aiohttp HTTP client, streams downloads to temp files
├── updater.py       # Orchestration: locking, parallelism, retry (tenacity)
├── models.py        # UpdateResult frozen dataclass
├── errors.py        # Exception hierarchy (see below)
├── _file_writer.py  # Atomic writes: extract tar.gz, hash verify, rename
├── _file_lock.py    # filelock wrapper
└── _defaults.py     # Platform-specific default paths
```

### Exception hierarchy

```
GeoIPUpdateError
├── ConfigError
├── DownloadError
│   ├── AuthenticationError
│   └── HTTPError (has .status_code, .body)
├── LockError
└── HashMismatchError (has .expected, .actual)
```

### Key patterns

- **Frozen dataclasses** for Config, UpdateResult, and client response types. Validation in `__post_init__`.
- **Async context managers** for Updater and Client. Updater uses `AsyncExitStack` for safe partial-init cleanup.
- **`except*` (ExceptionGroup)** in CLI to handle errors from `asyncio.TaskGroup` parallel downloads. Cannot call `sys.exit()` inside `except*`, so exit code is recorded and checked after.
- **Streaming downloads**: HTTP response streamed to temp file via `iter_chunked`, then tar.gz extraction streams to another temp file, then atomic rename. Never buffers a full database in memory.
- **Retry**: `tenacity` with exponential backoff in `updater.py`. `_is_retryable_error()` distinguishes transient (5xx, network, hash mismatch) from fatal (401, 4xx). `ConnectionError` is retryable but broader `OSError` is not (avoids futile retries on disk full).
- **Config precedence**: defaults < config file < environment variables < CLI arguments.

### Public API

`__init__.py` exports: `Config`, `Updater`, `UpdateResult`, all error classes, `__version__`. `Client` and `Metadata` are intentionally not public.

### Private modules

Prefixed with `_` (`_file_writer.py`, `_file_lock.py`, `_defaults.py`). Internal implementation details.

## Code conventions

- **Python 3.11 minimum**. Uses `asyncio.TaskGroup`, `except*`, `datetime.UTC`, `typing.Self`.
- **`from __future__ import annotations`** in every file.
- **Ruff with `select = ["ALL"]`** — nearly all rules enabled. See `pyproject.toml [tool.ruff.lint.ignore]` for the specific exclusions.
- **Union syntax**: `X | None` not `Optional[X]`.
- **Tuple for immutable sequences**: `edition_ids: tuple[str, ...]` not `list[str]` in frozen dataclasses.
- **Docstrings**: Google-style with Args/Returns/Raises sections for public API. Tests are exempt from docstring rules.
- **Test classes** group related tests: `class TestClient`, `class TestLocalFileWriter`, etc.
- **Async tests** use `@pytest.mark.asyncio` and `pytest-httpserver` for HTTP mocking.
- **Shared test helpers** in `tests/conftest.py` (`create_test_tar_gz`, `create_test_tar_gz_file`).
- **noqa comments** are used sparingly with specific codes: `# noqa: BLE001`, `# noqa: TRY400`, `# noqa: T201`.

## Commit messages

Imperative mood, focused subject line. Body explains *why*, not *what*.

```
Fix file descriptor leak on write failure

When os.write raises (e.g., disk full), the file descriptor was not
closed before the exception propagated. Use try/finally to ensure
os.close is always called.
```
