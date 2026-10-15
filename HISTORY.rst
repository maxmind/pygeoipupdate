.. :changelog:

History
-------

0.2.0
++++++++++++++++++

* The client now builds its ``Authorization`` header with
  ``aiohttp.encode_basic_auth()`` instead of the ``aiohttp.BasicAuth`` /
  ``auth=`` parameter, which are deprecated as of aiohttp 3.14.0. As a result,
  the minimum required ``aiohttp`` version is now 3.14.0.
* ``pygeoipupdate`` now identifies the database to download by its build
  epoch rather than its date. Previously, if a new build was published on the
  same day during an update, the download could fail with a checksum mismatch.

0.1.0 (2026-02-10)
++++++++++++++++++

* Initial release
* Python port of the Go geoipupdate tool
* Full compatibility with GeoIP.conf configuration format
* Support for environment variables (GEOIPUPDATE_*)
* Parallel download support
* Async HTTP client using aiohttp
* Retry logic with exponential backoff
* Atomic file writes with MD5 verification
* Cross-platform file locking
* JSON output mode for scripting
* CLI with click
