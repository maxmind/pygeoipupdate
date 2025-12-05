.. :changelog:

History
-------

1.0.0 (2024-12-05)
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
