# Local WAMP test results - 2026-10-23

Environment: Windows, Apache 2.4.58, mod_php 8.4.25, php-cgi 7.4.33.
The proxy_fcgi tests use php-cgi, not real PHP-FPM. Requests went only to
the local project test sites. The owner restarted Apache before the final
ProxyPassMatch run.

## Current guard in .htaccess

| Edition | Site | Result |
|---|---|---|
| multipart-guard | site (mod_php) | 71 passed, 0 failed |
| multipart-guard-doc | site (mod_php) | 71 passed, 0 failed |
| multipart-guard | site-fcgi (mod_fcgid) | 71 passed, 0 failed |
| multipart-guard-doc | site-fcgi (mod_fcgid) | 71 passed, 0 failed |
| multipart-guard | site-fpm (proxy_fcgi, SetHandler) | 71 passed, 0 failed |
| multipart-guard-doc | site-fpm (proxy_fcgi, SetHandler) | 71 passed, 0 failed |

Each suite returned exit code 0. The allowed-URL canary A2 produced its
required multipart warning. The malformed boundary tests A14/A15 were
refused before any script or multipart warning. S3 and O5 confirmed the
POST body limit in BLOCK and OBSERVE respectively.

The initial mod_php run exposed an overly strict test assumption:
an oversized chunked POST returned 413 but still executed article.php
with body_bytes=8323072, below PHP's post_max_size (8388608), and no size
warning. LIMIT was corrected to accept 200 or 413 from the expected script
only with a measured body size within post_max_size and no new warning.
A 413 without a script marker is also accepted. All six suites above
were run after that correction. Eight offline verdict cases checked the
correction, including oversized, missing and unknown body measurements,
wrong scripts, HTTP 500 and connection failure.

## ProxyPassMatch: 66 passed after owner restart

The final site-ppm run returned exit code 0: 66 passed, 0 failed. OBSERVE
tests are skipped because the guard is in server configuration. This makes
492 successful checks across the seven final runs.

Before the owner restarted Apache, the initial site-ppm run returned exit
code 1: 62 passed, 4 failed with the older configuration still loaded:

| Test | Observed result |
|---|---|
| A14, closing quote missing | HTTP 200, upload.php executed |
| A15, opening quote missing | HTTP 200, upload.php executed |
| S1, declared 9 MB urlencoded POST | HTTP 200, article.php executed, PHP warning |
| S2, declared 9 MB JSON POST | HTTP 200, article.php executed, PHP warning |

This matches an older guard still loaded in Apache. The installed local
fpm-test.conf includes the project's apache/guard-site-ppm.conf. That file
is synchronized with the current distributed guard (plus test URLs).
Apache's configuration check returned `Syntax OK` for the configuration
on disk, but this does not reload it. After the owner confirmed a restart
from the WAMP tray, the full site-ppm suite was rerun. A14/A15 and S1/S2
all returned 403, with no script marker and no new PHP parser warning.
The canary A2 still produced its required warning on the allowed URL.

## Other checks

- Bash syntax check passed for tests/run-tests.sh.
- PHP syntax checks passed for all four modified article.php fixtures
  and tests/raw.php.
- The historical mod_rewrite edition was not rerun.
- No production deployment, commit or push was performed.
