# Multipart Guard

*[Version française](readme-fr.md)*

> **Experimental working document, shared as is.** No support, no maintenance, no
> warranty: issues and requests will not be answered. This is **not** a
> security fix. Read it, test it on your own servers before use, and update
> PHP. Results apply only to the documented test environments and are not
> a guarantee of protection. Licence: [0BSD](LICENSE).

Created with GPT sol 6.1 medium && Claude Opus 5.5 medium.

A small Apache 2.4 rule set that **blocks file uploads on every URL of a site,
except the URLs you allow**. Blocked requests never reach PHP.

Why: in October 2026, two critical PHP bugs (CVE-2026-109618 and
CVE-2026-109619, "PHP2Shell") were found. One of the main attack paths uses
the way PHP reads uploads (`multipart/form-data`). PHP reads them **before**
your application code runs, so the application cannot protect itself. Most
URLs of a site never need to receive an upload, so Apache can refuse them.

> **This is not a fix.** Only updating PHP fixes the bugs. Multipart Guard
> removes one attack path on most URLs and makes the allowed upload URLs
> harder to abuse. See [Limits](#limits).

- No extra module, no proxy, no change to your PHP code.
- Works with mod_php, FastCGI (mod_fcgid) and PHP-FPM.
- One file to copy: [`guard/multipart-guard.htaccess`](guard/multipart-guard.htaccess)
  (short, ready to paste). Every line is explained in
  [`guard/multipart-guard-doc.htaccess`](guard/multipart-guard-doc.htaccess)
  (same rules).

---

## Quick start

1. **Check how PHP is connected to Apache** (see [Where to install](#where-to-install)).
   If you use PHP-FPM with `ProxyPassMatch`, `.htaccess` will **not** work:
   install in the VirtualHost instead.
2. Copy the whole content of `guard/multipart-guard.htaccess` to the **top** of the
   site's main `.htaccess`.
3. In the **SETTINGS** section:
   - turn on OBSERVE mode (remove the `#` in front of the `MPG_OBSERVE` line);
   - set the maximum upload size;
   - list the URLs that really receive uploads.
4. Install the log ([Log](#log)) and use the site normally for a few days.
5. Read the log, fix the list of allowed URLs, then switch back to BLOCK mode
   (put the `#` back).

`.htaccess` changes apply immediately, no restart needed.

---

## Settings

All settings are at the top of `guard/multipart-guard.htaccess`. Do not edit the
ENGINE section.

### 1. Mode

| Mode | What happens |
|---|---|
| **BLOCK** (default) | Forbidden uploads get `403 Forbidden`. |
| **OBSERVE** | Decisions are only logged. `LimitRequestBody` stays active. |

```apache
#SetEnvIf Request_URI ^ MPG_OBSERVE=1     <- BLOCK   (line commented)
SetEnvIf Request_URI ^ MPG_OBSERVE=1      <- OBSERVE (line active)
```

**OBSERVE is not a complete bypass.** It skips the authorization refusal,
but Apache still limits POST bodies with `LimitRequestBody`. Large bodies
can still get 413 or reach FastCGI truncated. The site's own access rules
also remain active.

### 2. Maximum POST size

In bytes, digits only. In BLOCK mode, a POST with a declared size above
this limit is refused before PHP runs: uploads (even on allowed URLs),
normal forms, JSON, etc. POST bodies without a declared size are limited
as they are read; FastCGI may receive a truncated body.
PUT and PATCH are not affected.

Two lines, **same number on both**:

```apache
SetEnvIf Request_URI ^ MPG_MAX_BYTES=8323072
<If "%{REQUEST_METHOD} == 'POST'">
    LimitRequestBody 8323072
</If>
```

- Line 1 checks the declared size (`Content-Length`): refused with 403/413,
  PHP is never called.
- Line 2 limits bodies sent without a declared size ("chunked"): 413 with
  mod_php, or a truncated body passed to PHP with the tested FastCGI setups.

**Use PHP's `post_max_size` minus 64 KB.** When a POST body is bigger than
`post_max_size`, PHP writes a warning (`POST Content-Length of … bytes
exceeds the limit`) *before* the script runs. Early warnings like this are
part of the CVE-2026-109619 attack path. With this setting, Apache refuses
these requests first and the warning never happens (tested on mod_php,
mod_fcgid and proxy_fcgi). The 64 KB margin is needed for chunked bodies:
Apache stops them a few KB after the limit (up to 8 KB measured with
mod_fcgid).

| `post_max_size` | Value for both lines |
|---|---|
| `2M` | `2031616` |
| `8M` (PHP default) | `8323072` |
| `10M` | `10420224` |
| `20M` | `20905984` |
| `50M` | `52363264` |
| `100M` | `104792064` |

Formula: `M × 1048576 − 65536`. If several PHP versions or pools serve the
site, use the smallest value.

If line 1 is wrong (for example `10M`) or missing, **all uploads are
refused** (the guard fails closed), but normal forms keep working: a typo
cannot take the whole site down.

### 3. Allowed upload URLs

One line per URL. Change only the text between the single quotes. The file
ships with examples only, commented out: **with no allowed URL, every upload
is blocked**.

```apache
SetEnvIfExpr "%{REQUEST_URI} == '/upload.php'"  MPG_ALLOWED=1
```

Do not put a comment at the end of a line: Apache would read it as part of
the directive. Put comments on their own line.

**WordPress.** The upload URLs below were checked in the WordPress 7.1
source code and tested with the guard. They are in both guard files,
commented out: remove the `#` on the lines you need.

| Upload | URL (WordPress at the domain root) | Needed |
|---|---|---|
| Media Library | `/wp-admin/async-upload.php` | almost always |
| Block editor | `/wp-json/wp/v2/media` | almost always |
| Block editor, extra image sizes | `^/wp-json/wp/v2/media/[0-9]+/sideload$` (pattern) | almost always |
| Saving menus (classic themes) | `/wp-admin/nav-menus.php` | classic themes |
| Plugin or theme ZIP upload | `/wp-admin/update.php` | if used |
| Media > Add New, browser uploader | `/wp-admin/media-new.php` | if used |
| Old media pop-up | `/wp-admin/media-upload.php` | if used |
| Custom header / background | `/wp-admin/themes.php` | classic themes |
| Tools > Import | `/wp-admin/admin.php` (broad: every plugin page) | only while importing |
| Multisite, add a site | `/wp-admin/network/site-new.php` | multisite |

- **"Plain" permalinks:** the REST API goes to
  `/index.php?rest_route=/wp/v2/media`. The documented file has a ready line
  for that case (path `/index.php` + strict check of the query string).
- **WordPress in a sub-folder:** add the folder in front of every path.
- **Plugins with front-end upload forms** (contact forms, etc.) use their own
  URLs, for example `/wp-json/contact-form-7/v1/contact-forms/<id>/feedback`
  or `/wp-admin/admin-ajax.php`. Find them with OBSERVE mode.
- Allowing a `wp-admin` URL does **not** require a login to reach PHP's
  upload parser: PHP parses the upload before WordPress checks the login.
  Protect `/wp-admin/` by IP address or password if you can.

**How to write a URL**

| Rule | Example |
|---|---|
| Path only, starting with `/`. No domain, no `?query`. | `https://example.org/blog/upload.php?id=3` → `'/blog/upload.php'` |
| Exact match. No wildcards. | `'/upload.php'` does not allow `'/upload.php/x'` |
| Upper/lower case matters. | `'/Upload.php'` ≠ `'/upload.php'` |
| A final `/` matters. | `'/api/upload'` ≠ `'/api/upload/'` |
| Include the sub-folder if the site is in one. | `'/blog/wp-admin/async-upload.php'` |
| Use the URL the **browser** sends, even if the site rewrites it to `index.php`. | `'/wp-json/wp/v2/media'` |

To find the right URL: open the browser's developer tools (F12 → Network),
upload a file, and look at the request path. Or use OBSERVE mode and read the
log.

**Good habits**

- Allow as few URLs as possible.
- Only allow a URL if you know it is a real upload form. **Never allow a URL
  just because it appears in the log**: anyone can send requests that put it
  there.
- A missing URL only breaks that one upload form. It never weakens the
  protection.

**Advanced: patterns.** For URLs with a variable part, a regular expression
can be used. Always start with `^` and end with `$`:

```apache
SetEnvIfExpr "%{REQUEST_URI} =~ m#^/api/items/[0-9]+/upload$#"  MPG_ALLOWED=1
```

---

## Where to install

It depends on how PHP is connected to Apache:

| PHP connection | In `.htaccess` | In the VirtualHost `<Location "/">` |
|---|---|---|
| mod_php | ✅ | ✅ |
| mod_fcgid (`FcgidWrapper`) | ✅ | ✅ |
| PHP-FPM with `SetHandler "proxy:fcgi://..."` | ✅ | ✅ |
| PHP-FPM with **`ProxyPassMatch`** | ❌ **ignored** | ✅ |

With `ProxyPassMatch`, Apache sends the request to PHP-FPM before it looks at
the site's folders, so **`.htaccess` files are never read**. Tested: the
upload reaches PHP, even for a script that does not exist.

To check a Linux server (read-only command):

```sh
grep -rn "ProxyPassMatch\|SetHandler.*proxy:" /etc/apache2/sites-enabled/
```

**Recommended: install in the VirtualHost.** It works in every case and is
safe from changes to `.htaccess` files.

### In a VirtualHost

Save `guard/multipart-guard.htaccess` (with your settings) as, for example,
`/etc/apache2/multipart-guard/example.org.conf`, then add to **each**
VirtualHost of the site (both `:80` and `:443`):

```apache
<VirtualHost *:443>
    ServerName example.org
    ...
    <Location "/">
        Include /etc/apache2/multipart-guard/example.org.conf
    </Location>
</VirtualHost>
```

Then check and reload:

```sh
apachectl configtest && systemctl reload apache2
```

Inside `<Location>`, the rules behave exactly as in `.htaccess` (tested).
Changing the mode or the URL list needs a reload.

### In .htaccess

Use this only if you cannot edit the VirtualHost, and only if PHP is not
connected with `ProxyPassMatch`. Needs `AllowOverride` with at least
`FileInfo` and `AuthConfig` (or `All`).

A sub-folder `.htaccess` cannot switch the guard off by accident (tested with
`RewriteEngine On`, `RewriteEngine Off` and `ErrorDocument`). But anyone who
can **write** a `.htaccess` can remove it.

---

## Log

[`apache/multipart-guard-log.conf`](apache/multipart-guard-log.conf) writes
one line per upload request, for all sites. It must go in the **server**
configuration (not in `.htaccess`):

- **Debian/Ubuntu:** copy it to `/etc/apache2/conf-available/`, then
  `a2enconf multipart-guard-log && systemctl reload apache2`.
  Change the log path in the file to `${APACHE_LOG_DIR}/multipart-guard.log`.
- **WAMP:** copy it to `c:/wamp64/alias/` and restart Apache.

Example:

```text
2026-10-22T15:24:58+0200 MULTIPART_GUARD action=deny_not_allowed observe=- status=403 ip=203.0.113.7 peer=203.0.113.7 host=example.org method=POST uri="/article.php" ctype="multipart/form-data; boundary=XyZ" cl=2133 te=-
```

- One line per event, `key=value` format: easy to `grep` and to use with
  Fail2ban later.
- Request bodies, query strings and cookies are never logged.
- In OBSERVE mode, `observe=1` and `status` is usually `200`: the line shows
  what *would* have been blocked.
- **Behind a reverse proxy** (CDN, load balancer), `ip` is the real client
  only if `mod_remoteip` is configured with `RemoteIPHeader` and
  `RemoteIPTrustedProxy`. `peer` is always the address of the TCP
  connection.

Each block also writes `AH01630: client denied by server configuration` in
Apache's error log.

---

## How it decides

For each request whose `Content-Type` contains `multipart` (any case), the
first matching rule wins:

| Order | Check | Log `action` |
|---|---|---|
| 1 | URL is not in the allowed list | `deny_not_allowed` |
| 2 | Method is not POST | `deny_method` |
| 3 | `Content-Type` is not exactly `multipart/form-data; boundary=...` | `deny_bad_ctype` |
| 4 | No `Content-Length` header (chunked body) | `deny_no_length` |
| 5 | `Content-Length` is above the size limit | `deny_too_large` |
| – | All checks passed | `allow` |

Any other POST (form, JSON…) whose `Content-Length` is above the size limit
is also refused, with `action=deny_too_large`.

Why these checks:

- **Wide detection.** PHP also treats `multipart/form-data,x` and
  `multipart/form-data x` as uploads (tested). A strict pattern such as
  `^multipart/form-data(;|$)` would miss them. So anything containing
  `multipart` is caught.
- **Strict format on allowed URLs.** Browsers always send one clean header.
  Anything else (duplicate header, extra parameter) is suspicious. For
  example, PHP finds the boundary by searching the text, so
  `xboundary=AAA; boundary=XyZ` makes PHP use `AAA`.
- **Content-Length required, with a limit.** CVE-2026-109618 can use upload
  bodies sent without a declared length. Apache never passes more than
  `Content-Length` bytes to PHP, so the limit is real.
- **Original request only.** A pretty URL that the site rewrites to
  `index.php` stays allowed. A forbidden URL is refused before any rewrite.
- **Refused requests stay refused**, even if an `ErrorDocument` points to a
  PHP script.

The block happens in Apache's authorization step, **before PHP is called**.

---

## Troubleshooting

**An upload form now gets 403.** Look at the log line for that request:

| `action` | Meaning | What to do |
|---|---|---|
| `deny_not_allowed` | URL not in the list | Check the exact path (case, final `/`, sub-folder) and add it. |
| `deny_method` | Not a POST | Usually an API client. Check it is legitimate. |
| `deny_bad_ctype` | Unusual `Content-Type` | Some non-browser clients add parameters. Check the `ctype` field. |
| `deny_no_length` | Body sent "chunked" | Some mobile apps or scripts do this. Browsers never do. |
| `deny_too_large` | File too big | Raise `MPG_MAX_BYTES` if needed. |

**Nothing is logged.** The log file is server configuration: check that it is
installed and Apache was restarted. With `.htaccess`, also check that the
guard is at the top and that the site does not use `ProxyPassMatch`.

---

## Uninstall

- `.htaccess`: delete the block. Takes effect immediately.
- VirtualHost: remove the `Include` lines, then
  `apachectl configtest && systemctl reload apache2`.
- Log: delete the file (or `a2disconf multipart-guard-log`) and reload Apache.

---

## Limits

- **Allowed URLs are still exposed.** An attacker can send a malicious upload
  to an allowed URL. The guard only limits its size and format. A small
  request can still use a lot of memory inside PHP.
- **CVE-2026-109619 is mostly not covered.** Its main paths (fatal errors
  during script execution, early PHP configuration warnings) do not need
  uploads.
- **Other attacks are not covered**: anything that does not use uploads.
- **Possible false positives** on allowed URLs: clients that send chunked
  uploads, extra `Content-Type` parameters, or another method than POST.
  Use OBSERVE mode first.
- Tested on Windows (WAMP). The "PHP-FPM" tests use `php-cgi` as a separate
  FastCGI server, not real PHP-FPM. Since the filtering happens in Apache,
  results should be the same, but a check on Linux with PHP-FPM is
  recommended.

**Also do:** update PHP, set `session.upload_progress.enabled = Off`, and
follow the official PHP advisories.

---

## Tests

### How we prove PHP received nothing

The test body [`tests/canary.bin`](tests/canary.bin) contains 21 files, while
PHP allows 20 (`max_file_uploads = 20`). If PHP's upload parser sees the
request, PHP writes a warning to `php_error.log` **while parsing, before any
script runs**. A block only counts as successful if:

1. the status is 403 (or 413 for a body that is too big);
2. no PHP script ran;
3. no new warning appeared.

The size tests use the same idea: PHP warns *before* the script runs when a
POST body is bigger than `post_max_size` (8M on WAMP). No warning means PHP
never saw a body that was too big.

The control test A2 (allowed URL) requires both execution of the expected
script and a new multipart warning. A missing or unreadable PHP log aborts
the suite. For a large chunked POST, the test requires either 413 without
a PHP marker, or 200/413 from the expected script with a measured body size
no greater than the test bench's `post_max_size` (8M). A connection failure
cannot pass that check.

### Run

The test bench is written for **WAMP on Windows** (Git Bash): the project
must be in `c:/wamp64/www/multipart2hell/`, and the script uses WAMP's PHP
and log paths (variables at the top of `tests/run-tests.sh`). The guard
itself has no such dependency.

```sh
bash tests/run-tests.sh multipart-guard site          # mod_php
bash tests/run-tests.sh multipart-guard site-fcgi     # FastCGI (mod_fcgid + php-cgi 7.4)
bash tests/run-tests.sh multipart-guard site-fpm      # PHP-FPM style, SetHandler
bash tests/run-tests.sh multipart-guard site-ppm      # PHP-FPM style, ProxyPassMatch
bash tests/run-tests.sh rewrite site       # mod_rewrite edition, for comparison
```

The script writes the test site's `.htaccess` (guard + PHP handler + app
rules) and leaves it in place. `site-fpm` and `site-ppm` need
`apache/fpm-test.conf` in `c:/wamp64/alias/` (then restart Apache) and a
separate FastCGI server:

```sh
cd /c/wamp64/bin/php/php7.4.33 && PHP_FCGI_MAX_REQUESTS=0 ./php-cgi.exe -b 127.0.0.1:9074
```

### What is tested

- **Normal traffic is unchanged:** GET, form posts, JSON, plain text, PUT,
  chunked bodies.
- **Uploads to forbidden URLs, in every form:** odd case, `,x`, spaces, folded
  headers, duplicate headers, chunked, PUT/PATCH, `multipart/mixed`, rewritten
  URLs, sub-folders, `ErrorDocument`.
- **Path tricks around allowed URLs:** `PATH_INFO`, case, `//`, `/./`, `%2e`,
  `../`, MultiViews, `::$DATA`, final dot, null byte, absolute URL.
- **Allowed URLs:** only the browser format passes.
- **POST size:** 9 MB forms and JSON refused, chunked 9 MB body never seen
  whole by PHP, 8 MB bodies and big PUT requests unchanged.
- **OBSERVE mode**, including the POST body limit that remains active.
- **Unpaired boundary quotes** are refused on allowed URLs.

### Results (WAMP, Apache 2.4.58, Windows)

Local tests on 2026-10-23, after the paired-boundary-quote fix and the
stricter test checks. Both distributed editions were tested separately.

| Edition | mod_php 8.4.25 | mod_fcgid 7.4.33 | FPM style, `SetHandler` | FPM style, `ProxyPassMatch` |
|---|---|---|---|---|
| `expr` in `.htaccess` (both editions) | **71/71 each** | **71/71 each** | **71/71 each** | ❌ ignored |
| `expr` in `<Location>` | – | – | – | **66/66** (OBSERVE not tested) |
| `rewrite` in `.htaccess` | 61/62 (earlier version without the POST size tests) | 61/62 | 61/62 | ❌ ignored |

The `rewrite` results are historical and were not rerun for this revision.
The `rewrite` edition fails test M19: a sub-folder with `RewriteEngine Off`
switches it off. This is why the recommended edition does not use
mod_rewrite. It also has no POST size check.

With chunked bodies over the limit, mod_php answers 413 and may still run
the script with a truncated body. mod_fcgid and proxy_fcgi answer 200 with
a truncated body. The tests check the measured size when a script runs,
as well as the absence of a PHP size warning.

The first `ProxyPassMatch` run used an older configuration still loaded in
Apache. After the owner restarted Apache, all 66 tests passed with the
current include, including unpaired quotes and large declared POST bodies.
OBSERVE was not tested for this setup because switching modes needs a reload.
See the [test report](tests/wamp-results-2026-10-23.md).

---

## Project files

| File | Purpose |
|---|---|
| [`guard/multipart-guard.htaccess`](guard/multipart-guard.htaccess) | **The guard**, ready to copy-paste |
| [`guard/multipart-guard-doc.htaccess`](guard/multipart-guard-doc.htaccess) | Same rules, with every explanation |
| [`guard/rewrite.htaccess`](guard/rewrite.htaccess) | mod_rewrite edition, for comparison only |
| [`apache/multipart-guard-log.conf`](apache/multipart-guard-log.conf) | Dedicated log (server configuration) |
| [`apache/fpm-test.conf`](apache/fpm-test.conf) | Test bench for PHP-FPM style setups |
| `site/` | Test site, PHP by mod_php |
| `site-fcgi/` | Same site, PHP by mod_fcgid + php-cgi 7.4 |
| `site-fpm/` | Same site, PHP by mod_proxy_fcgi + `SetHandler` |
| `site-ppm/` | Same site, PHP by mod_proxy_fcgi + `ProxyPassMatch` (guard in `<Location>`) |
| `control/` | Unprotected folder, used to see what PHP itself accepts |
| [`tests/run-tests.sh`](tests/run-tests.sh) | Automated tests (curl + raw client) |
| [`tests/raw.php`](tests/raw.php) | Raw HTTP client (duplicate headers, folded headers, etc.) |
