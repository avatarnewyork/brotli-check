# Brotli Check

A portable PHP Brotli decoder inventory for WordPress, Drupal and Symfony.

Version **0.1.0**, report format 2. Advisory baseline **October 27, 2026**. Custom operator tooling for
CVE-2026-111497; not an official scanner or an exploit test. The shell checker
requires POSIX `sh` and `awk`. It never invokes Python or jq.

## What this can establish

The useful primary measurement is **the decoder used by the relevant PHP
process**, not a filesystem search, CMS version or server response header.
PHP's `curl_version()` calls libcurl's runtime version API; libcurl obtains its
Brotli version from `BrotliDecoderVersion()`. This measures the linked decoder's
reported upstream version. It does not prove application reachability or
identify a vendor backport that retains an older version number.

The checker reports these separately:

- PHP Brotli decoding capability and reported decoder version.
- PHP binary, SAPI and INI, so CLI and web-runtime evidence can be distinguished.
- Decoder paths mapped in that PHP process, when Linux procfs is accessible.
- Local package inventory and, with dpkg, ownership of mapped decoder paths.
- Web-runtime coverage and any remaining review requirement.

No recursive filesystem search, application bootstrap, decompression, package
installation, service restart or remote website request is performed. Filenames
and package inventories are supporting evidence, never substitutes for the
runtime API. Node is optional; its absence says nothing about PHP Brotli support.

## Download

Download the ZIP and its checksum file from [GitHub Releases](https://github.com/avatarnewyork/brotli-check/releases/latest), or inspect [the standalone shell script](https://github.com/avatarnewyork/brotli-check/blob/main/check-brotli.sh). The release ZIP contains source, documentation, tests and file checksums.

## Run on the hosting environment

Download from a trusted source, inspect the saved file, then run it:

```sh
sh check-brotli.sh
sh check-brotli.sh > brotli-report.txt
```

Select the PHP executable corresponding to the site's configured PHP version
when the default CLI executable differs:

```sh
sh check-brotli.sh --php /actual/path/to/php
```

For a running Linux container, stream the saved local file into its shell:

```sh
docker exec -i YOUR_APP_CONTAINER /bin/sh -s < check-brotli.sh
```

Docker access is required on the host; `/bin/sh`, `awk` and PHP must be available
in the target to measure PHP. A separate curl executable cannot clear an
unmeasured PHP runtime. `--with-node` optionally adds the Node check if the site
uses Node services. The script is independent of Apache, Alpine and the CMS.

## Read the result

| Finding | Meaning |
| --- | --- |
| DETECTED | This PHP cURL binding has a Brotli decoder. Does not establish application use. |
| FIXED_VERSION | The measured decoder reports a published fixed upstream version. |
| REVIEW | An affected upstream number, separate extension, replaced library mapping or optional Node release needs investigation. |
| UNKNOWN | The probe failed or cannot classify the evidence. |
| NOT_DETECTED | This specific tool or capability was not detected; not a claim about the host or site. |
| INFO | Runtime context or supporting package/library evidence. |

Exit codes:

- **1 — REVIEW_REQUIRED:** update the affected component or obtain evidence of a
  vendor backport for the actual loaded copy. Other unknowns may also exist.
- **2 — INCOMPLETE / CLI_VERSIONS_FIXED_WEB_UNVERIFIED:** evidence is missing, or
  CLI versions are fixed but the site's web PHP has not been measured.
- **0 — PROBED_WEB_CURL_DECODER_FIXED:** a supplied web-runtime snapshot reports
  a fixed cURL decoder. This is limited to that snapshot, not whole-site clearance.

An installed distro package no longer causes a blanket UNKNOWN result. Its
version also cannot override a conflicting PHP decoder measurement. For example,
PHP using `/usr/local/lib/libbrotlidec.so.1.2.0` remains REVIEW even if an unrelated
`libbrotli1` package under `/usr/lib` has received a security update.

## Verify the actual web PHP

SSH and WP-CLI run CLI PHP. Neither proves what an existing PHP-FPM/Apache/LiteSpeed
worker uses. A portable shell cannot universally inspect another protected
process or invoke a hosting provider's private FPM socket.

The same embedded PHP probe can be supplied to the provider or run through
existing authenticated operator tooling **inside the real web runtime**:

```sh
sh check-brotli.sh --print-php-probe > brotli-runtime-probe.php
```

This writes a PHP source file to the operator's chosen location. It refuses
web execution with HTTP 403 unless trusted server-side tooling has already
set `BROTLI_CHECK_AUTHORIZED` to boolean `true` after authenticating and authorizing
the operator. The constant is not a password or an authentication mechanism.
Do not add an enabled wrapper to a public document root. No web endpoint is
created by the shell checker. Provider tooling should capture the probe's text
output, preserving its `BROTLI_CHECK_` records.

Assess that saved output with:

```sh
sh check-brotli.sh --report saved-web-runtime-output.txt
```

Report mode does not execute PHP, curl, Node or package-manager probes on the
machine reading the report. Confirm the report's trusted origin, site, PHP pool,
time and replica coverage. It does not authenticate a report or verify its
provenance. A CLI report or missing SAPI cannot clear web PHP. Restricted procfs
can prevent path inspection without preventing the cURL version measurement.

## Vendor backports and managed hosts

Fixed upstream C maintenance releases are **1.0.10, 1.1.1 and 1.2.1**. Vendor
patches can keep older upstream numbers. Ubuntu 24.04, for example, identifies
**1.1.0-2ubuntu0.1** as fixed; Debian Bookworm identifies **1.0.9-2+deb12u1**.
The checker deliberately does not auto-clear an older runtime version from a
package name alone. Verify the OS release, package provenance/build, ownership
of the actual mapped library and the vendor's CVE advisory. Custom builds can
require the hosting provider's build-specific confirmation.

For managed hosting, ask the provider to confirm the decoder loaded by the
site's actual web PHP, whether any older custom build contains this CVE's fix,
and that affected copies and workers have been replaced or restarted. A separate
PHP security notice or the PHP version alone does not establish the Brotli fix.

## Application use and remaining scope

WordPress's bundled Requests cURL transport enables automatic decoding of
supported encodings. Drupal's reviewed HTTP client uses Guzzle, whose cURL
handler enables decoding when `decode_content` is enabled. These are meaningful
paths to inspect, especially remote URL fetching and plugin/module integrations.
The reviewed Symfony CurlHttpClient defaults to advertising gzip; the presence
of Symfony alone does not establish Brotli decoding. Custom transports, plugins,
modules and integrations must be assessed in their actual versions/configuration.

This utility does not scan application code or send test requests. A decoder
being available is different from proving an attacker-controlled input reaches
it. Separate PHP Brotli extensions are flagged for vendor verification. Other
PHP builds, FPM pools, workers, containers, replicas, statically embedded copies
and other ecosystems require their own checks. After updates, replace/restart
affected workers and repeat the measurements.

## Development

Run the portable regression suite:

```sh
sh -n check-brotli.sh
sh test_shell.sh
```

See [VALIDATION.md](VALIDATION.md) for observed environments and limitations.
GitHub Actions runs the shell suite on Linux, macOS and Alpine BusyBox.

Maintainers can build the versioned ZIP and checksums using POSIX shell, zip
and either sha256sum or shasum:

```sh
sh scripts/package-release.sh 0.1.0
```

Review reports before sharing; they include software versions and local paths.
The checker inventories version evidence for one CVE and does not certify a
whole site as safe.

## License

[MIT](LICENSE). Copyright 2026 Avatar New York.

## Primary references

- [Brotli advisory and fixed maintenance releases](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
- [libcurl runtime version API](https://curl.se/libcurl/c/curl_version_info.html)
- [libcurl source calling BrotliDecoderVersion](https://github.com/curl/curl/blob/master/lib/version.c)
- [PHP curl_version implementation](https://github.com/php/php-src/blob/PHP-8.4/ext/curl/interface.c)
- [WordPress Requests cURL transport](https://github.com/WordPress/wordpress-develop/blob/trunk/src/wp-includes/Requests/src/Transport/Curl.php)
- [Drupal HTTP client services](https://github.com/drupal/drupal/blob/11.x/core/core.services.yml)
- [Guzzle cURL handler](https://github.com/guzzle/guzzle/blob/7.10/src/Handler/CurlFactory.php)
- [Symfony CurlHttpClient](https://github.com/symfony/symfony/blob/8.0/src/Symfony/Component/HttpClient/CurlHttpClient.php)
- [Ubuntu vendor fixes](https://ubuntu.com/security/CVE-2026-111497)
- [Debian vendor fixes](https://security-tracker.debian.org/tracker/CVE-2026-111497)
- [Nginx Brotli modules compress or serve pre-compressed responses](https://github.com/google/ngx_brotli)
- [Optional Node release baselines](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
