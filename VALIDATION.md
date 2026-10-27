# Validation observed on October 27, 2026

## Initial public version

| Environment or case | Observed result |
| --- | --- |
| macOS `/bin/sh` and awk | All 44 shell regression cases passed. Real host PHP cURL reported Brotli 1.2.0 and REVIEW. |
| Alpine 3.23 BusyBox `/bin/sh` and awk | All 44 regression cases passed in the existing patched Apache candidate. |
| Debian Bookworm dash and awk | All 44 regression cases passed in the existing Python slim image; the checker/test harness did not invoke Python. |
| Managed-hosting fixture with active `/usr/local/lib/libbrotlidec.so.1.2.0` plus a separately patched distro package | Active PHP cURL remained REVIEW. Exact package evidence did not override the measured decoder. This was a synthetic fixture, not a connection to a hosted site. |
| Known affected Apache image | Actual PHP cURL and curl CLI reported Brotli 1.2.0; REVIEW_REQUIRED, exit 1. |
| Known patched Apache candidate, shell script streamed into container | Actual PHP cURL and curl CLI reported Brotli 1.2.1; CLI_VERSIONS_FIXED_WEB_UNVERIFIED, exit 2. Default output did not probe Node. |
| Actual PHP-FPM 8.5.12 worker, patched image, unprivileged offline container | Authorized test wrapper returned SAPI `fpm-fcgi`, libcurl 8.23.0 and Brotli 1.2.1. Saved report assessed as PROBED_WEB_CURL_DECODER_FIXED, exit 0. The host's different PHP/curl/package observations were not used. |
| Same FPM worker, direct probe without trusted authorization constant | HTTP 403, no runtime records. |
| Actual Linux decoder mapping, patched image with writable disposable root | Probe reported `/usr/lib/libbrotlidec.so.1.2.1` from its own process maps. |
| Read-only disposable root under AMD64 emulation | procfs map read failed with a read-only-filesystem error; decoder API measurement still succeeded and mapping was reported unavailable. No production settings were changed to bypass this. |

The 44 cases include the original version boundaries plus custom/distro library
separation, deleted mappings, saved web snapshots, missing SAPI, extension review,
explicit PHP selection and isolation of imported reports from local package data.
The FPM test used a fixed local FastCGI client and an authorized test wrapper;
neither is a deployed public diagnostic endpoint. The exported PHP probe also
passed PHP syntax validation.

Package backports remain a vendor-verification step; the checker does not
automatically establish package provenance or source patch contents. Real managed-hosting
web-runtime configuration, real distro ownership queries, application-specific
request reachability, Windows/WSL, BSD and managed LiteSpeed/Apache-module PHP
have not been exercised by these tests. No live client site was accessed.
