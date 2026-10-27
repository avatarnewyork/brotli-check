#!/bin/sh
# Self-contained regression fixtures. No Python, Docker or network required.
set -eu
kit=$(CDPATH= cd "$(dirname "$0")" && pwd)
checker=$kit/check-brotli.sh
check_shell=${CHECK_SHELL:-/bin/sh}
fixture=$(mktemp -d "${TMPDIR:-/tmp}/brotli-shell-test.XXXXXX")
trap 'rm -rf "$fixture"' 0
trap 'exit 2' HUP INT TERM
mkdir "$fixture/bin"
ln -s "$(command -v awk)" "$fixture/bin/awk"
count=0

mock() {
    printf '#!/bin/sh\n%s\n' "$2" > "$fixture/bin/$1"
    chmod +x "$fixture/bin/$1"
}
reset() {
    rm -f "$fixture/bin/php" "$fixture/bin/node" "$fixture/bin/curl" \
        "$fixture/bin/apk" "$fixture/bin/dpkg-query" "$fixture/bin/rpm" "$fixture/bin/brew"
    # Fail visibly if the checker ever attempts to use Python.
    mock python3 'printf "Python unexpectedly invoked" >&2; exit 99'
    mock python 'printf "Python unexpectedly invoked" >&2; exit 99'
    FIXTURE_PHP=''
    FIXTURE_NODE=''
    FIXTURE_CURL=''
    FIXTURE_RC=0
    export FIXTURE_PHP FIXTURE_NODE FIXTURE_CURL FIXTURE_RC
}
php_mock() { mock php 'printf "%s\n" "$FIXTURE_PHP"; exit "$FIXTURE_RC"'; }
node_mock() { mock node 'printf "%s\n" "$FIXTURE_NODE"; exit "$FIXTURE_RC"'; }
curl_mock() { mock curl 'printf "%s\n" "$FIXTURE_CURL"; exit "$FIXTURE_RC"'; }
check() {
    expected_rc=$1
    expected_text=$2
    label=$3
    shift 3
    actual_rc=0
    PATH="$fixture/bin" "$check_shell" "$checker" --with-node "$@" > "$fixture/report" 2> "$fixture/stderr" || actual_rc=$?
    if [ "$actual_rc" -ne "$expected_rc" ] || ! grep -F "$expected_text" "$fixture/report" >/dev/null || [ -s "$fixture/stderr" ]; then
        printf 'FAIL: %s (expected exit %s, got %s)\n' "$label" "$expected_rc" "$actual_rc" >&2
        cat "$fixture/report" "$fixture/stderr" >&2
        exit 1
    fi
    count=$((count + 1))
    printf 'PASS: %s\n' "$label"
}

reset
check 2 'RESULT: INCOMPLETE' 'missing tools do not produce a clean bill of health'

reset; php_mock
for version in 1.0.10 1.1.1 1.2.1 1.2.2 1.2.1-r0; do
    FIXTURE_PHP="BROTLI_CHECK_PHP|8.5.12|brotli/$version|yes|no"
    check 2 'FIXED_VERSION | PHP CLI' "fixed CLI maintenance release $version does not clear web PHP"
done
for version in 1.0.3 1.0.9 1.1.0 1.2.0; do
    FIXTURE_PHP="BROTLI_CHECK_PHP|8.5.12|$version|yes|no"
    check 1 'REVIEW | PHP CLI' "affected C version $version despite modern PHP"
done
for version in 1.0.2 1.2.1-rc1 1.2.1-pre 1.2.1-nightly 1.2.1garbage 1.2.1.1 broken; do
    FIXTURE_PHP="BROTLI_CHECK_PHP|8.5.12|$version|yes|no"
    check 2 'UNKNOWN | PHP CLI' "unclassified version $version"
done
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|yes'
check 1 'REVIEW | PHP Brotli extension' 'separate PHP extension cannot be cleared by cURL'
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12||no|no'
check 2 'NOT_DETECTED | PHP CLI' 'no cURL Brotli feature is scoped to CLI'
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12||unknown|no'
check 2 'UNKNOWN | PHP CLI' 'old PHP introspection does not imply absence'
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no'
FIXTURE_RC=1
check 2 'UNKNOWN | PHP CLI | probe failed' 'failed command cannot emit a passing result'
FIXTURE_RC=0
FIXTURE_PHP='private startup log
BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no'
check 2 'FIXED_VERSION | PHP CLI' 'startup output is filtered'
if grep -F 'private startup log' "$fixture/report" >/dev/null; then exit 1; fi
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no
BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no'
check 2 'UNKNOWN | PHP CLI' 'ambiguous probe output rejected'

reset; node_mock
for version in 22.23.4 24.22.1 26.12.1; do
    FIXTURE_NODE="BROTLI_CHECK_NODE|$version|1.2.1"
    check 2 'RESULT: INCOMPLETE' "fixed Node release $version cannot clear unmeasured PHP"
done
for version in 22.23.3 24.22.0 26.12.0 20.19.2; do
    FIXTURE_NODE="BROTLI_CHECK_NODE|$version|1.2.1"
    check 1 'REVIEW | Node.js release' "older/vendor Node release $version needs confirmation"
done
FIXTURE_NODE='BROTLI_CHECK_NODE|24.22.1|1.2.0'
check 1 'REVIEW | Node.js 24.22.1' 'Node release number cannot override affected decoder'
FIXTURE_NODE='BROTLI_CHECK_NODE|24.22.1|'
check 2 'decoder version unavailable' 'missing Node decoder version'

reset; curl_mock
FIXTURE_CURL='curl 8.23.0 libcurl/8.23.0 brotli/1.2.1
Features: brotli SSL'
check 2 'FIXED_VERSION | curl CLI' 'fixed curl executable cannot clear unmeasured PHP'
FIXTURE_CURL='curl 8.23.0 libcurl/8.23.0
Features: brotli SSL'
check 2 'UNKNOWN | curl CLI' 'curl Brotli capability without version'
FIXTURE_CURL='curl 8.23.0 libcurl/8.23.0
Features: SSL'
check 2 'NOT_DETECTED | curl CLI' 'curl does not report Brotli'

reset; php_mock
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no'
mock dpkg-query 'printf "libbrotli1:arm64|1.0.9-2+deb12u1|installed\nlibbrotli-dev|1.0.9-2|config-files\n"'
check 2 'libbrotli1:arm64 1.0.9-2+deb12u1' 'exact installed vendor revision retained as evidence'
if grep -F 'libbrotli-dev' "$fixture/report" >/dev/null; then exit 1; fi

# Exercise a newer custom active copy alongside
# an older distro package. Disk metadata must not override the runtime API.
FIXTURE_PHP='BROTLI_CHECK_PHP|8.4.27|1.2.0|yes|no
BROTLI_CHECK_CONTEXT|/usr/bin/php8.4|cli|/etc/php/8.4/cli/php.ini
BROTLI_CHECK_LIBRARY|/usr/local/lib/libbrotlidec.so.1.2.0'
mock dpkg-query 'case "$1" in -S) exit 1 ;; *) printf "libbrotli1:amd64|1.1.0-2ubuntu0.1|installed\n" ;; esac'
check 1 'is not owned according to dpkg' 'a patched unrelated distro package cannot clear a custom active decoder'
if ! grep -F 'REVIEW | PHP CLI 8.4.27 cURL | Brotli 1.2.0' "$fixture/report" >/dev/null; then exit 1; fi
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no
BROTLI_CHECK_CONTEXT|/usr/local/bin/php|cli|/usr/local/etc/php/php.ini
BROTLI_CHECK_LIBRARY|/usr/local/lib/libbrotlidec.so.1.2.0 (deleted)'
check 1 'deleted/replaced library remains mapped' 'deleted worker mapping needs restart even with a fixed version string'

reset
printf '%s\n' 'BROTLI_CHECK_FORMAT|2' \
    'BROTLI_CHECK_PHP|8.4.27|1.2.1|yes|no' \
    'BROTLI_CHECK_CONTEXT|/usr/sbin/php-fpm8.4|fpm-fcgi|/etc/php/8.4/fpm/php.ini' \
    'BROTLI_CHECK_LIBRARY|/usr/local/lib/libbrotlidec.so.1.2.1' > "$fixture/web-report"
mock curl 'printf "curl 8.23.0 brotli/1.2.0\n"'
mock dpkg-query 'printf "wrong-host-package-must-not-appear\n"'
check 0 'RESULT: PROBED_WEB_CURL_DECODER_FIXED' 'web report assessed without borrowing local curl or package data' --report "$fixture/web-report"
if grep -F 'wrong-host-package' "$fixture/report" >/dev/null; then exit 1; fi

printf '%s\n' 'BROTLI_CHECK_FORMAT|2' \
    'BROTLI_CHECK_PHP|8.4.27|1.2.0|yes|no' \
    'BROTLI_CHECK_CONTEXT|/usr/sbin/php-fpm8.4|fpm-fcgi|/etc/php/8.4/fpm/php.ini' > "$fixture/web-report"
check 1 'REVIEW | PHP web runtime 8.4.27 cURL' 'web runtime with affected decoder requires update or vendor evidence' --report "$fixture/web-report"

printf '%s\n' 'BROTLI_CHECK_FORMAT|2' \
    'BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no' > "$fixture/web-report"
check 2 'WEB_RUNTIME: UNVERIFIED' 'missing context cannot turn a file into web-runtime proof' --report "$fixture/web-report"

printf '%s\n' 'BROTLI_CHECK_FORMAT|2' \
    'BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|yes' \
    'BROTLI_CHECK_CONTEXT|/usr/sbin/php-fpm|fpm-fcgi|php.ini' > "$fixture/web-report"
check 1 'PHP Brotli extension' 'fixed web cURL does not clear a separate Brotli extension' --report "$fixture/web-report"

printf '%s\n' 'not a runtime report' > "$fixture/web-report"
check 2 'probe failed' 'unrecognized report rejected' --report "$fixture/web-report"

reset; php_mock
FIXTURE_PHP='BROTLI_CHECK_PHP|8.5.12|1.2.1|yes|no'
check 2 'CLI_VERSIONS_FIXED_WEB_UNVERIFIED' 'explicit alternate PHP executable supported' --php "$fixture/bin/php"

printf '%s shell regression cases passed under %s.\n' "$count" "$check_shell"
