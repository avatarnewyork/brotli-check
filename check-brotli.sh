#!/bin/sh
# Brotli Check 0.1.0. Offline version inventory for CVE-2026-111497. Baseline: 2026-10-27.
# POSIX sh + awk. No Python, jq, root access, network or exploit required.
# Exit 0: probed web cURL decoder fixed; 1: review; 2: incomplete/web unverified.
# PHP-focused inventory for WordPress, Drupal and Symfony. Not an exploit test.

LC_ALL=C
export LC_ALL

php_bin=php
report_file=''
with_node=no
print_probe=no
while [ "$#" -gt 0 ]; do
    case $1 in
        --php|--report)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                printf '%s\n' 'Missing option value.' >&2; exit 2
            fi
            case $1 in --php) php_bin=$2 ;; --report) report_file=$2 ;; esac
            shift 2 ;;
        --with-node) with_node=yes; shift ;;
        --print-php-probe) print_probe=yes; shift ;;
        -h|--help)
            printf '%s\n' 'Usage: sh check-brotli.sh [--php /path/to/php] [--with-node]' \
                'Assess a saved PHP runtime probe: sh check-brotli.sh --report FILE' \
                'Print an operator PHP probe: sh check-brotli.sh --print-php-probe' \
                'Container: docker exec -i CONTAINER /bin/sh -s < check-brotli.sh'
            exit 0 ;;
        *) printf '%s\n' 'Unexpected argument. Use --help.' >&2; exit 2 ;;
    esac
done

# Same probe can be executed in PHP CLI or included by trusted, authenticated
# operator tooling in the actual web runtime. It refuses direct web execution.
# Never copy an enabled version into a public document root.
php_probe='
(function () {
if (PHP_SAPI !== "cli" && PHP_SAPI !== "phpdbg" &&
    (!defined("BROTLI_CHECK_AUTHORIZED") || BROTLI_CHECK_AUTHORIZED !== true)) {
    http_response_code(403);
    exit;
}
$clean = function ($value) { return str_replace(array("|", "\r", "\n"), "?", (string) $value); };
$c = function_exists("curl_version") ? curl_version() : array();
$b = isset($c["brotli_version"]) ? $c["brotli_version"] : "";
if (!$b && isset($c["brotli_ver_num"]) && $c["brotli_ver_num"] > 0) {
    $n = $c["brotli_ver_num"];
    $b = ($n >> 24) . "." . (($n >> 12) & 4095) . "." . ($n & 4095);
}
$f = defined("CURL_VERSION_BROTLI") && isset($c["features"])
    ? (($c["features"] & constant("CURL_VERSION_BROTLI")) ? "yes" : "no") : "unknown";
echo "BROTLI_CHECK_FORMAT|2\n";
echo "BROTLI_CHECK_PHP|", PHP_VERSION, "|", $clean($b), "|", $f, "|",
    (extension_loaded("brotli") ? "yes" : "no"), "\n";
echo "BROTLI_CHECK_CONTEXT|", $clean(PHP_BINARY), "|", PHP_SAPI, "|",
    $clean(php_ini_loaded_file()), "\n";
echo "BROTLI_CHECK_CURL|", $clean(isset($c["version"]) ? $c["version"] : "unavailable"), "\n";
$os = function_exists("parse_ini_file") ? @parse_ini_file("/etc/os-release", false, INI_SCANNER_RAW) : false;
echo "BROTLI_CHECK_OS|", PHP_OS, "|", $clean(isset($os["ID"]) ? $os["ID"] : "unknown"), "|",
    $clean(isset($os["VERSION_ID"]) ? $os["VERSION_ID"] : "unknown"), "\n";
$maps = function_exists("file_get_contents") ? @file_get_contents("/proc/self/maps") : false;
$paths = array();
if ($maps !== false) {
    foreach (explode("\n", $maps) as $line) {
        $parts = preg_split("/\\s+/", trim($line), 6);
        if (count($parts) === 6 && preg_match("~^/.*libbrotlidec\\.so(?:\\.[0-9.]+)?(?: \\(deleted\\))?$~", $parts[5])) {
            $paths[$parts[5]] = true;
        }
    }
}
foreach ($paths as $path => $unused) { echo "BROTLI_CHECK_LIBRARY|", $clean($path), "\n"; }
echo "BROTLI_CHECK_MAPS|", ($maps === false ? "unavailable" : (count($paths) ? "mapped" : "none")), "\n";
})();
'
if [ "$print_probe" = yes ]; then
    printf '<?php\n%s\n' "$php_probe"
    exit 0
fi
if ! command -v awk >/dev/null 2>&1; then
    printf '%s\n' 'UNKNOWN: awk is required.' >&2
    exit 2
fi

review=0
unknown=0
observed=0
php_status=UNKNOWN
php_sapi=unknown
emit() {
    printf '%s | %s | %s\n' "$1" "$2" "$3"
    case $1 in REVIEW) review=1 ;; UNKNOWN) unknown=1 ;; esac
}

# Numeric comparison, including the separate fixed C maintenance branches.
# Prereleases, unexpected suffixes and unsupported version shapes stay UNKNOWN.
classify() {
    awk -v raw="$1" -v kind="$2" 'BEGIN {
        v=raw; sub(/^brotli\//,"",v); sub(/^v/,"",v)
        if (tolower(v) ~ /rc|alpha|beta|dev|snapshot|pre|nightly|canary/) { print "UNKNOWN"; exit }
        sub(/[-+~].*$/, "", v)
        n=split(v,a,".")
        if (n != 3) { print "UNKNOWN"; exit }
        for (i=1;i<=3;i++) if (a[i] !~ /^[0-9]+$/) { print "UNKNOWN"; exit }
        # Only accept a numeric version with an optional vendor suffix.
        if (raw !~ /^(brotli\/)?v?[0-9]+\.[0-9]+\.[0-9]+([-+~].+)?$/) {
            print "UNKNOWN"; exit
        }
        major=a[1]+0; minor=a[2]+0; patch=a[3]+0
        if (kind == "node") {
            minminor=-1; minpatch=-1
            if (major == 22) { minminor=23; minpatch=4 }
            if (major == 24) { minminor=22; minpatch=1 }
            if (major == 26) { minminor=12; minpatch=1 }
            if (minminor >= 0 && (minor > minminor || (minor == minminor && patch >= minpatch)))
                print "FIXED_VERSION"
            else print "REVIEW"
        } else if (major > 1 || (major == 1 && \
            ((minor == 0 && patch >= 10) || (minor == 1 && patch >= 1) || \
             (minor == 2 && patch >= 1) || minor > 2))) print "FIXED_VERSION"
        else if (major == 1 && (minor > 0 || patch >= 3)) print "REVIEW"
        else print "UNKNOWN"
    }'
}

decoder() {
    observed=$((observed + 1))
    decoder_version=${2#brotli/}
    status=$(classify "$decoder_version" decoder)
    case $status in
        FIXED_VERSION) note='fixed upstream decoder version' ;;
        REVIEW) note='affected upstream number; update or confirm vendor backport' ;;
        *) note='version cannot be classified; verify with vendor' ;;
    esac
    emit "$status" "$1" "Brotli $decoder_version; $note"
}

printf '%s\n' 'PHP Brotli decoder inventory | CVE-2026-111497 | v0.1.0 | baseline 2026-10-27'
printf '%s\n' 'Target: WordPress / Drupal / Symfony. Presence, patch evidence and web-runtime coverage are separate findings.'

if [ -n "$report_file" ] || command -v "$php_bin" >/dev/null 2>&1; then
    # Do not print PHP startup logs: they can contain local paths or secrets.
    # -r avoids consuming stdin when this whole script is streamed into Docker.
    if [ -n "$report_file" ]; then
        php_data=$(awk '{print}' 2>/dev/null < "$report_file")
        php_rc=$?
        # Imported reports never borrow evidence from the machine reading them.
        report_format=$(printf '%s\n' "$php_data" | awk -F '|' '$1=="BROTLI_CHECK_FORMAT" {n++; v=$2} END {if(n==1) print v}')
        if [ "$report_format" != 2 ]; then php_rc=1; fi
    else
        php_data=$("$php_bin" -r "$php_probe" 2>/dev/null)
        php_rc=$?
    fi
    php_line=$(printf '%s\n' "$php_data" | awk -F '|' '
        $1=="BROTLI_CHECK_PHP" && NF==5 { n++; line=$0 }
        END { if(n==1) print line }')
    if [ "$php_rc" -ne 0 ] || [ -z "$php_line" ]; then
        emit UNKNOWN 'PHP CLI' 'probe failed'
    else
        IFS='|' read -r marker php_version php_brotli php_feature php_extension <<EOF
$php_line
EOF
        context_line=$(printf '%s\n' "$php_data" | awk -F '|' '$1=="BROTLI_CHECK_CONTEXT" && NF==4 {n++; v=$0} END {if(n==1) print v}')
        if [ -n "$context_line" ]; then
            IFS='|' read -r marker php_binary php_sapi php_ini <<EOF
$context_line
EOF
            emit INFO 'PHP runtime' "SAPI=$php_sapi; binary=$php_binary; INI=$php_ini"
        fi
        printf '%s\n' "$php_data" | awk -F '|' '$1=="BROTLI_CHECK_OS" && NF==4 {print "INFO | Runtime OS | " $2 "; " $3 " " $4}'
        printf '%s\n' "$php_data" | awk -F '|' '$1=="BROTLI_CHECK_CURL" && NF==2 {print "INFO | PHP-linked libcurl | " $2}'
        php_label="PHP CLI $php_version cURL"
        case $php_sapi in
            fpm-fcgi|apache2handler|cgi-fcgi|litespeed) php_label="PHP web runtime $php_version cURL" ;;
        esac
        if [ -n "$php_brotli" ]; then
            emit DETECTED 'PHP Brotli decoder' 'available through this PHP cURL binding; application reachability not tested'
            decoder "$php_label" "$php_brotli"
            php_status=$status
        elif [ "$php_feature" = no ]; then
            emit NOT_DETECTED "$php_label" 'Brotli feature not enabled in this binding; does not assess other PHP builds'
        else
            emit UNKNOWN "$php_label" 'decoder version unavailable'
        fi
        if [ "$php_extension" = yes ]; then
            emit REVIEW 'PHP Brotli extension' 'separate decoder not measured; check extension vendor/build'
        elif [ "$php_extension" != no ]; then
            emit UNKNOWN 'PHP Brotli extension' 'unexpected probe result'
        fi
        library_paths=$(printf '%s\n' "$php_data" | awk -F '|' '$1=="BROTLI_CHECK_LIBRARY" && NF==2 && $2 ~ /^\// {if(!seen[$2]++) print $2}')
        if [ -n "$library_paths" ]; then
            printf '%s\n' 'Decoder libraries mapped in the probed PHP process (filenames are not patch evidence):' "$library_paths"
            if printf '%s\n' "$library_paths" | awk '/ \(deleted\)$/ {found=1} END {exit !found}'; then
                emit REVIEW 'Running decoder mapping' 'deleted/replaced library remains mapped; restart and recheck this runtime'
            fi
            if [ -z "$report_file" ] && command -v dpkg-query >/dev/null 2>&1; then
                # A package elsewhere on disk cannot vouch for a custom library.
                while IFS= read -r library_path; do
                    case $library_path in *' (deleted)') continue ;; esac
                    owner=$(dpkg-query -S "$library_path" 2>/dev/null)
                    if [ -n "$owner" ]; then
                        printf 'Mapped-path package ownership: %s\n' "$owner"
                    else
                        emit INFO 'Mapped-path package ownership' "$library_path is not owned according to dpkg; a distro update alone may not replace it"
                    fi
                done <<EOF
$library_paths
EOF
            fi
        else
            emit INFO 'Decoder library mapping' 'not available through this probe; static linking, restricted procfs or another platform are possible'
        fi
    fi
else
    emit UNKNOWN 'PHP runtime' 'selected php executable not found; curl CLI or Node cannot clear a PHP site'
fi

if [ "$with_node" = yes ] && [ -z "$report_file" ]; then
if command -v node >/dev/null 2>&1; then
    node_data=$(node -e 'console.log("BROTLI_CHECK_NODE|" + process.versions.node + "|" + (process.versions.brotli || ""))' 2>/dev/null)
    node_rc=$?
    node_line=$(printf '%s\n' "$node_data" | awk -F '|' '
        $1=="BROTLI_CHECK_NODE" && NF==3 { n++; line=$0 }
        END { if(n==1) print line }')
    if [ "$node_rc" -ne 0 ] || [ -z "$node_line" ]; then
        emit UNKNOWN Node.js 'probe failed'
    else
        IFS='|' read -r marker node_version node_brotli <<EOF
$node_line
EOF
        if [ -n "$node_brotli" ]; then
            decoder "Node.js $node_version" "$node_brotli"
            node_status=$(classify "$node_version" node)
            if [ "$node_status" != FIXED_VERSION ]; then
                emit "$node_status" 'Node.js release' 'update to a fixed supported release or confirm vendor backport'
            fi
        else
            emit UNKNOWN "Node.js $node_version" 'decoder version unavailable'
        fi
    fi
else
    emit NOT_DETECTED Node.js 'node executable not found'
fi
fi

if [ -z "$report_file" ]; then
if command -v curl >/dev/null 2>&1; then
    curl_data=$(curl -q --version 2>/dev/null)
    curl_rc=$?
    curl_valid=$(printf '%s\n' "$curl_data" | awk 'NR==1 && $1=="curl" {print "yes"}')
    curl_brotli=$(printf '%s\n' "$curl_data" | awk 'NR==1 {
        for(i=1;i<=NF;i++) if($i ~ /^brotli\//) {sub(/^brotli\//,"",$i); print $i; exit}
    }')
    if [ "$curl_rc" -ne 0 ] || [ "$curl_valid" != yes ]; then
        emit UNKNOWN 'curl CLI' 'probe failed'
    elif [ -n "$curl_brotli" ]; then
        decoder 'curl CLI' "$curl_brotli"
    elif printf '%s\n' "$curl_data" | awk '/^Features:/ {for(i=2;i<=NF;i++) if($i=="brotli") found=1} END {exit !found}'; then
        emit UNKNOWN 'curl CLI' 'Brotli feature present but decoder version unavailable'
    else
        emit NOT_DETECTED 'curl CLI' 'Brotli support not reported'
    fi
else
    emit NOT_DETECTED 'curl CLI' 'curl executable not found'
fi

# Package metadata is evidence only: vendors can backport fixes to old versions.
# No package lists are refreshed and no remote repositories are queried.
printf '%s\n' '' 'Installed package evidence (does not measure libraries loaded by services):'
packages=''
package_manager=none
if command -v apk >/dev/null 2>&1; then
    package_manager=apk
    packages=$(apk info --no-network -v 2>/dev/null | awk '/^brotli(-libs|-dev)?-[0-9]/')
elif command -v dpkg-query >/dev/null 2>&1; then
    package_manager=dpkg
    packages=$(dpkg-query -W '-f=${binary:Package}|${Version}|${db:Status-Status}\n' '*brotli*' 2>/dev/null |
        awk -F '|' '$3=="installed" {print $1 " " $2}')
elif command -v rpm >/dev/null 2>&1; then
    package_manager=rpm
    packages=$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | awk 'tolower($1) ~ /brotli/')
elif command -v brew >/dev/null 2>&1; then
    package_manager=brew
    packages=$(HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 brew list --versions brotli 2>/dev/null)
fi
if [ -n "$packages" ]; then
    printf '%s\n' "$packages"
    emit INFO 'Package assessment' 'disk inventory only; does not override the PHP decoder observation; verify vendor backports against the mapped library'
else
    printf 'No Brotli package evidence returned by %s; absence is not established.\n' "$package_manager"
fi
fi

printf '%s\n' '' \
    'Scope: the PHP process probed; curl CLI is supporting evidence only. Node is optional (--with-node).' \
    'Not inspected: application request paths, other PHP builds/pools, other containers or running workers.' \
    'Presence means decoding capability, not proof that the application uses it on attacker-controlled input.' \
    'Older numbers may have vendor backports. Headers and benign decompression cannot prove this fix.'

web_context=no
case $php_sapi in fpm-fcgi|apache2handler|cgi-fcgi|litespeed) web_context=yes ;; esac
if [ "$web_context" != yes ]; then
    printf '%s\n' 'WEB_RUNTIME: UNVERIFIED. CLI PHP can differ from the site. Ask the provider to verify the effective web decoder and restart all affected workers.'
else
    printf '%s\n' 'WEB_RUNTIME: snapshot supplied for one web PHP process; confirm its origin, site, pool, time and all replicas.'
fi

if [ "$review" -eq 1 ]; then
    printf '%s\n' 'RESULT: REVIEW_REQUIRED (exit 1)'
    exit 1
elif [ "$unknown" -eq 1 ] || [ "$php_status" != FIXED_VERSION ]; then
    printf '%s\n' 'RESULT: INCOMPLETE (exit 2)'
    exit 2
elif [ "$web_context" != yes ]; then
    printf '%s\n' 'RESULT: CLI_VERSIONS_FIXED_WEB_UNVERIFIED (exit 2)'
    exit 2
else
    printf '%s\n' 'RESULT: PROBED_WEB_CURL_DECODER_FIXED (exit 0); version evidence only, not whole-site clearance'
    exit 0
fi
