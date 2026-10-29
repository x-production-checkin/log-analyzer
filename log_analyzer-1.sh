#!/usr/bin/env bash
# log_analyzer.sh
# Linux SSH authentication log analyzer.
#
# Supported input:
#   OpenSSH authentication messages in traditional syslog format.
#   Ubuntu/Debian: /var/log/auth.log
#   RHEL/Fedora-family: /var/log/secure
#   A regular text file or stdin (-f -)
#
# IPv4 detection only. No IP blocking or automatic remediation.
#
# Exit codes:
#   0 = Analysis completed; no threshold alerts
#   1 = Usage, input, or output error
#   2 = Analysis completed; one or more threshold alerts
#
# Requirements: Bash 4+, standard GNU/Linux utilities.

set -uo pipefail
umask 077
export LC_ALL=C

TOP_N=10
LOG_FILE=""
REPORT=""
THRESHOLD=10
ALERT_COUNT=0
WORK_DIR=""
REPORT_TMP=""

usage() {
    cat <<'EOF'
Usage: ./log_analyzer.sh [-f logfile] [-n top_count] [-o report_file] [-t threshold]

Options:
  -f FILE   Input log; '-' reads stdin
  -n N      Number of top entries (1-1000; default 10)
  -o FILE   Save report to FILE
  -t N      Alert threshold per IPv4 address (default 10)
  -h        Show help

Examples:
  sudo ./log_analyzer.sh
  ./log_analyzer.sh -f sample_auth.log -t 5
  ./log_analyzer.sh -f - -o report.txt
  zcat /var/log/auth.log.*.gz | ./log_analyzer.sh -f -

Exit codes:
  0 = Completed without alerts
  1 = Error
  2 = Completed with threshold alerts
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR"
    fi
    if [[ -n "$REPORT_TMP" && -f "$REPORT_TMP" ]]; then
        rm -f -- "$REPORT_TMP"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

while getopts ':f:n:o:t:h' opt; do
    case "$opt" in
        f) LOG_FILE=$OPTARG ;;
        n) TOP_N=$OPTARG ;;
        o) REPORT=$OPTARG ;;
        t) THRESHOLD=$OPTARG ;;
        h) usage; exit 0 ;;
        :) die "Option -$OPTARG requires an argument." ;;
        \?) die "Unknown option -$OPTARG." ;;
    esac
done

# Validate decimal input without allowing arithmetic overflow.
is_positive_decimal() {
    [[ "$1" =~ ^[0-9]{1,9}$ ]] && (( 10#$1 > 0 ))
}

is_positive_decimal "$TOP_N" ||
    die "-n must be a positive integer from 1 to 1000."
(( 10#$TOP_N <= 1000 )) ||
    die "-n must be between 1 and 1000."

is_positive_decimal "$THRESHOLD" ||
    die "-t must be a positive integer."

TOP_N=$((10#$TOP_N))
THRESHOLD=$((10#$THRESHOLD))

# Detect the default authentication log.
if [[ -z "$LOG_FILE" ]]; then
    if [[ -r /var/log/auth.log ]]; then
        LOG_FILE=/var/log/auth.log
    elif [[ -r /var/log/secure ]]; then
        LOG_FILE=/var/log/secure
    else
        die "No readable auth.log or secure file. Specify -f."
    fi
fi

# Validate the input before creating a report.
if [[ "$LOG_FILE" != "-" ]]; then
    [[ -f "$LOG_FILE" && -r "$LOG_FILE" ]] ||
        die "Input must be a readable regular file: $LOG_FILE"
fi

# Normalize the report destination and refuse symlinks.
if [[ -n "$REPORT" ]]; then
    REPORT_DIR=$(dirname -- "$REPORT")
    REPORT_BASE=$(basename -- "$REPORT")

    [[ "$REPORT_BASE" != "." && "$REPORT_BASE" != ".." &&
       -n "$REPORT_BASE" ]] ||
        die "Invalid report filename."

    [[ -d "$REPORT_DIR" && -w "$REPORT_DIR" ]] ||
        die "Report directory is missing or not writable."

    REPORT_DIR=$(cd -- "$REPORT_DIR" && pwd -P) ||
        die "Cannot resolve report directory."
    REPORT="$REPORT_DIR/$REPORT_BASE"

    [[ ! -L "$REPORT" ]] ||
        die "Refusing to write through a report symlink."

    if [[ -e "$REPORT" ]]; then
        [[ -f "$REPORT" && -w "$REPORT" ]] ||
            die "Report must be a writable regular file."
    fi

    if [[ "$LOG_FILE" != "-" ]]; then
        INPUT_REAL=$(readlink -f -- "$LOG_FILE") ||
            die "Cannot resolve input path."
        REPORT_REAL=$(readlink -m -- "$REPORT") ||
            die "Cannot resolve report path."
        [[ "$INPUT_REAL" != "$REPORT_REAL" ]] ||
            die "Report destination must not be the input log."
    fi

    REPORT_TMP=$(mktemp "$REPORT_DIR/.${REPORT_BASE}.tmp.XXXXXX") ||
        die "Cannot create temporary report."
fi

WORK_DIR=$(mktemp -d) ||
    die "Cannot create private working directory."

INPUT="$WORK_DIR/input.log"

# Snapshot the input so every section analyzes the same data.
if [[ "$LOG_FILE" == "-" ]]; then
    cat > "$INPUT" || die "Failed to read stdin."
else
    cat -- "$LOG_FILE" > "$INPUT" ||
        die "Failed to read input log."
fi

# Validate IPv4 octets and emit one source address per matching event.
# Count both failed-password and invalid-user SSH events.
# Each matching log line contributes at most one event.
extract_events() {
    awk '
    function valid_ipv4(ip, parts, n, i) {
        n = split(ip, parts, ".")
        if (n != 4) return 0

        for (i = 1; i <= 4; i++) {
            if (parts[i] !~ /^[0-9]+$/) return 0
            if (length(parts[i]) > 3) return 0
            if (parts[i] + 0 > 255) return 0
        }
        return 1
    }

    /Failed password|Invalid user/ {
        for (i = 1; i < NF; i++) {
            if ($i == "from" && valid_ipv4($(i+1))) {
                print $(i+1)
                break
            }
        }
    }' "$INPUT"
}

extract_failed_password_ips() {
    awk '
    function valid_ipv4(ip, parts, n, i) {
        n = split(ip, parts, ".")
        if (n != 4) return 0
        for (i = 1; i <= 4; i++) {
            if (parts[i] !~ /^[0-9]+$/ ||
                length(parts[i]) > 3 ||
                parts[i] + 0 > 255) return 0
        }
        return 1
    }

    /Failed password/ {
        for (i = 1; i < NF; i++) {
            if ($i == "from" && valid_ipv4($(i+1))) {
                print $(i+1)
                break
            }
        }
    }' "$INPUT"
}

count_lines() {
    local pattern=$1
    grep -cE "$pattern" "$INPUT" 2>/dev/null || true
}

top_ips() {
    extract_failed_password_ips |
        sort | uniq -c | sort -rn | head -n "$TOP_N"
}

top_users() {
    awk '
    /Failed password for / {
        for (i = 1; i < NF; i++) {
            if ($i == "for") {
                if ($(i+1) == "invalid" && $(i+2) == "user")
                    print $(i+3)
                else
                    print $(i+1)
                break
            }
        }
    }
    /Invalid user / {
        for (i = 1; i < NF; i++) {
            if ($i == "user") {
                print $(i+1)
                break
            }
        }
    }' "$INPUT" |
        sort | uniq -c | sort -rn | head -n "$TOP_N"
}

run_report() {
    local total failed invalid accepted root_failed
    local sudo_commands sudo_failures count ip

    total=$(wc -l < "$INPUT") ||
        die "Could not count log lines."

    failed=$(count_lines 'Failed password')
    invalid=$(count_lines 'Invalid user')
    accepted=$(count_lines 'Accepted ')
    root_failed=$(count_lines 'Failed password for root')
    sudo_commands=$(count_lines 'sudo:.*COMMAND=')
    sudo_failures=$(count_lines 'sudo:.*authentication failure')

    printf '%s\n' '=============================================='
    printf '%s\n' '        LINUX LOG ANALYZER REPORT'
    printf '%s\n' '=============================================='
    printf 'Host       : %s\n' "$(hostname)"
    printf 'Generated  : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'Log file   : %s\n' "$LOG_FILE"
    printf 'Total lines: %s\n\n' "$total"

    echo '---- [1] SSH AUTHENTICATION SUMMARY ----'
    printf 'Failed-password entries : %s\n' "$failed"
    printf 'Invalid-user entries    : %s\n' "$invalid"
    printf 'Successful-login entries: %s\n\n' "$accepted"

    echo "---- [2] TOP $TOP_N SOURCE IPv4 ADDRESSES ----"
    printf '%-8s %s\n' COUNT 'IP ADDRESS'
    top_ips | awk '{printf "%-8s %s\n", $1, $2}'
    echo

    echo "---- [3] TOP $TOP_N TARGETED USERNAMES ----"
    printf '%-8s %s\n' COUNT USERNAME
    top_users | awk '{printf "%-8s %s\n", $1, $2}'
    echo

    echo '---- [4] FAILED PASSWORDS BY HOUR ----'
    printf '%-8s %s\n' HOUR COUNT
    awk '
    /Failed password/ {
        if (match($0, /[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/))
            print substr($0, RSTART, 2)
    }' "$INPUT" |
        sort -n | uniq -c |
        awk '{printf "%-8s %s\n", $2 ":00", $1}'
    echo

    echo '---- [5] ROOT LOGIN ATTEMPTS ----'
    printf 'Failed root login entries: %s\n\n' "$root_failed"

    echo '---- [6] SUDO ACTIVITY ----'
    printf 'Sudo command entries : %s\n' "$sudo_commands"
    printf 'Sudo failure entries : %s\n\n' "$sudo_failures"

    echo "---- [7] SERVICE ERRORS (top $TOP_N) ----"
    printf '%-8s %s\n' COUNT 'SERVICE'
    awk '
        tolower($0) ~ /error|fail|critical|denied/ && NF >= 5 {
            service = $5
            sub(/\[[0-9]+\]/, "", service)
            sub(/:$/, "", service)
            if (service != "") print service
        }
    ' "$INPUT" |
        sort | uniq -c | sort -rn | head -n "$TOP_N" |
        awk '{printf "%-8s %s\n", $1, $2}'
    echo

    echo "---- [8] SOURCE ALERTS (threshold: $THRESHOLD) ----"

    while read -r count ip; do
        [[ -n "${count:-}" && -n "${ip:-}" ]] || continue

        if (( count >= THRESHOLD )); then
            printf '[!] Possible brute force: %s (%s SSH failure events)\n' \
                "$ip" "$count"
            (( ALERT_COUNT += 1 ))
        fi
    done < <(
        extract_events | sort | uniq -c | sort -rn
    )

    if (( ALERT_COUNT == 0 )); then
        printf 'No IPv4 source crossed the configured threshold.\n'
    fi

    echo
    printf '%s\n' '=============================================='
}

if [[ -n "$REPORT" ]]; then
    run_report > "$REPORT_TMP" ||
        die "Report generation failed."

    mv -f -- "$REPORT_TMP" "$REPORT" ||
        die "Could not save report."
    REPORT_TMP=""

    cat -- "$REPORT" ||
        die "Report saved, but terminal output failed."
    printf 'Report saved to: %s\n' "$REPORT"
else
    run_report || die "Report generation failed."
fi

if (( ALERT_COUNT > 0 )); then
    exit 2
fi

exit 0
