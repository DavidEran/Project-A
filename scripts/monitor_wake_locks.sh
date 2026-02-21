#!/usr/bin/env bash
# ============================================================
# monitor_wake_locks.sh
#
# Runtime Wake Lock monitor using ADB.
#
# Reads /proc/wakelocks (or the modern kernel wakeup sources)
# and the dumpsys power output to show:
#   - Which wake locks are currently held
#   - Which package holds them
#   - How long they have been held
#
# Usage:
#   ./monitor_wake_locks.sh [--package <pkg>] [--interval <secs>] [--once]
#
# Requirements:
#   - adb in PATH
#   - Android device/emulator connected via USB or TCP
# ============================================================

set -euo pipefail

# ---- Defaults -------------------------------------------------------
PACKAGE=""
INTERVAL=2
ONCE=false
ADB="adb"

# ---- Colours --------------------------------------------------------
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
BOLD="\033[1m"
RESET="\033[0m"

# ---- Argument parsing -----------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --package|-p) PACKAGE="$2"; shift 2 ;;
        --interval|-i) INTERVAL="$2"; shift 2 ;;
        --once|-1) ONCE=true; shift ;;
        --adb) ADB="$2"; shift 2 ;;
        --help|-h)
            sed -n '/^# Usage/,/^#$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ---- Sanity checks --------------------------------------------------
if ! command -v "$ADB" &>/dev/null; then
    echo -e "${RED}Error:${RESET} adb not found. Install Android Platform Tools." >&2
    exit 1
fi

if ! "$ADB" get-state &>/dev/null; then
    echo -e "${RED}Error:${RESET} No device connected. Run: adb devices" >&2
    exit 1
fi

DEVICE=$("$ADB" get-state)
echo -e "${CYAN}Device state:${RESET} $DEVICE"
echo -e "${CYAN}Monitoring wake locks${RESET}${PACKAGE:+ for package ${BOLD}${PACKAGE}${RESET}}..."
echo

# ---- Helper functions -----------------------------------------------

dump_power() {
    "$ADB" shell dumpsys power 2>/dev/null
}

check_wake_lock_permission() {
    local pkg="$1"
    local result
    result=$("$ADB" shell pm check-permission android.permission.WAKE_LOCK "$pkg" 2>/dev/null || true)
    echo "$result"
}

format_ms() {
    local ms=$1
    if   (( ms < 1000 ));       then echo "${ms} ms"
    elif (( ms < 60000 ));      then printf "%.1f s\n"   "$(echo "scale=1; $ms/1000"   | bc)"
    elif (( ms < 3600000 ));    then printf "%.1f min\n" "$(echo "scale=1; $ms/60000"  | bc)"
    else                             printf "%.2f h\n"   "$(echo "scale=2; $ms/3600000"| bc)"
    fi
}

# ---- Permission check -----------------------------------------------
if [[ -n "$PACKAGE" ]]; then
    echo -e "${BOLD}== Wake Lock Permission Check ==${RESET}"
    perm=$(check_wake_lock_permission "$PACKAGE")
    if echo "$perm" | grep -q "PERMISSION_GRANTED"; then
        echo -e "  ${GREEN}GRANTED${RESET}  ($PACKAGE)"
    else
        echo -e "  ${RED}NOT GRANTED${RESET}  ($PACKAGE)"
        echo -e "  The app cannot hold wake locks."
    fi
    echo
fi

# ---- Main monitoring loop -------------------------------------------
show_wake_locks() {
    local dump
    dump=$(dump_power)

    local timestamp
    timestamp=$(date "+%H:%M:%S")

    echo -e "${BOLD}[$timestamp] Wake Locks${RESET}"
    echo "------------------------------------------------------------"

    # Extract the Wake Locks section from dumpsys power
    local in_section=false
    local found_any=false

    while IFS= read -r line; do
        if echo "$line" | grep -q "Wake Locks:"; then
            in_section=true
            continue
        fi
        if $in_section; then
            # End of section: blank line or next major section header
            if [[ -z "$line" ]] || echo "$line" | grep -qE "^[A-Z]"; then
                break
            fi
            # Filter by package if specified
            if [[ -n "$PACKAGE" ]] && ! echo "$line" | grep -q "$PACKAGE"; then
                continue
            fi
            echo -e "  $line"
            found_any=true
        fi
    done <<< "$dump"

    if ! $found_any; then
        echo -e "  ${YELLOW}No active wake locks${RESET}${PACKAGE:+ for $PACKAGE}"
    fi

    echo
    echo -e "${BOLD}Wakeup Sources (kernel):${RESET}"
    echo "------------------------------------------------------------"

    # /proc/wakelocks (old) or /sys/kernel/debug/wakeup_sources (new)
    local wakeup_data
    wakeup_data=$("$ADB" shell "cat /sys/kernel/debug/wakeup_sources 2>/dev/null || \
                               cat /proc/wakelocks 2>/dev/null || echo 'Not available'")

    if echo "$wakeup_data" | grep -q "Not available"; then
        echo -e "  ${YELLOW}Kernel wakeup source info not available on this device${RESET}"
    else
        # Print header + any active (active_count > 0) entries
        local header=true
        local found_active=false
        while IFS= read -r line; do
            if $header; then
                echo "  $line"
                header=false
                continue
            fi
            # Column 7 is active_count in /sys/kernel/debug/wakeup_sources
            local active_count
            active_count=$(echo "$line" | awk '{print $7}' 2>/dev/null || echo "0")
            if [[ "$active_count" =~ ^[0-9]+$ ]] && (( active_count > 0 )); then
                if [[ -n "$PACKAGE" ]] && ! echo "$line" | grep -q "$PACKAGE"; then
                    continue
                fi
                echo "  $line"
                found_active=true
            fi
        done <<< "$wakeup_data"
        if ! $found_active; then
            echo -e "  ${YELLOW}No active kernel wakeup sources${RESET}"
        fi
    fi

    echo
}

if $ONCE; then
    show_wake_locks
else
    while true; do
        clear 2>/dev/null || true
        show_wake_locks
        echo -e "  ${CYAN}(refreshing every ${INTERVAL}s — Ctrl+C to stop)${RESET}"
        sleep "$INTERVAL"
    done
fi
