#!/usr/bin/env bash
# ============================================================
# check_apk_permission.sh
#
# Quick shell script to check an installed APK's Wake Lock
# permission status via ADB (no Python required).
#
# Usage:
#   ./check_apk_permission.sh <package_name>
#
# Example:
#   ./check_apk_permission.sh com.example.myapp
# ============================================================

set -euo pipefail

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BOLD="\033[1m"
RESET="\033[0m"

PACKAGE="${1:-}"

if [[ -z "$PACKAGE" ]]; then
    echo "Usage: $0 <package_name>" >&2
    exit 1
fi

if ! command -v adb &>/dev/null; then
    echo -e "${RED}Error:${RESET} adb not found." >&2
    exit 1
fi

echo -e "${BOLD}=== Wake Lock Permission Check ===${RESET}"
echo -e "Package: ${BOLD}${PACKAGE}${RESET}"
echo

# 1. Check if package is installed
if ! adb shell pm list packages 2>/dev/null | grep -q "package:${PACKAGE}"; then
    echo -e "${YELLOW}Package not installed on connected device.${RESET}"
    echo "Checking permission declaration from dumpsys only..."
fi

# 2. Permission check via pm
PERM_RESULT=$(adb shell pm check-permission android.permission.WAKE_LOCK "$PACKAGE" 2>/dev/null || true)
echo -n "  WAKE_LOCK permission: "
if echo "$PERM_RESULT" | grep -q "PERMISSION_GRANTED"; then
    echo -e "${GREEN}GRANTED${RESET}"
    GRANTED=true
else
    echo -e "${RED}NOT GRANTED${RESET}"
    GRANTED=false
fi

# 3. Show permission details from dumpsys package
echo
echo -e "${BOLD}Permission Details:${RESET}"
adb shell dumpsys package "$PACKAGE" 2>/dev/null \
    | grep -A 2 "WAKE_LOCK" \
    | sed 's/^/  /' \
    || echo "  (could not retrieve package details)"

# 4. Show currently held wake locks by this package
echo
echo -e "${BOLD}Currently Held Wake Locks:${RESET}"
adb shell dumpsys power 2>/dev/null \
    | grep -A 1 "Wake Locks:" \
    | grep "$PACKAGE" \
    | sed 's/^/  /' \
    || echo "  (none)"

echo
if $GRANTED; then
    exit 0
else
    exit 1
fi
