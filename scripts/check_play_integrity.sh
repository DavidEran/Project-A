#!/usr/bin/env bash
# ============================================================
# check_play_integrity.sh
#
# Check whether an installed Android app uses the Google Play
# Integrity API, which can block or redirect sideloaded installs
# back to the Play Store.
#
# The script uses ADB to inspect the installed package, pull its
# APK to a temporary location, and optionally run the Python
# play_integrity_analyzer on it.
#
# Usage:
#   ./check_play_integrity.sh <package_name>
#   ./check_play_integrity.sh <package_name> --verbose
#   ./check_play_integrity.sh <package_name> --json
#
# Example:
#   ./check_play_integrity.sh com.example.myapp
#   ./check_play_integrity.sh com.example.myapp --verbose
# ============================================================

set -euo pipefail

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BOLD="\033[1m"
RESET="\033[0m"

PACKAGE="${1:-}"
VERBOSE=false
JSON_MODE=false

# Parse optional flags
shift || true
for arg in "$@"; do
    case "$arg" in
        --verbose|-v) VERBOSE=true ;;
        --json)       JSON_MODE=true ;;
    esac
done

if [[ -z "$PACKAGE" ]]; then
    echo "Usage: $0 <package_name> [--verbose] [--json]" >&2
    exit 1
fi

if ! command -v adb &>/dev/null; then
    echo -e "${RED}Error:${RESET} adb not found. Install Android Platform Tools and ensure a device is connected." >&2
    exit 1
fi

# -------------------------------------------------------
# 1. Verify the package is installed
# -------------------------------------------------------
if ! $JSON_MODE; then
    echo -e "${BOLD}=== Play Integrity / Sideload Risk Check ===${RESET}"
    echo -e "Package: ${BOLD}${PACKAGE}${RESET}"
    echo
fi

if ! adb shell pm list packages 2>/dev/null | grep -q "^package:${PACKAGE}$"; then
    echo -e "${YELLOW}Warning:${RESET} Package '${PACKAGE}' not found on the connected device." >&2
    echo "Ensure the device is connected and the package name is correct." >&2
    exit 1
fi

# -------------------------------------------------------
# 2. Show the install source (Play Store vs sideloaded)
# -------------------------------------------------------
INSTALLER=""
INSTALL_SOURCE_RAW=$(adb shell dumpsys package "${PACKAGE}" 2>/dev/null \
    | grep -i "installerPackageName" | head -1 || true)

if echo "$INSTALL_SOURCE_RAW" | grep -q "com.android.vending"; then
    INSTALLER="com.android.vending"
    INSTALL_LABEL="Google Play Store"
elif [[ -n "$INSTALL_SOURCE_RAW" ]]; then
    INSTALLER=$(echo "$INSTALL_SOURCE_RAW" | sed 's/.*=//; s/[[:space:]]//g')
    INSTALL_LABEL="${INSTALLER:-unknown (likely sideloaded)}"
else
    INSTALL_LABEL="unknown (likely sideloaded)"
fi

if ! $JSON_MODE; then
    echo -e "${BOLD}Install Source:${RESET}"
    if [[ "$INSTALLER" == "com.android.vending" ]]; then
        echo -e "  Installed via: ${GREEN}${INSTALL_LABEL}${RESET}"
    else
        echo -e "  Installed via: ${YELLOW}${INSTALL_LABEL}${RESET}"
        echo -e "  ${YELLOW}Note:${RESET} This app was not installed from Google Play."
    fi
    echo
fi

# -------------------------------------------------------
# 3. Pull the APK from the device to a temporary file
# -------------------------------------------------------
APK_PATH_ON_DEVICE=$(adb shell pm path "${PACKAGE}" 2>/dev/null \
    | grep "^package:" | head -1 | sed 's/^package://')

if [[ -z "$APK_PATH_ON_DEVICE" ]]; then
    echo -e "${RED}Error:${RESET} Could not locate APK path for '${PACKAGE}' on device." >&2
    exit 1
fi

TMP_APK=$(mktemp /tmp/play_integrity_check_XXXXXX.apk)
trap 'rm -f "$TMP_APK"' EXIT

if ! $JSON_MODE; then
    echo -e "${BOLD}Pulling APK:${RESET}"
    echo "  Device path : ${APK_PATH_ON_DEVICE}"
    echo "  Local copy  : ${TMP_APK}"
    echo
fi

adb pull "${APK_PATH_ON_DEVICE}" "${TMP_APK}" &>/dev/null

# -------------------------------------------------------
# 4. Run Python analyzer if available
# -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="${SCRIPT_DIR}/../analyzer/play_integrity_analyzer.py"

if command -v python3 &>/dev/null && [[ -f "$ANALYZER" ]]; then
    PYTHON_ARGS=("${TMP_APK}")
    $VERBOSE && PYTHON_ARGS+=("--verbose")
    $JSON_MODE && PYTHON_ARGS+=("--json")

    if ! $JSON_MODE; then
        echo -e "${BOLD}Static Analysis Results:${RESET}"
        echo
    fi

    # Propagate the analyzer exit code: 0 = no integrity, 1 = integrity detected
    python3 "${ANALYZER}" "${PYTHON_ARGS[@]}" && ANALYSIS_EXIT=0 || ANALYSIS_EXIT=$?
    exit $ANALYSIS_EXIT

else
    # Fallback: basic string grep without Python
    if ! $JSON_MODE; then
        echo -e "${YELLOW}Note:${RESET} python3 or play_integrity_analyzer.py not found."
        echo "Running basic string search instead..."
        echo
        echo -e "${BOLD}String matches in APK:${RESET}"
    fi

    FOUND_INTEGRITY=false
    FOUND_SAFETYNET=false

    if strings "${TMP_APK}" 2>/dev/null | grep -q "play/core/integrity"; then
        FOUND_INTEGRITY=true
        if ! $JSON_MODE; then
            echo -e "  ${RED}[FOUND]${RESET} Play Integrity API strings detected"
        fi
    fi

    if strings "${TMP_APK}" 2>/dev/null | grep -q "safetynet"; then
        FOUND_SAFETYNET=true
        if ! $JSON_MODE; then
            echo -e "  ${YELLOW}[FOUND]${RESET} SafetyNet (legacy) strings detected"
        fi
    fi

    if $JSON_MODE; then
        echo "{\"package\":\"${PACKAGE}\",\"uses_play_integrity\":${FOUND_INTEGRITY},\"uses_safetynet\":${FOUND_SAFETYNET},\"note\":\"basic string scan only\"}"
    else
        if ! $FOUND_INTEGRITY && ! $FOUND_SAFETYNET; then
            echo -e "  ${GREEN}[CLEAR]${RESET} No Play Integrity or SafetyNet strings found"
            echo
            echo "  Sideloaded installs are unlikely to be blocked."
        fi
        echo
        echo "  Install python3 and ensure analyzer/play_integrity_analyzer.py"
        echo "  is available for a full static analysis report."
    fi

    $FOUND_INTEGRITY || $FOUND_SAFETYNET
fi
