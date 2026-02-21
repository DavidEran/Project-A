#!/usr/bin/env python3
"""
Wake Lock Analyzer - Static analysis tool for Android APKs.

Checks if an APK declares the WAKE_LOCK permission and scans for
wake lock usage patterns in the app's code.
"""

import argparse
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET


WAKE_LOCK_PERMISSION = "android.permission.WAKE_LOCK"
WAKE_LOCK_CLASS = "android/os/PowerManager$WakeLock"
ACQUIRE_METHOD = "acquire"
ACQUIRE_WITH_TIMEOUT_METHOD = "acquire:(J)V"
RELEASE_METHOD = "release"
POWER_MANAGER_CLASS = "android/os/PowerManager"
NEW_WAKE_LOCK_METHOD = "newWakeLock"

# Wake lock level flags (from Android SDK)
WAKE_LOCK_LEVELS = {
    0x00000001: "PARTIAL_WAKE_LOCK",
    0x00000006: "FULL_WAKE_LOCK (deprecated)",
    0x0000000A: "SCREEN_DIM_WAKE_LOCK (deprecated)",
    0x0000000A: "SCREEN_BRIGHT_WAKE_LOCK",
    0x00000010: "PROXIMITY_SCREEN_OFF_WAKE_LOCK",
    0x40000000: "ACQUIRE_CAUSES_WAKEUP",
    0x20000000: "ON_AFTER_RELEASE",
    0x80000000: "UNIMPORTANT_FOR_LOGGING (hidden)",
}


@dataclass
class WakeLockUsage:
    """Represents a wake lock usage found in the code."""
    file: str
    line_number: int
    usage_type: str          # acquire, acquire_with_timeout, release, new_wake_lock
    timeout_ms: Optional[int] = None
    context_lines: list = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Full analysis result for an APK."""
    apk_path: str
    package_name: str
    app_label: str
    has_wake_lock_permission: bool
    permission_protection_level: str
    wake_lock_usages: list = field(default_factory=list)
    acquire_count: int = 0
    release_count: int = 0
    timed_acquires: list = field(default_factory=list)   # list of timeout_ms values
    files_analyzed: int = 0
    errors: list = field(default_factory=list)

    @property
    def is_balanced(self) -> bool:
        """True if acquire and release counts match."""
        return self.acquire_count == self.release_count

    @property
    def max_timeout_ms(self) -> Optional[int]:
        if self.timed_acquires:
            return max(self.timed_acquires)
        return None

    @property
    def min_timeout_ms(self) -> Optional[int]:
        if self.timed_acquires:
            return min(self.timed_acquires)
        return None

    def summary(self) -> dict:
        return {
            "apk": self.apk_path,
            "package": self.package_name,
            "label": self.app_label,
            "has_wake_lock_permission": self.has_wake_lock_permission,
            "permission_protection_level": self.permission_protection_level,
            "acquire_count": self.acquire_count,
            "release_count": self.release_count,
            "is_balanced": self.is_balanced,
            "timed_acquires": self.timed_acquires,
            "max_timeout_ms": self.max_timeout_ms,
            "min_timeout_ms": self.min_timeout_ms,
            "files_analyzed": self.files_analyzed,
            "errors": self.errors,
            "usages": [
                {
                    "file": u.file,
                    "line": u.line_number,
                    "type": u.usage_type,
                    "timeout_ms": u.timeout_ms,
                }
                for u in self.wake_lock_usages
            ],
        }


class WakeLockAnalyzer:
    """Analyzes an Android APK for wake lock permission and usage."""

    def __init__(self, apk_path: str, verbose: bool = False):
        self.apk_path = apk_path
        self.verbose = verbose

    def analyze(self) -> AnalysisResult:
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        if not zipfile.is_zipfile(self.apk_path):
            raise ValueError(f"Not a valid APK (zip) file: {self.apk_path}")

        result = AnalysisResult(
            apk_path=self.apk_path,
            package_name="",
            app_label="",
            has_wake_lock_permission=False,
            permission_protection_level="normal",
        )

        with zipfile.ZipFile(self.apk_path, "r") as apk:
            self._analyze_manifest(apk, result)
            self._analyze_dex_files(apk, result)
            self._analyze_smali_if_present(apk, result)

        return result

    # ------------------------------------------------------------------
    # Manifest analysis
    # ------------------------------------------------------------------

    def _analyze_manifest(self, apk: zipfile.ZipFile, result: AnalysisResult) -> None:
        """Parse AndroidManifest.xml (binary XML inside APK)."""
        try:
            manifest_data = apk.read("AndroidManifest.xml")
            # Try to parse as plain text first (some tools produce text manifests)
            try:
                manifest_text = manifest_data.decode("utf-8")
                self._parse_text_manifest(manifest_text, result)
            except UnicodeDecodeError:
                # Binary XML – extract readable strings from bytes
                self._parse_binary_manifest(manifest_data, result)
        except KeyError:
            result.errors.append("AndroidManifest.xml not found in APK")

    def _parse_text_manifest(self, text: str, result: AnalysisResult) -> None:
        """Parse a plain-text (decoded) AndroidManifest.xml."""
        try:
            root = ET.fromstring(text)
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            result.package_name = root.get("package", "unknown")

            # App label
            app_el = root.find("application")
            if app_el is not None:
                label = app_el.get("{http://schemas.android.com/apk/res/android}label", "")
                result.app_label = label

            # Permissions
            for perm in root.findall("uses-permission"):
                name = perm.get("{http://schemas.android.com/apk/res/android}name", "")
                if name == WAKE_LOCK_PERMISSION:
                    result.has_wake_lock_permission = True

            for perm in root.findall("permission"):
                name = perm.get("{http://schemas.android.com/apk/res/android}name", "")
                if name == WAKE_LOCK_PERMISSION:
                    pl = perm.get(
                        "{http://schemas.android.com/apk/res/android}protectionLevel", "normal"
                    )
                    result.permission_protection_level = pl

        except ET.ParseError as e:
            result.errors.append(f"Manifest XML parse error: {e}")
            # Fallback: regex scan
            self._regex_scan_manifest(text, result)

    def _parse_binary_manifest(self, data: bytes, result: AnalysisResult) -> None:
        """Extract useful strings from binary AndroidManifest.xml."""
        # Android binary XML (AXML) stores strings as UTF-16LE in the string pool.
        # A plain latin-1 decode won't match ASCII permission strings because each
        # character is interleaved with a null byte.  Check the raw bytes directly.
        if WAKE_LOCK_PERMISSION.encode("utf-16-le") in data:
            result.has_wake_lock_permission = True

        # Try to recover package name / label from the UTF-16LE string pool.
        try:
            utf16_text = data.decode("utf-16-le", errors="ignore")
            if not result.package_name:
                pkg_match = re.search(r'package="([^"]+)"', utf16_text)
                if pkg_match:
                    result.package_name = pkg_match.group(1)
            if not result.app_label:
                label_match = re.search(r'android:label="([^"]+)"', utf16_text)
                if label_match:
                    result.app_label = label_match.group(1)
        except Exception:
            pass

        # Also fall back to the latin-1 regex scan (catches UTF-8 string pools
        # and picks up any remaining fields not yet populated above).
        text = data.decode("latin-1")
        self._regex_scan_manifest(text, result)

    def _regex_scan_manifest(self, text: str, result: AnalysisResult) -> None:
        """Regex-based fallback for manifest scanning."""
        if WAKE_LOCK_PERMISSION in text:
            result.has_wake_lock_permission = True

        pkg_match = re.search(r'package="([^"]+)"', text)
        if pkg_match:
            result.package_name = pkg_match.group(1)

        label_match = re.search(r'android:label="([^"]+)"', text)
        if label_match:
            result.app_label = label_match.group(1)

        # Binary manifest: package name often in null-separated UTF-16LE
        if not result.package_name:
            pkg_match2 = re.search(
                r"package\x00{0,4}([\w.]+)", text, re.IGNORECASE
            )
            if pkg_match2:
                result.package_name = pkg_match2.group(1)

    # ------------------------------------------------------------------
    # DEX / smali analysis
    # ------------------------------------------------------------------

    def _analyze_dex_files(self, apk: zipfile.ZipFile, result: AnalysisResult) -> None:
        """Scan DEX files for wake lock API calls using string pattern matching."""
        dex_files = [n for n in apk.namelist() if re.match(r"classes\d*\.dex", n)]
        if not dex_files:
            result.errors.append("No DEX files found in APK")
            return

        for dex_name in dex_files:
            if self.verbose:
                print(f"  Scanning DEX: {dex_name}")
            try:
                dex_data = apk.read(dex_name)
                self._scan_dex_bytes(dex_data, dex_name, result)
                result.files_analyzed += 1
            except Exception as e:
                result.errors.append(f"Error reading {dex_name}: {e}")

    def _scan_dex_bytes(self, data: bytes, filename: str, result: AnalysisResult) -> None:
        """
        Scan raw DEX bytes for wake lock string references.

        DEX files contain a string pool; we extract UTF-8 strings and
        look for wake lock related patterns.
        """
        # Decode bytes as latin-1 to preserve all byte values
        text = data.decode("latin-1")

        # Check for WakeLock class reference
        if WAKE_LOCK_CLASS not in text and "WakeLock" not in text:
            return  # No wake lock usage in this DEX

        # Find acquire calls with timeout (long argument)
        # In DEX smali-level, acquire(long) is distinct from acquire()
        acquire_timeout_pattern = re.compile(
            r"invoke-virtual.*?Landroid/os/PowerManager\$WakeLock;->acquire\(J\)V"
        )
        # Look for acquire() without arguments
        acquire_pattern = re.compile(
            r"invoke-virtual.*?Landroid/os/PowerManager\$WakeLock;->acquire\(\)V"
        )
        release_pattern = re.compile(
            r"invoke-virtual.*?Landroid/os/PowerManager\$WakeLock;->release\b"
        )
        new_wake_lock_pattern = re.compile(
            r"invoke-virtual.*?Landroid/os/PowerManager;->newWakeLock"
        )

        lines = text.split("\n")
        for i, line in enumerate(lines):
            if acquire_timeout_pattern.search(line):
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="acquire_with_timeout",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                # Try to extract timeout constant from surrounding context
                timeout = self._extract_timeout_from_context(lines, i)
                if timeout is not None:
                    usage.timeout_ms = timeout
                    result.timed_acquires.append(timeout)
                result.wake_lock_usages.append(usage)
                result.acquire_count += 1

            elif acquire_pattern.search(line):
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="acquire",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                result.wake_lock_usages.append(usage)
                result.acquire_count += 1

            if release_pattern.search(line):
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="release",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                result.wake_lock_usages.append(usage)
                result.release_count += 1

            if new_wake_lock_pattern.search(line):
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="new_wake_lock",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                result.wake_lock_usages.append(usage)

        # Also scan string pool for literal timeout values next to WakeLock
        self._scan_string_pool_for_timeouts(text, filename, result)

    def _extract_timeout_from_context(
        self, lines: list, acquire_line_idx: int
    ) -> Optional[int]:
        """Look backwards from acquire() for a const-wide or long constant."""
        # Look up to 5 lines before the acquire call
        start = max(0, acquire_line_idx - 5)
        context = lines[start:acquire_line_idx]

        # const-wide/16/32 patterns in smali
        const_pattern = re.compile(
            r"const-wide(?:/\d+)?\s+\w+,\s*(0x[\da-fA-F]+|-?\d+)"
        )
        for line in reversed(context):
            m = const_pattern.search(line)
            if m:
                try:
                    return int(m.group(1), 0)
                except ValueError:
                    pass
        return None

    def _scan_string_pool_for_timeouts(
        self, text: str, filename: str, result: AnalysisResult
    ) -> None:
        """
        Scan string pool for common timeout values near WakeLock strings.
        This is a heuristic – not perfectly accurate.
        """
        # Look for long literals (e.g. 60000L, 300000L) near WakeLock strings
        timeout_pattern = re.compile(r"\b(\d{3,10})L?\b")
        wl_positions = [m.start() for m in re.finditer(r"WakeLock", text)]
        for pos in wl_positions:
            snippet = text[max(0, pos - 200): pos + 200]
            for m in timeout_pattern.finditer(snippet):
                val = int(m.group(1))
                # Plausible timeout: 1 second to 24 hours in ms
                if 1000 <= val <= 86_400_000:
                    if val not in result.timed_acquires:
                        result.timed_acquires.append(val)

    def _analyze_smali_if_present(
        self, apk: zipfile.ZipFile, result: AnalysisResult
    ) -> None:
        """If the APK contains pre-extracted smali files, analyze them too."""
        smali_files = [n for n in apk.namelist() if n.endswith(".smali")]
        for smali_name in smali_files:
            try:
                content = apk.read(smali_name).decode("utf-8", errors="replace")
                self._scan_smali_text(content, smali_name, result)
                result.files_analyzed += 1
            except Exception as e:
                result.errors.append(f"Error reading {smali_name}: {e}")

    def _scan_smali_text(
        self, content: str, filename: str, result: AnalysisResult
    ) -> None:
        """Scan a smali text file for wake lock patterns."""
        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()

            if "PowerManager$WakeLock;->acquire(J)V" in stripped:
                timeout = self._extract_timeout_from_context(lines, i)
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="acquire_with_timeout",
                    timeout_ms=timeout,
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                if timeout is not None and timeout not in result.timed_acquires:
                    result.timed_acquires.append(timeout)
                result.wake_lock_usages.append(usage)
                result.acquire_count += 1

            elif "PowerManager$WakeLock;->acquire()V" in stripped:
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="acquire",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                result.wake_lock_usages.append(usage)
                result.acquire_count += 1

            if "PowerManager$WakeLock;->release" in stripped:
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="release",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                result.wake_lock_usages.append(usage)
                result.release_count += 1

            if "PowerManager;->newWakeLock" in stripped:
                usage = WakeLockUsage(
                    file=filename,
                    line_number=i + 1,
                    usage_type="new_wake_lock",
                    context_lines=lines[max(0, i - 2): i + 3],
                )
                result.wake_lock_usages.append(usage)


# ------------------------------------------------------------------
# Reporting
# ------------------------------------------------------------------

def ms_to_human(ms: Optional[int]) -> str:
    if ms is None:
        return "N/A"
    if ms < 1000:
        return f"{ms} ms"
    s = ms / 1000
    if s < 60:
        return f"{s:.1f} s"
    m = s / 60
    if m < 60:
        return f"{m:.1f} min"
    h = m / 60
    return f"{h:.2f} h"


def print_report(result: AnalysisResult, verbose: bool = False) -> None:
    SEP = "=" * 60
    print(SEP)
    print("  WAKE LOCK ANALYSIS REPORT")
    print(SEP)
    print(f"  APK          : {result.apk_path}")
    print(f"  Package      : {result.package_name or 'unknown'}")
    print(f"  App Label    : {result.app_label or 'unknown'}")
    print(SEP)

    perm_status = "YES" if result.has_wake_lock_permission else "NO"
    perm_color = "\033[92m" if result.has_wake_lock_permission else "\033[91m"
    reset = "\033[0m"
    print(f"  WAKE_LOCK permission declared: {perm_color}{perm_status}{reset}")

    if not result.has_wake_lock_permission:
        print()
        print("  No WAKE_LOCK permission found. The app cannot hold wake")
        print("  locks. Any attempt to acquire one will be silently ignored")
        print("  (or throw an exception on some devices).")
        print(SEP)
        if result.errors:
            print("  Errors:")
            for e in result.errors:
                print(f"    - {e}")
        return

    print(f"  Protection level        : {result.permission_protection_level}")
    print()
    print(f"  acquire() calls         : {result.acquire_count}")
    print(f"  release() calls         : {result.release_count}")
    balance = "BALANCED" if result.is_balanced else "UNBALANCED (potential leak)"
    balance_color = "\033[92m" if result.is_balanced else "\033[93m"
    print(f"  acquire/release balance : {balance_color}{balance}{reset}")
    print()

    if result.timed_acquires:
        print(f"  Timed acquires ({len(result.timed_acquires)} found):")
        for t in sorted(result.timed_acquires):
            print(f"    - {t} ms  ({ms_to_human(t)})")
        print(f"  Max timeout            : {ms_to_human(result.max_timeout_ms)}")
        print(f"  Min timeout            : {ms_to_human(result.min_timeout_ms)}")
    else:
        print("  No explicit timeout values detected.")
        print("  The app may hold wake locks indefinitely until release() is called.")

    print()
    print(f"  Files analyzed          : {result.files_analyzed}")

    if verbose and result.wake_lock_usages:
        print()
        print("  Detailed usages:")
        for u in result.wake_lock_usages:
            print(f"    [{u.usage_type}] {u.file}:{u.line_number}", end="")
            if u.timeout_ms is not None:
                print(f"  timeout={ms_to_human(u.timeout_ms)}", end="")
            print()

    if result.errors:
        print()
        print("  Errors:")
        for e in result.errors:
            print(f"    - {e}")

    print(SEP)


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze an Android APK for Wake Lock permission and usage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk
  %(prog)s app.apk --verbose
  %(prog)s app.apk --json
  %(prog)s app.apk --json --output result.json
        """,
    )
    parser.add_argument("apk", help="Path to the APK file to analyze")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show detailed usage locations"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", help="Write JSON output to FILE"
    )
    args = parser.parse_args()

    analyzer = WakeLockAnalyzer(args.apk, verbose=args.verbose)
    try:
        result = analyzer.analyze()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json or args.output:
        data = json.dumps(result.summary(), indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(data)
            print(f"Results written to {args.output}")
        else:
            print(data)
    else:
        print_report(result, verbose=args.verbose)

    # Exit code: 0 = has permission, 1 = no permission
    sys.exit(0 if result.has_wake_lock_permission else 1)


if __name__ == "__main__":
    main()
