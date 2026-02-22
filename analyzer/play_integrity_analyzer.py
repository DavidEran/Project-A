#!/usr/bin/env python3
"""
Play Integrity Analyzer - Static analysis tool for Android APKs.

Detects whether an APK uses the Google Play Integrity API, which apps
can use to identify sideloaded installs and block or redirect users to
the Play Store.

The tool reports a sideload risk level:
  HIGH   - App checks for UNRECOGNIZED_VERSION (the exact sideload verdict)
  MEDIUM - App requests tokens and inspects verdict fields
  LOW    - Integrity library present but no clear enforcement found
  NONE   - No Play Integrity or SafetyNet detected
"""

import argparse
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Classic Play Integrity API (com.google.android.play:integrity library)
CLASSIC_API_INDICATORS = [
    "com/google/android/play/core/integrity/IntegrityManager",
    "com/google/android/play/core/integrity/IntegrityManagerFactory",
    "com/google/android/play/core/integrity/IntegrityTokenRequest",
    "com/google/android/play/core/integrity/IntegrityTokenResponse",
]

# Standard (newer) Play Integrity API – preferred since Play Integrity 1.1
STANDARD_API_INDICATORS = [
    "com/google/android/play/core/integrity/StandardIntegrityManager",
    "com/google/android/play/core/integrity/StandardIntegrityTokenProvider",
    "com/google/android/play/core/integrity/StandardIntegrityTokenRequest",
]

# Method names that trigger an integrity check
REQUEST_METHOD_INDICATORS = [
    "requestIntegrityToken",
    "prepareIntegrityToken",   # Standard API warm-up call
]

# Verdict-related strings that indicate the app inspects the integrity response.
# These are the JSON field names / enum values from the Play Integrity verdict.
VERDICT_INDICATORS = [
    "appRecognitionVerdict",
    "PLAY_RECOGNIZED",
    "UNRECOGNIZED_VERSION",    # Issued for sideloaded / modified installs
    "UNEVALUATED",
    "deviceRecognitionVerdict",
    "appLicensingVerdict",
    "NO_LICENSE",
    "LICENSED",
]

# The specific verdict value issued when an app is sideloaded
SIDELOAD_VERDICT = "UNRECOGNIZED_VERSION"

# Legacy SafetyNet API (deprecated by Google, superseded by Play Integrity)
SAFETYNET_INDICATORS = [
    "com/google/android/gms/safetynet/SafetyNet",
    "com/google/android/gms/safetynet/SafetyNetClient",
    "com/google/android/gms/safetynet/SafetyNetApi",
]

# Play Core components that may appear in AndroidManifest.xml
PLAY_CORE_MANIFEST_INDICATORS = [
    "com.google.android.play.core",
]


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IntegrityUsage:
    """A single detected Play Integrity or SafetyNet API usage site."""
    file: str
    line_number: int
    # "classic_api" | "standard_api" | "token_request" | "verdict_check" | "safetynet"
    usage_type: str
    matched_string: str
    context_lines: list = field(default_factory=list)


@dataclass
class IntegrityAnalysisResult:
    """Complete analysis result for Play Integrity detection in an APK."""
    apk_path: str
    package_name: str
    app_label: str

    # Presence flags
    uses_play_integrity: bool = False    # Any Play Integrity API class found
    uses_classic_api: bool = False       # IntegrityManager (classic) API
    uses_standard_api: bool = False      # StandardIntegrityManager (newer) API
    uses_safetynet: bool = False         # Legacy SafetyNet (deprecated)

    # Enforcement signals
    requests_token: bool = False         # requestIntegrityToken / prepareIntegrityToken found
    checks_verdict: bool = False         # Verdict strings found (appRecognitionVerdict etc.)
    checks_unrecognized: bool = False    # UNRECOGNIZED_VERSION found (strongest sideload signal)

    # Manifest indicators
    has_play_core_components: bool = False

    usages: list = field(default_factory=list)
    files_analyzed: int = 0
    errors: list = field(default_factory=list)

    @property
    def sideload_risk(self) -> str:
        """
        Estimated risk that sideloading will trigger a block or redirect.

        HIGH   - App requests integrity tokens AND explicitly handles
                 UNRECOGNIZED_VERSION, the verdict issued for sideloaded installs.
        MEDIUM - App requests integrity tokens AND inspects verdict fields,
                 but UNRECOGNIZED_VERSION was not found in the binary.
        LOW    - Play Integrity library present but no clear enforcement found.
        NONE   - No Play Integrity or SafetyNet detected.
        """
        if not self.uses_play_integrity and not self.uses_safetynet:
            return "NONE"
        if self.requests_token and self.checks_unrecognized:
            return "HIGH"
        if self.requests_token and self.checks_verdict:
            return "MEDIUM"
        return "LOW"

    def summary(self) -> dict:
        return {
            "apk": self.apk_path,
            "package": self.package_name,
            "label": self.app_label,
            "uses_play_integrity": self.uses_play_integrity,
            "uses_classic_api": self.uses_classic_api,
            "uses_standard_api": self.uses_standard_api,
            "uses_safetynet": self.uses_safetynet,
            "requests_token": self.requests_token,
            "checks_verdict": self.checks_verdict,
            "checks_unrecognized_version": self.checks_unrecognized,
            "has_play_core_components": self.has_play_core_components,
            "sideload_risk": self.sideload_risk,
            "files_analyzed": self.files_analyzed,
            "errors": self.errors,
            "usages": [
                {
                    "file": u.file,
                    "line": u.line_number,
                    "type": u.usage_type,
                    "matched": u.matched_string,
                }
                for u in self.usages
            ],
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class PlayIntegrityAnalyzer:
    """Analyzes an Android APK for Google Play Integrity API usage."""

    def __init__(self, apk_path: str, verbose: bool = False):
        self.apk_path = apk_path
        self.verbose = verbose

    def analyze(self) -> IntegrityAnalysisResult:
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK not found: {self.apk_path}")

        if not zipfile.is_zipfile(self.apk_path):
            raise ValueError(f"Not a valid APK (zip) file: {self.apk_path}")

        result = IntegrityAnalysisResult(
            apk_path=self.apk_path,
            package_name="",
            app_label="",
        )

        with zipfile.ZipFile(self.apk_path, "r") as apk:
            self._analyze_manifest(apk, result)
            self._analyze_dex_files(apk, result)
            self._analyze_smali_if_present(apk, result)

        return result

    # ------------------------------------------------------------------
    # Manifest analysis
    # ------------------------------------------------------------------

    def _analyze_manifest(self, apk: zipfile.ZipFile, result: IntegrityAnalysisResult) -> None:
        """Parse AndroidManifest.xml (binary or text) for Play Core components."""
        try:
            manifest_data = apk.read("AndroidManifest.xml")
            try:
                manifest_text = manifest_data.decode("utf-8")
                self._parse_text_manifest(manifest_text, result)
            except UnicodeDecodeError:
                self._parse_binary_manifest(manifest_data, result)
        except KeyError:
            result.errors.append("AndroidManifest.xml not found in APK")

    def _parse_text_manifest(self, text: str, result: IntegrityAnalysisResult) -> None:
        try:
            root = ET.fromstring(text)
            result.package_name = root.get("package", "")
            app_el = root.find("application")
            if app_el is not None:
                result.app_label = app_el.get(
                    "{http://schemas.android.com/apk/res/android}label", ""
                )
        except ET.ParseError as e:
            result.errors.append(f"Manifest XML parse error: {e}")
        self._scan_manifest_text(text, result)

    def _parse_binary_manifest(self, data: bytes, result: IntegrityAnalysisResult) -> None:
        """Extract metadata and Play Core indicators from binary AXML."""
        # Android binary XML stores strings as UTF-16LE in its string pool.
        try:
            utf16_text = data.decode("utf-16-le", errors="ignore")
            if not result.package_name:
                m = re.search(r'package="([^"]+)"', utf16_text)
                if m:
                    result.package_name = m.group(1)
            if not result.app_label:
                m = re.search(r'android:label="([^"]+)"', utf16_text)
                if m:
                    result.app_label = m.group(1)
        except Exception:
            pass
        # Also scan the raw bytes decoded as latin-1 to catch all string formats.
        latin1_text = data.decode("latin-1")
        self._scan_manifest_text(latin1_text, result)

    def _scan_manifest_text(self, text: str, result: IntegrityAnalysisResult) -> None:
        """Scan manifest text for Play Core component declarations."""
        if not result.package_name:
            m = re.search(r'package="([^"]+)"', text)
            if m:
                result.package_name = m.group(1)
        if not result.app_label:
            m = re.search(r'android:label="([^"]+)"', text)
            if m:
                result.app_label = m.group(1)
        for indicator in PLAY_CORE_MANIFEST_INDICATORS:
            if indicator in text:
                result.has_play_core_components = True
                break

    # ------------------------------------------------------------------
    # DEX analysis
    # ------------------------------------------------------------------

    def _analyze_dex_files(self, apk: zipfile.ZipFile, result: IntegrityAnalysisResult) -> None:
        """Scan DEX files for Play Integrity string references."""
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

    def _scan_dex_bytes(
        self, data: bytes, filename: str, result: IntegrityAnalysisResult
    ) -> None:
        """
        Scan raw DEX bytes for Play Integrity string references.

        DEX files contain a UTF-8 string pool.  Decoding as latin-1 preserves
        every byte value so that string pattern matching works without
        misinterpreting high bytes.  Class names and method names appear
        verbatim in the string pool, separated by NUL / control characters
        that become innocuous characters in latin-1.
        """
        text = data.decode("latin-1")

        # Fast pre-check: skip DEX files with no relevant strings at all.
        if not any(s in text for s in ["play/core/integrity", "SafetyNet", "safetynet"]):
            return

        # Track what we've already recorded from this file to avoid flooding
        # the usages list with duplicate entries from the string pool.
        seen_in_file: set = set()

        lines = text.split("\n")
        for i, line in enumerate(lines):
            ctx = lines[max(0, i - 1): i + 2]

            for indicator in CLASSIC_API_INDICATORS:
                if indicator in line:
                    key = ("classic_api", indicator)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.uses_play_integrity = True
                        result.uses_classic_api = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="classic_api",
                            matched_string=indicator,
                            context_lines=ctx,
                        ))

            for indicator in STANDARD_API_INDICATORS:
                if indicator in line:
                    key = ("standard_api", indicator)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.uses_play_integrity = True
                        result.uses_standard_api = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="standard_api",
                            matched_string=indicator,
                            context_lines=ctx,
                        ))

            for method in REQUEST_METHOD_INDICATORS:
                if method in line:
                    key = ("token_request", method)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.uses_play_integrity = True
                        result.requests_token = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="token_request",
                            matched_string=method,
                            context_lines=ctx,
                        ))

            for verdict in VERDICT_INDICATORS:
                if verdict in line:
                    key = ("verdict_check", verdict)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.checks_verdict = True
                        if verdict == SIDELOAD_VERDICT:
                            result.checks_unrecognized = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="verdict_check",
                            matched_string=verdict,
                            context_lines=ctx,
                        ))

            for indicator in SAFETYNET_INDICATORS:
                if indicator in line:
                    key = ("safetynet", indicator)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.uses_safetynet = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="safetynet",
                            matched_string=indicator,
                            context_lines=ctx,
                        ))

    def _analyze_smali_if_present(
        self, apk: zipfile.ZipFile, result: IntegrityAnalysisResult
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
        self, content: str, filename: str, result: IntegrityAnalysisResult
    ) -> None:
        """Scan a smali text file for Play Integrity patterns."""
        lines = content.splitlines()
        for i, line in enumerate(lines):
            ctx = lines[max(0, i - 1): i + 2]
            stripped = line.strip()

            for indicator in CLASSIC_API_INDICATORS:
                if indicator in stripped:
                    result.uses_play_integrity = True
                    result.uses_classic_api = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="classic_api", matched_string=indicator,
                        context_lines=ctx,
                    ))

            for indicator in STANDARD_API_INDICATORS:
                if indicator in stripped:
                    result.uses_play_integrity = True
                    result.uses_standard_api = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="standard_api", matched_string=indicator,
                        context_lines=ctx,
                    ))

            for method in REQUEST_METHOD_INDICATORS:
                if method in stripped:
                    result.uses_play_integrity = True
                    result.requests_token = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="token_request", matched_string=method,
                        context_lines=ctx,
                    ))

            for verdict in VERDICT_INDICATORS:
                if verdict in stripped:
                    result.checks_verdict = True
                    if verdict == SIDELOAD_VERDICT:
                        result.checks_unrecognized = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="verdict_check", matched_string=verdict,
                        context_lines=ctx,
                    ))

            for indicator in SAFETYNET_INDICATORS:
                if indicator in stripped:
                    result.uses_safetynet = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="safetynet", matched_string=indicator,
                        context_lines=ctx,
                    ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(result: IntegrityAnalysisResult, verbose: bool = False) -> None:
    SEP = "=" * 60
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"

    risk = result.sideload_risk
    risk_color = {
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": YELLOW,
        "NONE": GREEN,
    }.get(risk, RESET)

    def yn(flag: bool, color_if_yes: str = "") -> str:
        if flag:
            return f"{color_if_yes}YES{RESET}" if color_if_yes else "YES"
        return "no"

    print(SEP)
    print("  PLAY INTEGRITY / SIDELOAD RISK REPORT")
    print(SEP)
    print(f"  APK     : {result.apk_path}")
    print(f"  Package : {result.package_name or 'unknown'}")
    print(f"  Label   : {result.app_label or 'unknown'}")
    print(SEP)
    print(f"  SIDELOAD RISK: {risk_color}{risk}{RESET}")
    print()
    print(f"  Play Integrity API present   : {yn(result.uses_play_integrity)}")
    if result.uses_play_integrity:
        print(f"    Classic API (IntegrityManager)          : {yn(result.uses_classic_api)}")
        print(f"    Standard API (StandardIntegrityManager) : {yn(result.uses_standard_api)}")
    print(f"  SafetyNet (legacy) present   : {yn(result.uses_safetynet)}")
    print()
    print(f"  Requests integrity token     : {yn(result.requests_token, RED)}")
    print(f"  Inspects verdict fields      : {yn(result.checks_verdict, RED)}")
    print(f"  Checks UNRECOGNIZED_VERSION  : {yn(result.checks_unrecognized, RED)}")
    print(f"  Play Core manifest components: {yn(result.has_play_core_components)}")
    print()

    explanations = {
        "NONE": (
            "No Play Integrity or SafetyNet detected.\n"
            "  Sideloaded installs should work without being redirected\n"
            "  or blocked by the app."
        ),
        "HIGH": (
            "This app explicitly handles UNRECOGNIZED_VERSION,\n"
            "  the verdict value issued for sideloaded or modified installs.\n"
            "  Sideloading this app will very likely trigger a block or\n"
            "  redirect to the Google Play Store."
        ),
        "MEDIUM": (
            "This app requests integrity tokens and inspects verdict fields.\n"
            "  Sideloaded installs may be blocked depending on how the app\n"
            "  handles non-Play install verdicts."
        ),
        "LOW": (
            "The Play Integrity library is present but no strong enforcement\n"
            "  pattern was detected. The app may use integrity for purposes\n"
            "  other than sideload detection (e.g. transaction protection).\n"
            "  Sideloading may or may not be affected."
        ),
    }
    print(f"  {explanations.get(risk, '')}")
    print()
    print(f"  Files analyzed: {result.files_analyzed}")

    if verbose and result.usages:
        print()
        print("  Detected indicators:")
        seen: set = set()
        for u in result.usages:
            key = (u.usage_type, u.matched_string)
            if key not in seen:
                seen.add(key)
                print(f"    [{u.usage_type:15s}] {u.matched_string!r}  ({u.file}:{u.line_number})")

    if result.errors:
        print()
        print("  Errors:")
        for e in result.errors:
            print(f"    - {e}")

    print(SEP)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze an Android APK for Google Play Integrity API usage.\n"
            "Reports whether a sideloaded install is likely to be blocked\n"
            "or redirected to the Play Store."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk
  %(prog)s app.apk --verbose
  %(prog)s app.apk --json
  %(prog)s app.apk --json --output result.json

Exit codes:
  0  No Play Integrity detected (safe to sideload)
  1  Play Integrity detected (sideloading may be blocked)
        """,
    )
    parser.add_argument("apk", help="Path to the APK file to analyze")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed indicator locations",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", help="Write JSON output to FILE"
    )
    args = parser.parse_args()

    analyzer = PlayIntegrityAnalyzer(args.apk, verbose=args.verbose)
    try:
        result = analyzer.analyze()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

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

    # Exit 0 = no integrity (safe), 1 = integrity detected
    sys.exit(0 if not result.uses_play_integrity and not result.uses_safetynet else 1)


if __name__ == "__main__":
    main()
