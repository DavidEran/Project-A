#!/usr/bin/env python3
"""
Play Integrity Analyzer - Static analysis tool for Android APKs.

Detects whether an APK uses the Google Play Integrity API, which apps
can use to identify sideloaded installs and block or redirect users to
the Play Store.

The tool reports a sideload risk level:
  HIGH   - App actively blocks or redirects non-Play installs.  Any of:
             • Checks UNRECOGNIZED_VERSION (appRecognitionVerdict for sideloads)
             • Checks UNLICENSED (appLicensingVerdict for non-Play-licensed installs)
             • Uses a remediation dialog / Play Store redirect
               (requestAndShowDialog, GET_LICENSED, CLOSE_UNKNOWN_SOURCE_DIALOG)
             • Checks installer source (getInstallerPackageName / com.android.vending)
  MEDIUM - App requests integrity tokens and inspects verdict fields, but no
           explicit blocking pattern was found — depends on server-side logic.
  LOW    - Integrity library present but no clear enforcement found.
  NONE   - No Play Integrity or SafetyNet detected.
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
# Includes both the original 'core' path (library <1.3) and the restructured
# path without 'core' introduced in library 1.3+.
CLASSIC_API_INDICATORS = [
    # library < 1.3 (original package layout)
    "com/google/android/play/core/integrity/IntegrityManager",
    "com/google/android/play/core/integrity/IntegrityManagerFactory",
    "com/google/android/play/core/integrity/IntegrityTokenRequest",
    "com/google/android/play/core/integrity/IntegrityTokenResponse",
    # library 1.3+ (restructured – 'core' removed from path)
    "com/google/android/play/integrity/IntegrityManager",
    "com/google/android/play/integrity/IntegrityManagerFactory",
    "com/google/android/play/integrity/IntegrityTokenRequest",
    "com/google/android/play/integrity/IntegrityTokenResponse",
]

# Standard (newer) Play Integrity API – preferred since Play Integrity 1.1
STANDARD_API_INDICATORS = [
    # library < 1.3
    "com/google/android/play/core/integrity/StandardIntegrityManager",
    "com/google/android/play/core/integrity/StandardIntegrityTokenProvider",
    "com/google/android/play/core/integrity/StandardIntegrityTokenRequest",
    # library 1.3+
    "com/google/android/play/integrity/StandardIntegrityManager",
    "com/google/android/play/integrity/StandardIntegrityTokenProvider",
    "com/google/android/play/integrity/StandardIntegrityTokenRequest",
]

# Method names that trigger an integrity check
REQUEST_METHOD_INDICATORS = [
    "requestIntegrityToken",
    "prepareIntegrityToken",    # Standard API warm-up call
    "requestAndShowDialog",     # Standard API dialog-based flow (library 1.2+)
                                # NOTE: also sets uses_remediation_dialog — see scanner
]

# Verdict-related strings that indicate the app inspects the integrity response.
# These are the JSON field names / enum values from the Play Integrity verdict.
VERDICT_INDICATORS = [
    # Field names
    "appRecognitionVerdict",
    "deviceRecognitionVerdict",
    "appLicensingVerdict",
    # appRecognitionVerdict values
    "PLAY_RECOGNIZED",
    "UNRECOGNIZED_VERSION",     # Non-Play install (sideload / Digital Turbine) → HIGH risk
    "UNEVALUATED",
    # appLicensingVerdict values
    "LICENSED",
    "UNLICENSED",               # Non-Play-licensed install (Digital Turbine) → HIGH risk
    # Legacy / alternative strings kept for coverage
    "NO_LICENSE",               # Seen in some older integrations
]

# Verdict values that definitively identify a non-Play-Store install.
# Both are returned for apps sideloaded via Digital Turbine or similar:
#   UNRECOGNIZED_VERSION → appRecognitionVerdict for unknown install sources
#   UNLICENSED           → appLicensingVerdict for apps not purchased/licensed via Play
SIDELOAD_VERDICTS = frozenset({"UNRECOGNIZED_VERSION", "UNLICENSED"})

# Kept for backwards compat (single canonical string used in older code paths)
SIDELOAD_VERDICT = "UNRECOGNIZED_VERSION"

# Play Integrity remediation dialog / Play Store redirect indicators.
# These constants appear when an app shows a "get this from the Play Store" popup
# or redirects the user, which blocks non-Play (e.g. Digital Turbine) users.
#   GET_LICENSED              → IntegrityDialogTypeCode: prompts user to license app via Play
#   CLOSE_UNKNOWN_SOURCE_DIALOG → IntegrityDialogTypeCode: warns user about sideloading
# requestAndShowDialog is also a remediation path but lives in REQUEST_METHOD_INDICATORS.
REMEDIATION_INDICATORS = [
    "GET_LICENSED",
    "CLOSE_UNKNOWN_SOURCE_DIALOG",
]

# Installer source check indicators.
# Apps that embed these strings are checking whether they were installed from Play Store.
# When combined with Play Integrity, this is a direct sideload-blocking pattern.
#   getInstallerPackageName → PackageManager API to retrieve installer package
#   getInstallSourceInfo    → Newer PackageManager API (API 30+) for install source details
#   com.android.vending     → Google Play Store package name; if hardcoded, the app is
#                             comparing the installer against Play Store
INSTALLER_CHECK_INDICATORS = [
    "getInstallerPackageName",
    "getInstallSourceInfo",
    "com.android.vending",
]

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
    # "classic_api" | "standard_api" | "token_request" | "verdict_check" |
    # "safetynet"   | "remediation"  | "installer_check"
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
    checks_verdict: bool = False         # Any verdict string found
    checks_unrecognized: bool = False    # UNRECOGNIZED_VERSION found (sideload signal)
    checks_unlicensed: bool = False      # UNLICENSED found (Digital Turbine / non-Play licensing)
    uses_remediation_dialog: bool = False  # Play Store redirect/dialog detected
    checks_installer_source: bool = False  # Installer package source check detected

    # Manifest indicators
    has_play_core_components: bool = False

    usages: list = field(default_factory=list)
    files_analyzed: int = 0
    errors: list = field(default_factory=list)

    @property
    def sideload_risk(self) -> str:
        """
        Estimated risk that sideloading (including Digital Turbine distribution)
        will trigger a block or redirect.

        HIGH   - App actively blocks or redirects non-Play installs via any of:
                 • Checks UNRECOGNIZED_VERSION or UNLICENSED after requesting a token
                 • Shows a remediation dialog (requestAndShowDialog, GET_LICENSED, etc.)
                 • Checks installer package source (getInstallerPackageName, com.android.vending)
        MEDIUM - App requests integrity tokens and inspects verdict fields, but no
                 explicit sideload-blocking pattern was found.  Behavior depends on
                 how the app handles non-Play verdicts server-side.
        LOW    - Play Integrity library present but no active enforcement detected.
        NONE   - No Play Integrity or SafetyNet detected.
        """
        if not self.uses_play_integrity and not self.uses_safetynet:
            return "NONE"
        # HIGH: any pattern that directly blocks or redirects non-Play installs
        if self.requests_token and (self.checks_unrecognized or self.checks_unlicensed):
            return "HIGH"
        if self.uses_remediation_dialog:
            return "HIGH"
        if self.checks_installer_source:
            return "HIGH"
        # MEDIUM: token requested + some verdict inspected, but no explicit blocking string
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
            "checks_unlicensed": self.checks_unlicensed,
            "uses_remediation_dialog": self.uses_remediation_dialog,
            "checks_installer_source": self.checks_installer_source,
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
        # "play/core/integrity" matches the original library layout (<1.3).
        # "play/integrity"      matches the restructured layout (1.3+) where
        #                       'core' was removed from the package path.
        # Both are needed: "play/integrity" is NOT a substring of "play/core/integrity".
        if not any(s in text for s in ["play/core/integrity", "play/integrity", "SafetyNet", "safetynet"]):
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
                        # requestAndShowDialog always presents a remediation dialog.
                        if method == "requestAndShowDialog":
                            result.uses_remediation_dialog = True
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
                        if verdict == "UNRECOGNIZED_VERSION":
                            result.checks_unrecognized = True
                        if verdict == "UNLICENSED":
                            result.checks_unlicensed = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="verdict_check",
                            matched_string=verdict,
                            context_lines=ctx,
                        ))

            for indicator in REMEDIATION_INDICATORS:
                if indicator in line:
                    key = ("remediation", indicator)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.uses_remediation_dialog = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="remediation",
                            matched_string=indicator,
                            context_lines=ctx,
                        ))

            for indicator in INSTALLER_CHECK_INDICATORS:
                if indicator in line:
                    key = ("installer_check", indicator)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.checks_installer_source = True
                        result.usages.append(IntegrityUsage(
                            file=filename,
                            line_number=i + 1,
                            usage_type="installer_check",
                            matched_string=indicator,
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
                    if method == "requestAndShowDialog":
                        result.uses_remediation_dialog = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="token_request", matched_string=method,
                        context_lines=ctx,
                    ))

            for verdict in VERDICT_INDICATORS:
                if verdict in stripped:
                    result.checks_verdict = True
                    if verdict == "UNRECOGNIZED_VERSION":
                        result.checks_unrecognized = True
                    if verdict == "UNLICENSED":
                        result.checks_unlicensed = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="verdict_check", matched_string=verdict,
                        context_lines=ctx,
                    ))

            for indicator in REMEDIATION_INDICATORS:
                if indicator in stripped:
                    result.uses_remediation_dialog = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="remediation", matched_string=indicator,
                        context_lines=ctx,
                    ))

            for indicator in INSTALLER_CHECK_INDICATORS:
                if indicator in stripped:
                    result.checks_installer_source = True
                    result.usages.append(IntegrityUsage(
                        file=filename, line_number=i + 1,
                        usage_type="installer_check", matched_string=indicator,
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
    print(f"  Play Integrity API present      : {yn(result.uses_play_integrity)}")
    if result.uses_play_integrity:
        print(f"    Classic API (IntegrityManager)          : {yn(result.uses_classic_api)}")
        print(f"    Standard API (StandardIntegrityManager) : {yn(result.uses_standard_api)}")
    print(f"  SafetyNet (legacy) present      : {yn(result.uses_safetynet)}")
    print()
    print(f"  Requests integrity token        : {yn(result.requests_token, RED)}")
    print(f"  Inspects verdict fields         : {yn(result.checks_verdict, RED)}")
    print(f"  Checks UNRECOGNIZED_VERSION     : {yn(result.checks_unrecognized, RED)}")
    print(f"  Checks UNLICENSED               : {yn(result.checks_unlicensed, RED)}")
    print(f"  Uses remediation dialog         : {yn(result.uses_remediation_dialog, RED)}")
    print(f"  Checks installer source         : {yn(result.checks_installer_source, RED)}")
    print(f"  Play Core manifest components   : {yn(result.has_play_core_components)}")
    print()

    explanations = {
        "NONE": (
            "No Play Integrity or SafetyNet detected.\n"
            "  Sideloaded or third-party distributed installs (e.g. Digital Turbine)\n"
            "  should work without being redirected or blocked by the app."
        ),
        "HIGH": (
            "This app actively blocks or redirects non-Play installs.\n"
            "  Apps installed via Digital Turbine or other third-party distributors\n"
            "  will be blocked or redirected to the Google Play Store.\n"
            "  Detected signals: " + ", ".join(filter(None, [
                "UNRECOGNIZED_VERSION check" if result.checks_unrecognized else "",
                "UNLICENSED check" if result.checks_unlicensed else "",
                "remediation dialog" if result.uses_remediation_dialog else "",
                "installer source check" if result.checks_installer_source else "",
            ]))
        ),
        "MEDIUM": (
            "This app requests integrity tokens and inspects verdict fields.\n"
            "  Whether a third-party install is blocked depends on how the app\n"
            "  handles non-Play verdicts.  Review the app's enforcement logic."
        ),
        "LOW": (
            "The Play Integrity library is present but no active enforcement\n"
            "  pattern was detected.  The app may use integrity for purposes\n"
            "  other than sideload detection (e.g. transaction protection).\n"
            "  Third-party installs are likely unaffected."
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
            "Reports whether a sideloaded or third-party distributed install\n"
            "(e.g. Digital Turbine) is likely to be blocked or redirected."
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
