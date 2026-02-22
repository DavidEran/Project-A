#!/usr/bin/env python3
"""
Privacy Policy Analyzer - Static analysis tool for Android APKs.

Checks whether an APK declares a privacy policy and identifies data-collection
practices by inspecting:
  1. AndroidManifest.xml - privacy policy URL meta-data, sensitive permissions,
     and Play Store metadata attributes.
  2. DEX string pools    - embedded privacy policy URLs, known analytics /
                           tracking SDK class names, and data-collection API calls.
  3. Smali files         - same patterns in pre-extracted assembly form.

Reports one of three overall verdicts:

  PRESENT  - A privacy policy reference was found AND data-collection SDKs or
             sensitive permissions are declared (policy covers the observed
             data practices).
  PARTIAL  - A privacy policy reference was found but no data-collection SDKs
             or sensitive permissions were detected, OR data-collection SDKs /
             sensitive permissions are present but no policy reference was
             found.
  MISSING  - No privacy policy reference found and no data-collection signals
             detected (or the app clearly collects data with no policy at all).
"""

import argparse
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Known URL schemes / patterns for privacy policy references embedded in APKs.
# Matches http(s) URLs containing common privacy-policy path segments.
PRIVACY_URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>]{5,200}(?:privacy[_\-]?policy|privacy|dataprivacy|'
    r'data[-_]policy|privacynotice|legal/privacy|terms[-_]privacy)[^\s\'"<>]*',
    re.IGNORECASE,
)

# AndroidManifest meta-data key names that hold a privacy policy URL.
PRIVACY_METAKEY_PATTERN = re.compile(
    r'privacy[_\-]?policy|privacyUrl|privacy_url|data_privacy',
    re.IGNORECASE,
)

# The Android 10+ app store privacy policy attribute.
PRIVACY_ATTR_PATTERN = re.compile(r'android:privacyPolicy', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Data-collection SDK signatures (class name prefixes found in the DEX string pool)
# ---------------------------------------------------------------------------

DATA_COLLECTION_SDKS: List[dict] = [
    # Analytics
    {"name": "Firebase Analytics",    "pattern": "com/google/firebase/analytics"},
    {"name": "Google Analytics (UA)", "pattern": "com/google/android/gms/analytics"},
    {"name": "Amplitude",             "pattern": "com/amplitude/api"},
    {"name": "Mixpanel",              "pattern": "com/mixpanel/android"},
    {"name": "Segment",               "pattern": "com/segment/analytics"},
    {"name": "Heap",                  "pattern": "io/heap/android"},
    {"name": "Countly",               "pattern": "ly/count/android"},
    # Advertising / attribution
    {"name": "Facebook Ads SDK",      "pattern": "com/facebook/ads"},
    {"name": "Facebook Analytics",    "pattern": "com/facebook/appevents"},
    {"name": "Adjust",                "pattern": "com/adjust/sdk"},
    {"name": "AppsFlyer",             "pattern": "com/appsflyer"},
    {"name": "Branch",                "pattern": "io/branch/referral"},
    {"name": "MoPub",                 "pattern": "com/mopub"},
    {"name": "AdMob",                 "pattern": "com/google/android/gms/ads"},
    # Crash / performance reporting
    {"name": "Crashlytics",           "pattern": "com/google/firebase/crashlytics"},
    {"name": "Sentry",                "pattern": "io/sentry/android"},
    {"name": "Bugsnag",               "pattern": "com/bugsnag/android"},
    {"name": "Instabug",              "pattern": "com/instabug/library"},
    # Identity / auth (may collect PII)
    {"name": "OneSignal",             "pattern": "com/onesignal"},
    {"name": "Braze (Appboy)",        "pattern": "com/braze"},
    {"name": "CleverTap",             "pattern": "com/clevertap/android"},
    {"name": "Intercom",              "pattern": "io/intercom/android"},
]

# ---------------------------------------------------------------------------
# Sensitive Android permissions
# ---------------------------------------------------------------------------

SENSITIVE_PERMISSIONS: List[dict] = [
    {"permission": "android.permission.ACCESS_FINE_LOCATION",    "data": "Precise location"},
    {"permission": "android.permission.ACCESS_COARSE_LOCATION",  "data": "Approximate location"},
    {"permission": "android.permission.READ_CONTACTS",           "data": "Contacts"},
    {"permission": "android.permission.WRITE_CONTACTS",          "data": "Contacts (write)"},
    {"permission": "android.permission.READ_CALL_LOG",           "data": "Call log"},
    {"permission": "android.permission.PROCESS_OUTGOING_CALLS",  "data": "Call log"},
    {"permission": "android.permission.READ_SMS",                "data": "SMS messages"},
    {"permission": "android.permission.RECEIVE_SMS",             "data": "SMS messages"},
    {"permission": "android.permission.SEND_SMS",                "data": "SMS messages"},
    {"permission": "android.permission.RECORD_AUDIO",            "data": "Microphone / audio"},
    {"permission": "android.permission.CAMERA",                  "data": "Camera"},
    {"permission": "android.permission.READ_EXTERNAL_STORAGE",   "data": "External storage (read)"},
    {"permission": "android.permission.READ_MEDIA_IMAGES",       "data": "Photos"},
    {"permission": "android.permission.READ_MEDIA_VIDEO",        "data": "Videos"},
    {"permission": "android.permission.READ_MEDIA_AUDIO",        "data": "Audio files"},
    {"permission": "android.permission.BODY_SENSORS",            "data": "Body sensors / health"},
    {"permission": "android.permission.ACTIVITY_RECOGNITION",    "data": "Physical activity"},
    {"permission": "android.permission.GET_ACCOUNTS",            "data": "Account list"},
    {"permission": "android.permission.READ_PHONE_STATE",        "data": "Device / phone identifiers"},
    {"permission": "android.permission.READ_PHONE_NUMBERS",      "data": "Phone number"},
    {"permission": "com.google.android.gms.permission.AD_ID",    "data": "Advertising ID"},
]

# Build a quick lookup set for permission names.
SENSITIVE_PERMISSION_NAMES = {p["permission"] for p in SENSITIVE_PERMISSIONS}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SdkDetection:
    """A single detected data-collection SDK."""
    sdk_name: str
    matched_pattern: str
    file: str
    line_number: int


@dataclass
class PrivacyPolicyResult:
    """Complete analysis result for privacy policy detection in an APK."""
    apk_path: str
    package_name: str
    app_label: str

    # Privacy policy presence
    has_privacy_policy: bool = False
    policy_urls: List[str] = field(default_factory=list)
    policy_found_in: List[str] = field(default_factory=list)  # "manifest", "dex", "smali"

    # Data collection signals
    detected_sdks: List[SdkDetection] = field(default_factory=list)
    declared_sensitive_permissions: List[dict] = field(default_factory=list)

    # Metadata
    files_analyzed: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def collects_data(self) -> bool:
        """True if any data-collection SDK or sensitive permission was found."""
        return bool(self.detected_sdks or self.declared_sensitive_permissions)

    @property
    def unique_sdk_names(self) -> List[str]:
        seen = set()
        names = []
        for s in self.detected_sdks:
            if s.sdk_name not in seen:
                seen.add(s.sdk_name)
                names.append(s.sdk_name)
        return names

    @property
    def verdict(self) -> str:
        """
        PRESENT - Privacy policy found AND data-collection signals detected.
        PARTIAL - Policy found but no data-collection signals, OR data-collection
                  signals found but no policy reference.
        MISSING - No privacy policy found and no data-collection signals at all
                  (clean app), OR data clearly collected with no policy.
        """
        if self.has_privacy_policy and self.collects_data:
            return "PRESENT"
        if self.has_privacy_policy or self.collects_data:
            return "PARTIAL"
        return "MISSING"

    def summary(self) -> dict:
        return {
            "apk": self.apk_path,
            "package": self.package_name,
            "label": self.app_label,
            "verdict": self.verdict,
            "has_privacy_policy": self.has_privacy_policy,
            "policy_urls": self.policy_urls,
            "policy_found_in": self.policy_found_in,
            "collects_data": self.collects_data,
            "detected_sdks": self.unique_sdk_names,
            "declared_sensitive_permissions": [
                p["permission"] for p in self.declared_sensitive_permissions
            ],
            "data_categories": sorted({
                p["data"] for p in self.declared_sensitive_permissions
            }),
            "files_analyzed": self.files_analyzed,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class PrivacyPolicyAnalyzer:
    """Analyzes an Android APK for privacy policy presence and data collection."""

    def __init__(self, apk_path: str, verbose: bool = False):
        self.apk_path = apk_path
        self.verbose = verbose

    def analyze(self) -> PrivacyPolicyResult:
        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK not found: {self.apk_path}")
        if not zipfile.is_zipfile(self.apk_path):
            raise ValueError(f"Not a valid APK (zip) file: {self.apk_path}")

        result = PrivacyPolicyResult(
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

    def _analyze_manifest(self, apk: zipfile.ZipFile, result: PrivacyPolicyResult) -> None:
        try:
            manifest_data = apk.read("AndroidManifest.xml")
            try:
                manifest_text = manifest_data.decode("utf-8")
                self._parse_text_manifest(manifest_text, result)
            except UnicodeDecodeError:
                self._parse_binary_manifest(manifest_data, result)
        except KeyError:
            result.errors.append("AndroidManifest.xml not found in APK")

    def _parse_text_manifest(self, text: str, result: PrivacyPolicyResult) -> None:
        # Extract package / label via XML parser for accuracy.
        try:
            root = ET.fromstring(text)
            result.package_name = root.get("package", "")
            app_el = root.find("application")
            if app_el is not None:
                result.app_label = app_el.get(
                    "{http://schemas.android.com/apk/res/android}label", ""
                )
            # Collect declared permissions.
            for perm_el in root.iter("uses-permission"):
                name = perm_el.get(
                    "{http://schemas.android.com/apk/res/android}name", ""
                )
                self._record_permission(name, result)
            # Check meta-data for privacy policy key/value pairs.
            for meta_el in root.iter("meta-data"):
                key = meta_el.get(
                    "{http://schemas.android.com/apk/res/android}name", ""
                )
                value = meta_el.get(
                    "{http://schemas.android.com/apk/res/android}value", ""
                )
                if PRIVACY_METAKEY_PATTERN.search(key):
                    result.has_privacy_policy = True
                    if value and value not in result.policy_urls:
                        result.policy_urls.append(value)
                    if "manifest" not in result.policy_found_in:
                        result.policy_found_in.append("manifest")
            # android:privacyPolicy attribute on <application>
            if app_el is not None:
                pp_attr = app_el.get(
                    "{http://schemas.android.com/apk/res/android}privacyPolicy", ""
                )
                if pp_attr:
                    result.has_privacy_policy = True
                    if pp_attr not in result.policy_urls:
                        result.policy_urls.append(pp_attr)
                    if "manifest" not in result.policy_found_in:
                        result.policy_found_in.append("manifest")
        except ET.ParseError as e:
            result.errors.append(f"Manifest XML parse error: {e}")

        # Fall-through: also regex-scan the raw text (catches binary XML fragments
        # decoded as UTF-8 with some garbage chars).
        self._regex_scan_text(text, "manifest", result)

    def _parse_binary_manifest(self, data: bytes, result: PrivacyPolicyResult) -> None:
        """Extract metadata from binary AXML via UTF-16LE and latin-1 decoding."""
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
            self._regex_scan_text(utf16_text, "manifest", result)
            # Collect permissions from binary XML via regex.
            for perm in re.findall(r'android\.permission\.[A-Z_]+', utf16_text):
                self._record_permission(perm, result)
            for perm in re.findall(r'com\.google\.android\.gms\.permission\.[A-Z_]+', utf16_text):
                self._record_permission(perm, result)
        except Exception:
            pass
        # Also scan as latin-1.
        latin1_text = data.decode("latin-1")
        self._regex_scan_text(latin1_text, "manifest", result)
        for perm in re.findall(r'android\.permission\.[A-Z_]+', latin1_text):
            self._record_permission(perm, result)
        for perm in re.findall(r'com\.google\.android\.gms\.permission\.[A-Z_]+', latin1_text):
            self._record_permission(perm, result)

    def _record_permission(self, name: str, result: PrivacyPolicyResult) -> None:
        if name in SENSITIVE_PERMISSION_NAMES:
            # Find the matching entry to get the human-readable data category.
            for p in SENSITIVE_PERMISSIONS:
                if p["permission"] == name:
                    if p not in result.declared_sensitive_permissions:
                        result.declared_sensitive_permissions.append(p)
                    break

    def _regex_scan_text(self, text: str, source: str, result: PrivacyPolicyResult) -> None:
        """Scan raw text for privacy policy URLs and meta-data key patterns."""
        for url in PRIVACY_URL_PATTERN.findall(text):
            result.has_privacy_policy = True
            if url not in result.policy_urls:
                result.policy_urls.append(url)
            if source not in result.policy_found_in:
                result.policy_found_in.append(source)
        if PRIVACY_ATTR_PATTERN.search(text):
            result.has_privacy_policy = True
            if source not in result.policy_found_in:
                result.policy_found_in.append(source)

    # ------------------------------------------------------------------
    # DEX analysis
    # ------------------------------------------------------------------

    def _analyze_dex_files(self, apk: zipfile.ZipFile, result: PrivacyPolicyResult) -> None:
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
        self, data: bytes, filename: str, result: PrivacyPolicyResult
    ) -> None:
        """
        Scan raw DEX bytes for privacy policy URLs and SDK class references.

        Decoded as latin-1 so every byte is preserved and string pool content
        can be matched without misinterpreting high bytes.
        """
        text = data.decode("latin-1")

        # Privacy policy URLs embedded in the DEX string pool.
        for url in PRIVACY_URL_PATTERN.findall(text):
            result.has_privacy_policy = True
            if url not in result.policy_urls:
                result.policy_urls.append(url)
            if "dex" not in result.policy_found_in:
                result.policy_found_in.append("dex")

        # Data-collection SDK detection.
        seen_in_file: set = set()
        lines = text.split("\n")
        for i, line in enumerate(lines):
            for sdk in DATA_COLLECTION_SDKS:
                pattern = sdk["pattern"]
                if pattern in line:
                    key = (sdk["name"], filename)
                    if key not in seen_in_file:
                        seen_in_file.add(key)
                        result.detected_sdks.append(SdkDetection(
                            sdk_name=sdk["name"],
                            matched_pattern=pattern,
                            file=filename,
                            line_number=i + 1,
                        ))

    # ------------------------------------------------------------------
    # Smali analysis
    # ------------------------------------------------------------------

    def _analyze_smali_if_present(
        self, apk: zipfile.ZipFile, result: PrivacyPolicyResult
    ) -> None:
        smali_files = [n for n in apk.namelist() if n.endswith(".smali")]
        for smali_name in smali_files:
            try:
                content = apk.read(smali_name).decode("utf-8", errors="replace")
                self._scan_smali_text(content, smali_name, result)
                result.files_analyzed += 1
            except Exception as e:
                result.errors.append(f"Error reading {smali_name}: {e}")

    def _scan_smali_text(
        self, content: str, filename: str, result: PrivacyPolicyResult
    ) -> None:
        """Scan a smali text file for privacy policy URLs and SDK patterns."""
        for url in PRIVACY_URL_PATTERN.findall(content):
            result.has_privacy_policy = True
            if url not in result.policy_urls:
                result.policy_urls.append(url)
            if "smali" not in result.policy_found_in:
                result.policy_found_in.append("smali")

        lines = content.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            for sdk in DATA_COLLECTION_SDKS:
                if sdk["pattern"] in stripped:
                    result.detected_sdks.append(SdkDetection(
                        sdk_name=sdk["name"],
                        matched_pattern=sdk["pattern"],
                        file=filename,
                        line_number=i + 1,
                    ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(result: PrivacyPolicyResult, verbose: bool = False) -> None:
    SEP = "=" * 60
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"

    verdict = result.verdict
    verdict_color = {
        "PRESENT": GREEN,
        "PARTIAL": YELLOW,
        "MISSING": RED,
    }.get(verdict, RESET)

    def yn(flag: bool, color_if_yes: str = "") -> str:
        if flag:
            return f"{color_if_yes}YES{RESET}" if color_if_yes else "YES"
        return "no"

    print(SEP)
    print("  PRIVACY POLICY REPORT")
    print(SEP)
    print(f"  APK     : {result.apk_path}")
    print(f"  Package : {result.package_name or 'unknown'}")
    print(f"  Label   : {result.app_label or 'unknown'}")
    print(SEP)
    print(f"  VERDICT: {verdict_color}{verdict}{RESET}")
    print()

    print(f"  Privacy policy reference found : {yn(result.has_privacy_policy, GREEN)}")
    if result.policy_urls:
        print("  Policy URL(s):")
        for url in result.policy_urls:
            print(f"    {url}")
    if result.policy_found_in:
        print(f"  Found in: {', '.join(result.policy_found_in)}")
    print()

    print(f"  Data-collection SDKs detected  : {yn(bool(result.detected_sdks), YELLOW)}")
    if result.unique_sdk_names:
        for name in result.unique_sdk_names:
            print(f"    - {name}")
    print()

    print(f"  Sensitive permissions declared : {yn(bool(result.declared_sensitive_permissions), YELLOW)}")
    if result.declared_sensitive_permissions:
        for p in result.declared_sensitive_permissions:
            print(f"    - {p['permission']}")
            print(f"        Data category: {p['data']}")
    print()

    data_categories = sorted({p["data"] for p in result.declared_sensitive_permissions})
    if data_categories:
        print("  Data categories inferred from permissions:")
        for cat in data_categories:
            print(f"    * {cat}")
        print()

    explanations = {
        "PRESENT": (
            "A privacy policy reference was found and data-collection\n"
            "  activity was detected. The policy should disclose how the\n"
            "  collected data is used. Verify the linked policy covers\n"
            "  the SDKs and permissions listed above."
        ),
        "PARTIAL": (
            "Either a privacy policy was found with no detected data\n"
            "  collection, or data collection was detected without a\n"
            "  privacy policy reference. Review carefully:\n"
            "  - If data IS collected, a policy is legally required in\n"
            "    most jurisdictions (GDPR, CCPA, Google Play policy).\n"
            "  - If no data is collected, the policy reference may be\n"
            "    a placeholder or from a bundled SDK."
        ),
        "MISSING": (
            "No privacy policy reference was found.\n"
            "  If the app collects any user data (even via third-party\n"
            "  SDKs), a privacy policy is required by Google Play and\n"
            "  applicable data-protection laws."
        ),
    }
    print(f"  {explanations.get(verdict, '')}")
    print()
    print(f"  Files analyzed: {result.files_analyzed}")

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
            "Analyze an Android APK for privacy policy presence and\n"
            "data-collection practices."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk
  %(prog)s app.apk --verbose
  %(prog)s app.apk --json
  %(prog)s app.apk --json --output result.json

Exit codes:
  0  Privacy policy found and data collection detected (PRESENT)
  1  Partial coverage or mismatch (PARTIAL)
  2  No privacy policy found (MISSING)
        """,
    )
    parser.add_argument("apk", help="Path to the APK file to analyze")
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show detailed scan progress",
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results as JSON"
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE", help="Write JSON output to FILE"
    )
    args = parser.parse_args()

    analyzer = PrivacyPolicyAnalyzer(args.apk, verbose=args.verbose)
    try:
        result = analyzer.analyze()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(3)

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

    exit_codes = {"PRESENT": 0, "PARTIAL": 1, "MISSING": 2}
    sys.exit(exit_codes.get(result.verdict, 2))


if __name__ == "__main__":
    main()
