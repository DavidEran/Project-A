#!/usr/bin/env python3
"""
Unit tests for the Play Integrity Analyzer.
"""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from play_integrity_analyzer import (
    PlayIntegrityAnalyzer,
    IntegrityAnalysisResult,
    IntegrityUsage,
    print_report,
    CLASSIC_API_INDICATORS,
    STANDARD_API_INDICATORS,
    VERDICT_INDICATORS,
    SAFETYNET_INDICATORS,
    SIDELOAD_VERDICT,
    SIDELOAD_VERDICTS,
    REMEDIATION_INDICATORS,
    INSTALLER_CHECK_INDICATORS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_apk(manifest_content: str, dex_content: bytes = b"") -> bytes:
    """Create a minimal APK zip in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
        if dex_content:
            zf.writestr("classes.dex", dex_content)
    return buf.getvalue()


def make_manifest(package: str, label: str = "TestApp",
                  play_core_service: bool = False) -> str:
    service = ""
    if play_core_service:
        service = (
            '    <service android:name="com.google.android.play.core.tasks.PlayCoreTasksService" />\n'
        )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}">
    <application android:label="{label}">
{service}    </application>
</manifest>"""


def write_tmp_apk(apk_bytes: bytes) -> str:
    """Write APK bytes to a temp file and return the path."""
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        f.write(apk_bytes)
        return f.name


def analyze(manifest: str, dex: bytes = b"") -> IntegrityAnalysisResult:
    """Create a temp APK and run PlayIntegrityAnalyzer on it."""
    tmp = write_tmp_apk(make_apk(manifest, dex))
    try:
        return PlayIntegrityAnalyzer(tmp).analyze()
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# DEX byte sequences that simulate string pool content
# ---------------------------------------------------------------------------

# Classic API - IntegrityManagerFactory class descriptor
DEX_CLASSIC_FACTORY = b"Lcom/google/android/play/core/integrity/IntegrityManagerFactory;\n"

# Classic API - IntegrityManager interface descriptor
DEX_CLASSIC_MANAGER = b"Lcom/google/android/play/core/integrity/IntegrityManager;\n"

# Token request method name
DEX_REQUEST_TOKEN = b"requestIntegrityToken\n"

# Standard API - StandardIntegrityManager class descriptor
DEX_STANDARD_MANAGER = b"Lcom/google/android/play/core/integrity/StandardIntegrityManager;\n"

# Standard API token preparation method
DEX_PREPARE_TOKEN = b"prepareIntegrityToken\n"

# Verdict field name (inspecting the response)
DEX_VERDICT_FIELD = b"appRecognitionVerdict\n"

# The specific verdict value for sideloaded installs
DEX_UNRECOGNIZED_VERSION = b"UNRECOGNIZED_VERSION\n"

# PLAY_RECOGNIZED verdict value
DEX_PLAY_RECOGNIZED = b"PLAY_RECOGNIZED\n"

# SafetyNet class reference (legacy)
DEX_SAFETYNET = b"Lcom/google/android/gms/safetynet/SafetyNetClient;\n"

# --- Library 1.3+ paths (without 'core' in the package) ---
DEX_NEW_CLASSIC_FACTORY  = b"Lcom/google/android/play/integrity/IntegrityManagerFactory;\n"
DEX_NEW_CLASSIC_MANAGER  = b"Lcom/google/android/play/integrity/IntegrityManager;\n"
DEX_NEW_STANDARD_MANAGER = b"Lcom/google/android/play/integrity/StandardIntegrityManager;\n"
DEX_NEW_STANDARD_PROVIDER = b"Lcom/google/android/play/integrity/StandardIntegrityTokenProvider;\n"

# requestAndShowDialog – Standard API dialog-based flow (library 1.2+)
DEX_REQUEST_SHOW_DIALOG  = b"requestAndShowDialog\n"

# UNLICENSED – appLicensingVerdict for non-Play-licensed installs (Digital Turbine)
DEX_UNLICENSED           = b"UNLICENSED\n"

# Play Integrity remediation dialog type codes
DEX_GET_LICENSED         = b"GET_LICENSED\n"
DEX_CLOSE_UNKNOWN_SOURCE = b"CLOSE_UNKNOWN_SOURCE_DIALOG\n"

# Installer source check strings
DEX_GET_INSTALLER_PKG    = b"getInstallerPackageName\n"
DEX_GET_INSTALL_SOURCE   = b"getInstallSourceInfo\n"
DEX_PLAY_STORE_PKG       = b"com.android.vending\n"


# ---------------------------------------------------------------------------
# Tests: sideload_risk property
# ---------------------------------------------------------------------------

class TestSideloadRisk(unittest.TestCase):
    def _result(self, **kwargs) -> IntegrityAnalysisResult:
        r = IntegrityAnalysisResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_risk_none_when_no_api(self):
        r = self._result()
        self.assertEqual(r.sideload_risk, "NONE")

    def test_risk_low_when_library_only(self):
        r = self._result(uses_play_integrity=True, uses_classic_api=True)
        self.assertEqual(r.sideload_risk, "LOW")

    def test_risk_medium_when_token_requested_and_verdict_checked(self):
        r = self._result(
            uses_play_integrity=True,
            requests_token=True,
            checks_verdict=True,
        )
        self.assertEqual(r.sideload_risk, "MEDIUM")

    def test_risk_high_when_unrecognized_version_found(self):
        r = self._result(
            uses_play_integrity=True,
            requests_token=True,
            checks_verdict=True,
            checks_unrecognized=True,
        )
        self.assertEqual(r.sideload_risk, "HIGH")

    def test_risk_low_when_only_safetynet(self):
        r = self._result(uses_safetynet=True)
        self.assertEqual(r.sideload_risk, "LOW")

    def test_risk_medium_without_unrecognized(self):
        # Has token request + checks other verdict fields but NOT UNRECOGNIZED_VERSION
        r = self._result(
            uses_play_integrity=True,
            requests_token=True,
            checks_verdict=True,
            checks_unrecognized=False,
        )
        self.assertEqual(r.sideload_risk, "MEDIUM")


# ---------------------------------------------------------------------------
# Tests: summary() keys
# ---------------------------------------------------------------------------

class TestSummaryKeys(unittest.TestCase):
    def test_summary_has_all_expected_keys(self):
        r = IntegrityAnalysisResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        s = r.summary()
        expected = {
            "apk", "package", "label",
            "uses_play_integrity", "uses_classic_api", "uses_standard_api",
            "uses_safetynet", "requests_token", "checks_verdict",
            "checks_unrecognized_version", "checks_unlicensed",
            "uses_remediation_dialog", "checks_installer_source",
            "has_play_core_components",
            "sideload_risk", "files_analyzed", "errors", "usages",
        }
        self.assertEqual(set(s.keys()), expected)

    def test_summary_is_json_serialisable(self):
        r = IntegrityAnalysisResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        r.uses_play_integrity = True
        r.usages.append(IntegrityUsage(
            file="classes.dex", line_number=1,
            usage_type="classic_api",
            matched_string="com/google/android/play/core/integrity/IntegrityManager",
        ))
        json_str = json.dumps(r.summary())
        data = json.loads(json_str)
        self.assertTrue(data["uses_play_integrity"])


# ---------------------------------------------------------------------------
# Tests: manifest parsing
# ---------------------------------------------------------------------------

class TestManifestParsing(unittest.TestCase):
    def test_package_name_extracted(self):
        result = analyze(make_manifest("com.example.app"))
        self.assertEqual(result.package_name, "com.example.app")

    def test_app_label_extracted(self):
        result = analyze(make_manifest("com.example.app", label="MyApp"))
        self.assertEqual(result.app_label, "MyApp")

    def test_play_core_service_detected(self):
        result = analyze(make_manifest("com.example.app", play_core_service=True))
        self.assertTrue(result.has_play_core_components)

    def test_no_play_core_service(self):
        result = analyze(make_manifest("com.example.app", play_core_service=False))
        self.assertFalse(result.has_play_core_components)

    def test_no_dex_recorded_in_errors(self):
        result = analyze(make_manifest("com.example.app"))
        self.assertTrue(any("No DEX files" in e for e in result.errors))


# ---------------------------------------------------------------------------
# Tests: DEX scanning - Classic API
# ---------------------------------------------------------------------------

class TestDexClassicApi(unittest.TestCase):
    def test_factory_class_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_CLASSIC_FACTORY)
        self.assertTrue(result.uses_play_integrity)
        self.assertTrue(result.uses_classic_api)

    def test_manager_class_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_CLASSIC_MANAGER)
        self.assertTrue(result.uses_classic_api)

    def test_token_request_method_detected(self):
        result = analyze(
            make_manifest("com.ex"),
            dex=DEX_CLASSIC_MANAGER + DEX_REQUEST_TOKEN,
        )
        self.assertTrue(result.requests_token)

    def test_no_standard_api_flag_when_only_classic(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_CLASSIC_FACTORY)
        self.assertFalse(result.uses_standard_api)


# ---------------------------------------------------------------------------
# Tests: DEX scanning - Standard API
# ---------------------------------------------------------------------------

class TestDexStandardApi(unittest.TestCase):
    def test_standard_manager_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_STANDARD_MANAGER)
        self.assertTrue(result.uses_play_integrity)
        self.assertTrue(result.uses_standard_api)

    def test_prepare_token_sets_requests_token(self):
        result = analyze(
            make_manifest("com.ex"),
            dex=DEX_STANDARD_MANAGER + DEX_PREPARE_TOKEN,
        )
        self.assertTrue(result.requests_token)

    def test_no_classic_api_flag_when_only_standard(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_STANDARD_MANAGER)
        self.assertFalse(result.uses_classic_api)


# ---------------------------------------------------------------------------
# Tests: DEX scanning - Verdict checks
# ---------------------------------------------------------------------------

class TestDexVerdictChecks(unittest.TestCase):
    def test_verdict_field_detected(self):
        result = analyze(
            make_manifest("com.ex"),
            dex=DEX_CLASSIC_MANAGER + DEX_VERDICT_FIELD,
        )
        self.assertTrue(result.checks_verdict)

    def test_unrecognized_version_sets_checks_unrecognized(self):
        result = analyze(
            make_manifest("com.ex"),
            dex=DEX_CLASSIC_MANAGER + DEX_UNRECOGNIZED_VERSION,
        )
        self.assertTrue(result.checks_unrecognized)

    def test_play_recognized_sets_checks_verdict(self):
        result = analyze(
            make_manifest("com.ex"),
            dex=DEX_CLASSIC_MANAGER + DEX_PLAY_RECOGNIZED,
        )
        self.assertTrue(result.checks_verdict)

    def test_verdict_without_integrity_api(self):
        # Verdict strings alone (without any integrity API class strings in the same
        # DEX) are NOT detected.  The analyzer skips DEX files that contain no
        # Play Integrity / SafetyNet package strings to avoid false positives.
        result = analyze(make_manifest("com.ex"), dex=DEX_VERDICT_FIELD)
        self.assertFalse(result.uses_play_integrity)
        self.assertFalse(result.checks_verdict)


# ---------------------------------------------------------------------------
# Tests: DEX scanning - SafetyNet (legacy)
# ---------------------------------------------------------------------------

class TestDexSafetyNet(unittest.TestCase):
    def test_safetynet_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_SAFETYNET)
        self.assertTrue(result.uses_safetynet)

    def test_safetynet_does_not_set_play_integrity_flag(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_SAFETYNET)
        self.assertFalse(result.uses_play_integrity)

    def test_safetynet_risk_is_low(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_SAFETYNET)
        self.assertEqual(result.sideload_risk, "LOW")


# ---------------------------------------------------------------------------
# Tests: high-risk scenario (full sideload detection pattern)
# ---------------------------------------------------------------------------

class TestHighRiskScenario(unittest.TestCase):
    def test_high_risk_full_pattern(self):
        """App with classic API + token request + UNRECOGNIZED_VERSION check."""
        dex = (
            DEX_CLASSIC_FACTORY
            + DEX_REQUEST_TOKEN
            + DEX_UNRECOGNIZED_VERSION
            + DEX_VERDICT_FIELD
        )
        result = analyze(make_manifest("com.target.app"), dex=dex)
        self.assertTrue(result.uses_play_integrity)
        self.assertTrue(result.uses_classic_api)
        self.assertTrue(result.requests_token)
        self.assertTrue(result.checks_verdict)
        self.assertTrue(result.checks_unrecognized)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_medium_risk_no_unrecognized(self):
        """App with classic API + token request + verdict field, no UNRECOGNIZED_VERSION."""
        dex = DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN + DEX_VERDICT_FIELD
        result = analyze(make_manifest("com.target.app"), dex=dex)
        self.assertEqual(result.sideload_risk, "MEDIUM")


# ---------------------------------------------------------------------------
# Tests: no integrity at all
# ---------------------------------------------------------------------------

class TestNoIntegrity(unittest.TestCase):
    def test_clean_apk(self):
        dex = b"Hello world - no play integrity here"
        result = analyze(make_manifest("com.clean.app"), dex=dex)
        self.assertFalse(result.uses_play_integrity)
        self.assertFalse(result.uses_safetynet)
        self.assertEqual(result.sideload_risk, "NONE")
        self.assertEqual(result.files_analyzed, 1)


# ---------------------------------------------------------------------------
# Tests: usages list
# ---------------------------------------------------------------------------

class TestUsagesList(unittest.TestCase):
    def test_usages_populated(self):
        dex = DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN
        result = analyze(make_manifest("com.ex"), dex=dex)
        types = {u.usage_type for u in result.usages}
        self.assertIn("classic_api", types)
        self.assertIn("token_request", types)

    def test_dedup_within_dex(self):
        """Repeated occurrences of the same string in a DEX should be deduped."""
        dex = DEX_CLASSIC_FACTORY * 5  # Same string repeated 5 times
        result = analyze(make_manifest("com.ex"), dex=dex)
        classic_usages = [u for u in result.usages if u.usage_type == "classic_api"
                          and "IntegrityManagerFactory" in u.matched_string]
        # Should appear at most once per (type, matched_string) per file
        self.assertEqual(len(classic_usages), 1)


# ---------------------------------------------------------------------------
# Tests: smali text scanning
# ---------------------------------------------------------------------------

class TestSmaliScanning(unittest.TestCase):
    def _make_analyzer(self) -> PlayIntegrityAnalyzer:
        manifest = make_manifest("com.example")
        tmp = write_tmp_apk(make_apk(manifest))
        self._tmp = tmp
        return PlayIntegrityAnalyzer(tmp)

    def tearDown(self):
        if hasattr(self, "_tmp") and os.path.exists(self._tmp):
            os.unlink(self._tmp)

    def test_smali_classic_api(self):
        a = self._make_analyzer()
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        content = (
            "invoke-static {v0}, "
            "Lcom/google/android/play/core/integrity/IntegrityManagerFactory;"
            "->create(Landroid/content/Context;)"
            "Lcom/google/android/play/core/integrity/IntegrityManager;"
        )
        a._scan_smali_text(content, "Main.smali", result)
        self.assertTrue(result.uses_classic_api)

    def test_smali_request_token(self):
        a = self._make_analyzer()
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        content = (
            "invoke-interface {v0, v1}, "
            "Lcom/google/android/play/core/integrity/IntegrityManager;"
            "->requestIntegrityToken(...)"
        )
        a._scan_smali_text(content, "Main.smali", result)
        self.assertTrue(result.requests_token)

    def test_smali_verdict_check(self):
        a = self._make_analyzer()
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        content = 'const-string v0, "UNRECOGNIZED_VERSION"'
        a._scan_smali_text(content, "Main.smali", result)
        self.assertTrue(result.checks_verdict)
        self.assertTrue(result.checks_unrecognized)

    def test_smali_safetynet(self):
        a = self._make_analyzer()
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        content = "Lcom/google/android/gms/safetynet/SafetyNetClient;"
        a._scan_smali_text(content, "Main.smali", result)
        self.assertTrue(result.uses_safetynet)


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------

class TestErrorHandling(unittest.TestCase):
    def test_missing_file(self):
        analyzer = PlayIntegrityAnalyzer("/nonexistent/path/app.apk")
        with self.assertRaises(FileNotFoundError):
            analyzer.analyze()

    def test_not_a_zip(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a zip file")
            tmp = f.name
        try:
            analyzer = PlayIntegrityAnalyzer(tmp)
            with self.assertRaises(ValueError):
                analyzer.analyze()
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Tests: print_report smoke tests
# ---------------------------------------------------------------------------

class TestPrintReport(unittest.TestCase):
    def _capture(self, result: IntegrityAnalysisResult, verbose: bool = False) -> str:
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(result, verbose=verbose)
        return buf.getvalue()

    def _make_result(self, **kwargs) -> IntegrityAnalysisResult:
        r = IntegrityAnalysisResult(
            apk_path="test.apk",
            package_name="com.example",
            app_label="Test",
        )
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_report_none_risk(self):
        output = self._capture(self._make_result())
        self.assertIn("NONE", output)

    def test_report_high_risk(self):
        r = self._make_result(
            uses_play_integrity=True,
            requests_token=True,
            checks_verdict=True,
            checks_unrecognized=True,
        )
        output = self._capture(r)
        self.assertIn("HIGH", output)
        self.assertIn("UNRECOGNIZED_VERSION", output)

    def test_report_medium_risk(self):
        r = self._make_result(
            uses_play_integrity=True,
            requests_token=True,
            checks_verdict=True,
        )
        output = self._capture(r)
        self.assertIn("MEDIUM", output)

    def test_report_low_risk(self):
        r = self._make_result(uses_play_integrity=True, uses_classic_api=True)
        output = self._capture(r)
        self.assertIn("LOW", output)

    def test_verbose_shows_indicators(self):
        r = self._make_result(uses_play_integrity=True)
        r.usages.append(IntegrityUsage(
            file="classes.dex", line_number=42,
            usage_type="classic_api",
            matched_string="com/google/android/play/core/integrity/IntegrityManager",
        ))
        output = self._capture(r, verbose=True)
        self.assertIn("classic_api", output)

    def test_report_shows_package(self):
        r = self._make_result()
        output = self._capture(r)
        self.assertIn("com.example", output)

    def test_report_shows_errors(self):
        r = self._make_result()
        r.errors.append("No DEX files found in APK")
        output = self._capture(r)
        self.assertIn("No DEX files found", output)


# ---------------------------------------------------------------------------
# Tests: multi-DEX support
# ---------------------------------------------------------------------------

class TestMultiDex(unittest.TestCase):
    def test_multi_dex_analyzed(self):
        """Integrity strings in classes2.dex are detected correctly."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("AndroidManifest.xml", make_manifest("com.multi"))
            zf.writestr("classes.dex", b"no integrity here")
            zf.writestr(
                "classes2.dex",
                DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN + DEX_UNRECOGNIZED_VERSION,
            )
        tmp = write_tmp_apk(buf.getvalue())
        try:
            result = PlayIntegrityAnalyzer(tmp).analyze()
            self.assertTrue(result.uses_play_integrity)
            self.assertTrue(result.requests_token)
            self.assertTrue(result.checks_unrecognized)
            self.assertEqual(result.files_analyzed, 2)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Tests: library 1.3+ paths (without 'core' in package)
# These were the source of false-negatives: the pre-check filter only matched
# "play/core/integrity", so DEX files from newer library builds were silently
# skipped and the APK was incorrectly reported as having no Play Integrity.
# ---------------------------------------------------------------------------

class TestNewStyleClassicApi(unittest.TestCase):
    """Classic API classes at the restructured path (library 1.3+)."""

    def test_new_factory_class_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_CLASSIC_FACTORY)
        self.assertTrue(result.uses_play_integrity)
        self.assertTrue(result.uses_classic_api)

    def test_new_manager_class_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_CLASSIC_MANAGER)
        self.assertTrue(result.uses_classic_api)

    def test_new_no_standard_flag_when_only_classic(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_CLASSIC_FACTORY)
        self.assertFalse(result.uses_standard_api)

    def test_new_classic_with_token_request(self):
        dex = DEX_NEW_CLASSIC_MANAGER + DEX_REQUEST_TOKEN
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.requests_token)

    def test_new_classic_high_risk_full_pattern(self):
        dex = (
            DEX_NEW_CLASSIC_FACTORY
            + DEX_REQUEST_TOKEN
            + DEX_UNRECOGNIZED_VERSION
            + DEX_VERDICT_FIELD
        )
        result = analyze(make_manifest("com.target.app"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")


class TestNewStyleStandardApi(unittest.TestCase):
    """Standard API classes at the restructured path (library 1.3+)."""

    def test_new_standard_manager_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_STANDARD_MANAGER)
        self.assertTrue(result.uses_play_integrity)
        self.assertTrue(result.uses_standard_api)

    def test_new_standard_provider_detected(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_STANDARD_PROVIDER)
        self.assertTrue(result.uses_standard_api)

    def test_new_no_classic_flag_when_only_standard(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_STANDARD_MANAGER)
        self.assertFalse(result.uses_classic_api)

    def test_new_standard_with_prepare_token(self):
        dex = DEX_NEW_STANDARD_MANAGER + DEX_PREPARE_TOKEN
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.requests_token)

    def test_new_standard_high_risk_full_pattern(self):
        dex = (
            DEX_NEW_STANDARD_MANAGER
            + DEX_PREPARE_TOKEN
            + DEX_UNRECOGNIZED_VERSION
            + DEX_VERDICT_FIELD
        )
        result = analyze(make_manifest("com.target.app"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")


class TestRequestAndShowDialog(unittest.TestCase):
    """requestAndShowDialog – dialog-based integrity flow (library 1.2+)."""

    def test_request_show_dialog_sets_requests_token(self):
        dex = DEX_NEW_STANDARD_MANAGER + DEX_REQUEST_SHOW_DIALOG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.requests_token)

    def test_request_show_dialog_old_path(self):
        dex = DEX_STANDARD_MANAGER + DEX_REQUEST_SHOW_DIALOG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.requests_token)

    def test_request_show_dialog_sets_play_integrity(self):
        dex = DEX_NEW_STANDARD_MANAGER + DEX_REQUEST_SHOW_DIALOG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.uses_play_integrity)


# ---------------------------------------------------------------------------
# Tests: UNLICENSED verdict (Digital Turbine / non-Play-licensed installs)
# ---------------------------------------------------------------------------

class TestUnlicensedVerdict(unittest.TestCase):
    """UNLICENSED is the appLicensingVerdict for apps not licensed via Play Store.
    Digital Turbine installs receive this verdict, so any app checking for it
    will block Digital Turbine users and must be flagged HIGH."""

    def test_unlicensed_sets_checks_unlicensed(self):
        result = analyze(make_manifest("com.ex"),
                         dex=DEX_CLASSIC_MANAGER + DEX_UNLICENSED)
        self.assertTrue(result.checks_unlicensed)

    def test_unlicensed_sets_checks_verdict(self):
        result = analyze(make_manifest("com.ex"),
                         dex=DEX_CLASSIC_MANAGER + DEX_UNLICENSED)
        self.assertTrue(result.checks_verdict)

    def test_unlicensed_does_not_set_checks_unrecognized(self):
        result = analyze(make_manifest("com.ex"),
                         dex=DEX_CLASSIC_MANAGER + DEX_UNLICENSED)
        self.assertFalse(result.checks_unrecognized)

    def test_high_risk_when_token_requested_and_unlicensed_checked(self):
        dex = DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN + DEX_UNLICENSED
        result = analyze(make_manifest("com.target.app"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_high_risk_new_style_path_with_unlicensed(self):
        dex = DEX_NEW_STANDARD_MANAGER + DEX_PREPARE_TOKEN + DEX_UNLICENSED
        result = analyze(make_manifest("com.target.app"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_unlicensed_in_smali(self):
        a = PlayIntegrityAnalyzer.__new__(PlayIntegrityAnalyzer)
        a.verbose = False
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        a._scan_smali_text(
            'const-string v0, "UNLICENSED"', "Main.smali", result
        )
        self.assertTrue(result.checks_unlicensed)
        self.assertTrue(result.checks_verdict)


# ---------------------------------------------------------------------------
# Tests: remediation dialog indicators
# ---------------------------------------------------------------------------

class TestRemediationDialog(unittest.TestCase):
    """Remediation dialogs redirect users to the Play Store — HIGH risk."""

    def test_get_licensed_sets_remediation_flag(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_LICENSED
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.uses_remediation_dialog)

    def test_close_unknown_source_sets_remediation_flag(self):
        dex = DEX_CLASSIC_MANAGER + DEX_CLOSE_UNKNOWN_SOURCE
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.uses_remediation_dialog)

    def test_get_licensed_alone_is_high_risk(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_LICENSED
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_close_unknown_source_alone_is_high_risk(self):
        dex = DEX_CLASSIC_MANAGER + DEX_CLOSE_UNKNOWN_SOURCE
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_request_and_show_dialog_sets_remediation_flag(self):
        # requestAndShowDialog already sets requests_token; it must ALSO set remediation.
        dex = DEX_NEW_STANDARD_MANAGER + DEX_REQUEST_SHOW_DIALOG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.uses_remediation_dialog)

    def test_request_and_show_dialog_is_high_risk(self):
        dex = DEX_NEW_STANDARD_MANAGER + DEX_REQUEST_SHOW_DIALOG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_get_licensed_in_smali(self):
        a = PlayIntegrityAnalyzer.__new__(PlayIntegrityAnalyzer)
        a.verbose = False
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        a._scan_smali_text('const/4 v0, GET_LICENSED', "Main.smali", result)
        self.assertTrue(result.uses_remediation_dialog)


# ---------------------------------------------------------------------------
# Tests: installer source check indicators
# ---------------------------------------------------------------------------

class TestInstallerSourceCheck(unittest.TestCase):
    """Installer source checks verify the app was installed from Play Store.
    Combined with Play Integrity, this is a direct sideload-blocking pattern."""

    def test_get_installer_package_name_sets_flag(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_INSTALLER_PKG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.checks_installer_source)

    def test_get_install_source_info_sets_flag(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_INSTALL_SOURCE
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.checks_installer_source)

    def test_android_vending_sets_flag(self):
        dex = DEX_CLASSIC_MANAGER + DEX_PLAY_STORE_PKG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertTrue(result.checks_installer_source)

    def test_installer_check_is_high_risk(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_INSTALLER_PKG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_android_vending_is_high_risk(self):
        dex = DEX_CLASSIC_MANAGER + DEX_PLAY_STORE_PKG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_installer_check_in_smali(self):
        a = PlayIntegrityAnalyzer.__new__(PlayIntegrityAnalyzer)
        a.verbose = False
        result = IntegrityAnalysisResult("t.apk", "com.ex", "Ex")
        content = (
            "invoke-virtual {v0, v1}, Landroid/content/pm/PackageManager;"
            "->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;"
        )
        a._scan_smali_text(content, "Main.smali", result)
        self.assertTrue(result.checks_installer_source)


# ---------------------------------------------------------------------------
# Tests: updated HIGH-risk conditions cover all Digital Turbine blocking paths
# ---------------------------------------------------------------------------

class TestHighRiskAllPaths(unittest.TestCase):
    """Every scenario that would block a Digital Turbine install must be HIGH."""

    def test_unrecognized_version_still_high(self):
        dex = DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN + DEX_UNRECOGNIZED_VERSION
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_unlicensed_verdict_high(self):
        dex = DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN + DEX_UNLICENSED
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_get_licensed_dialog_high(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_LICENSED
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_request_and_show_dialog_high(self):
        dex = DEX_NEW_STANDARD_MANAGER + DEX_REQUEST_SHOW_DIALOG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_installer_package_check_high(self):
        dex = DEX_CLASSIC_MANAGER + DEX_GET_INSTALLER_PKG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_android_vending_hardcoded_high(self):
        dex = DEX_CLASSIC_MANAGER + DEX_PLAY_STORE_PKG
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "HIGH")

    def test_verdict_only_still_medium(self):
        """Checks some verdict field but not a blocking one → MEDIUM, not HIGH."""
        dex = DEX_CLASSIC_FACTORY + DEX_REQUEST_TOKEN + DEX_VERDICT_FIELD
        result = analyze(make_manifest("com.ex"), dex=dex)
        self.assertEqual(result.sideload_risk, "MEDIUM")

    def test_library_only_still_low(self):
        result = analyze(make_manifest("com.ex"), dex=DEX_CLASSIC_FACTORY)
        self.assertEqual(result.sideload_risk, "LOW")


# ---------------------------------------------------------------------------
# Tests: SIDELOAD_VERDICTS constant covers both blocking values
# ---------------------------------------------------------------------------

class TestSideloadVerdictsConstant(unittest.TestCase):
    def test_unrecognized_version_in_set(self):
        self.assertIn("UNRECOGNIZED_VERSION", SIDELOAD_VERDICTS)

    def test_unlicensed_in_set(self):
        self.assertIn("UNLICENSED", SIDELOAD_VERDICTS)

    def test_licensed_not_in_set(self):
        self.assertNotIn("LICENSED", SIDELOAD_VERDICTS)

    def test_play_recognized_not_in_set(self):
        self.assertNotIn("PLAY_RECOGNIZED", SIDELOAD_VERDICTS)


class TestPreCheckFilter(unittest.TestCase):
    """Verify the DEX pre-check accepts both old and new library paths."""

    def test_old_path_not_silently_skipped(self):
        """DEX with only old-style (play/core/integrity) path must be scanned."""
        result = analyze(make_manifest("com.ex"), dex=DEX_CLASSIC_FACTORY)
        self.assertTrue(result.uses_play_integrity,
                        "Old-style path was silently skipped by the pre-check filter")

    def test_new_path_not_silently_skipped(self):
        """DEX with only new-style (play/integrity) path must be scanned."""
        result = analyze(make_manifest("com.ex"), dex=DEX_NEW_CLASSIC_FACTORY)
        self.assertTrue(result.uses_play_integrity,
                        "New-style path was silently skipped by the pre-check filter")

    def test_unrelated_dex_still_skipped(self):
        """DEX with no Play Integrity content should report no usage."""
        result = analyze(make_manifest("com.ex"), dex=b"just some random dex content here")
        self.assertFalse(result.uses_play_integrity)
        self.assertFalse(result.uses_safetynet)


if __name__ == "__main__":
    unittest.main(verbosity=2)
