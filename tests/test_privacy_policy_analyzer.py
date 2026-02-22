#!/usr/bin/env python3
"""
Unit tests for the Privacy Policy Analyzer.
"""

import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from privacy_policy_analyzer import (
    PrivacyPolicyAnalyzer,
    PrivacyPolicyResult,
    SdkDetection,
    print_report,
    DATA_COLLECTION_SDKS,
    SENSITIVE_PERMISSIONS,
    SENSITIVE_PERMISSION_NAMES,
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


def make_manifest(
    package: str,
    label: str = "TestApp",
    permissions: list = None,
    privacy_url_meta: str = "",
    play_core_service: bool = False,
) -> str:
    perms = ""
    if permissions:
        perms = "\n".join(
            f'    <uses-permission android:name="{p}" />' for p in permissions
        )
    meta = ""
    if privacy_url_meta:
        meta = (
            f'        <meta-data android:name="privacy_policy" '
            f'android:value="{privacy_url_meta}" />\n'
        )
    service = ""
    if play_core_service:
        service = (
            '        <service android:name="com.google.android.play.core.tasks.PlayCoreTasksService" />\n'
        )
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}">
{perms}
    <application android:label="{label}">
{meta}{service}    </application>
</manifest>"""


def write_tmp_apk(apk_bytes: bytes) -> str:
    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
        f.write(apk_bytes)
        return f.name


def analyze(
    manifest: str = None,
    dex: bytes = b"",
    package: str = "com.example",
    permissions: list = None,
    privacy_url_meta: str = "",
) -> PrivacyPolicyResult:
    if manifest is None:
        manifest = make_manifest(package, permissions=permissions,
                                 privacy_url_meta=privacy_url_meta)
    tmp = write_tmp_apk(make_apk(manifest, dex))
    try:
        return PrivacyPolicyAnalyzer(tmp).analyze()
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# DEX byte helpers
# ---------------------------------------------------------------------------

DEX_FIREBASE_ANALYTICS = b"com/google/firebase/analytics/FirebaseAnalytics\n"
DEX_FACEBOOK_APPEVENTS = b"com/facebook/appevents/AppEventsLogger\n"
DEX_ADMOB             = b"com/google/android/gms/ads/AdRequest\n"
DEX_ADJUST            = b"com/adjust/sdk/Adjust\n"
DEX_CRASHLYTICS       = b"com/google/firebase/crashlytics/FirebaseCrashlytics\n"
DEX_MIXPANEL          = b"com/mixpanel/android/mpmetrics/MixpanelAPI\n"
DEX_APPSFLYER         = b"com/appsflyer/AppsFlyerLib\n"
DEX_ONESIGNAL         = b"com/onesignal/OneSignal\n"

PRIVACY_URL_IN_DEX = (
    b"https://example.com/privacy-policy\n"
)
NON_PRIVACY_URL_IN_DEX = b"https://example.com/terms-of-service\n"


# ---------------------------------------------------------------------------
# Tests: verdict property
# ---------------------------------------------------------------------------

class TestVerdict(unittest.TestCase):
    def _result(self, **kwargs) -> PrivacyPolicyResult:
        r = PrivacyPolicyResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_verdict_missing_when_clean(self):
        r = self._result()
        self.assertEqual(r.verdict, "MISSING")

    def test_verdict_present_when_policy_and_sdk(self):
        r = self._result(
            has_privacy_policy=True,
            detected_sdks=[
                SdkDetection("Firebase Analytics", "com/google/firebase/analytics",
                             "classes.dex", 1)
            ],
        )
        self.assertEqual(r.verdict, "PRESENT")

    def test_verdict_present_when_policy_and_permission(self):
        r = self._result(
            has_privacy_policy=True,
            declared_sensitive_permissions=[
                {"permission": "android.permission.CAMERA", "data": "Camera"}
            ],
        )
        self.assertEqual(r.verdict, "PRESENT")

    def test_verdict_partial_when_policy_no_data_collection(self):
        r = self._result(has_privacy_policy=True)
        self.assertEqual(r.verdict, "PARTIAL")

    def test_verdict_partial_when_sdk_no_policy(self):
        r = self._result(
            detected_sdks=[
                SdkDetection("Firebase Analytics", "com/google/firebase/analytics",
                             "classes.dex", 1)
            ],
        )
        self.assertEqual(r.verdict, "PARTIAL")

    def test_verdict_partial_when_permission_no_policy(self):
        r = self._result(
            declared_sensitive_permissions=[
                {"permission": "android.permission.RECORD_AUDIO", "data": "Microphone / audio"}
            ],
        )
        self.assertEqual(r.verdict, "PARTIAL")


# ---------------------------------------------------------------------------
# Tests: collects_data property
# ---------------------------------------------------------------------------

class TestCollectsData(unittest.TestCase):
    def _result(self, **kwargs) -> PrivacyPolicyResult:
        r = PrivacyPolicyResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_false_when_nothing(self):
        self.assertFalse(self._result().collects_data)

    def test_true_when_sdk_present(self):
        r = self._result(detected_sdks=[
            SdkDetection("Adjust", "com/adjust/sdk", "classes.dex", 1)
        ])
        self.assertTrue(r.collects_data)

    def test_true_when_sensitive_permission(self):
        r = self._result(declared_sensitive_permissions=[
            {"permission": "android.permission.CAMERA", "data": "Camera"}
        ])
        self.assertTrue(r.collects_data)


# ---------------------------------------------------------------------------
# Tests: manifest parsing - package & label
# ---------------------------------------------------------------------------

class TestManifestParsing(unittest.TestCase):
    def test_package_name_extracted(self):
        result = analyze(package="com.example.myapp")
        self.assertEqual(result.package_name, "com.example.myapp")

    def test_app_label_extracted(self):
        manifest = make_manifest("com.example", label="CoolApp")
        result = analyze(manifest=manifest)
        self.assertEqual(result.app_label, "CoolApp")

    def test_no_dex_recorded_in_errors(self):
        result = analyze()
        self.assertTrue(any("No DEX files" in e for e in result.errors))


# ---------------------------------------------------------------------------
# Tests: manifest - sensitive permissions
# ---------------------------------------------------------------------------

class TestSensitivePermissions(unittest.TestCase):
    def test_camera_permission_detected(self):
        result = analyze(permissions=["android.permission.CAMERA"])
        perms = [p["permission"] for p in result.declared_sensitive_permissions]
        self.assertIn("android.permission.CAMERA", perms)

    def test_location_permission_detected(self):
        result = analyze(permissions=["android.permission.ACCESS_FINE_LOCATION"])
        perms = [p["permission"] for p in result.declared_sensitive_permissions]
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", perms)

    def test_non_sensitive_permission_not_recorded(self):
        result = analyze(permissions=["android.permission.INTERNET"])
        self.assertEqual(len(result.declared_sensitive_permissions), 0)

    def test_multiple_sensitive_permissions(self):
        result = analyze(permissions=[
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        ])
        perms = [p["permission"] for p in result.declared_sensitive_permissions]
        self.assertIn("android.permission.CAMERA", perms)
        self.assertIn("android.permission.RECORD_AUDIO", perms)
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", perms)

    def test_data_category_populated(self):
        result = analyze(permissions=["android.permission.CAMERA"])
        categories = {p["data"] for p in result.declared_sensitive_permissions}
        self.assertIn("Camera", categories)

    def test_ad_id_permission_detected(self):
        result = analyze(permissions=["com.google.android.gms.permission.AD_ID"])
        perms = [p["permission"] for p in result.declared_sensitive_permissions]
        self.assertIn("com.google.android.gms.permission.AD_ID", perms)


# ---------------------------------------------------------------------------
# Tests: manifest - privacy policy meta-data
# ---------------------------------------------------------------------------

class TestManifestPrivacyMeta(unittest.TestCase):
    def test_privacy_policy_url_from_meta_data(self):
        result = analyze(privacy_url_meta="https://example.com/privacy-policy")
        self.assertTrue(result.has_privacy_policy)
        self.assertIn("https://example.com/privacy-policy", result.policy_urls)

    def test_policy_found_in_manifest(self):
        result = analyze(privacy_url_meta="https://example.com/privacy-policy")
        self.assertIn("manifest", result.policy_found_in)

    def test_no_policy_when_no_meta(self):
        result = analyze()
        self.assertFalse(result.has_privacy_policy)


# ---------------------------------------------------------------------------
# Tests: DEX scanning - privacy policy URL
# ---------------------------------------------------------------------------

class TestDexPrivacyUrl(unittest.TestCase):
    def test_privacy_url_in_dex_detected(self):
        result = analyze(dex=PRIVACY_URL_IN_DEX)
        self.assertTrue(result.has_privacy_policy)

    def test_policy_found_in_dex(self):
        result = analyze(dex=PRIVACY_URL_IN_DEX)
        self.assertIn("dex", result.policy_found_in)

    def test_policy_url_captured(self):
        result = analyze(dex=PRIVACY_URL_IN_DEX)
        self.assertTrue(any("privacy" in url.lower() for url in result.policy_urls))

    def test_non_privacy_url_not_detected(self):
        result = analyze(dex=NON_PRIVACY_URL_IN_DEX)
        self.assertFalse(result.has_privacy_policy)

    def test_no_dex_no_policy(self):
        result = analyze(dex=b"no relevant content here at all")
        self.assertFalse(result.has_privacy_policy)


# ---------------------------------------------------------------------------
# Tests: DEX scanning - SDK detection
# ---------------------------------------------------------------------------

class TestDexSdkDetection(unittest.TestCase):
    def test_firebase_analytics_detected(self):
        result = analyze(dex=DEX_FIREBASE_ANALYTICS)
        names = result.unique_sdk_names
        self.assertIn("Firebase Analytics", names)

    def test_facebook_appevents_detected(self):
        result = analyze(dex=DEX_FACEBOOK_APPEVENTS)
        names = result.unique_sdk_names
        self.assertIn("Facebook Analytics", names)

    def test_admob_detected(self):
        result = analyze(dex=DEX_ADMOB)
        names = result.unique_sdk_names
        self.assertIn("AdMob", names)

    def test_adjust_detected(self):
        result = analyze(dex=DEX_ADJUST)
        self.assertIn("Adjust", result.unique_sdk_names)

    def test_crashlytics_detected(self):
        result = analyze(dex=DEX_CRASHLYTICS)
        self.assertIn("Crashlytics", result.unique_sdk_names)

    def test_mixpanel_detected(self):
        result = analyze(dex=DEX_MIXPANEL)
        self.assertIn("Mixpanel", result.unique_sdk_names)

    def test_appsflyer_detected(self):
        result = analyze(dex=DEX_APPSFLYER)
        self.assertIn("AppsFlyer", result.unique_sdk_names)

    def test_no_sdk_in_clean_dex(self):
        result = analyze(dex=b"nothing here no SDK at all")
        self.assertEqual(result.unique_sdk_names, [])

    def test_multiple_sdks_detected(self):
        dex = DEX_FIREBASE_ANALYTICS + DEX_ADJUST + DEX_ADMOB
        result = analyze(dex=dex)
        names = result.unique_sdk_names
        self.assertIn("Firebase Analytics", names)
        self.assertIn("Adjust", names)
        self.assertIn("AdMob", names)

    def test_sdk_deduped_per_file(self):
        # Same SDK pattern repeated many times should appear only once per file.
        dex = DEX_FIREBASE_ANALYTICS * 10
        result = analyze(dex=dex)
        firebase_hits = [s for s in result.detected_sdks if s.sdk_name == "Firebase Analytics"]
        self.assertEqual(len(firebase_hits), 1)


# ---------------------------------------------------------------------------
# Tests: smali scanning
# ---------------------------------------------------------------------------

class TestSmaliScanning(unittest.TestCase):
    def _make_analyzer_and_result(self):
        manifest = make_manifest("com.example")
        tmp = write_tmp_apk(make_apk(manifest))
        self._tmp = tmp
        a = PrivacyPolicyAnalyzer(tmp)
        r = PrivacyPolicyResult("t.apk", "com.ex", "Ex")
        return a, r

    def tearDown(self):
        if hasattr(self, "_tmp") and os.path.exists(self._tmp):
            os.unlink(self._tmp)

    def test_smali_privacy_url_detected(self):
        a, r = self._make_analyzer_and_result()
        content = 'const-string v0, "https://example.com/privacy-policy"'
        a._scan_smali_text(content, "Main.smali", r)
        self.assertTrue(r.has_privacy_policy)
        self.assertIn("smali", r.policy_found_in)

    def test_smali_sdk_detected(self):
        a, r = self._make_analyzer_and_result()
        content = "invoke-static {v0}, Lcom/google/firebase/analytics/FirebaseAnalytics;->getInstance()"
        a._scan_smali_text(content, "Main.smali", r)
        self.assertIn("Firebase Analytics", [s.sdk_name for s in r.detected_sdks])

    def test_smali_no_match(self):
        a, r = self._make_analyzer_and_result()
        content = "invoke-virtual {v0}, Ljava/lang/String;->length()I"
        a._scan_smali_text(content, "Main.smali", r)
        self.assertFalse(r.has_privacy_policy)
        self.assertEqual(r.detected_sdks, [])


# ---------------------------------------------------------------------------
# Tests: combined verdict scenarios
# ---------------------------------------------------------------------------

class TestCombinedVerdicts(unittest.TestCase):
    def test_present_policy_in_manifest_sdk_in_dex(self):
        manifest = make_manifest(
            "com.example",
            privacy_url_meta="https://example.com/privacy-policy",
        )
        result = analyze(manifest=manifest, dex=DEX_FIREBASE_ANALYTICS)
        self.assertEqual(result.verdict, "PRESENT")

    def test_present_policy_in_dex_permission_in_manifest(self):
        manifest = make_manifest(
            "com.example",
            permissions=["android.permission.CAMERA"],
        )
        result = analyze(manifest=manifest, dex=PRIVACY_URL_IN_DEX)
        self.assertEqual(result.verdict, "PRESENT")

    def test_partial_policy_only(self):
        result = analyze(privacy_url_meta="https://example.com/privacy-policy")
        self.assertEqual(result.verdict, "PARTIAL")

    def test_partial_sdk_no_policy(self):
        result = analyze(dex=DEX_FIREBASE_ANALYTICS)
        self.assertEqual(result.verdict, "PARTIAL")

    def test_partial_sensitive_permission_no_policy(self):
        result = analyze(permissions=["android.permission.RECORD_AUDIO"])
        self.assertEqual(result.verdict, "PARTIAL")

    def test_missing_clean_apk(self):
        result = analyze(dex=b"just some random bytes")
        self.assertEqual(result.verdict, "MISSING")


# ---------------------------------------------------------------------------
# Tests: multi-DEX
# ---------------------------------------------------------------------------

class TestMultiDex(unittest.TestCase):
    def test_sdk_detected_in_secondary_dex(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("AndroidManifest.xml", make_manifest("com.multi"))
            zf.writestr("classes.dex", b"nothing here")
            zf.writestr("classes2.dex", DEX_FIREBASE_ANALYTICS + PRIVACY_URL_IN_DEX)
        tmp = write_tmp_apk(buf.getvalue())
        try:
            result = PrivacyPolicyAnalyzer(tmp).analyze()
            self.assertIn("Firebase Analytics", result.unique_sdk_names)
            self.assertTrue(result.has_privacy_policy)
            self.assertEqual(result.files_analyzed, 2)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# Tests: summary() output
# ---------------------------------------------------------------------------

class TestSummary(unittest.TestCase):
    def test_summary_has_expected_keys(self):
        r = PrivacyPolicyResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        s = r.summary()
        expected = {
            "apk", "package", "label", "verdict",
            "has_privacy_policy", "policy_urls", "policy_found_in",
            "collects_data", "detected_sdks", "declared_sensitive_permissions",
            "data_categories", "files_analyzed", "errors",
        }
        self.assertEqual(set(s.keys()), expected)

    def test_summary_is_json_serialisable(self):
        r = PrivacyPolicyResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        r.has_privacy_policy = True
        r.policy_urls.append("https://example.com/privacy-policy")
        r.detected_sdks.append(
            SdkDetection("Firebase Analytics", "com/google/firebase/analytics",
                         "classes.dex", 1)
        )
        json_str = json.dumps(r.summary())
        data = json.loads(json_str)
        self.assertEqual(data["verdict"], "PRESENT")
        self.assertIn("Firebase Analytics", data["detected_sdks"])

    def test_data_categories_sorted(self):
        r = PrivacyPolicyResult(apk_path="t.apk", package_name="com.ex", app_label="Ex")
        r.declared_sensitive_permissions = [
            {"permission": "android.permission.CAMERA", "data": "Camera"},
            {"permission": "android.permission.RECORD_AUDIO", "data": "Microphone / audio"},
        ]
        s = r.summary()
        self.assertEqual(s["data_categories"], sorted(s["data_categories"]))


# ---------------------------------------------------------------------------
# Tests: print_report smoke tests
# ---------------------------------------------------------------------------

class TestPrintReport(unittest.TestCase):
    import contextlib

    def _capture(self, result: PrivacyPolicyResult) -> str:
        import io as _io
        from contextlib import redirect_stdout
        buf = _io.StringIO()
        with redirect_stdout(buf):
            print_report(result)
        return buf.getvalue()

    def _make_result(self, **kwargs) -> PrivacyPolicyResult:
        r = PrivacyPolicyResult(apk_path="test.apk", package_name="com.example", app_label="Test")
        for k, v in kwargs.items():
            setattr(r, k, v)
        return r

    def test_report_missing(self):
        output = self._capture(self._make_result())
        self.assertIn("MISSING", output)

    def test_report_present(self):
        r = self._make_result(
            has_privacy_policy=True,
            policy_urls=["https://example.com/privacy"],
            detected_sdks=[SdkDetection("Adjust", "com/adjust/sdk", "classes.dex", 1)],
        )
        output = self._capture(r)
        self.assertIn("PRESENT", output)
        self.assertIn("Adjust", output)
        self.assertIn("https://example.com/privacy", output)

    def test_report_partial(self):
        r = self._make_result(has_privacy_policy=True)
        output = self._capture(r)
        self.assertIn("PARTIAL", output)

    def test_report_shows_package(self):
        output = self._capture(self._make_result())
        self.assertIn("com.example", output)

    def test_report_shows_sensitive_permissions(self):
        r = self._make_result(
            declared_sensitive_permissions=[
                {"permission": "android.permission.CAMERA", "data": "Camera"}
            ]
        )
        output = self._capture(r)
        self.assertIn("android.permission.CAMERA", output)
        self.assertIn("Camera", output)

    def test_report_shows_errors(self):
        r = self._make_result()
        r.errors.append("No DEX files found in APK")
        output = self._capture(r)
        self.assertIn("No DEX files found", output)


# ---------------------------------------------------------------------------
# Tests: error handling
# ---------------------------------------------------------------------------

class TestErrorHandling(unittest.TestCase):
    def test_missing_file(self):
        a = PrivacyPolicyAnalyzer("/nonexistent/path/app.apk")
        with self.assertRaises(FileNotFoundError):
            a.analyze()

    def test_not_a_zip(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a zip file")
            tmp = f.name
        try:
            a = PrivacyPolicyAnalyzer(tmp)
            with self.assertRaises(ValueError):
                a.analyze()
        finally:
            os.unlink(tmp)


if __name__ == "__main__":
    unittest.main(verbosity=2)
