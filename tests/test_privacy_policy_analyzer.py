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
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from privacy_policy_analyzer import (
    PrivacyPolicyAnalyzer,
    PrivacyPolicyResult,
    PolicyFinding,
    _is_play_store_url,
    _package_from_play_url,
    _url_matches_privacy,
    _url_matches_terms,
    _text_matches_privacy_link,
    _text_matches_terms_link,
    _is_privacy_policy_document,
    _is_terms_document,
    _detect_disclosed_data_categories,
    _extract_links_from_html,
    _extract_text_from_html,
    _resolve_url,
    print_report,
    PERSONAL_DATA_CATEGORIES,
    MIN_DATA_CATEGORIES,
)


# ---------------------------------------------------------------------------
# APK / HTML factory helpers
# ---------------------------------------------------------------------------

def _make_apk(manifest: str, extras: dict[str, bytes] | None = None) -> bytes:
    """Build a minimal APK (zip) in memory.

    Args:
        manifest: XML string for AndroidManifest.xml.
        extras:   Additional files to include, keyed by name with bytes values.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        for name, content in (extras or {}).items():
            zf.writestr(name, content)
    return buf.getvalue()


def _make_manifest(
    package: str = "com.example.app",
    label: str = "ExampleApp",
    privacy_policy_attr: str = "",
) -> str:
    pp_attr = f' android:privacyPolicy="{privacy_policy_attr}"' if privacy_policy_attr else ""
    return (
        f'<?xml version="1.0" encoding="utf-8"?>\n'
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    package="{package}">\n'
        f'    <application android:label="{label}"{pp_attr}>\n'
        f'    </application>\n'
        f'</manifest>'
    )


def _write_tmp_apk(apk_bytes: bytes) -> str:
    """Write APK bytes to a temp file and return its path."""
    f = tempfile.NamedTemporaryFile(suffix=".apk", delete=False)
    f.write(apk_bytes)
    f.close()
    return f.name


PRIVACY_POLICY_TEXT = """
Privacy Policy

We collect the following personal information:
- Your name and email address for account creation.
- Your location data to provide location-based services.
- Device identifiers such as your IP address and device ID.
- Usage data including analytics and log data about how you use the app.
- Payment information when you make purchases.

We use your personal data to improve our services.
This privacy policy describes how we collect and process your information.
"""

TERMS_TEXT = """
Terms of Service

By using our application, you agree to the following terms and conditions.
These terms of use govern your use of our services.
Acceptance of terms: You agree to be bound by these terms.
Your use of the service is subject to these terms.
"""

THIN_PRIVACY_TEXT = """
Privacy Policy

We care about your privacy. We collect some information.
This privacy policy explains how we handle data.
"""

PLAY_STORE_HTML = """
<html>
<head><title>Example App - Apps on Google Play</title></head>
<body>
  <div class="app-info">
    <h1>Example App</h1>
    <a href="https://example.com/privacy-policy">Privacy Policy</a>
    <a href="https://example.com/terms-of-service">Terms of Service</a>
    <a href="https://play.google.com/about/play-terms">Google Play Terms</a>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# URL helper tests
# ---------------------------------------------------------------------------

class TestPlayStoreUrlDetection(unittest.TestCase):
    def test_recognises_play_url(self):
        self.assertTrue(_is_play_store_url(
            "https://play.google.com/store/apps/details?id=com.example"
        ))

    def test_rejects_apk_path(self):
        self.assertFalse(_is_play_store_url("/path/to/app.apk"))

    def test_rejects_arbitrary_url(self):
        self.assertFalse(_is_play_store_url("https://example.com/app"))

    def test_extracts_package_id(self):
        url = "https://play.google.com/store/apps/details?id=com.foo.bar&hl=en"
        self.assertEqual(_package_from_play_url(url), "com.foo.bar")

    def test_extracts_package_id_no_hl(self):
        url = "https://play.google.com/store/apps/details?id=org.example"
        self.assertEqual(_package_from_play_url(url), "org.example")

    def test_returns_empty_for_missing_id(self):
        url = "https://play.google.com/store/apps/details"
        self.assertEqual(_package_from_play_url(url), "")


class TestPrivacyUrlMatching(unittest.TestCase):
    def test_privacy_policy_url(self):
        self.assertTrue(_url_matches_privacy("https://example.com/privacy-policy"))

    def test_privacypolicy_no_separator(self):
        self.assertTrue(_url_matches_privacy("https://example.com/privacypolicy"))

    def test_gdpr_url(self):
        self.assertTrue(_url_matches_privacy("https://example.com/gdpr"))

    def test_data_protection(self):
        self.assertTrue(_url_matches_privacy("https://example.com/data-protection"))

    def test_non_privacy_url(self):
        self.assertFalse(_url_matches_privacy("https://example.com/about"))

    def test_terms_url_not_matched(self):
        self.assertFalse(_url_matches_privacy("https://example.com/terms"))


class TestTermsUrlMatching(unittest.TestCase):
    def test_terms_of_service(self):
        self.assertTrue(_url_matches_terms("https://example.com/terms-of-service"))

    def test_tos(self):
        self.assertTrue(_url_matches_terms("https://example.com/tos"))

    def test_eula(self):
        self.assertTrue(_url_matches_terms("https://example.com/eula"))

    def test_user_agreement(self):
        self.assertTrue(_url_matches_terms("https://example.com/user-agreement"))

    def test_non_terms_url(self):
        self.assertFalse(_url_matches_terms("https://example.com/about"))

    def test_privacy_url_not_matched(self):
        self.assertFalse(_url_matches_terms("https://example.com/privacy"))


class TestLinkTextMatching(unittest.TestCase):
    def test_privacy_link_text(self):
        self.assertTrue(_text_matches_privacy_link("Privacy Policy"))
        self.assertTrue(_text_matches_privacy_link("privacy notice"))
        self.assertTrue(_text_matches_privacy_link("Data Privacy"))

    def test_terms_link_text(self):
        self.assertTrue(_text_matches_terms_link("Terms of Service"))
        self.assertTrue(_text_matches_terms_link("Terms and Conditions"))
        self.assertTrue(_text_matches_terms_link("terms of use"))
        self.assertTrue(_text_matches_terms_link("EULA"))

    def test_unrelated_text_not_matched(self):
        self.assertFalse(_text_matches_privacy_link("Contact Us"))
        self.assertFalse(_text_matches_terms_link("About Us"))


# ---------------------------------------------------------------------------
# Content analysis tests
# ---------------------------------------------------------------------------

class TestDocumentClassification(unittest.TestCase):
    def test_privacy_policy_document_detected(self):
        self.assertTrue(_is_privacy_policy_document(PRIVACY_POLICY_TEXT))

    def test_terms_document_detected(self):
        self.assertTrue(_is_terms_document(TERMS_TEXT))

    def test_empty_string_is_not_privacy_policy(self):
        self.assertFalse(_is_privacy_policy_document(""))

    def test_random_text_is_not_privacy_policy(self):
        self.assertFalse(_is_privacy_policy_document("Hello world! Buy now."))

    def test_random_text_is_not_terms(self):
        self.assertFalse(_is_terms_document("Hello world! Click here."))


class TestPersonalDataDetection(unittest.TestCase):
    def test_detects_identity_category(self):
        cats = _detect_disclosed_data_categories("We collect your name and username.")
        self.assertIn("identity", cats)

    def test_detects_contact_category(self):
        cats = _detect_disclosed_data_categories("We collect your email address and phone number.")
        self.assertIn("contact", cats)

    def test_detects_location_category(self):
        cats = _detect_disclosed_data_categories("We access your location data via GPS.")
        self.assertIn("location", cats)

    def test_detects_device_identifiers(self):
        cats = _detect_disclosed_data_categories("We collect your IP address and device identifier.")
        self.assertIn("device_identifiers", cats)

    def test_detects_financial_category(self):
        cats = _detect_disclosed_data_categories("We process payment information and billing information.")
        self.assertIn("financial", cats)

    def test_detects_usage_analytics(self):
        cats = _detect_disclosed_data_categories("We collect usage data and analytics.")
        self.assertIn("usage_analytics", cats)

    def test_detects_multiple_categories(self):
        cats = _detect_disclosed_data_categories(PRIVACY_POLICY_TEXT)
        self.assertGreaterEqual(len(cats), MIN_DATA_CATEGORIES)

    def test_returns_empty_for_no_data(self):
        cats = _detect_disclosed_data_categories("Hello world.")
        self.assertEqual(cats, [])

    def test_all_defined_categories_tested(self):
        # Ensure every PERSONAL_DATA_CATEGORIES key can be found by at least
        # one keyword match — guards against accidentally empty keyword lists.
        for category, keywords in PERSONAL_DATA_CATEGORIES.items():
            self.assertGreater(
                len(keywords), 0,
                f"Category '{category}' has no keywords defined",
            )


# ---------------------------------------------------------------------------
# HTML helpers tests
# ---------------------------------------------------------------------------

class TestHtmlHelpers(unittest.TestCase):
    def test_extract_links(self):
        html = '<a href="https://example.com/privacy">Privacy Policy</a>'
        links = _extract_links_from_html(html)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0][0], "https://example.com/privacy")
        self.assertEqual(links[0][1], "Privacy Policy")

    def test_extract_multiple_links(self):
        links = _extract_links_from_html(PLAY_STORE_HTML)
        hrefs = [h for h, _ in links]
        self.assertIn("https://example.com/privacy-policy", hrefs)
        self.assertIn("https://example.com/terms-of-service", hrefs)

    def test_extract_text_strips_tags(self):
        html = "<p>Hello <b>world</b>!</p>"
        text = _extract_text_from_html(html)
        self.assertIn("Hello", text)
        self.assertIn("world", text)
        self.assertNotIn("<b>", text)

    def test_extract_text_removes_scripts(self):
        html = "<script>alert('xss')</script><p>Safe content</p>"
        text = _extract_text_from_html(html)
        self.assertNotIn("alert", text)
        self.assertIn("Safe content", text)

    def test_resolve_relative_url(self):
        full = _resolve_url("/privacy", "https://example.com/app")
        self.assertEqual(full, "https://example.com/privacy")

    def test_resolve_absolute_url_unchanged(self):
        full = _resolve_url("https://other.com/privacy", "https://example.com/app")
        self.assertEqual(full, "https://other.com/privacy")


# ---------------------------------------------------------------------------
# PrivacyPolicyResult model tests
# ---------------------------------------------------------------------------

class TestPrivacyPolicyResultModel(unittest.TestCase):
    def _make_result(
        self,
        has_pp: bool = False,
        has_tc: bool = False,
        categories: list | None = None,
    ) -> PrivacyPolicyResult:
        r = PrivacyPolicyResult(
            source="test.apk",
            package_name="com.example",
            app_label="Example",
        )
        r.has_privacy_policy = has_pp
        r.has_terms_and_conditions = has_tc
        r.disclosed_data_categories = categories or []
        r.discloses_collected_data = len(r.disclosed_data_categories) >= MIN_DATA_CATEGORIES
        return r

    def test_compliant_score(self):
        r = self._make_result(
            has_pp=True,
            has_tc=True,
            categories=["identity", "contact", "location"],
        )
        self.assertEqual(r.compliance_score, "COMPLIANT")

    def test_non_compliant_no_privacy_policy(self):
        r = self._make_result(has_pp=False)
        self.assertEqual(r.compliance_score, "NON_COMPLIANT")

    def test_partial_missing_tc(self):
        r = self._make_result(
            has_pp=True,
            has_tc=False,
            categories=["identity", "contact"],
        )
        self.assertEqual(r.compliance_score, "PARTIAL")

    def test_partial_insufficient_data_disclosure(self):
        # Only 1 category — below MIN_DATA_CATEGORIES
        r = self._make_result(has_pp=True, has_tc=True, categories=["identity"])
        r.discloses_collected_data = False
        self.assertEqual(r.compliance_score, "PARTIAL")

    def test_summary_contains_required_keys(self):
        r = self._make_result(has_pp=True, has_tc=True, categories=["identity", "contact"])
        s = r.summary()
        for key in ("source", "package", "label", "compliance_score", "checks", "errors", "findings"):
            self.assertIn(key, s)

    def test_summary_checks_structure(self):
        r = self._make_result(has_pp=True, has_tc=True, categories=["identity", "contact"])
        checks = r.summary()["checks"]
        for key in (
            "privacy_policy_present",
            "privacy_policy_url",
            "terms_and_conditions_present",
            "terms_url",
            "discloses_collected_data",
            "disclosed_data_categories",
        ):
            self.assertIn(key, checks)


# ---------------------------------------------------------------------------
# APK analysis (offline, skip_fetch=True)
# ---------------------------------------------------------------------------

class TestApkAnalysisOffline(unittest.TestCase):
    """Tests that do not make any HTTP requests (skip_fetch=True)."""

    def _analyze(self, apk_bytes: bytes) -> PrivacyPolicyResult:
        tmp = _write_tmp_apk(apk_bytes)
        try:
            return PrivacyPolicyAnalyzer(tmp, skip_fetch=True).analyze()
        finally:
            os.unlink(tmp)

    def test_package_name_extracted(self):
        apk = _make_apk(_make_manifest(package="com.test.pkg"))
        result = self._analyze(apk)
        self.assertEqual(result.package_name, "com.test.pkg")

    def test_app_label_extracted(self):
        apk = _make_apk(_make_manifest(label="MyLabel"))
        result = self._analyze(apk)
        self.assertEqual(result.app_label, "MyLabel")

    def test_privacy_url_in_manifest_attribute(self):
        apk = _make_apk(_make_manifest(
            privacy_policy_attr="https://example.com/privacy-policy"
        ))
        result = self._analyze(apk)
        self.assertTrue(result.has_privacy_policy)
        self.assertIn("https://example.com/privacy-policy", result.all_policy_urls_found)

    def test_privacy_url_in_manifest_text(self):
        manifest = (
            _make_manifest() +
            "<!-- https://example.com/privacy_policy -->"
        )
        apk = _make_apk(manifest)
        result = self._analyze(apk)
        self.assertIn("https://example.com/privacy_policy", result.all_policy_urls_found)

    def test_terms_url_in_dex(self):
        dex_content = (
            b"some binary data "
            b"https://example.com/terms-of-service "
            b"more data"
        )
        apk = _make_apk(
            _make_manifest(),
            {"classes.dex": dex_content},
        )
        result = self._analyze(apk)
        self.assertTrue(result.has_terms_and_conditions)
        self.assertIn("https://example.com/terms-of-service", result.all_terms_urls_found)

    def test_privacy_url_in_dex(self):
        dex_content = (
            b"binary data "
            b"https://myapp.io/privacy-policy "
            b"more bytes"
        )
        apk = _make_apk(
            _make_manifest(),
            {"classes.dex": dex_content},
        )
        result = self._analyze(apk)
        self.assertTrue(result.has_privacy_policy)

    def test_both_urls_in_dex(self):
        dex_content = (
            b"https://example.com/privacy-policy "
            b"https://example.com/terms-of-service"
        )
        apk = _make_apk(_make_manifest(), {"classes.dex": dex_content})
        result = self._analyze(apk)
        self.assertTrue(result.has_privacy_policy)
        self.assertTrue(result.has_terms_and_conditions)

    def test_privacy_url_in_resources(self):
        res_content = b"some resource data https://example.com/privacypolicy binary"
        apk = _make_apk(_make_manifest(), {"resources.arsc": res_content})
        result = self._analyze(apk)
        self.assertIn("https://example.com/privacypolicy", result.all_policy_urls_found)

    def test_no_urls_found(self):
        apk = _make_apk(_make_manifest())
        result = self._analyze(apk)
        self.assertFalse(result.has_privacy_policy)
        self.assertFalse(result.has_terms_and_conditions)
        self.assertEqual(result.compliance_score, "NON_COMPLIANT")

    def test_missing_apk_raises(self):
        with self.assertRaises(FileNotFoundError):
            PrivacyPolicyAnalyzer("/nonexistent/app.apk").analyze()

    def test_invalid_zip_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a zip file")
            tmp = f.name
        try:
            with self.assertRaises(ValueError):
                PrivacyPolicyAnalyzer(tmp).analyze()
        finally:
            os.unlink(tmp)

    def test_asset_bundled_privacy_policy(self):
        """An APK bundling a privacy policy HTML asset is detected offline."""
        html_asset = PRIVACY_POLICY_TEXT.encode()
        apk = _make_apk(_make_manifest(), {"assets/privacy.html": html_asset})
        result = self._analyze(apk)
        self.assertTrue(result.has_privacy_policy)

    def test_asset_bundled_terms(self):
        """An APK bundling a T&C text asset is detected offline."""
        txt_asset = TERMS_TEXT.encode()
        apk = _make_apk(_make_manifest(), {"assets/terms.txt": txt_asset})
        result = self._analyze(apk)
        self.assertTrue(result.has_terms_and_conditions)


# ---------------------------------------------------------------------------
# APK analysis with mocked HTTP
# ---------------------------------------------------------------------------

class TestApkAnalysisWithFetch(unittest.TestCase):
    """Tests that mock HTTP so we can verify fetch + content analysis."""

    def _analyze_with_fetch(
        self,
        apk_bytes: bytes,
        url_to_content: dict[str, str],
    ) -> PrivacyPolicyResult:
        def fake_fetch(url: str, timeout: int = 15) -> str | None:
            return url_to_content.get(url)

        tmp = _write_tmp_apk(apk_bytes)
        try:
            with patch("privacy_policy_analyzer._fetch_url", side_effect=fake_fetch):
                return PrivacyPolicyAnalyzer(tmp, skip_fetch=False).analyze()
        finally:
            os.unlink(tmp)

    def test_fetches_and_confirms_privacy_policy(self):
        dex = b"https://example.com/privacy-policy"
        apk = _make_apk(_make_manifest(), {"classes.dex": dex})
        result = self._analyze_with_fetch(
            apk,
            {"https://example.com/privacy-policy": PRIVACY_POLICY_TEXT},
        )
        self.assertTrue(result.has_privacy_policy)
        self.assertEqual(result.privacy_policy_url, "https://example.com/privacy-policy")

    def test_fetches_and_confirms_terms(self):
        dex = b"https://example.com/terms-of-service"
        apk = _make_apk(_make_manifest(), {"classes.dex": dex})
        result = self._analyze_with_fetch(
            apk,
            {"https://example.com/terms-of-service": TERMS_TEXT},
        )
        self.assertTrue(result.has_terms_and_conditions)
        self.assertEqual(result.terms_url, "https://example.com/terms-of-service")

    def test_detects_data_categories_from_policy(self):
        dex = b"https://example.com/privacy-policy"
        apk = _make_apk(_make_manifest(), {"classes.dex": dex})
        result = self._analyze_with_fetch(
            apk,
            {"https://example.com/privacy-policy": PRIVACY_POLICY_TEXT},
        )
        self.assertTrue(result.discloses_collected_data)
        self.assertGreaterEqual(len(result.disclosed_data_categories), MIN_DATA_CATEGORIES)

    def test_thin_policy_fails_data_disclosure(self):
        dex = b"https://example.com/privacy-policy"
        apk = _make_apk(_make_manifest(), {"classes.dex": dex})
        result = self._analyze_with_fetch(
            apk,
            {"https://example.com/privacy-policy": THIN_PRIVACY_TEXT},
        )
        # Thin policy is a valid privacy policy document but discloses nothing
        self.assertTrue(result.has_privacy_policy)
        self.assertFalse(result.discloses_collected_data)
        self.assertEqual(result.compliance_score, "PARTIAL")

    def test_fetch_failure_recorded_as_error(self):
        dex = b"https://example.com/privacy-policy"
        apk = _make_apk(_make_manifest(), {"classes.dex": dex})
        # _fetch_url returns None (network failure)
        result = self._analyze_with_fetch(apk, {})
        self.assertTrue(any("Could not fetch" in e for e in result.errors))

    def test_full_compliant_analysis(self):
        dex = (
            b"https://example.com/privacy-policy "
            b"https://example.com/terms-of-service"
        )
        apk = _make_apk(_make_manifest(), {"classes.dex": dex})
        result = self._analyze_with_fetch(
            apk,
            {
                "https://example.com/privacy-policy": PRIVACY_POLICY_TEXT,
                "https://example.com/terms-of-service": TERMS_TEXT,
            },
        )
        self.assertEqual(result.compliance_score, "COMPLIANT")


# ---------------------------------------------------------------------------
# Google Play URL analysis (mocked)
# ---------------------------------------------------------------------------

class TestPlayUrlAnalysis(unittest.TestCase):

    def _analyze_play(
        self,
        play_url: str,
        fetch_map: dict[str, str],
    ) -> PrivacyPolicyResult:
        def fake_fetch(url: str, timeout: int = 15) -> str | None:
            return fetch_map.get(url)

        with patch("privacy_policy_analyzer._fetch_url", side_effect=fake_fetch):
            return PrivacyPolicyAnalyzer(play_url).analyze()

    PLAY_URL = "https://play.google.com/store/apps/details?id=com.example.app"
    PLAY_PAGE = (
        "https://play.google.com/store/apps/details"
        "?id=com.example.app&hl=en"
    )

    def test_package_extracted_from_url(self):
        result = PrivacyPolicyAnalyzer(self.PLAY_URL, skip_fetch=True).analyze()
        self.assertEqual(result.package_name, "com.example.app")

    def test_bad_play_url_no_id(self):
        bad_url = "https://play.google.com/store/apps/details"
        result = PrivacyPolicyAnalyzer(bad_url, skip_fetch=True).analyze()
        self.assertTrue(any("package ID" in e for e in result.errors))

    def test_play_page_fetch_failure(self):
        result = self._analyze_play(self.PLAY_URL, {})
        self.assertTrue(any("Could not fetch Play Store" in e for e in result.errors))

    def test_privacy_link_found_on_play_page(self):
        result = self._analyze_play(
            self.PLAY_URL,
            {
                self.PLAY_PAGE: PLAY_STORE_HTML,
                "https://example.com/privacy-policy": PRIVACY_POLICY_TEXT,
                "https://example.com/terms-of-service": TERMS_TEXT,
            },
        )
        self.assertTrue(result.has_privacy_policy)

    def test_terms_link_found_on_play_page(self):
        result = self._analyze_play(
            self.PLAY_URL,
            {
                self.PLAY_PAGE: PLAY_STORE_HTML,
                "https://example.com/privacy-policy": PRIVACY_POLICY_TEXT,
                "https://example.com/terms-of-service": TERMS_TEXT,
            },
        )
        self.assertTrue(result.has_terms_and_conditions)

    def test_compliant_play_analysis(self):
        result = self._analyze_play(
            self.PLAY_URL,
            {
                self.PLAY_PAGE: PLAY_STORE_HTML,
                "https://example.com/privacy-policy": PRIVACY_POLICY_TEXT,
                "https://example.com/terms-of-service": TERMS_TEXT,
            },
        )
        self.assertEqual(result.compliance_score, "COMPLIANT")


# ---------------------------------------------------------------------------
# Reporting smoke tests
# ---------------------------------------------------------------------------

class TestPrintReport(unittest.TestCase):
    def _compliant_result(self) -> PrivacyPolicyResult:
        r = PrivacyPolicyResult(
            source="test.apk",
            package_name="com.example",
            app_label="TestApp",
        )
        r.has_privacy_policy = True
        r.privacy_policy_url = "https://example.com/privacy"
        r.has_terms_and_conditions = True
        r.terms_url = "https://example.com/terms"
        r.disclosed_data_categories = ["identity", "contact", "location"]
        r.discloses_collected_data = True
        return r

    def test_report_compliant_smoke(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(self._compliant_result(), verbose=False)
        output = buf.getvalue()
        self.assertIn("COMPLIANT", output)
        self.assertIn("YES", output)

    def test_report_verbose_shows_findings(self):
        r = self._compliant_result()
        r.findings.append(PolicyFinding(
            source="DEX",
            finding_type="privacy_url",
            detail="Privacy URL found",
            url="https://example.com/privacy",
        ))
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(r, verbose=True)
        output = buf.getvalue()
        self.assertIn("privacy_url", output)

    def test_report_non_compliant(self):
        r = PrivacyPolicyResult(
            source="test.apk",
            package_name="com.example",
            app_label="TestApp",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(r, verbose=False)
        output = buf.getvalue()
        self.assertIn("NON_COMPLIANT", output)

    def test_report_partial(self):
        r = PrivacyPolicyResult(
            source="test.apk",
            package_name="com.example",
            app_label="TestApp",
        )
        r.has_privacy_policy = True
        r.privacy_policy_url = "https://example.com/privacy"
        r.has_terms_and_conditions = False
        r.discloses_collected_data = False
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(r, verbose=False)
        output = buf.getvalue()
        self.assertIn("PARTIAL", output)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

class TestJsonOutput(unittest.TestCase):
    def test_summary_is_json_serialisable(self):
        r = PrivacyPolicyResult(
            source="test.apk",
            package_name="com.example",
            app_label="TestApp",
        )
        r.has_privacy_policy = True
        r.disclosed_data_categories = ["identity", "contact"]
        data = json.dumps(r.summary())  # must not raise
        parsed = json.loads(data)
        self.assertEqual(parsed["package"], "com.example")
        self.assertTrue(parsed["checks"]["privacy_policy_present"])

    def test_summary_findings_serialised(self):
        r = PrivacyPolicyResult(
            source="test.apk",
            package_name="com.example",
            app_label="TestApp",
        )
        r.findings.append(PolicyFinding(
            source="DEX",
            finding_type="privacy_url",
            detail="Found privacy URL",
            url="https://example.com/privacy",
        ))
        data = json.dumps(r.summary())
        parsed = json.loads(data)
        self.assertEqual(len(parsed["findings"]), 1)
        self.assertEqual(parsed["findings"][0]["type"], "privacy_url")


if __name__ == "__main__":
    unittest.main(verbosity=2)
