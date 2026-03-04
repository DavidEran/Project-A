#!/usr/bin/env python3
"""
Privacy Policy Analyzer - Compliance checker for Android apps.

Analyzes an APK file or Google Play Store URL to verify:
  1. A privacy policy is in place and accessible
  2. Terms & Conditions (T&C) are in place and accessible
  3. The privacy policy discloses which personal data is collected

Input modes:
  APK file  — static scan of the binary for embedded policy URLs, then fetches
              and analyzes each URL found.
  Play URL  — fetches the Google Play Store listing to extract the developer's
              privacy policy and T&C links, then analyzes their content.

Usage:
  python3 privacy_policy_analyzer.py app.apk
  python3 privacy_policy_analyzer.py "https://play.google.com/store/apps/details?id=com.example.app"
  python3 privacy_policy_analyzer.py app.apk --json
  python3 privacy_policy_analyzer.py app.apk --verbose
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Personal data categories and detection patterns
# ---------------------------------------------------------------------------

# Maps category name -> list of keywords indicating that category is disclosed.
# Matching is case-insensitive against the full policy text.
PERSONAL_DATA_CATEGORIES: dict[str, list[str]] = {
    "identity": [
        "your name", "first name", "last name", "full name", "username",
        "user id", "account name", "profile name", "display name",
    ],
    "contact": [
        "email address", "e-mail", "phone number", "telephone", "mobile number",
        "postal address", "mailing address", "zip code", "postcode",
    ],
    "location": [
        "location", "gps", "geolocation", "geo-location", "latitude", "longitude",
        "geographic location", "location data", "whereabouts",
    ],
    "device_identifiers": [
        "device id", "device identifier", "imei", "imsi", "mac address",
        "ip address", "advertising id", "android id", "hardware identifier",
        "unique identifier", "device information",
        # Explicit advertising / platform identifier phrases
        "unique device identifier", "identifier for advertising",
        "advertising identifier", "google advertiser id",
        "apple id for advertising", "idfa", "gaid",
        "google advertising id",
    ],
    "financial": [
        "payment information", "credit card", "debit card", "billing information",
        "purchase history", "transaction", "bank account", "financial information",
    ],
    "health": [
        "health data", "health information", "medical information", "biometric",
        "fitness data", "heart rate", "blood pressure", "weight",
    ],
    "usage_analytics": [
        "usage data", "analytics", "log data", "activity data", "crash report",
        "diagnostic", "app usage", "browsing history", "search history",
        "interactions", "clickstream",
    ],
    "communications": [
        "messages", "contact list", "call logs", "sms", "chat history",
        "communications", "address book",
    ],
    "media": [
        "photos", "camera", "images", "videos", "audio recordings",
        "microphone", "media files",
    ],
    "demographics": [
        "age", "date of birth", "birthday", "gender", "nationality",
        "ethnicity", "religion", "marital status",
    ],
    "credentials": [
        "password", "security question", "authentication token", "access token",
        "login credentials",
    ],
}

# Phrases that strongly indicate the document is a privacy policy
PRIVACY_POLICY_INDICATORS = [
    "privacy policy",
    "privacy notice",
    "data privacy",
    "data protection policy",
    "information we collect",
    "data we collect",
    "we collect",
    "personal information",
    "personal data",
    "how we use your",
]

# Phrases that strongly indicate the document is a T&C
TERMS_INDICATORS = [
    "terms of service",
    "terms and conditions",
    "terms of use",
    "user agreement",
    "end user license agreement",
    "eula",
    "by using our",
    "you agree to",
    "acceptance of terms",
    "your use of",
]

# URL sub-patterns (applied against the full URL, case-insensitive)
PRIVACY_URL_PATTERNS = [
    r"privacy[_\-]?polic",
    r"privacy[_\-]?notice",
    r"data[_\-]?privacy",
    r"data[_\-]?protection",
    r"privacynotice",
    r"datapolicy",
    r"gdpr",
]

TERMS_URL_PATTERNS = [
    r"terms[_\-]?of[_\-]?service",
    r"terms[_\-]?of[_\-]?use",
    r"terms[_\-]?and[_\-]?conditions",
    r"terms[_\-]?conditions",
    r"termsofservice",
    r"termsofuse",
    r"\btos\b",
    r"user[_\-]?agreement",
    r"eula",
    r"legal[_\-]?notice",
]

# Link-text phrases to match (case-insensitive) when scanning HTML
PRIVACY_LINK_TEXT = ["privacy policy", "privacy notice", "data privacy", "privacy"]
TERMS_LINK_TEXT = [
    "terms of service", "terms and conditions", "terms of use",
    "user agreement", "terms", "eula",
]

# Minimum number of personal data categories that must be disclosed for
# the privacy policy to be considered informative.
MIN_DATA_CATEGORIES = 1

# Phrases that indicate the developer explicitly declares they collect no
# personal data.  When matched, check 3 is treated as passed (the
# disclosure IS "we collect nothing").
NO_DATA_COLLECTION_PHRASES = [
    "we do not collect",
    "we don't collect",
    "we do not store",
    "we don't store",
    "no personal information is collected",
    "no personal data is collected",
    "no personal information collected",
    "no personally identifiable information",
    "does not collect any personal",
    "do not collect any personal",
    "not collect or store",
    "we collect no personal",
    "no data is collected",
    "no information is collected",
]

# HTTP request timeout in seconds
HTTP_TIMEOUT = 15

# Common User-Agent for fetching web pages
HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 10; Mobile) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PolicyFinding:
    """A single finding recorded during analysis."""
    source: str      # Where this was found (e.g. "AndroidManifest.xml", "DEX", "Play Store")
    finding_type: str  # "privacy_url", "terms_url", "data_category", "policy_indicator", "error"
    detail: str
    url: Optional[str] = None


@dataclass
class PrivacyPolicyResult:
    """Complete analysis result for a privacy policy compliance check."""
    source: str                  # APK path or Play Store URL
    package_name: str
    app_label: str

    # Check 1: Privacy policy
    has_privacy_policy: bool = False
    privacy_policy_url: Optional[str] = None

    # Check 2: Terms & Conditions
    has_terms_and_conditions: bool = False
    terms_url: Optional[str] = None

    # Check 3: Personal data disclosure
    discloses_collected_data: bool = False
    disclosed_data_categories: list = field(default_factory=list)  # category names found
    # True when the policy explicitly declares that no personal data is
    # collected (rather than simply not mentioning any categories).
    declares_no_data_collection: bool = False

    # Supporting data
    all_policy_urls_found: list = field(default_factory=list)   # all candidate privacy URLs
    all_terms_urls_found: list = field(default_factory=list)    # all candidate terms URLs
    findings: list = field(default_factory=list)                # PolicyFinding objects
    errors: list = field(default_factory=list)
    # URLs whose identity is confirmed by an authoritative label (e.g. the
    # Play Store "Privacy Policy" link).  Content-check failures are ignored
    # for these — the label itself is sufficient confirmation.
    trusted_policy_urls: set = field(default_factory=set)
    # Same for T&C: URLs whose link text explicitly said "Terms & Conditions"
    # (or equivalent) on the developer's own website.
    trusted_terms_urls: set = field(default_factory=set)

    @property
    def compliance_score(self) -> str:
        """
        Overall compliance verdict.

        COMPLIANT     - Privacy policy present, T&C present, data disclosure found.
        PARTIAL       - Privacy policy present but T&C missing OR insufficient
                        data disclosure.
        NON_COMPLIANT - No privacy policy detected.
        """
        if not self.has_privacy_policy:
            return "NON_COMPLIANT"
        if self.has_terms_and_conditions and self.discloses_collected_data:
            return "COMPLIANT"
        return "PARTIAL"

    def summary(self) -> dict:
        return {
            "source": self.source,
            "package": self.package_name,
            "label": self.app_label,
            "compliance_score": self.compliance_score,
            "checks": {
                "privacy_policy_present": self.has_privacy_policy,
                "privacy_policy_url": self.privacy_policy_url,
                "terms_and_conditions_present": self.has_terms_and_conditions,
                "terms_url": self.terms_url,
                "discloses_collected_data": self.discloses_collected_data,
                "disclosed_data_categories": self.disclosed_data_categories,
                "declares_no_data_collection": self.declares_no_data_collection,
            },
            "all_privacy_urls_found": self.all_policy_urls_found,
            "all_terms_urls_found": self.all_terms_urls_found,
            "errors": self.errors,
            "findings": [
                {
                    "source": f.source,
                    "type": f.finding_type,
                    "detail": f.detail,
                    "url": f.url,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """Minimal HTMLParser subclass that collects (href, link_text) pairs."""

    def __init__(self):
        super().__init__()
        self._current_href: Optional[str] = None
        self._current_text: list[str] = []
        self.links: list[tuple[str, str]] = []   # (href, text)

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "a":
            attr_dict = dict(attrs)
            self._current_href = attr_dict.get("href", "")
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._current_href is not None:
            text = " ".join(self._current_text).strip()
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


def _extract_links_from_html(html_text: str) -> list[tuple[str, str]]:
    """Return a list of (href, link_text) from an HTML document."""
    parser = _LinkExtractor()
    try:
        parser.feed(html_text)
    except Exception:
        pass
    return parser.links


def _extract_text_from_html(html_text: str) -> str:
    """Strip HTML tags and return plain text (best-effort)."""
    # Remove script and style blocks
    text = re.sub(r"<(script|style)[^>]*>.*?</(script|style)>", " ", html_text,
                  flags=re.DOTALL | re.IGNORECASE)
    # Remove all remaining tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Decode HTML entities
    try:
        import html as html_module
        text = html_module.unescape(text)
    except Exception:
        pass
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _is_play_store_url(source: str) -> bool:
    return "play.google.com/store/apps" in source


def _package_from_play_url(url: str) -> str:
    """Extract the package ID from a Google Play Store URL."""
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    return qs.get("id", [""])[0]


def _url_matches_privacy(url: str) -> bool:
    low = url.lower()
    return any(re.search(p, low) for p in PRIVACY_URL_PATTERNS)


def _url_matches_terms(url: str) -> bool:
    low = url.lower()
    return any(re.search(p, low) for p in TERMS_URL_PATTERNS)


def _text_matches_privacy_link(text: str) -> bool:
    low = text.lower().strip()
    return any(phrase in low for phrase in PRIVACY_LINK_TEXT)


def _text_matches_terms_link(text: str) -> bool:
    low = text.lower().strip()
    return any(phrase in low for phrase in TERMS_LINK_TEXT)


def _fetch_url(url: str, timeout: int = HTTP_TIMEOUT) -> Optional[str]:
    """
    Fetch a URL and return the response body as a string.
    Returns None on any error (network, HTTP, encoding).
    """
    try:
        req = urllib.request.Request(url, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            charset = "utf-8"
            ct = resp.headers.get_content_charset()
            if ct:
                charset = ct
            return raw.decode(charset, errors="replace")
    except Exception:
        return None


def _resolve_url(href: str, base_url: str) -> str:
    """Resolve a potentially relative URL against a base URL."""
    return urllib.parse.urljoin(base_url, href)


def _extract_play_store_support_urls(
    html: str,
) -> tuple[Optional[str], Optional[str]]:
    """
    Extract (privacy_policy_url, developer_website_url) from a raw Play Store
    HTML page.

    Strategy (mirrors what a user sees on the Play Store page):
      - The link labelled "Privacy Policy" IS the app's privacy policy.
        Google mandates it, so it is always present.  The label alone
        is sufficient — we do not inspect the URL shape at all.
      - The link labelled "Website" is the developer's homepage.  We
        fetch that page separately to find T&C.

    Google Play embeds these as JSON strings in <script> tags.  The URL
    may appear before or after its label, so we use nearest-neighbour
    matching: find the non-Google quoted URL sitting closest (in either
    direction) to the label text in the raw HTML.
    """
    # Play Store JSON encodes forward-slashes as \/ (e.g. "https:\/\/example.com").
    # Normalise before any processing so the URL regex matches them.
    html = html.replace('\\/', '/')

    QUOTED_URL = re.compile(r'"(https?://[^"\s]{8,})"')

    # Index all non-Google quoted URLs once.
    all_candidates: list[tuple[int, str]] = [
        (m.start(), m.group(1))
        for m in QUOTED_URL.finditer(html)
        if not _is_google_url(m.group(1))
    ]

    def _nearest(
        keywords: list,
        candidates: list,
        max_dist: int = 1000,
    ) -> Optional[str]:
        best_url: Optional[str] = None
        best_dist = max_dist + 1
        for keyword in keywords:
            for km in re.finditer(re.escape(keyword), html, re.IGNORECASE):
                kpos = km.start()
                for upos, url in candidates:
                    dist = abs(upos - kpos)
                    if dist < best_dist:
                        best_dist = dist
                        best_url = url
        return best_url

    # PP: label is the signal, no URL-pattern filtering needed.
    pp_url = _nearest(
        ["privacy policy", "privacypolicy", "privacy_policy"],
        all_candidates,
    )

    # Website: skip URLs that look like policy pages so we get the homepage.
    web_candidates = [
        (upos, url) for upos, url in all_candidates
        if not _url_matches_privacy(url) and not _url_matches_terms(url)
    ]
    website_url = _nearest(
        # Play Store renders "Visit website" as the App Support button label;
        # older/alternate renders may use "Website" or "Developer website".
        ['"Visit website"', '"website"', "developer website", "visit website"],
        web_candidates,
        max_dist=1200,
    )

    return pp_url, website_url


# Domains owned by Google that should never be treated as an app's own
# privacy policy or T&C source.
_GOOGLE_DOMAINS = frozenset({
    "google.com",
    "googlepolicies.com",
    "googleapis.com",
    "gstatic.com",
    "android.com",
    "googletagmanager.com",
    "doubleclick.net",
    "ggpht.com",
    "g.co",
    "googleusercontent.com",
    "youtube.com",
})


def _is_google_url(url: str) -> bool:
    """Return True if the URL belongs to a Google-owned domain."""
    try:
        host = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
        return any(host == gd or host.endswith("." + gd) for gd in _GOOGLE_DOMAINS)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Content analysis
# ---------------------------------------------------------------------------

def _is_privacy_policy_document(text: str) -> bool:
    """Return True if the text looks like a privacy policy."""
    low = text.lower()
    hits = sum(1 for kw in PRIVACY_POLICY_INDICATORS if kw in low)
    return hits >= 2


def _is_terms_document(text: str) -> bool:
    """Return True if the text looks like a Terms & Conditions document."""
    low = text.lower()
    hits = sum(1 for kw in TERMS_INDICATORS if kw in low)
    return hits >= 2


def _detect_disclosed_data_categories(text: str) -> list[str]:
    """
    Return the list of personal data category names mentioned in the text.
    Matching is case-insensitive; each keyword must appear as a whole phrase.
    """
    low = text.lower()
    found = []
    for category, keywords in PERSONAL_DATA_CATEGORIES.items():
        if any(kw in low for kw in keywords):
            found.append(category)
    return found


def _declares_no_personal_data_collected(text: str) -> bool:
    """
    Return True if the text contains an explicit declaration that no
    personal data is collected (e.g. "We do not collect any personal
    information").
    """
    low = text.lower()
    return any(phrase in low for phrase in NO_DATA_COLLECTION_PHRASES)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class PrivacyPolicyAnalyzer:
    """
    Checks an Android app (APK or Play Store URL) for privacy compliance:
      1. Privacy policy present
      2. Terms & Conditions present
      3. Privacy policy discloses personal data categories
    """

    def __init__(self, source: str, verbose: bool = False, skip_fetch: bool = False):
        """
        Args:
            source:     APK file path or Google Play Store URL.
            verbose:    Log progress details to stdout.
            skip_fetch: Do not make HTTP requests (useful for offline tests).
        """
        self.source = source
        self.verbose = verbose
        self.skip_fetch = skip_fetch

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self) -> PrivacyPolicyResult:
        if _is_play_store_url(self.source):
            return self._analyze_play_url()
        else:
            return self._analyze_apk()

    # ------------------------------------------------------------------
    # APK analysis
    # ------------------------------------------------------------------

    def _analyze_apk(self) -> PrivacyPolicyResult:
        if not os.path.isfile(self.source):
            raise FileNotFoundError(f"APK not found: {self.source}")
        if not zipfile.is_zipfile(self.source):
            raise ValueError(f"Not a valid APK (zip) file: {self.source}")

        result = PrivacyPolicyResult(
            source=self.source,
            package_name="",
            app_label="",
        )

        with zipfile.ZipFile(self.source, "r") as apk:
            self._apk_analyze_manifest(apk, result)
            self._apk_scan_dex(apk, result)
            self._apk_scan_resources(apk, result)
            self._apk_scan_assets(apk, result)

        self._deduplicate_urls(result)

        if not self.skip_fetch:
            self._fetch_and_classify_urls(result)

        self._finalize(result)
        return result

    def _apk_analyze_manifest(
        self, apk: zipfile.ZipFile, result: PrivacyPolicyResult
    ) -> None:
        try:
            manifest_data = apk.read("AndroidManifest.xml")
        except KeyError:
            result.errors.append("AndroidManifest.xml not found in APK")
            return

        # Try text XML first, then binary
        try:
            manifest_text = manifest_data.decode("utf-8")
            self._parse_manifest_text(manifest_text, result)
        except UnicodeDecodeError:
            self._parse_manifest_binary(manifest_data, result)

    def _parse_manifest_text(self, text: str, result: PrivacyPolicyResult) -> None:
        try:
            root = ET.fromstring(text)
            result.package_name = root.get("package", "")
            app_el = root.find("application")
            if app_el is not None:
                result.app_label = app_el.get(
                    "{http://schemas.android.com/apk/res/android}label", ""
                )
                # Android 10+ supports android:privacyPolicy attribute
                pp = app_el.get(
                    "{http://schemas.android.com/apk/res/android}privacyPolicy", ""
                )
                if pp and pp.startswith("http"):
                    self._record_privacy_url(pp, "AndroidManifest.xml (android:privacyPolicy)", result)
        except ET.ParseError as exc:
            result.errors.append(f"Manifest XML parse error: {exc}")

        # Also scan as raw text for any embedded URLs
        self._scan_text_for_urls("AndroidManifest.xml", text, result)

    def _parse_manifest_binary(self, data: bytes, result: PrivacyPolicyResult) -> None:
        """Extract package name and scan binary AXML for embedded URLs."""
        try:
            utf16 = data.decode("utf-16-le", errors="ignore")
            if not result.package_name:
                m = re.search(r'package="([^"]+)"', utf16)
                if m:
                    result.package_name = m.group(1)
            if not result.app_label:
                m = re.search(r'android:label="([^"]+)"', utf16)
                if m:
                    result.app_label = m.group(1)
        except Exception:
            pass

        latin1_text = data.decode("latin-1")
        self._scan_text_for_urls("AndroidManifest.xml", latin1_text, result)

        # Also try to pull the package from latin-1 decoded text
        if not result.package_name:
            m = re.search(r"package=\"([^\"]+)\"", latin1_text)
            if m:
                result.package_name = m.group(1)

    def _apk_scan_dex(self, apk: zipfile.ZipFile, result: PrivacyPolicyResult) -> None:
        dex_files = [n for n in apk.namelist() if re.match(r"classes\d*\.dex", n)]
        for dex_name in dex_files:
            if self.verbose:
                print(f"  Scanning DEX: {dex_name}")
            try:
                dex_data = apk.read(dex_name)
                text = dex_data.decode("latin-1")
                self._scan_text_for_urls(dex_name, text, result)
            except Exception as exc:
                result.errors.append(f"Error reading {dex_name}: {exc}")

    def _apk_scan_resources(
        self, apk: zipfile.ZipFile, result: PrivacyPolicyResult
    ) -> None:
        """Scan resources.arsc (binary) for embedded policy URLs."""
        if "resources.arsc" not in apk.namelist():
            return
        if self.verbose:
            print("  Scanning resources.arsc")
        try:
            data = apk.read("resources.arsc")
            text = data.decode("latin-1")
            self._scan_text_for_urls("resources.arsc", text, result)
        except Exception as exc:
            result.errors.append(f"Error reading resources.arsc: {exc}")

    def _apk_scan_assets(
        self, apk: zipfile.ZipFile, result: PrivacyPolicyResult
    ) -> None:
        """
        Scan text/HTML assets for bundled privacy policy or T&C content.
        Any asset whose name or content suggests a policy document is analyzed.
        """
        asset_files = [
            n for n in apk.namelist()
            if n.startswith("assets/") and (
                n.endswith(".html") or n.endswith(".htm") or n.endswith(".txt")
            )
        ]
        for asset_name in asset_files:
            if self.verbose:
                print(f"  Scanning asset: {asset_name}")
            try:
                raw = apk.read(asset_name).decode("utf-8", errors="replace")
                # Check if this asset is itself a privacy policy
                plain = _extract_text_from_html(raw)
                if _is_privacy_policy_document(plain):
                    result.has_privacy_policy = True
                    result.findings.append(PolicyFinding(
                        source=asset_name,
                        finding_type="privacy_url",
                        detail=f"Bundled privacy policy document found in asset: {asset_name}",
                    ))
                    categories = _detect_disclosed_data_categories(plain)
                    self._record_data_categories(categories, asset_name, result)
                elif _is_terms_document(plain):
                    result.has_terms_and_conditions = True
                    result.findings.append(PolicyFinding(
                        source=asset_name,
                        finding_type="terms_url",
                        detail=f"Bundled T&C document found in asset: {asset_name}",
                    ))
                # Also scan for URLs pointing to external policies
                self._scan_text_for_urls(asset_name, raw, result)
            except Exception as exc:
                result.errors.append(f"Error reading asset {asset_name}: {exc}")

    # ------------------------------------------------------------------
    # Google Play Store analysis
    # ------------------------------------------------------------------

    def _analyze_play_url(self) -> PrivacyPolicyResult:
        package_id = _package_from_play_url(self.source)
        result = PrivacyPolicyResult(
            source=self.source,
            package_name=package_id,
            app_label="",
        )

        if not package_id:
            result.errors.append(
                "Could not extract package ID from Play Store URL. "
                "Expected format: https://play.google.com/store/apps/details?id=com.example"
            )
            self._finalize(result)
            return result

        if self.skip_fetch:
            self._finalize(result)
            return result

        self._playwright_scrape_play_listing(result)
        self._fetch_and_classify_urls(result)
        self._finalize(result)
        return result

    def _playwright_scrape_play_listing(self, result: PrivacyPolicyResult) -> None:
        """
        Use a headless browser (Playwright) to render the Play Store listing,
        extract the Privacy Policy URL from the App Support section, click the
        "Website" link to open the developer's homepage in a new tab, then scan
        that page's rendered DOM for privacy policy and T&C links.

        This replaces the old urllib-based _fetch_play_listing approach: a real
        browser handles JavaScript rendering, Google's redirect chains, and the
        target="_blank" new-tab behaviour of the Website button.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            result.errors.append(
                "playwright is not installed. "
                "Run: pip install playwright && playwright install chromium"
            )
            return

        play_url = (
            f"https://play.google.com/store/apps/details"
            f"?id={urllib.parse.quote(result.package_name)}&hl=en"
        )

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                locale="en-US",
                viewport={"width": 1280, "height": 900},
            )
            page = context.new_page()

            # --- Load Play Store listing ---
            try:
                if self.verbose:
                    print(f"  [browser] Loading Play Store page: {play_url}")
                page.goto(play_url, wait_until="networkidle", timeout=30_000)
            except Exception as exc:
                result.errors.append(f"Could not load Play Store page: {exc}")
                browser.close()
                return

            # App label from page title ("App Name - Apps on Google Play")
            result.app_label = re.sub(r"\s*[-–|].*$", "", page.title()).strip()

            # --- Privacy Policy link (App Support section) ---
            # get_by_role("link") matches <a> elements by their accessible name,
            # which is the visible label text even when icons have aria-hidden.
            pp_href: Optional[str] = None
            for selector in [
                lambda: page.get_by_role("link", name=re.compile(r"privacy policy", re.IGNORECASE)).first,
                lambda: page.locator("a:has-text('Privacy policy'), a:has-text('Privacy Policy')").first,
            ]:
                try:
                    pp_href = selector().get_attribute("href", timeout=5_000)
                    if pp_href:
                        break
                except Exception:
                    continue

            if pp_href and not _is_google_url(pp_href):
                if self.verbose:
                    print(f"  [browser] App Support PP URL: {pp_href}")
                self._record_privacy_url(pp_href, "Play Store App Support", result)
                # Explicitly labelled by Google Play — trust it even if content
                # checks are inconclusive.
                result.trusted_policy_urls.add(pp_href)
            else:
                result.errors.append(
                    "Could not locate Privacy Policy URL in Play Store App Support section"
                )

            # --- Website button: click it, capture the new tab ---
            try:
                website_link = None
                for selector in [
                    lambda: page.get_by_role("link", name=re.compile(r"^website$", re.IGNORECASE)).first,
                    lambda: page.locator("a:has-text('Website')").first,
                ]:
                    try:
                        candidate = selector()
                        candidate.wait_for(state="visible", timeout=5_000)
                        website_link = candidate
                        break
                    except Exception:
                        continue

                if website_link is None:
                    raise RuntimeError("Website link not found on page")

                if self.verbose:
                    print("  [browser] Clicking Website link …")

                with context.expect_page(timeout=10_000) as popup_info:
                    website_link.click(timeout=5_000)

                dev_page = popup_info.value
                dev_page.wait_for_load_state("domcontentloaded", timeout=15_000)
                dev_url = dev_page.url

                if self.verbose:
                    print(f"  [browser] Developer website: {dev_url}")

                # Scan all rendered links on the developer homepage
                for link in dev_page.get_by_role("link").all():
                    try:
                        href = link.get_attribute("href")
                        text = link.inner_text().strip()
                    except Exception:
                        continue
                    if not href:
                        continue
                    full_url = _resolve_url(href, dev_url)
                    if _is_google_url(full_url):
                        continue
                    if _text_matches_privacy_link(text) or _url_matches_privacy(full_url):
                        self._record_privacy_url(full_url, "Developer website", result)
                    elif _text_matches_terms_link(text) or _url_matches_terms(full_url):
                        self._record_terms_url(full_url, "Developer website", result)
                        if _text_matches_terms_link(text):
                            result.trusted_terms_urls.add(full_url)

                dev_page.close()

            except Exception as exc:
                result.errors.append(
                    "Could not locate developer Website URL in Play Store App Support section"
                )
                if self.verbose:
                    print(f"  [browser] Website navigation failed: {exc}")

            browser.close()

    # ------------------------------------------------------------------
    # URL scanning helpers
    # ------------------------------------------------------------------

    def _scan_text_for_urls(
        self, source_label: str, text: str, result: PrivacyPolicyResult,
        skip_google: bool = False,
        skip_terms: bool = False,
    ) -> None:
        """Extract all https?:// URLs from text and classify privacy/terms ones."""
        urls = re.findall(r"https?://[^\s\"'<>\\,\x00-\x1f]{10,}", text)
        for url in urls:
            # Strip trailing punctuation that is likely not part of the URL
            url = url.rstrip(".,;:)'\"")
            if skip_google and _is_google_url(url):
                continue
            if _url_matches_privacy(url):
                self._record_privacy_url(url, source_label, result)
            elif not skip_terms and _url_matches_terms(url):
                self._record_terms_url(url, source_label, result)

    def _record_privacy_url(
        self, url: str, source_label: str, result: PrivacyPolicyResult
    ) -> None:
        if url not in result.all_policy_urls_found:
            result.all_policy_urls_found.append(url)
            result.findings.append(PolicyFinding(
                source=source_label,
                finding_type="privacy_url",
                detail=f"Privacy policy URL found: {url}",
                url=url,
            ))
            if self.verbose:
                print(f"    [privacy_url] {url}")

    def _record_terms_url(
        self, url: str, source_label: str, result: PrivacyPolicyResult
    ) -> None:
        if url not in result.all_terms_urls_found:
            result.all_terms_urls_found.append(url)
            result.findings.append(PolicyFinding(
                source=source_label,
                finding_type="terms_url",
                detail=f"T&C URL found: {url}",
                url=url,
            ))
            if self.verbose:
                print(f"    [terms_url] {url}")

    def _deduplicate_urls(self, result: PrivacyPolicyResult) -> None:
        result.all_policy_urls_found = list(dict.fromkeys(result.all_policy_urls_found))
        result.all_terms_urls_found = list(dict.fromkeys(result.all_terms_urls_found))

    # ------------------------------------------------------------------
    # URL fetching and content analysis
    # ------------------------------------------------------------------

    def _fetch_and_classify_urls(self, result: PrivacyPolicyResult) -> None:
        """
        Fetch each candidate URL, confirm its type, and analyse content.
        Stops fetching once both privacy policy and T&C are confirmed.
        """
        # Process privacy policy URLs
        for url in result.all_policy_urls_found:
            if result.has_privacy_policy and result.discloses_collected_data:
                break
            self._process_privacy_url(url, result)

        # Process terms URLs
        for url in result.all_terms_urls_found:
            if result.has_terms_and_conditions:
                break
            self._process_terms_url(url, result)

    def _process_privacy_url(self, url: str, result: PrivacyPolicyResult) -> None:
        if self.verbose:
            print(f"  Fetching privacy policy: {url}")
        content = _fetch_url(url)
        if content is None:
            result.errors.append(f"Could not fetch privacy policy URL: {url}")
            return

        plain = _extract_text_from_html(content)

        trusted = url in result.trusted_policy_urls
        if _is_privacy_policy_document(plain) or trusted:
            result.has_privacy_policy = True
            if not result.privacy_policy_url:
                result.privacy_policy_url = url
            if not trusted:
                result.findings.append(PolicyFinding(
                    source="HTTP fetch",
                    finding_type="privacy_url",
                    detail=f"Confirmed privacy policy document at: {url}",
                    url=url,
                ))
            categories = _detect_disclosed_data_categories(plain)
            self._record_data_categories(categories, url, result)

            if not categories and _declares_no_personal_data_collected(plain):
                result.declares_no_data_collection = True
                result.findings.append(PolicyFinding(
                    source="HTTP fetch",
                    finding_type="data_category",
                    detail="Policy explicitly declares no personal data is collected",
                    url=url,
                ))

            # Fallback: the privacy policy page sometimes links to the T&C.
            # Scan it for T&C links (skip Google URLs).
            if not result.all_terms_urls_found:
                pp_links = _extract_links_from_html(content)
                for href, link_text in pp_links:
                    if not href:
                        continue
                    full = _resolve_url(href, url)
                    if _is_google_url(full):
                        continue
                    if _text_matches_terms_link(link_text) or _url_matches_terms(full):
                        self._record_terms_url(full, "Privacy policy page", result)
        else:
            result.errors.append(
                f"Fetched privacy URL but content does not look like a "
                f"privacy policy: {url}"
            )

    def _process_terms_url(self, url: str, result: PrivacyPolicyResult) -> None:
        if self.verbose:
            print(f"  Fetching T&C: {url}")
        content = _fetch_url(url)
        if content is None:
            result.errors.append(f"Could not fetch T&C URL: {url}")
            return

        plain = _extract_text_from_html(content)

        trusted = url in result.trusted_terms_urls
        if _is_terms_document(plain) or trusted:
            result.has_terms_and_conditions = True
            if not result.terms_url:
                result.terms_url = url
            if not trusted:
                result.findings.append(PolicyFinding(
                    source="HTTP fetch",
                    finding_type="terms_url",
                    detail=f"Confirmed T&C document at: {url}",
                    url=url,
                ))
        else:
            result.errors.append(
                f"Fetched T&C URL but content does not look like a "
                f"T&C document: {url}"
            )

    def _record_data_categories(
        self, categories: list[str], source: str, result: PrivacyPolicyResult
    ) -> None:
        for cat in categories:
            if cat not in result.disclosed_data_categories:
                result.disclosed_data_categories.append(cat)
                result.findings.append(PolicyFinding(
                    source=source,
                    finding_type="data_category",
                    detail=f"Personal data category disclosed: {cat}",
                ))

    # ------------------------------------------------------------------
    # Finalise result flags
    # ------------------------------------------------------------------

    def _finalize(self, result: PrivacyPolicyResult) -> None:
        """Set summary flags based on accumulated findings."""
        # has_privacy_policy may have been set during asset scanning; if URLs
        # were found and fetching was skipped, treat URL presence as sufficient.
        if not result.has_privacy_policy and result.all_policy_urls_found:
            if self.skip_fetch:
                result.has_privacy_policy = True
                result.privacy_policy_url = result.all_policy_urls_found[0]

        if not result.has_terms_and_conditions and result.all_terms_urls_found:
            if self.skip_fetch:
                result.has_terms_and_conditions = True
                result.terms_url = result.all_terms_urls_found[0]

        # Determine data disclosure sufficiency.
        # A developer who explicitly declares "we collect nothing" also passes —
        # that declaration IS the required disclosure.
        result.discloses_collected_data = (
            len(result.disclosed_data_categories) >= MIN_DATA_CATEGORIES
            or result.declares_no_data_collection
        )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(result: PrivacyPolicyResult, verbose: bool = False) -> None:
    SEP = "=" * 62
    RESET = "\033[0m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"

    score = result.compliance_score
    score_color = {
        "COMPLIANT": GREEN,
        "PARTIAL": YELLOW,
        "NON_COMPLIANT": RED,
    }.get(score, RESET)

    def yn(flag: bool, good_color: str = GREEN, bad_color: str = RED) -> str:
        if flag:
            return f"{good_color}YES{RESET}"
        return f"{bad_color}NO{RESET}"

    print(SEP)
    print(f"  {BOLD}PRIVACY POLICY COMPLIANCE REPORT{RESET}")
    print(SEP)
    print(f"  Source  : {result.source}")
    print(f"  Package : {result.package_name or 'unknown'}")
    print(f"  Label   : {result.app_label or 'unknown'}")
    print(SEP)
    print(f"  Overall compliance: {score_color}{BOLD}{score}{RESET}")
    print()

    # Check 1
    print(f"  [1] Privacy policy present   : {yn(result.has_privacy_policy)}")
    if result.privacy_policy_url:
        print(f"      URL : {result.privacy_policy_url}")
    elif result.all_policy_urls_found:
        print(f"      Candidate URLs ({len(result.all_policy_urls_found)}):")
        for u in result.all_policy_urls_found[:3]:
            print(f"        - {u}")

    print()

    # Check 2
    print(f"  [2] Terms & Conditions present: {yn(result.has_terms_and_conditions)}")
    if result.terms_url:
        print(f"      URL : {result.terms_url}")
    elif result.all_terms_urls_found:
        print(f"      Candidate URLs ({len(result.all_terms_urls_found)}):")
        for u in result.all_terms_urls_found[:3]:
            print(f"        - {u}")

    print()

    # Check 3
    print(f"  [3] Privacy policy discloses personal data: {yn(result.discloses_collected_data)}")
    if result.disclosed_data_categories:
        print(f"      Data categories disclosed ({len(result.disclosed_data_categories)}):")
        for cat in result.disclosed_data_categories:
            print(f"        - {cat}")
    elif result.declares_no_data_collection:
        print(f"      {GREEN}App developer declared no personal data is collected.{RESET}")
    elif result.has_privacy_policy:
        print(f"      {YELLOW}Warning: No personal data categories detected in the policy.{RESET}")

    print()

    # Explanations
    explanations = {
        "COMPLIANT": (
            f"{GREEN}All three checks passed.{RESET}\n"
            "  The app has a privacy policy, T&C, and the policy discloses\n"
            "  which personal data is collected."
        ),
        "PARTIAL": (
            f"{YELLOW}Partially compliant.{RESET}\n"
            "  A privacy policy was found, but one or more of the following\n"
            "  are missing:\n"
            "    - Terms & Conditions\n"
            "    - Disclosure of personal data categories in the privacy policy"
        ),
        "NON_COMPLIANT": (
            f"{RED}Non-compliant.{RESET}\n"
            "  No privacy policy was detected. This is required by most app\n"
            "  store policies (Google Play, Apple App Store) and privacy\n"
            "  regulations (GDPR, CCPA)."
        ),
    }
    print(f"  {explanations.get(score, '')}")
    print()

    if verbose and result.findings:
        print("  Findings:")
        seen: set = set()
        for f in result.findings:
            key = (f.finding_type, f.detail)
            if key not in seen:
                seen.add(key)
                url_part = f"  →  {f.url}" if f.url else ""
                print(f"    [{f.finding_type:18s}] {f.detail}{url_part}")
        print()

    if result.errors:
        print("  Errors / Warnings:")
        for err in result.errors:
            print(f"    {YELLOW}- {err}{RESET}")
        print()

    print(SEP)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Check an Android app for privacy policy compliance.\n\n"
            "Verifies:\n"
            "  1. A privacy policy is in place\n"
            "  2. Terms & Conditions are in place\n"
            "  3. The privacy policy discloses which personal data is collected\n\n"
            "Accepts an APK file path or a Google Play Store URL."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk
  %(prog)s app.apk --verbose
  %(prog)s app.apk --json
  %(prog)s app.apk --json --output result.json
  %(prog)s "https://play.google.com/store/apps/details?id=com.example.app"
  %(prog)s "https://play.google.com/store/apps/details?id=com.example.app" --verbose

Exit codes:
  0  Compliant (all three checks passed)
  1  Non-compliant or partial compliance
  2  Input error (file not found, invalid APK, etc.)
        """,
    )
    parser.add_argument(
        "source",
        help="Path to an APK file, or a Google Play Store URL",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed findings",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write JSON output to FILE",
    )
    args = parser.parse_args()

    analyzer = PrivacyPolicyAnalyzer(args.source, verbose=args.verbose)
    try:
        result = analyzer.analyze()
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
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

    sys.exit(0 if result.compliance_score == "COMPLIANT" else 1)


if __name__ == "__main__":
    main()
