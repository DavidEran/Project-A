#!/usr/bin/env python3
"""
Privacy Policy Analyzer — Streamlit Web UI

Run locally:
    streamlit run web_ui.py

Or deploy directly to Streamlit Cloud.
"""

import os
import sys
import tempfile
from pathlib import Path

import streamlit as st

# Make the analyzer importable
sys.path.insert(0, str(Path(__file__).parent / "analyzer"))
from privacy_policy_analyzer import PrivacyPolicyAnalyzer  # noqa: E402

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Privacy Policy Analyzer",
    page_icon="🔒",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
/* Header strip */
.hero {
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-radius: 14px;
    padding: 28px 32px 24px;
    margin-bottom: 28px;
    color: #f8fafc;
}
.hero h1 { font-size: 1.65rem; font-weight: 800; margin: 0; }
.hero p  { color: #94a3b8; margin: 8px 0 0; font-size: 0.93rem; line-height: 1.6; }

/* Compliance badge */
.badge {
    display: inline-block;
    padding: 6px 18px;
    border-radius: 999px;
    font-size: 0.82rem;
    font-weight: 800;
    letter-spacing: 0.05em;
}
.badge-COMPLIANT     { background: #dcfce7; color: #15803d; }
.badge-PARTIAL       { background: #fef9c3; color: #92400e; }
.badge-NON_COMPLIANT { background: #fee2e2; color: #b91c1c; }

/* Verdict box */
.verdict {
    border-radius: 10px;
    padding: 14px 18px;
    font-size: 0.88rem;
    line-height: 1.6;
    margin: 4px 0 18px;
}
.verdict-COMPLIANT     { background:#f0fdf4; border:1px solid #bbf7d0; color:#166534; }
.verdict-PARTIAL       { background:#fefce8; border:1px solid #fde68a; color:#713f12; }
.verdict-NON_COMPLIANT { background:#fef2f2; border:1px solid #fecaca; color:#991b1b; }

/* Check rows */
.check-row {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    padding: 14px 16px;
    border-radius: 10px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    margin-bottom: 10px;
}
.chk-icon {
    flex-shrink: 0;
    width: 28px; height: 28px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.85rem; font-weight: 800;
    margin-top: 1px;
}
.chk-pass { background:#dcfce7; color:#15803d; }
.chk-fail { background:#fee2e2; color:#b91c1c; }
.chk-body strong { display:block; font-size:0.93rem; font-weight:700; color:#1e293b; }
.chk-body a      { font-size:0.78rem; color:#3b82f6; word-break:break-all; }
.chk-body .note  { font-size:0.78rem; color:#94a3b8; font-style:italic; }

/* Category pills */
.pill-wrap { display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }
.pill {
    background:#ede9fe; color:#5b21b6;
    border-radius:999px; padding:3px 11px;
    font-size:0.72rem; font-weight:700;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Hero header
# ---------------------------------------------------------------------------
st.markdown("""
<div class="hero">
  <h1>🔒 Privacy Policy Analyzer</h1>
  <p>Check if an Android app has a privacy policy, Terms &amp; Conditions,
     and discloses what personal data it collects.</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Input section
# ---------------------------------------------------------------------------
mode = st.radio(
    "Input method",
    ["📦 Upload APK", "🔗 Play Store URL"],
    horizontal=True,
    label_visibility="collapsed",
)

result_data = None
error_msg = None

if mode == "📦 Upload APK":
    uploaded = st.file_uploader("Upload APK file", type=["apk"], label_visibility="collapsed")
    analyze_clicked = st.button("🔍 Analyze", use_container_width=True, type="primary",
                                disabled=(uploaded is None))

    if analyze_clicked and uploaded:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
                f.write(uploaded.read())
                tmp_path = f.name

            with st.spinner("Analyzing APK…"):
                analyzer = PrivacyPolicyAnalyzer(tmp_path)
                result_data = analyzer.analyze().summary()
        except (FileNotFoundError, ValueError) as exc:
            error_msg = str(exc)
        except Exception as exc:
            error_msg = f"Analysis error: {exc}"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

else:
    url_input = st.text_input(
        "Play Store URL",
        placeholder="https://play.google.com/store/apps/details?id=com.example.app",
        label_visibility="collapsed",
    )
    analyze_clicked = st.button("🔍 Analyze", use_container_width=True, type="primary",
                                disabled=(not url_input.strip()))

    if analyze_clicked and url_input.strip():
        url = url_input.strip()
        if "play.google.com/store/apps" not in url:
            error_msg = "Please enter a valid Google Play Store URL (play.google.com/store/apps/details?id=…)"
        else:
            try:
                with st.spinner("Fetching Play Store listing and analyzing…"):
                    analyzer = PrivacyPolicyAnalyzer(url)
                    result_data = analyzer.analyze().summary()
            except Exception as exc:
                error_msg = f"Analysis error: {exc}"

# ---------------------------------------------------------------------------
# Error display
# ---------------------------------------------------------------------------
if error_msg:
    st.error(error_msg)

# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------
if result_data:
    d = result_data
    checks = d.get("checks", {})
    score  = d.get("compliance_score", "NON_COMPLIANT")

    st.divider()

    # ── App info + badge ────────────────────────────────────────────────────
    col_info, col_badge = st.columns([3, 1])
    with col_info:
        label   = d.get("label") or d.get("package") or "—"
        package = d.get("package") or ""
        st.markdown(f"**{label}**")
        if package and package != label:
            st.caption(package)
    with col_badge:
        badge_labels = {
            "COMPLIANT":     "✓ COMPLIANT",
            "PARTIAL":       "⚠ PARTIAL",
            "NON_COMPLIANT": "✗ NON-COMPLIANT",
        }
        st.markdown(
            f'<span class="badge badge-{score}">{badge_labels.get(score, score)}</span>',
            unsafe_allow_html=True,
        )

    # ── Verdict ─────────────────────────────────────────────────────────────
    verdict_text = {
        "COMPLIANT": (
            "✓ All three checks passed. The app has a privacy policy, Terms & Conditions, "
            "and the policy discloses which personal data is collected."
        ),
        "PARTIAL": (
            "⚠ A privacy policy was found, but one or more checks failed — "
            "either Terms & Conditions are missing, or the privacy policy does not "
            "adequately disclose personal data categories."
        ),
        "NON_COMPLIANT": (
            "✗ No privacy policy was detected. This is required by Google Play Store "
            "policy and privacy regulations such as GDPR and CCPA."
        ),
    }
    st.markdown(
        f'<div class="verdict verdict-{score}">{verdict_text.get(score, "")}</div>',
        unsafe_allow_html=True,
    )

    # ── Three checks ─────────────────────────────────────────────────────────
    def check_row(passed: bool, title: str, url: str | None, fail_note: str, extra_html: str = "") -> str:
        icon_cls  = "chk-pass" if passed else "chk-fail"
        icon_char = "✓" if passed else "✗"
        detail = ""
        if passed and url:
            detail = f'<a href="{url}" target="_blank">{url}</a>'
        elif not passed:
            detail = f'<span class="note">{fail_note}</span>'
        return (
            f'<div class="check-row">'
            f'  <div class="chk-icon {icon_cls}">{icon_char}</div>'
            f'  <div class="chk-body"><strong>{title}</strong>{detail}{extra_html}</div>'
            f'</div>'
        )

    # Check 1
    st.markdown(check_row(
        checks.get("privacy_policy_present", False),
        "Privacy policy present",
        checks.get("privacy_policy_url"),
        "No privacy policy URL found or confirmed.",
    ), unsafe_allow_html=True)

    # Check 2
    st.markdown(check_row(
        checks.get("terms_and_conditions_present", False),
        "Terms &amp; Conditions present",
        checks.get("terms_url"),
        "No Terms &amp; Conditions URL found or confirmed.",
    ), unsafe_allow_html=True)

    # Check 3 — data disclosure with category pills
    cats = checks.get("disclosed_data_categories", [])
    pills_html = ""
    if cats:
        pills = "".join(
            f'<span class="pill">{c.replace("_", " ")}</span>' for c in cats
        )
        pills_html = f'<div class="pill-wrap">{pills}</div>'

    discloses = checks.get("discloses_collected_data", False)
    fail_note_chk3 = (
        "No personal data categories detected in the privacy policy text."
        if checks.get("privacy_policy_present")
        else "Cannot check — no privacy policy found."
    )
    st.markdown(check_row(
        discloses,
        "Privacy policy discloses personal data collected",
        None,
        fail_note_chk3,
        extra_html=pills_html,
    ), unsafe_allow_html=True)

    # ── Findings (expander) ──────────────────────────────────────────────────
    findings = d.get("findings", [])
    if findings:
        with st.expander(f"Findings ({len(findings)})"):
            for f_item in findings:
                ftype  = f_item.get("type", "")
                detail = f_item.get("detail", "")
                st.markdown(
                    f"`{ftype}` &nbsp; {detail}",
                    unsafe_allow_html=True,
                )

    # ── Errors (expander) ────────────────────────────────────────────────────
    errors = d.get("errors", [])
    if errors:
        with st.expander(f"Warnings / Errors ({len(errors)})"):
            for err in errors:
                st.warning(err)

    # ── JSON download ─────────────────────────────────────────────────────────
    st.divider()
    import json
    st.download_button(
        "⬇ Download full JSON report",
        data=json.dumps(result_data, indent=2),
        file_name="privacy_analysis.json",
        mime="application/json",
        use_container_width=True,
    )
