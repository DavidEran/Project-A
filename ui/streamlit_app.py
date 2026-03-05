"""
Play Integrity Analyzer — Streamlit UI

Run with:
    streamlit run ui/streamlit_app.py
"""

import sys
import tempfile
import os
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))
from play_integrity_analyzer import PlayIntegrityAnalyzer  # noqa: E402

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Play Integrity Analyzer",
    page_icon="🔍",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

st.markdown("""
<style>
/* Verdict banners */
.verdict-HIGH   { background:#ef444422; border:1px solid #ef4444; border-radius:12px;
                  padding:20px 24px; margin-bottom:16px; }
.verdict-MEDIUM { background:#eab30822; border:1px solid #eab308; border-radius:12px;
                  padding:20px 24px; margin-bottom:16px; }
.verdict-LOW    { background:#ca8a0422; border:1px solid #ca8a04; border-radius:12px;
                  padding:20px 24px; margin-bottom:16px; }
.verdict-NONE   { background:#22c55e22; border:1px solid #22c55e; border-radius:12px;
                  padding:20px 24px; margin-bottom:16px; }
.verdict-title-HIGH   { color:#fca5a5; font-size:1.1rem; font-weight:700; }
.verdict-title-MEDIUM { color:#fde047; font-size:1.1rem; font-weight:700; }
.verdict-title-LOW    { color:#fde68a; font-size:1.1rem; font-weight:700; }
.verdict-title-NONE   { color:#86efac; font-size:1.1rem; font-weight:700; }
.signal-tag { display:inline-block; background:#6366f122; color:#a5b4fc;
              border-radius:6px; padding:2px 10px; font-size:0.8rem;
              font-family:monospace; margin:3px 3px 3px 0; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.title("🔍 Play Integrity Analyzer")
st.markdown(
    "Drop an APK to check whether it will **block or redirect** installs from "
    "**Digital Turbine** or other third-party distributors."
)
st.divider()

# ---------------------------------------------------------------------------
# File upload (drag-and-drop built into Streamlit)
# ---------------------------------------------------------------------------

uploaded = st.file_uploader(
    "Drag & drop your APK here, or click to browse",
    type=["apk"],
    help="Accepts .apk files only",
)

if not uploaded:
    st.stop()

# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------

with st.spinner(f"Analyzing **{uploaded.name}**…"):
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name
        result = PlayIntegrityAnalyzer(tmp_path).analyze()
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        st.stop()
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

# ---------------------------------------------------------------------------
# Verdict card
# ---------------------------------------------------------------------------

risk = result.sideload_risk

VERDICT_META = {
    "HIGH":   ("🚫 Will Block Third-Party Installs",
               "This app actively enforces Play Store distribution. "
               "Installs via Digital Turbine or other third-party distributors "
               "will be **blocked or redirected** to Google Play."),
    "MEDIUM": ("⚠️ May Block — Review Required",
               "This app requests Play Integrity tokens and inspects verdict fields. "
               "Whether a Digital Turbine install is blocked depends on the app's "
               "server-side enforcement logic."),
    "LOW":    ("⚠️ Likely Compatible",
               "The Play Integrity library is present but no active enforcement "
               "pattern was detected. Third-party installs are likely unaffected, "
               "but monitor for changes."),
    "NONE":   ("✅ Compatible — No Play Integrity Detected",
               "No Play Integrity or SafetyNet detected. Installation via Digital "
               "Turbine or sideloading should work without being blocked or redirected."),
}

title, desc = VERDICT_META[risk]

st.markdown(
    f'<div class="verdict-{risk}">'
    f'<div class="verdict-title-{risk}">{title}</div>'
    f'</div>',
    unsafe_allow_html=True,
)
st.markdown(desc)

# Detected signal tags
signals = [
    ("UNRECOGNIZED_VERSION", result.checks_unrecognized),
    ("UNLICENSED",           result.checks_unlicensed),
    ("remediation dialog",   result.uses_remediation_dialog),
    ("installer source check", result.checks_installer_source),
    ("SafetyNet (legacy)",   result.uses_safetynet),
]
active = [label for label, flag in signals if flag]
if active:
    tags = " ".join(f'<span class="signal-tag">{s}</span>' for s in active)
    st.markdown(f"**Detected signals:** {tags}", unsafe_allow_html=True)

st.divider()

# ---------------------------------------------------------------------------
# Details
# ---------------------------------------------------------------------------

col1, col2 = st.columns(2)

with col1:
    st.markdown("**App Info**")
    st.markdown(f"- **File:** `{uploaded.name}`")
    st.markdown(f"- **Package:** `{result.package_name or 'unknown'}`")
    st.markdown(f"- **Label:** {result.app_label or 'unknown'}")
    st.markdown(f"- **Files analyzed:** {result.files_analyzed}")

with col2:
    st.markdown("**Library Detected**")
    def yn(flag): return "✅ Yes" if flag else "—"
    st.markdown(f"- Play Integrity API: {yn(result.uses_play_integrity)}")
    st.markdown(f"- Classic API: {yn(result.uses_classic_api)}")
    st.markdown(f"- Standard API: {yn(result.uses_standard_api)}")
    st.markdown(f"- SafetyNet (legacy): {yn(result.uses_safetynet)}")

st.divider()
st.markdown("**Enforcement Signals**")

def signal_row(label, flag, note=""):
    icon = "🔴" if flag else "⚪"
    extra = f" — {note}" if note and flag else ""
    st.markdown(f"{icon} **{label}**{extra}")

signal_row("Requests integrity token",              result.requests_token)
signal_row("Checks UNRECOGNIZED_VERSION",           result.checks_unrecognized,
           "sideloaded / unknown install")
signal_row("Checks UNLICENSED",                     result.checks_unlicensed,
           "Digital Turbine / non-Play-licensed install")
signal_row("Uses remediation / Play Store dialog",  result.uses_remediation_dialog,
           "GET_LICENSED, CLOSE_UNKNOWN_SOURCE_DIALOG, or requestAndShowDialog")
signal_row("Checks installer source",               result.checks_installer_source,
           "getInstallerPackageName / com.android.vending")

# Errors
if result.errors:
    st.divider()
    with st.expander("⚠️ Warnings / errors during analysis"):
        for e in result.errors:
            st.warning(e)
