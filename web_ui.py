#!/usr/bin/env python3
"""
Privacy Policy Analyzer — Web UI

A self-contained web interface for the Privacy Policy Analyzer.
No third-party libraries required; uses only the Python standard library.

Usage:
    python3 web_ui.py                  # http://localhost:5000
    python3 web_ui.py --port 8080      # custom port
    python3 web_ui.py --host 0.0.0.0   # listen on all interfaces
"""

import argparse
import email
import json
import os
import sys
import tempfile
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# Make sure the analyzer module is importable
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent / "analyzer"))
from privacy_policy_analyzer import PrivacyPolicyAnalyzer  # noqa: E402


# ---------------------------------------------------------------------------
# Embedded HTML / CSS / JS
# ---------------------------------------------------------------------------

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy Policy Analyzer</title>
<style>
/* ── Reset & base ──────────────────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: #f0f4f8;
  color: #1e293b;
  min-height: 100vh;
}

/* ── Header ────────────────────────────────────────────────────────── */
header {
  background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
  color: #f8fafc;
  padding: 28px 24px 24px;
  border-bottom: 3px solid #334155;
}
header h1 { font-size: 1.6rem; font-weight: 700; letter-spacing: -0.3px; }
header p  { margin-top: 6px; color: #94a3b8; font-size: 0.92rem; line-height: 1.5; }

/* ── Layout ────────────────────────────────────────────────────────── */
main {
  max-width: 780px;
  margin: 0 auto;
  padding: 32px 20px 60px;
}

/* ── Card ──────────────────────────────────────────────────────────── */
.card {
  background: #fff;
  border-radius: 14px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08), 0 4px 16px rgba(0,0,0,0.05);
  padding: 28px;
  margin-bottom: 24px;
}

/* ── Tabs ──────────────────────────────────────────────────────────── */
.tabs {
  display: flex;
  gap: 6px;
  margin-bottom: 24px;
  border-bottom: 2px solid #e2e8f0;
  padding-bottom: 0;
}
.tab-btn {
  background: none;
  border: none;
  padding: 10px 18px;
  font-size: 0.9rem;
  font-weight: 600;
  color: #64748b;
  cursor: pointer;
  border-radius: 8px 8px 0 0;
  position: relative;
  bottom: -2px;
  border-bottom: 3px solid transparent;
  transition: color 0.15s, border-color 0.15s;
}
.tab-btn:hover  { color: #3b82f6; }
.tab-btn.active { color: #3b82f6; border-bottom-color: #3b82f6; }

/* ── Dropzone ──────────────────────────────────────────────────────── */
.dropzone {
  border: 2px dashed #cbd5e1;
  border-radius: 10px;
  padding: 44px 24px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
  background: #f8fafc;
}
.dropzone:hover, .dropzone.drag-over {
  border-color: #3b82f6;
  background: #eff6ff;
}
.dropzone .dz-icon  { font-size: 2.4rem; display: block; margin-bottom: 12px; }
.dropzone .dz-title { font-size: 1rem; font-weight: 600; color: #334155; }
.dropzone .dz-sub   { font-size: 0.82rem; color: #94a3b8; margin-top: 4px; }
.dropzone .dz-file  {
  display: inline-flex; align-items: center; gap: 6px;
  margin-top: 12px; padding: 6px 14px;
  background: #dbeafe; color: #1e40af;
  border-radius: 20px; font-size: 0.82rem; font-weight: 600;
}

/* ── URL input ─────────────────────────────────────────────────────── */
.url-label {
  display: block;
  font-size: 0.82rem;
  font-weight: 600;
  color: #475569;
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.url-input {
  width: 100%;
  padding: 12px 16px;
  font-size: 0.92rem;
  border: 2px solid #e2e8f0;
  border-radius: 8px;
  outline: none;
  transition: border-color 0.15s;
  color: #1e293b;
}
.url-input:focus { border-color: #3b82f6; }
.url-hint {
  margin-top: 8px;
  font-size: 0.78rem;
  color: #94a3b8;
}

/* ── Analyze button ────────────────────────────────────────────────── */
.btn-analyze {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 22px;
  width: 100%;
  padding: 14px;
  background: linear-gradient(135deg, #3b82f6, #2563eb);
  color: #fff;
  font-size: 1rem;
  font-weight: 700;
  border: none;
  border-radius: 10px;
  cursor: pointer;
  transition: opacity 0.15s, transform 0.1s;
  letter-spacing: 0.02em;
}
.btn-analyze:hover   { opacity: 0.92; transform: translateY(-1px); }
.btn-analyze:active  { transform: translateY(0); }
.btn-analyze:disabled { opacity: 0.55; cursor: not-allowed; transform: none; }

/* ── Spinner ───────────────────────────────────────────────────────── */
.spinner {
  display: inline-block;
  width: 18px; height: 18px;
  border: 3px solid rgba(255,255,255,0.4);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Error banner ──────────────────────────────────────────────────── */
.error-banner {
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 10px;
  padding: 16px 20px;
  color: #991b1b;
  font-size: 0.88rem;
  margin-bottom: 20px;
  display: none;
}

/* ── Results ───────────────────────────────────────────────────────── */
#results { display: none; }

.result-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}
.result-app-info h2 { font-size: 1.15rem; font-weight: 700; color: #0f172a; }
.result-app-info p  { font-size: 0.82rem; color: #64748b; margin-top: 3px; }

/* Compliance badge */
.badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 6px 16px;
  border-radius: 999px;
  font-size: 0.82rem;
  font-weight: 700;
  white-space: nowrap;
  letter-spacing: 0.04em;
}
.badge-COMPLIANT     { background: #dcfce7; color: #15803d; }
.badge-PARTIAL       { background: #fef9c3; color: #92400e; }
.badge-NON_COMPLIANT { background: #fee2e2; color: #b91c1c; }

/* ── Check rows ────────────────────────────────────────────────────── */
.checks { display: flex; flex-direction: column; gap: 14px; margin-bottom: 22px; }

.check-row {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 16px 18px;
  border-radius: 10px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
}
.check-icon {
  flex-shrink: 0;
  width: 28px; height: 28px;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.85rem;
  font-weight: 700;
}
.check-icon.pass { background: #dcfce7; color: #15803d; }
.check-icon.fail { background: #fee2e2; color: #b91c1c; }

.check-body { flex: 1; min-width: 0; }
.check-body strong {
  display: block;
  font-size: 0.92rem;
  font-weight: 700;
  color: #1e293b;
  margin-bottom: 3px;
}
.check-body .check-url {
  font-size: 0.78rem;
  color: #3b82f6;
  word-break: break-all;
  text-decoration: none;
}
.check-body .check-url:hover { text-decoration: underline; }
.check-body .check-fail-note {
  font-size: 0.78rem;
  color: #94a3b8;
  font-style: italic;
}

/* Data category pills */
.category-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}
.category-pill {
  background: #ede9fe;
  color: #5b21b6;
  border-radius: 999px;
  padding: 3px 10px;
  font-size: 0.73rem;
  font-weight: 600;
  letter-spacing: 0.02em;
}

/* ── Verdict explanation ───────────────────────────────────────────── */
.verdict-box {
  border-radius: 10px;
  padding: 14px 18px;
  font-size: 0.88rem;
  line-height: 1.6;
  margin-bottom: 22px;
}
.verdict-box.COMPLIANT     { background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; }
.verdict-box.PARTIAL       { background: #fefce8; border: 1px solid #fde68a; color: #713f12; }
.verdict-box.NON_COMPLIANT { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; }

/* ── Collapsible sections ──────────────────────────────────────────── */
.collapsible-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  cursor: pointer;
  padding: 10px 0;
  border-top: 1px solid #e2e8f0;
  font-size: 0.85rem;
  font-weight: 600;
  color: #475569;
  user-select: none;
}
.collapsible-header:hover { color: #1e293b; }
.collapsible-header .arrow { transition: transform 0.2s; font-size: 0.7rem; }
.collapsible-header.open .arrow { transform: rotate(180deg); }
.collapsible-body { padding: 12px 0 4px; }

/* Findings list */
.finding-item {
  display: flex;
  gap: 10px;
  padding: 7px 0;
  border-bottom: 1px solid #f1f5f9;
  font-size: 0.8rem;
  color: #475569;
}
.finding-item:last-child { border-bottom: none; }
.finding-type-badge {
  flex-shrink: 0;
  background: #f1f5f9;
  border-radius: 4px;
  padding: 1px 7px;
  font-size: 0.7rem;
  font-weight: 700;
  color: #64748b;
  letter-spacing: 0.04em;
  white-space: nowrap;
  align-self: flex-start;
  margin-top: 1px;
}
.finding-detail { flex: 1; }

/* Errors list */
.error-item {
  font-size: 0.8rem;
  color: #b91c1c;
  padding: 5px 0;
  border-bottom: 1px solid #fee2e2;
}
.error-item:last-child { border-bottom: none; }

/* ── Footer ────────────────────────────────────────────────────────── */
footer {
  text-align: center;
  color: #94a3b8;
  font-size: 0.78rem;
  padding: 0 0 32px;
}
</style>
</head>
<body>

<header>
  <h1>&#128274; Privacy Policy Analyzer</h1>
  <p>Check if an Android app has a privacy policy, Terms &amp; Conditions, and discloses what personal data it collects.</p>
</header>

<main>

  <!-- Input card -->
  <div class="card">
    <div class="tabs">
      <button class="tab-btn active" id="tab-apk-btn" onclick="switchTab('apk')">&#128230; Upload APK</button>
      <button class="tab-btn"        id="tab-url-btn" onclick="switchTab('url')">&#128279; Play Store URL</button>
    </div>

    <!-- APK upload pane -->
    <div id="pane-apk">
      <div class="dropzone" id="dropzone"
           onclick="document.getElementById('file-input').click()"
           ondragover="onDragOver(event)"
           ondragleave="onDragLeave(event)"
           ondrop="onDrop(event)">
        <span class="dz-icon" id="dz-icon">&#128228;</span>
        <span class="dz-title" id="dz-title">Drop your APK here or click to browse</span>
        <span class="dz-sub"   id="dz-sub">.apk files only</span>
        <span class="dz-file"  id="dz-file" style="display:none"></span>
      </div>
      <input type="file" id="file-input" accept=".apk" style="display:none" onchange="onFileSelected(event)">
    </div>

    <!-- URL pane -->
    <div id="pane-url" style="display:none">
      <label class="url-label" for="url-input">Google Play Store URL</label>
      <input  class="url-input" id="url-input" type="url"
              placeholder="https://play.google.com/store/apps/details?id=com.example.app"
              oninput="clearError()">
      <p class="url-hint">e.g. https://play.google.com/store/apps/details?id=com.google.android.apps.maps</p>
    </div>

    <div class="error-banner" id="error-banner"></div>

    <button class="btn-analyze" id="btn-analyze" onclick="analyze()">
      <span id="btn-label">&#128269; Analyze</span>
    </button>
  </div>

  <!-- Results -->
  <div id="results">
    <div class="card">
      <!-- App header -->
      <div class="result-header">
        <div class="result-app-info">
          <h2 id="res-label">—</h2>
          <p id="res-package">—</p>
        </div>
        <span class="badge" id="res-badge">—</span>
      </div>

      <!-- Verdict explanation -->
      <div class="verdict-box" id="res-verdict"></div>

      <!-- Three checks -->
      <div class="checks">
        <!-- Check 1 -->
        <div class="check-row" id="chk1">
          <div class="check-icon" id="chk1-icon">—</div>
          <div class="check-body">
            <strong>Privacy policy present</strong>
            <span id="chk1-detail"></span>
          </div>
        </div>
        <!-- Check 2 -->
        <div class="check-row" id="chk2">
          <div class="check-icon" id="chk2-icon">—</div>
          <div class="check-body">
            <strong>Terms &amp; Conditions present</strong>
            <span id="chk2-detail"></span>
          </div>
        </div>
        <!-- Check 3 -->
        <div class="check-row" id="chk3">
          <div class="check-icon" id="chk3-icon">—</div>
          <div class="check-body">
            <strong>Privacy policy discloses personal data collected</strong>
            <span id="chk3-detail"></span>
          </div>
        </div>
      </div>

      <!-- Findings (collapsible) -->
      <div id="findings-section" style="display:none">
        <div class="collapsible-header" id="findings-toggle" onclick="toggleSection('findings')">
          <span id="findings-label">Findings</span>
          <span class="arrow">&#9660;</span>
        </div>
        <div class="collapsible-body" id="findings-body" style="display:none">
          <div id="findings-list"></div>
        </div>
      </div>

      <!-- Errors (collapsible) -->
      <div id="errors-section" style="display:none">
        <div class="collapsible-header" id="errors-toggle" onclick="toggleSection('errors')">
          <span id="errors-label">Warnings / Errors</span>
          <span class="arrow">&#9660;</span>
        </div>
        <div class="collapsible-body" id="errors-body" style="display:none">
          <div id="errors-list"></div>
        </div>
      </div>

    </div>
  </div>

</main>

<footer>Privacy Policy Analyzer &mdash; static &amp; dynamic Android app analysis</footer>

<script>
// ── State ──────────────────────────────────────────────────────────────────
let activeTab   = 'apk';
let selectedFile = null;

// ── Tab switching ──────────────────────────────────────────────────────────
function switchTab(tab) {
  activeTab = tab;
  document.getElementById('pane-apk').style.display = tab === 'apk' ? '' : 'none';
  document.getElementById('pane-url').style.display = tab === 'url' ? '' : 'none';
  document.getElementById('tab-apk-btn').classList.toggle('active', tab === 'apk');
  document.getElementById('tab-url-btn').classList.toggle('active', tab === 'url');
  clearError();
}

// ── File selection ─────────────────────────────────────────────────────────
function onFileSelected(e) {
  const file = e.target.files[0];
  if (file) setFile(file);
}

function setFile(file) {
  selectedFile = file;
  document.getElementById('dz-icon').textContent  = '📦';
  document.getElementById('dz-title').textContent = 'APK selected';
  document.getElementById('dz-sub').textContent   = '';
  const badge = document.getElementById('dz-file');
  badge.textContent = '📄 ' + file.name;
  badge.style.display = 'inline-flex';
  clearError();
}

// ── Drag & drop ────────────────────────────────────────────────────────────
function onDragOver(e) {
  e.preventDefault();
  document.getElementById('dropzone').classList.add('drag-over');
}
function onDragLeave(e) {
  document.getElementById('dropzone').classList.remove('drag-over');
}
function onDrop(e) {
  e.preventDefault();
  document.getElementById('dropzone').classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith('.apk')) {
    setFile(file);
  } else {
    showError('Please drop a valid .apk file.');
  }
}

// ── Errors ─────────────────────────────────────────────────────────────────
function showError(msg) {
  const el = document.getElementById('error-banner');
  el.textContent = msg;
  el.style.display = 'block';
}
function clearError() {
  document.getElementById('error-banner').style.display = 'none';
}

// ── Analyze ────────────────────────────────────────────────────────────────
function setLoading(on) {
  const btn   = document.getElementById('btn-analyze');
  const label = document.getElementById('btn-label');
  btn.disabled = on;
  if (on) {
    label.innerHTML = '<span class="spinner"></span> Analyzing&hellip;';
  } else {
    label.innerHTML = '&#128269; Analyze';
  }
}

async function analyze() {
  clearError();

  if (activeTab === 'apk') {
    if (!selectedFile) { showError('Please select an APK file first.'); return; }
    await analyzeApk();
  } else {
    const url = document.getElementById('url-input').value.trim();
    if (!url) { showError('Please enter a Google Play Store URL.'); return; }
    if (!url.includes('play.google.com/store/apps')) {
      showError('URL must be a Google Play Store app URL (play.google.com/store/apps/details?id=…)');
      return;
    }
    await analyzeUrl(url);
  }
}

async function analyzeApk() {
  const formData = new FormData();
  formData.append('apk', selectedFile, selectedFile.name);
  setLoading(true);
  try {
    const resp = await fetch('/analyze', { method: 'POST', body: formData });
    const data = await resp.json();
    if (data.error) { showError(data.error); return; }
    renderResults(data);
  } catch (err) {
    showError('Request failed: ' + err.message);
  } finally {
    setLoading(false);
  }
}

async function analyzeUrl(url) {
  const formData = new FormData();
  formData.append('url', url);
  setLoading(true);
  try {
    const resp = await fetch('/analyze', { method: 'POST', body: formData });
    const data = await resp.json();
    if (data.error) { showError(data.error); return; }
    renderResults(data);
  } catch (err) {
    showError('Request failed: ' + err.message);
  } finally {
    setLoading(false);
  }
}

// ── Render results ─────────────────────────────────────────────────────────
function renderResults(d) {
  const checks = d.checks;
  const score  = d.compliance_score;

  // App info
  document.getElementById('res-label').textContent   = d.label || d.package || '—';
  document.getElementById('res-package').textContent = d.package || '';

  // Badge
  const badge = document.getElementById('res-badge');
  const scoreLabels = {
    COMPLIANT: '✓ COMPLIANT',
    PARTIAL: '⚠ PARTIAL',
    NON_COMPLIANT: '✗ NON-COMPLIANT',
  };
  badge.textContent  = scoreLabels[score] || score;
  badge.className    = 'badge badge-' + score;

  // Verdict explanation
  const verdictMessages = {
    COMPLIANT: '✓ All three checks passed. The app has a privacy policy, Terms & Conditions, and the policy discloses which personal data is collected.',
    PARTIAL:   '⚠ A privacy policy was found, but one or more checks failed — either Terms & Conditions are missing, or the privacy policy does not adequately disclose personal data categories.',
    NON_COMPLIANT: '✗ No privacy policy was detected. This is required by Google Play Store policy and privacy regulations such as GDPR and CCPA.',
  };
  const vbox = document.getElementById('res-verdict');
  vbox.textContent = verdictMessages[score] || '';
  vbox.className   = 'verdict-box ' + score;

  // Check 1 — Privacy policy
  renderCheck(
    'chk1',
    checks.privacy_policy_present,
    checks.privacy_policy_url,
    'No privacy policy URL found or confirmed.'
  );

  // Check 2 — T&C
  renderCheck(
    'chk2',
    checks.terms_and_conditions_present,
    checks.terms_url,
    'No Terms & Conditions URL found or confirmed.'
  );

  // Check 3 — Data disclosure
  const cats = checks.disclosed_data_categories || [];
  let chk3Detail = '';
  if (checks.discloses_collected_data && cats.length) {
    chk3Detail = makeCategoryPills(cats);
  } else if (checks.privacy_policy_present) {
    chk3Detail = '<span class="check-fail-note">No personal data categories were detected in the privacy policy text.</span>';
  } else {
    chk3Detail = '<span class="check-fail-note">Cannot check — no privacy policy found.</span>';
  }
  setCheckIcon('chk3-icon', checks.discloses_collected_data);
  document.getElementById('chk3-detail').innerHTML = chk3Detail;

  // Findings
  const findings = d.findings || [];
  if (findings.length) {
    document.getElementById('findings-label').textContent = `Findings (${findings.length})`;
    const list = document.getElementById('findings-list');
    list.innerHTML = findings.map(f =>
      `<div class="finding-item">
         <span class="finding-type-badge">${esc(f.type)}</span>
         <span class="finding-detail">${esc(f.detail)}</span>
       </div>`
    ).join('');
    document.getElementById('findings-section').style.display = '';
  } else {
    document.getElementById('findings-section').style.display = 'none';
  }

  // Errors
  const errors = d.errors || [];
  if (errors.length) {
    document.getElementById('errors-label').textContent = `Warnings / Errors (${errors.length})`;
    const list = document.getElementById('errors-list');
    list.innerHTML = errors.map(e =>
      `<div class="error-item">${esc(e)}</div>`
    ).join('');
    document.getElementById('errors-section').style.display = '';
  } else {
    document.getElementById('errors-section').style.display = 'none';
  }

  // Show results
  document.getElementById('results').style.display = '';
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderCheck(id, passed, url, failNote) {
  setCheckIcon(id + '-icon', passed);
  const detail = document.getElementById(id + '-detail');
  if (passed && url) {
    detail.innerHTML = `<a class="check-url" href="${esc(url)}" target="_blank" rel="noopener">${esc(url)}</a>`;
  } else if (!passed) {
    detail.innerHTML = `<span class="check-fail-note">${failNote}</span>`;
  } else {
    detail.innerHTML = '';
  }
}

function setCheckIcon(id, passed) {
  const el = document.getElementById(id);
  el.textContent = passed ? '✓' : '✗';
  el.className   = 'check-icon ' + (passed ? 'pass' : 'fail');
}

function makeCategoryPills(cats) {
  return '<div class="category-list">' +
    cats.map(c => `<span class="category-pill">${esc(c.replace(/_/g, ' '))}</span>`).join('') +
    '</div>';
}

// ── Collapsible sections ───────────────────────────────────────────────────
function toggleSection(name) {
  const toggle = document.getElementById(name + '-toggle');
  const body   = document.getElementById(name + '-body');
  const open   = body.style.display !== 'none';
  body.style.display = open ? 'none' : '';
  toggle.classList.toggle('open', !open);
}

// ── Helpers ────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Multipart form-data parser (stdlib only)
# ---------------------------------------------------------------------------

def _parse_multipart(raw_body: bytes, content_type: str) -> dict:
    """
    Parse a multipart/form-data body and return a dict:
      { field_name: value }   where value is bytes for files, str for text fields.
    """
    # Build a minimal MIME message so email.message can parse the parts.
    header_bytes = f"Content-Type: {content_type}\r\n\r\n".encode()
    msg = email.message_from_bytes(header_bytes + raw_body)
    result = {}
    if msg.is_multipart():
        for part in msg.get_payload():
            disp = part.get("Content-Disposition", "")
            # Extract field name
            name_match = _re_search(r'name="([^"]+)"', disp)
            if not name_match:
                continue
            name = name_match.group(1)
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = (part.get_payload() or "").encode()
            # Text fields: decode to str; binary (file) fields: keep bytes
            filename_match = _re_search(r'filename="([^"]*)"', disp)
            if filename_match:
                result[name] = {"filename": filename_match.group(1), "data": payload}
            else:
                result[name] = payload.decode("utf-8", errors="replace")
    return result


def _re_search(pattern, text):
    import re
    return re.search(pattern, text)


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class PrivacyAnalyzerHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Quiet unless it's an error
        if args and str(args[1]).startswith(("4", "5")):
            super().log_message(fmt, *args)

    # ── GET ──────────────────────────────────────────────────────────────────
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_html()
        elif self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "Not found"})

    def _serve_html(self):
        body = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── POST /analyze ────────────────────────────────────────────────────────
    def do_POST(self):
        if self.path != "/analyze":
            self._json(404, {"error": "Not found"})
            return

        content_type = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if "multipart/form-data" not in content_type:
            self._json(400, {"error": "Expected multipart/form-data"})
            return

        try:
            fields = _parse_multipart(body, content_type)
        except Exception as exc:
            self._json(400, {"error": f"Could not parse form data: {exc}"})
            return

        # ── APK upload ───────────────────────────────────────────────────────
        if "apk" in fields:
            self._handle_apk(fields["apk"])

        # ── Play Store URL ───────────────────────────────────────────────────
        elif "url" in fields:
            self._handle_url(fields["url"])

        else:
            self._json(400, {"error": "No 'apk' file or 'url' field provided."})

    def _handle_apk(self, file_field):
        if not isinstance(file_field, dict):
            self._json(400, {"error": "APK field is not a file."})
            return

        tmp_path = None
        try:
            suffix = ".apk"
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
                f.write(file_field["data"])
                tmp_path = f.name

            analyzer = PrivacyPolicyAnalyzer(tmp_path)
            result   = analyzer.analyze()
            self._json(200, result.summary())

        except (FileNotFoundError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {
                "error": f"Analysis failed: {exc}",
                "traceback": traceback.format_exc(),
            })
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _handle_url(self, url: str):
        url = url.strip()
        if not url.startswith("http"):
            self._json(400, {"error": "URL must start with http:// or https://"})
            return
        try:
            analyzer = PrivacyPolicyAnalyzer(url)
            result   = analyzer.analyze()
            self._json(200, result.summary())
        except Exception as exc:
            self._json(500, {
                "error": f"Analysis failed: {exc}",
                "traceback": traceback.format_exc(),
            })

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Privacy Policy Analyzer — Web UI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Open http://localhost:<port> in your browser after starting.",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Interface to listen on (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port to listen on (default: 5000)")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), PrivacyAnalyzerHandler)
    url = f"http://{'localhost' if args.host == '127.0.0.1' else args.host}:{args.port}"
    print(f"  Privacy Policy Analyzer")
    print(f"  Listening on {url}")
    print(f"  Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
