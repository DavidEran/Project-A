#!/usr/bin/env python3
"""
Play Integrity Analyzer — Web UI

Runs a local web server with a drag-and-drop APK analysis interface.

Usage:
    python3 ui/server.py [--port 8080]

Then open http://localhost:8080 in your browser.
"""

import argparse
import http.server
import json
import os
import re
import sys
import tempfile
from pathlib import Path

# Allow importing the analyzer from the parent directory.
sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))
from play_integrity_analyzer import PlayIntegrityAnalyzer  # noqa: E402

# ---------------------------------------------------------------------------
# Embedded HTML / CSS / JS — single-file, no external dependencies
# ---------------------------------------------------------------------------

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Play Integrity Analyzer</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f1117;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }
    h1 {
      font-size: 1.8rem;
      font-weight: 700;
      letter-spacing: -0.5px;
      margin-bottom: 6px;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 0.95rem;
      margin-bottom: 40px;
      text-align: center;
    }

    /* Drop zone */
    .drop-zone {
      width: 100%;
      max-width: 560px;
      border: 2px dashed #334155;
      border-radius: 16px;
      padding: 56px 32px;
      text-align: center;
      cursor: pointer;
      transition: border-color 0.2s, background 0.2s;
    }
    .drop-zone:hover, .drop-zone.drag-over {
      border-color: #6366f1;
      background: rgba(99,102,241,0.07);
    }
    .drop-icon { font-size: 3rem; margin-bottom: 16px; }
    .drop-zone p { color: #94a3b8; font-size: 0.95rem; margin-bottom: 8px; }
    .browse-label {
      color: #6366f1;
      cursor: pointer;
      text-decoration: underline;
      font-weight: 500;
    }
    #fileInput { display: none; }

    /* Loading */
    .loading {
      display: none;
      flex-direction: column;
      align-items: center;
      gap: 16px;
      margin-top: 32px;
    }
    .spinner {
      width: 40px; height: 40px;
      border: 4px solid #1e293b;
      border-top-color: #6366f1;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .loading p { color: #94a3b8; font-size: 0.9rem; }

    /* Result card */
    .result { display: none; width: 100%; max-width: 560px; margin-top: 32px; }

    .verdict-card {
      border-radius: 16px;
      padding: 28px 32px;
      margin-bottom: 20px;
    }
    .verdict-card.HIGH   { background: rgba(239,68,68,0.12);  border: 1px solid rgba(239,68,68,0.35); }
    .verdict-card.MEDIUM { background: rgba(234,179,8,0.10);  border: 1px solid rgba(234,179,8,0.35); }
    .verdict-card.LOW    { background: rgba(234,179,8,0.08);  border: 1px solid rgba(234,179,8,0.25); }
    .verdict-card.NONE   { background: rgba(34,197,94,0.10);  border: 1px solid rgba(34,197,94,0.35); }

    .verdict-header {
      display: flex;
      align-items: center;
      gap: 14px;
      margin-bottom: 14px;
    }
    .verdict-badge {
      font-size: 1rem;
      font-weight: 800;
      letter-spacing: 1px;
      padding: 4px 14px;
      border-radius: 999px;
    }
    .HIGH   .verdict-badge { background: #ef4444; color: #fff; }
    .MEDIUM .verdict-badge { background: #eab308; color: #000; }
    .LOW    .verdict-badge { background: #ca8a04; color: #fff; }
    .NONE   .verdict-badge { background: #22c55e; color: #000; }

    .verdict-title { font-size: 1.1rem; font-weight: 700; }
    .HIGH   .verdict-title { color: #fca5a5; }
    .MEDIUM .verdict-title { color: #fde047; }
    .LOW    .verdict-title { color: #fde68a; }
    .NONE   .verdict-title { color: #86efac; }

    .verdict-desc { font-size: 0.88rem; color: #94a3b8; line-height: 1.6; }

    /* Details table */
    .details-card {
      background: #1e293b;
      border-radius: 14px;
      padding: 22px 26px;
      margin-bottom: 16px;
    }
    .details-card h3 {
      font-size: 0.8rem;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #64748b;
      margin-bottom: 14px;
    }
    .detail-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 0;
      border-bottom: 1px solid #0f1117;
      font-size: 0.88rem;
    }
    .detail-row:last-child { border-bottom: none; }
    .detail-label { color: #94a3b8; }
    .pill {
      font-size: 0.78rem;
      font-weight: 600;
      padding: 2px 10px;
      border-radius: 999px;
    }
    .pill.yes { background: rgba(239,68,68,0.2); color: #fca5a5; }
    .pill.no  { background: #0f1117; color: #475569; }
    .pill.info{ background: rgba(99,102,241,0.2); color: #a5b4fc; }

    /* App info */
    .app-info {
      font-size: 0.85rem;
      color: #64748b;
      margin-bottom: 6px;
    }
    .app-info span { color: #94a3b8; }

    /* Signals list */
    .signals { margin-top: 8px; }
    .signal-tag {
      display: inline-block;
      font-size: 0.78rem;
      padding: 3px 10px;
      border-radius: 6px;
      margin: 3px 3px 3px 0;
      background: rgba(99,102,241,0.15);
      color: #a5b4fc;
      font-family: monospace;
    }

    /* Reset button */
    .reset-btn {
      display: block;
      width: 100%;
      max-width: 560px;
      margin-top: 10px;
      padding: 12px;
      background: #1e293b;
      color: #94a3b8;
      border: 1px solid #334155;
      border-radius: 10px;
      font-size: 0.9rem;
      cursor: pointer;
      transition: background 0.2s;
    }
    .reset-btn:hover { background: #273548; color: #e2e8f0; }

    .error-box {
      background: rgba(239,68,68,0.12);
      border: 1px solid rgba(239,68,68,0.35);
      border-radius: 12px;
      padding: 18px 22px;
      color: #fca5a5;
      font-size: 0.9rem;
      margin-top: 20px;
      width: 100%;
      max-width: 560px;
      display: none;
    }
  </style>
</head>
<body>

  <h1>🔍 Play Integrity Analyzer</h1>
  <p class="subtitle">
    Drop an APK to check whether it will block installs from<br>
    Digital Turbine or other third-party distributors.
  </p>

  <!-- Drop zone -->
  <div class="drop-zone" id="dropZone">
    <div class="drop-icon">📱</div>
    <p><strong>Drag &amp; drop your APK here</strong></p>
    <p>or <label for="fileInput" class="browse-label">browse files</label></p>
    <input type="file" id="fileInput" accept=".apk" />
  </div>

  <!-- Loading -->
  <div class="loading" id="loading">
    <div class="spinner"></div>
    <p id="loadingMsg">Analyzing APK…</p>
  </div>

  <!-- Error -->
  <div class="error-box" id="errorBox"></div>

  <!-- Result -->
  <div class="result" id="result"></div>

  <!-- Reset button -->
  <button class="reset-btn" id="resetBtn" style="display:none"
          onclick="reset()">← Analyze another APK</button>

<script>
const dropZone   = document.getElementById('dropZone');
const fileInput  = document.getElementById('fileInput');
const loading    = document.getElementById('loading');
const loadingMsg = document.getElementById('loadingMsg');
const resultDiv  = document.getElementById('result');
const errorBox   = document.getElementById('errorBox');
const resetBtn   = document.getElementById('resetBtn');

// Drag-and-drop
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
});
dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files[0]) uploadFile(fileInput.files[0]);
});

function reset() {
  dropZone.style.display = '';
  loading.style.display = 'none';
  resultDiv.style.display = 'none';
  resultDiv.innerHTML = '';
  errorBox.style.display = 'none';
  resetBtn.style.display = 'none';
  fileInput.value = '';
}

function showError(msg) {
  loading.style.display = 'none';
  errorBox.textContent = '⚠ ' + msg;
  errorBox.style.display = 'block';
  resetBtn.style.display = 'block';
}

async function uploadFile(file) {
  if (!file.name.toLowerCase().endsWith('.apk')) {
    showError('Please select an .apk file.');
    return;
  }
  dropZone.style.display = 'none';
  loading.style.display = 'flex';
  loadingMsg.textContent = 'Analyzing ' + file.name + '…';
  errorBox.style.display = 'none';
  resultDiv.style.display = 'none';

  const fd = new FormData();
  fd.append('apk', file, file.name);

  try {
    const resp = await fetch('/analyze', { method: 'POST', body: fd });
    const data = await resp.json();
    if (!resp.ok) { showError(data.error || 'Analysis failed.'); return; }
    loading.style.display = 'none';
    renderResult(data, file.name);
  } catch (err) {
    showError('Network error: ' + err.message);
  }
}

const VERDICTS = {
  HIGH:   { title: 'Will Block Third-Party Installs',
            desc:  'This app actively enforces Play Store distribution. Apps installed via Digital Turbine or other third-party distributors will be blocked or redirected to Google Play.' },
  MEDIUM: { title: 'May Block — Review Required',
            desc:  'This app requests Play Integrity tokens and inspects verdict fields. Whether a Digital Turbine install is blocked depends on the app\'s server-side enforcement logic.' },
  LOW:    { title: 'Likely Compatible',
            desc:  'The Play Integrity library is present but no active enforcement pattern was detected. Third-party installs are likely unaffected, but monitor for changes.' },
  NONE:   { title: 'Compatible — No Play Integrity Detected',
            desc:  'No Play Integrity or SafetyNet detected. Installation via Digital Turbine or sideloading should work without being blocked or redirected.' },
};

function pill(val, labelYes, labelNo) {
  const on = !!val;
  return `<span class="pill ${on ? 'yes' : 'no'}">${on ? (labelYes||'YES') : (labelNo||'no')}</span>`;
}

function renderResult(d, filename) {
  const v = d.sideload_risk;
  const info = VERDICTS[v] || VERDICTS.NONE;

  // Collect detected signal tags
  const signals = [];
  if (d.checks_unrecognized_version) signals.push('UNRECOGNIZED_VERSION');
  if (d.checks_unlicensed)           signals.push('UNLICENSED');
  if (d.uses_remediation_dialog)     signals.push('remediation dialog');
  if (d.checks_installer_source)     signals.push('installer source check');
  if (d.uses_safetynet)              signals.push('SafetyNet (legacy)');
  const signalHTML = signals.length
    ? '<div class="signals">' + signals.map(s => `<span class="signal-tag">${s}</span>`).join('') + '</div>'
    : '';

  resultDiv.innerHTML = `
    <div class="verdict-card ${v}">
      <div class="verdict-header">
        <span class="verdict-badge">${v}</span>
        <span class="verdict-title">${info.title}</span>
      </div>
      <p class="verdict-desc">${info.desc}</p>
      ${signalHTML}
    </div>

    <div class="details-card">
      <h3>App Info</h3>
      <div class="detail-row">
        <span class="detail-label">File</span>
        <span class="pill info">${filename}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Package</span>
        <span style="font-family:monospace;font-size:0.85rem;color:#cbd5e1">${d.package||'unknown'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Label</span>
        <span style="color:#cbd5e1">${d.label||'unknown'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Files analyzed</span>
        <span class="pill info">${d.files_analyzed}</span>
      </div>
    </div>

    <div class="details-card">
      <h3>Play Integrity Detection</h3>
      <div class="detail-row">
        <span class="detail-label">Play Integrity API present</span>
        ${pill(d.uses_play_integrity)}
      </div>
      <div class="detail-row">
        <span class="detail-label">Classic API (IntegrityManager)</span>
        ${pill(d.uses_classic_api)}
      </div>
      <div class="detail-row">
        <span class="detail-label">Standard API (StandardIntegrityManager)</span>
        ${pill(d.uses_standard_api)}
      </div>
      <div class="detail-row">
        <span class="detail-label">SafetyNet (legacy)</span>
        ${pill(d.uses_safetynet)}
      </div>
    </div>

    <div class="details-card">
      <h3>Enforcement Signals</h3>
      <div class="detail-row">
        <span class="detail-label">Requests integrity token</span>
        ${pill(d.requests_token, 'YES', 'no')}
      </div>
      <div class="detail-row">
        <span class="detail-label">Checks UNRECOGNIZED_VERSION</span>
        ${pill(d.checks_unrecognized_version, 'YES ⚠', 'no')}
      </div>
      <div class="detail-row">
        <span class="detail-label">Checks UNLICENSED (Digital Turbine verdict)</span>
        ${pill(d.checks_unlicensed, 'YES ⚠', 'no')}
      </div>
      <div class="detail-row">
        <span class="detail-label">Uses remediation / Play Store dialog</span>
        ${pill(d.uses_remediation_dialog, 'YES ⚠', 'no')}
      </div>
      <div class="detail-row">
        <span class="detail-label">Checks installer source (com.android.vending)</span>
        ${pill(d.checks_installer_source, 'YES ⚠', 'no')}
      </div>
    </div>
  `;

  resultDiv.style.display = 'block';
  resetBtn.style.display = 'block';
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Multipart parser (stdlib only — no cgi module dependency)
# ---------------------------------------------------------------------------

def _parse_multipart(body: bytes, boundary: str) -> dict:
    """Extract files/fields from a multipart/form-data body.

    Returns a dict mapping field names to dicts with keys:
      'filename' (str | None) and 'content' (bytes).
    """
    sep = ("--" + boundary).encode()
    parts = body.split(sep)
    result = {}
    for part in parts[1:]:
        if part in (b"--\r\n", b"--", b"--\r\n--", b"--\n"):
            break
        # Split header block from content
        if b"\r\n\r\n" in part:
            head_raw, content = part.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part:
            head_raw, content = part.split(b"\n\n", 1)
        else:
            continue
        content = content.rstrip(b"\r\n")
        headers = head_raw.decode("utf-8", errors="ignore")
        name_m = re.search(r'name="([^"]+)"', headers)
        file_m = re.search(r'filename="([^"]*)"', headers)
        if name_m:
            result[name_m.group(1)] = {
                "filename": file_m.group(1) if file_m else None,
                "content": content,
            }
    return result


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):  # silence default access log
        pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = _HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/analyze":
            self.send_response(404)
            self.end_headers()
            return

        content_type = self.headers.get("Content-Type", "")
        boundary_m = re.search(r"boundary=([^\s;]+)", content_type)
        if not boundary_m:
            self._json_error(400, "Missing multipart boundary")
            return

        boundary = boundary_m.group(1).strip('"')
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        parts = _parse_multipart(body, boundary)
        if "apk" not in parts or not parts["apk"]["content"]:
            self._json_error(400, "No APK file received")
            return

        apk_bytes = parts["apk"]["content"]
        filename = parts["apk"].get("filename") or "upload.apk"

        # Write to a temporary file and analyze
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp.write(apk_bytes)
                tmp_path = tmp.name

            analyzer = PlayIntegrityAnalyzer(tmp_path)
            result = analyzer.analyze()
            self._json_ok(result.summary())
        except (FileNotFoundError, ValueError) as exc:
            self._json_error(400, str(exc))
        except Exception as exc:
            self._json_error(500, f"Internal error: {exc}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _json_ok(self, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_error(self, code: int, message: str):
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Play Integrity Analyzer — local web UI server"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=8080,
        help="Port to listen on (default: 8080)"
    )
    args = parser.parse_args()

    import socketserver
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", args.port), _Handler) as httpd:
        url = f"http://localhost:{args.port}"
        print(f"Play Integrity Analyzer UI running at {url}")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.")


if __name__ == "__main__":
    main()
