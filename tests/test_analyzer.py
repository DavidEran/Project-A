#!/usr/bin/env python3
"""
Unit tests for the Wake Lock Analyzer.
"""

import io
import json
import os
import struct
import sys
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

# Allow importing the analyzer from the parent directory tree
sys.path.insert(0, str(Path(__file__).parent.parent / "analyzer"))

from wake_lock_analyzer import (
    WakeLockAnalyzer,
    AnalysisResult,
    WakeLockUsage,
    ms_to_human,
    print_report,
    WAKE_LOCK_PERMISSION,
)


# ---------------------------------------------------------------------------
# Helpers to build fake APK (zip) files in memory
# ---------------------------------------------------------------------------

def make_apk(manifest_content: str, dex_content: bytes = b"") -> bytes:
    """Create a minimal APK zip in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
        if dex_content:
            zf.writestr("classes.dex", dex_content)
    return buf.getvalue()


def make_manifest(package: str, has_wake_lock: bool, label: str = "TestApp") -> str:
    perms = ""
    if has_wake_lock:
        perms = f'    <uses-permission android:name="{WAKE_LOCK_PERMISSION}" />\n'
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}">
{perms}    <application android:label="{label}">
    </application>
</manifest>"""


SMALI_ACQUIRE = (
    b"invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->acquire()V\n"
)
SMALI_ACQUIRE_TIMEOUT = (
    b"const-wide/16 v2, 0xEA60\n"
    b"invoke-virtual {v0, v2, v3}, "
    b"Landroid/os/PowerManager$WakeLock;->acquire(J)V\n"
)
SMALI_RELEASE = (
    b"invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->release()V\n"
)
SMALI_NEW_WAKE_LOCK = (
    b"invoke-virtual {v1, v2, v3}, "
    b"Landroid/os/PowerManager;->newWakeLock(ILjava/lang/String;)"
    b"Landroid/os/PowerManager$WakeLock;\n"
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMsToHuman(unittest.TestCase):
    def test_none(self):
        self.assertEqual(ms_to_human(None), "N/A")

    def test_milliseconds(self):
        self.assertEqual(ms_to_human(500), "500 ms")

    def test_seconds(self):
        self.assertIn("s", ms_to_human(5_000))

    def test_minutes(self):
        self.assertIn("min", ms_to_human(120_000))

    def test_hours(self):
        self.assertIn("h", ms_to_human(7_200_000))


class TestAnalysisResultProperties(unittest.TestCase):
    def _make_result(self, acquire=0, release=0, timed=None):
        r = AnalysisResult(
            apk_path="test.apk",
            package_name="com.example",
            app_label="Example",
            has_wake_lock_permission=True,
            permission_protection_level="normal",
        )
        r.acquire_count = acquire
        r.release_count = release
        r.timed_acquires = timed or []
        return r

    def test_balanced(self):
        r = self._make_result(acquire=3, release=3)
        self.assertTrue(r.is_balanced)

    def test_unbalanced(self):
        r = self._make_result(acquire=2, release=1)
        self.assertFalse(r.is_balanced)

    def test_max_timeout(self):
        r = self._make_result(timed=[60000, 300000, 10000])
        self.assertEqual(r.max_timeout_ms, 300000)

    def test_min_timeout(self):
        r = self._make_result(timed=[60000, 300000, 10000])
        self.assertEqual(r.min_timeout_ms, 10000)

    def test_no_timed(self):
        r = self._make_result()
        self.assertIsNone(r.max_timeout_ms)
        self.assertIsNone(r.min_timeout_ms)

    def test_summary_keys(self):
        r = self._make_result(acquire=1, release=1, timed=[60000])
        s = r.summary()
        expected_keys = {
            "apk", "package", "label", "has_wake_lock_permission",
            "permission_protection_level", "acquire_count", "release_count",
            "is_balanced", "timed_acquires", "max_timeout_ms", "min_timeout_ms",
            "files_analyzed", "errors", "usages",
        }
        self.assertEqual(set(s.keys()), expected_keys)


class TestManifestParsing(unittest.TestCase):
    def _analyze(self, manifest: str, dex: bytes = b"") -> AnalysisResult:
        apk_bytes = make_apk(manifest, dex)
        buf = io.BytesIO(apk_bytes)
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            tmp = f.name
        try:
            analyzer = WakeLockAnalyzer(tmp)
            return analyzer.analyze()
        finally:
            os.unlink(tmp)

    def test_has_permission(self):
        manifest = make_manifest("com.example.app", has_wake_lock=True)
        result = self._analyze(manifest)
        self.assertTrue(result.has_wake_lock_permission)
        self.assertEqual(result.package_name, "com.example.app")

    def test_no_permission(self):
        manifest = make_manifest("com.noperm.app", has_wake_lock=False)
        result = self._analyze(manifest)
        self.assertFalse(result.has_wake_lock_permission)
        self.assertEqual(result.package_name, "com.noperm.app")

    def test_app_label(self):
        manifest = make_manifest("com.example", has_wake_lock=True, label="MyApp")
        result = self._analyze(manifest)
        self.assertEqual(result.app_label, "MyApp")

    def test_no_dex(self):
        manifest = make_manifest("com.example", has_wake_lock=True)
        result = self._analyze(manifest)
        self.assertIn("No DEX files found", str(result.errors))


class TestDexScanning(unittest.TestCase):
    def _analyze(self, manifest: str, dex: bytes) -> AnalysisResult:
        apk_bytes = make_apk(manifest, dex)
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            tmp = f.name
        try:
            return WakeLockAnalyzer(tmp).analyze()
        finally:
            os.unlink(tmp)

    def test_acquire_detected(self):
        manifest = make_manifest("com.example", has_wake_lock=True)
        dex = SMALI_ACQUIRE + SMALI_RELEASE
        result = self._analyze(manifest, dex)
        self.assertEqual(result.acquire_count, 1)
        self.assertEqual(result.release_count, 1)

    def test_acquire_with_timeout_detected(self):
        manifest = make_manifest("com.example", has_wake_lock=True)
        dex = SMALI_ACQUIRE_TIMEOUT + SMALI_RELEASE
        result = self._analyze(manifest, dex)
        self.assertEqual(result.acquire_count, 1)
        self.assertEqual(result.release_count, 1)
        self.assertIsNotNone(result.timed_acquires)

    def test_unbalanced_detected(self):
        manifest = make_manifest("com.example", has_wake_lock=True)
        # Two acquires, one release
        dex = SMALI_ACQUIRE + SMALI_ACQUIRE + SMALI_RELEASE
        result = self._analyze(manifest, dex)
        self.assertFalse(result.is_balanced)

    def test_new_wake_lock_detected(self):
        manifest = make_manifest("com.example", has_wake_lock=True)
        dex = SMALI_NEW_WAKE_LOCK
        result = self._analyze(manifest, dex)
        types = [u.usage_type for u in result.wake_lock_usages]
        self.assertIn("new_wake_lock", types)

    def test_no_wake_lock_in_dex(self):
        manifest = make_manifest("com.example", has_wake_lock=True)
        dex = b"Hello world - no wake lock here"
        result = self._analyze(manifest, dex)
        self.assertEqual(result.acquire_count, 0)
        self.assertEqual(result.release_count, 0)


class TestSmaliScanning(unittest.TestCase):
    """Test the smali text-file scanning path (used when smali is pre-extracted)."""

    def _make_analyzer(self) -> WakeLockAnalyzer:
        # Create a dummy APK just to construct the analyzer
        import tempfile, os
        manifest = make_manifest("com.example", True)
        apk_bytes = make_apk(manifest)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            self._tmp = f.name
        return WakeLockAnalyzer(self._tmp)

    def tearDown(self):
        if hasattr(self, "_tmp") and os.path.exists(self._tmp):
            os.unlink(self._tmp)

    def test_smali_acquire(self):
        analyzer = self._make_analyzer()
        result = AnalysisResult("t.apk", "com.ex", "Ex", True, "normal")
        content = "invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->acquire()V"
        analyzer._scan_smali_text(content, "Main.smali", result)
        self.assertEqual(result.acquire_count, 1)

    def test_smali_release(self):
        analyzer = self._make_analyzer()
        result = AnalysisResult("t.apk", "com.ex", "Ex", True, "normal")
        content = "invoke-virtual {v0}, Landroid/os/PowerManager$WakeLock;->release()V"
        analyzer._scan_smali_text(content, "Main.smali", result)
        self.assertEqual(result.release_count, 1)

    def test_smali_acquire_with_timeout(self):
        analyzer = self._make_analyzer()
        result = AnalysisResult("t.apk", "com.ex", "Ex", True, "normal")
        content = (
            "    const-wide/16 v2, 0xEA60\n"
            "    invoke-virtual {v0, v2, v3}, "
            "Landroid/os/PowerManager$WakeLock;->acquire(J)V\n"
        )
        analyzer._scan_smali_text(content, "Main.smali", result)
        self.assertEqual(result.acquire_count, 1)
        self.assertIn(60000, result.timed_acquires)


class TestFileNotFound(unittest.TestCase):
    def test_missing_file(self):
        analyzer = WakeLockAnalyzer("/nonexistent/path/app.apk")
        with self.assertRaises(FileNotFoundError):
            analyzer.analyze()

    def test_not_a_zip(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"not a zip file")
            tmp = f.name
        try:
            analyzer = WakeLockAnalyzer(tmp)
            with self.assertRaises(ValueError):
                analyzer.analyze()
        finally:
            os.unlink(tmp)


class TestPrintReport(unittest.TestCase):
    """Smoke-test that print_report doesn't crash."""

    def _result_with_perm(self, has_perm: bool) -> AnalysisResult:
        r = AnalysisResult(
            apk_path="test.apk",
            package_name="com.example",
            app_label="Test",
            has_wake_lock_permission=has_perm,
            permission_protection_level="normal",
        )
        r.acquire_count = 2
        r.release_count = 2
        r.timed_acquires = [60000, 300000]
        return r

    def test_report_with_permission(self):
        r = self._result_with_perm(True)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(r, verbose=False)
        output = buf.getvalue()
        self.assertIn("YES", output)
        self.assertIn("BALANCED", output)

    def test_report_without_permission(self):
        r = self._result_with_perm(False)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_report(r, verbose=False)
        output = buf.getvalue()
        self.assertIn("NO", output)


class TestTimeoutExtraction(unittest.TestCase):
    def _analyzer(self) -> WakeLockAnalyzer:
        import tempfile, os
        manifest = make_manifest("com.example", True)
        apk_bytes = make_apk(manifest)
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(apk_bytes)
            self._tmp = f.name
        return WakeLockAnalyzer(self._tmp)

    def tearDown(self):
        if hasattr(self, "_tmp") and os.path.exists(self._tmp):
            os.unlink(self._tmp)

    def test_hex_constant(self):
        a = self._analyzer()
        lines = [
            "    const-wide/16 v2, 0xEA60",   # 60000
            "    invoke-virtual {v0, v2, v3}, Landroid/os/PowerManager$WakeLock;->acquire(J)V",
        ]
        timeout = a._extract_timeout_from_context(lines, 1)
        self.assertEqual(timeout, 60000)

    def test_decimal_constant(self):
        a = self._analyzer()
        lines = [
            "    const-wide v2, 300000",
            "    invoke-virtual {v0, v2, v3}, Landroid/os/PowerManager$WakeLock;->acquire(J)V",
        ]
        timeout = a._extract_timeout_from_context(lines, 1)
        self.assertEqual(timeout, 300000)

    def test_no_constant(self):
        a = self._analyzer()
        lines = [
            "    some-unrelated-instruction",
            "    invoke-virtual {v0, v2, v3}, Landroid/os/PowerManager$WakeLock;->acquire(J)V",
        ]
        timeout = a._extract_timeout_from_context(lines, 1)
        self.assertIsNone(timeout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
