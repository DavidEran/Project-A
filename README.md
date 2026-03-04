# Wake Lock Tester

A toolkit for verifying whether an Android app has the `WAKE_LOCK` permission
and, if so, for how long it holds wake locks.

## Components

| Component | Purpose |
|-----------|---------|
| `analyzer/wake_lock_analyzer.py` | Python CLI — static analysis of APK files |
| `analyzer/play_integrity_analyzer.py` | Python CLI — Play Integrity / sideload-risk analysis |
| `analyzer/privacy_policy_analyzer.py` | Python CLI — privacy policy compliance analysis |
| `android-app/` | Android app — runtime wake lock acquisition and timing |
| `scripts/monitor_wake_locks.sh` | Shell script — live monitoring via ADB |
| `scripts/check_apk_permission.sh` | Shell script — quick permission check via ADB |

---

## 1. Python Static Analyzer

Inspects an APK file **without installing it** on a device.  Checks:

- Whether `android.permission.WAKE_LOCK` is declared in the manifest
- How many times `acquire()` / `release()` are called in the DEX bytecode
- Whether any timed `acquire(long)` calls are present, and what timeout values
  are used
- Whether acquire/release calls are balanced (a mismatch suggests a wake lock
  leak)

### Requirements

- Python 3.8+
- No third-party libraries required

### Usage

```bash
# Basic check
python3 analyzer/wake_lock_analyzer.py app.apk

# Verbose (show file/line of each usage)
python3 analyzer/wake_lock_analyzer.py app.apk --verbose

# JSON output
python3 analyzer/wake_lock_analyzer.py app.apk --json

# Save JSON result to a file
python3 analyzer/wake_lock_analyzer.py app.apk --json --output result.json
```

### Example output

```
============================================================
  WAKE LOCK ANALYSIS REPORT
============================================================
  APK          : myapp.apk
  Package      : com.example.myapp
  App Label    : My App
============================================================
  WAKE_LOCK permission declared: YES
  Protection level        : normal

  acquire() calls         : 2
  release() calls         : 2
  acquire/release balance : BALANCED

  Timed acquires (1 found):
    - 60000 ms  (60.0 s)
  Max timeout            : 60.0 s
  Min timeout            : 60.0 s

  Files analyzed          : 1
============================================================
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | WAKE_LOCK permission is present |
| `1`  | WAKE_LOCK permission is absent |

### Running the tests

```bash
python3 -m unittest discover -s tests -v
```

---

## 2. Android App (Runtime Tester)

An Android application (`android-app/`) that lets you:

- See whether the app itself has the `WAKE_LOCK` permission at runtime
- Acquire a `PARTIAL_WAKE_LOCK` with a custom **tag** and optional **timeout**
- Watch a live timer while the lock is held
- Release the lock manually or by timeout
- Review a history of completed sessions with their hold durations

### Permissions declared

```xml
<uses-permission android:name="android.permission.WAKE_LOCK" />
```

### Building

```bash
cd android-app
./gradlew assembleDebug
```

Install on a connected device / emulator:

```bash
./gradlew installDebug
```

### Architecture

```
WakeLockManager          — core class, manages PowerManager.WakeLock lifecycle
  acquire(tag, timeoutMs) → Boolean
  release(tag)            → Session?
  releaseAll()            → List<Session>
  activeSessions()        → List<Session>
  completedSessions()     → List<Session>

Session                  — immutable record of one acquire/release cycle
  .tag                   String
  .acquireTimeMs         Long
  .timeoutMs             Long?     (null = indefinite)
  .releaseTimeMs         Long?     (null = still active)
  .durationMs            Long      (live if still active)
  .durationHuman         String    ("1.5 min", "2.3 s", …)
  .isActive              Boolean

MainActivity             — UI: permission badge, acquire/release controls,
                           live duration display, session history
```

### Running unit tests

```bash
cd android-app
./gradlew test
```

---

## 3. ADB Scripts

### monitor_wake_locks.sh

Live monitor for wake locks on a connected device.

```bash
# Watch all wake locks (refresh every 2 seconds)
./scripts/monitor_wake_locks.sh

# Filter to a specific package
./scripts/monitor_wake_locks.sh --package com.example.myapp

# Single snapshot
./scripts/monitor_wake_locks.sh --once

# Custom refresh interval
./scripts/monitor_wake_locks.sh --interval 5
```

### check_apk_permission.sh

Quick permission check for an **installed** app.

```bash
./scripts/check_apk_permission.sh com.example.myapp
```

Output:

```
=== Wake Lock Permission Check ===
Package: com.example.myapp

  WAKE_LOCK permission: GRANTED

Permission Details:
  ...

Currently Held Wake Locks:
  (none)
```

---

---

## 4. Privacy Policy Analyzer

Checks whether an Android app complies with privacy policy requirements by
analyzing either an **APK file** (static) or a **Google Play Store URL** (live).

Three compliance checks are performed:

| # | Check | Pass condition |
|---|-------|----------------|
| 1 | **Privacy policy present** | A privacy policy URL is found in the APK binary / Play listing, and the fetched page is confirmed to be a privacy policy document |
| 2 | **Terms & Conditions present** | A T&C URL is found and confirmed |
| 3 | **Personal data disclosure** | The privacy policy text mentions ≥ 2 personal data categories (identity, contact, location, device identifiers, financial, health, usage/analytics, communications, media, demographics, credentials) |

**Overall verdict:**

| Score | Meaning |
|-------|---------|
| `COMPLIANT` | All three checks passed |
| `PARTIAL` | Privacy policy found but T&C or data-disclosure check failed |
| `NON_COMPLIANT` | No privacy policy detected |

### Requirements

- Python 3.10+
- No third-party libraries required (standard library only: `urllib`, `html.parser`, `zipfile`, `re`, …)
- Internet access required when fetching remote policy URLs (APK mode) or the Play Store listing

### Usage

```bash
# Analyze an APK file
python3 analyzer/privacy_policy_analyzer.py app.apk

# Analyze a Google Play Store listing
python3 analyzer/privacy_policy_analyzer.py \
    "https://play.google.com/store/apps/details?id=com.example.app"

# Verbose (show each finding)
python3 analyzer/privacy_policy_analyzer.py app.apk --verbose

# JSON output
python3 analyzer/privacy_policy_analyzer.py app.apk --json

# Save JSON result to a file
python3 analyzer/privacy_policy_analyzer.py app.apk --json --output result.json
```

### Example output

```
==============================================================
  PRIVACY POLICY COMPLIANCE REPORT
==============================================================
  Source  : app.apk
  Package : com.example.app
  Label   : Example App
==============================================================
  Overall compliance: COMPLIANT

  [1] Privacy policy present   : YES
      URL : https://example.com/privacy-policy

  [2] Terms & Conditions present: YES
      URL : https://example.com/terms-of-service

  [3] Privacy policy discloses personal data: YES
      Data categories disclosed (5):
        - identity
        - contact
        - location
        - device_identifiers
        - usage_analytics

  All three checks passed.
  The app has a privacy policy, T&C, and the policy discloses
  which personal data is collected.

  Files analyzed: 1
==============================================================
```

### How APK scanning works

1. **`AndroidManifest.xml`** — parsed for the `android:privacyPolicy` attribute
   (Android 10+) and scanned for any embedded `https://` URLs.
2. **`classes*.dex`** — decoded as latin-1 and scanned for URL strings containing
   `privacy`, `terms`, `gdpr`, `eula`, etc.
3. **`resources.arsc`** — raw binary scan for the same URL patterns (catches
   string resources stored in the resource table).
4. **`assets/*.html` / `assets/*.txt`** — text/HTML assets are parsed directly;
   bundled privacy policy or T&C documents are detected and analysed without a
   network request.
5. Confirmed candidate URLs are then **fetched** to verify content and detect
   personal-data category disclosures.

### How Play Store scanning works

1. The package ID is extracted from the `?id=` query parameter.
2. The Play Store listing page is fetched (`https://play.google.com/store/apps/details?id=…&hl=en`).
3. All `<a>` links are extracted; those whose text or `href` matches privacy /
   terms patterns are recorded.
4. Each candidate URL is fetched and its content is analysed.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | `COMPLIANT` — all three checks passed |
| `1`  | `PARTIAL` or `NON_COMPLIANT` |
| `2`  | Input error (file not found, not a valid APK, etc.) |

### Running the tests

```bash
python3 -m unittest tests/test_privacy_policy_analyzer.py -v
```

---

## Wake Lock primer

| Concept | Details |
|---------|---------|
| Permission | `android.permission.WAKE_LOCK` — normal protection level, granted at install time |
| `PARTIAL_WAKE_LOCK` | Keeps CPU running; screen may turn off. Most common for background work. |
| `acquire()` | Holds the lock indefinitely until `release()` is called. Risky if `release()` is forgotten. |
| `acquire(long timeout)` | Automatically released after `timeout` ms. Safer pattern. |
| Leak | `acquire()` with no matching `release()` drains the battery. |

---

## Project structure

```
Project-A/
├── analyzer/
│   ├── __init__.py
│   ├── wake_lock_analyzer.py         # Python CLI static analyzer
│   ├── play_integrity_analyzer.py    # Play Integrity / sideload-risk analyzer
│   └── privacy_policy_analyzer.py   # Privacy policy compliance analyzer
├── android-app/
│   ├── app/
│   │   ├── build.gradle.kts
│   │   ├── proguard-rules.pro
│   │   └── src/
│   │       ├── main/
│   │       │   ├── AndroidManifest.xml
│   │       │   ├── java/com/wakelocktester/
│   │       │   │   ├── MainActivity.kt
│   │       │   │   └── WakeLockManager.kt
│   │       │   └── res/
│   │       │       ├── layout/activity_main.xml
│   │       │       └── values/{strings,themes}.xml
│   │       └── test/java/com/wakelocktester/
│   │           └── WakeLockManagerTest.kt
│   ├── build.gradle.kts
│   ├── gradle.properties
│   └── settings.gradle.kts
├── scripts/
│   ├── check_apk_permission.sh
│   └── monitor_wake_locks.sh
├── tests/
│   ├── test_analyzer.py                    # Wake Lock Analyzer unit tests
│   └── test_privacy_policy_analyzer.py     # Privacy Policy Analyzer unit tests
├── requirements.txt
└── README.md
```
