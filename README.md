# C2BD — Android C2 Beacon Detector

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android%20(ADB)-green?style=flat-square&logo=android"/>
  <img src="https://img.shields.io/badge/Language-Python%203.10+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/Root%20Required-No-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Internet%20Required-No-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/Use%20Case-Defence%20%7C%20Forensics-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square"/>
</p>

<p align="center">
  <b>A no-root, offline Android security triage tool that detects Command-and-Control (C2) beaconing, app collusion, and behavioral entropy anomalies — via ADB.</b>
</p>

---

## The Problem

In sensitive Indian government and defence installations — Army bases, DRDO labs, intelligence bureaus, and border checkpoints — personnel carry mobile devices that pose critical security risks:

- A phone compromised by **Pegasus, LightSpy, or state-sponsored RATs** phones home silently
- All traffic is **HTTPS-encrypted** — conventional tools cannot read it
- **No lightweight, field-deployable tool** exists for rapid device inspection without root or expensive lab equipment
- A security officer at a BSF checkpoint has **5 minutes and a USB cable** — nothing more

> **C2BD solves this.** It does not decrypt traffic. Instead, it detects the *pattern* of communication — because malware phones home on a fixed timer, and that regularity is measurable.

---

## How It Works

```
Android Phone (USB)
      │
      ▼
  ADB Shell
      │
      ├─ /proc/net/tcp  ──► Which servers is this phone talking to?
      ├─ /proc/net/tcp6 ──► Same for IPv6
      │
      ▼
  Inode Tracking
      │
      ├─ New inode = new socket = real event ──► SCORED
      └─ Same inode = persistent connection  ──► EXCLUDED (prevents false positives)
      │
      ▼
  Regularity Score = 1 - CoeffVariation(intervals)
      │
      ├─ Score ≥ 0.85 ──► HIGH_REGULARITY    🔴 Investigate immediately
      ├─ Score ≥ 0.65 ──► MODERATE_REGULARITY 🟡 Investigate
      └─ Score < 0.65 ──► LOW_REGULARITY      🟢 Likely clean
      │
      ▼
  SHA-256 Signed JSON Report  +  .sha256 sidecar
```

**The key insight:** Malware beacons home at *regular* intervals — every 30s, 60s, 5min. Legitimate apps (WhatsApp, Gmail) connect when *you* use them — irregularly. This difference is statistically measurable without decrypting a single byte.

---

## Features

| Feature | Description |
|---|---|
| **C2 Beacon Detection** | Tracks new socket events per endpoint via inode IDs. Scores timing regularity using CV + median-absolute-deviation |
| **Inode-Based Deduplication** | Persistent HTTPS connections are *not* counted as repeated beacons — fixes the #1 false-positive in similar tools |
| **Preflight Visibility Check** | If `/proc/net/tcp` is unreadable, tool **aborts** — never shows false "clean" result |
| **App Collusion Detection** | Detects pairs of apps that together form a spyware chain (e.g., App A has CAMERA, App B has INTERNET) |
| **Behavioral Entropy** | Shannon entropy analysis of per-UID network activity for anomaly detection |
| **Honest Verdict Labels** | `HIGH_REGULARITY` not "BEACON DETECTED" — does not overclaim |
| **SHA-256 Signed Reports** | JSON report + `.sha256` sidecar, permissions 600, UTC timestamps, serial hashed |
| **No Root Required** | Works on production Android devices |
| **Fully Offline** | No API keys, no internet needed in field |
| **CLI Configurable** | `--duration`, `--interval`, `--min-events`, `--allow-cidr`, `--device` |

---

## Compared to Existing Tools

| Tool | Beacon Detection | App Collusion | No Root | Offline | Field-Ready |
|---|---|---|---|---|---|
| MobSF | ❌ | ❌ | ❌ | ✅ | ❌ |
| ALEAPP | ❌ | ❌ | ✅ | ✅ | ❌ |
| Autopsy Mobile | ❌ | ❌ | ❌ | ✅ | ❌ |
| Cellebrite UFED | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| **C2BD** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Quick Start

### Requirements

```bash
# macOS / Linux
brew install android-platform-tools   # ADB
pip3 install rich                      # Terminal UI
```

### Connect Phone

```bash
# Enable Developer Options → USB Debugging on phone
adb devices          # verify device shows as "device"
```

### Run

```bash
# Quick scan (5 min, default)
python3 c2bd.py

# Deep scan (10 min, 1s interval)
python3 c2bd.py --duration 600 --interval 1

# Exclude your own network CIDR
python3 c2bd.py --allow-cidr 192.168.1.0/24

# Target specific device
python3 c2bd.py --device YOUR_ADB_SERIAL

# Skip geolocation (fully offline)
python3 c2bd.py --no-geo
```

### Validate the Algorithm (No Phone Needed)

```bash
python3 validate.py --validate
```

Expected output:
```
PASS  Perfect beacon (30s, no jitter)      Score: 1.000  → HIGH_REGULARITY
PASS  Near-perfect beacon (±0.5s jitter)   Score: 0.987  → HIGH_REGULARITY
PASS  Slightly irregular (±5s jitter)      Score: 0.693  → MODERATE_REGULARITY
PASS  Random human browsing                Score: 0.000  → LOW_REGULARITY
PASS  WhatsApp push (variable)             Score: 0.000  → LOW_REGULARITY
PASS  Persistent connection (Chrome)       → PERSISTENT_CONNECTION (excluded)

Result: 6/6 tests passed ✓
```

---

## Sample Output

```
  IP                   Port    Events   Persist   Score    AvgInt    Label
  ──────────────────────────────────────────────────────────────────────────────
  203.0.113.55         443     14       0         0.934    29.87s    HIGH_REGULARITY
    com.hidden.analytics
    [CN] Shanghai / AS4134 China Telecom

  157.240.22.35        443     3        87        0.000    —         PERSISTENT_CONNECTION
    com.whatsapp

  142.250.183.46       443     2        12        0.312    —         LOW_REGULARITY
    com.google.android.gms
```

---

## CLI Reference

```
usage: c2bd.py [-h] [--device SERIAL] [--duration SEC] [--interval SEC]
               [--min-events N] [--high-threshold 0-1] [--medium-threshold 0-1]
               [--allow-cidr CIDR] [--include-udp] [--no-geo]

options:
  --device SERIAL        ADB device serial (auto-detected if omitted)
  --duration SEC         Scan duration in seconds (default: 300)
  --interval SEC         Poll interval in seconds (default: 2.0)
  --min-events N         Min new-socket events to score (default: 5)
  --high-threshold       Regularity ≥ this → HIGH_REGULARITY (default: 0.85)
  --medium-threshold     Regularity ≥ this → MODERATE_REGULARITY (default: 0.65)
  --allow-cidr CIDR      CIDR to exclude from analysis (repeatable)
  --include-udp          Also scan connected UDP peers (noisy)
  --no-geo               Skip IP geolocation (fully offline)
```

---

## Regularity Score Formula

The regularity score combines **Coefficient of Variation (CV)** with **Median-Absolute-Deviation (MAD)** to reduce sensitivity to outliers:

$$\text{score} = 1 - \frac{CV + MAD}{2}$$

where:

$$CV = \frac{\sigma}{\mu}, \quad MAD = \frac{\overline{|x_i - \tilde{x}|}}{\tilde{x}}$$

A score of **1.0** means perfectly periodic. A score near **0.0** means random/human-driven traffic.

---

## Honest Limitations

> ⚠️ This tool is a **behavioral triage aid** — not a malware detector.

| Claim | Reality |
|---|---|
| "Detects Pegasus" | Cannot confirm specific malware families |
| "100% accurate" | Push notifications, analytics, sync can appear periodic |
| "Proves C2" | `HIGH_REGULARITY` = investigate further, not a verdict |
| "Works on all Android" | `/proc/net/tcp` may be restricted on some Android 10+ builds |

If `/proc/net/tcp` is inaccessible, the tool will **abort with an explicit error** — never silently showing a false "clean" result.

---

## Report Format

Reports are saved to `~/Desktop/C2BD_Reports/` with:
- **JSON** — structured scan results, signed with SHA-256
- **.sha256** — sidecar integrity file
- **Permissions** — `600` (owner read/write only)
- **Serial** — hashed (privacy-preserving)

```json
{
  "tool": "C2BD v2.0",
  "disclaimer": "Heuristic triage tool. HIGH_REGULARITY is NOT confirmation of C2.",
  "timestamp_utc": "2026-10-03T18:30:00+00:00",
  "device_serial_hash": "a3f2c8d1e092",
  "threat_summary": {
    "high_regularity": 1,
    "moderate_regularity": 2,
    "low_regularity": 8
  },
  "integrity_sha256": "e3b0c44298fc...",
  ...
}
```

---

## Validation Tool

`validate.py` provides three modes for testing and demonstration:

```bash
# 1. Unit test the scoring algorithm (no phone needed)
python3 validate.py --validate

# 2. Start a fake C2 server on your laptop
python3 validate.py --server --port 18080

# 3. Simulate a beacon client (in another terminal)
python3 validate.py --client --host 127.0.0.1 --interval 10 --jitter 0.5
```

Use all three together to do a controlled end-to-end test of detection.

---

## Use Cases

- **BSF / ITBP border checkpoints** — Rapid device screening of confiscated phones
- **DRDO / ISRO installations** — Routine security audits of employee devices
- **CBI / NIA digital forensics** — Quick triage before full lab analysis
- **Indian Army field units** — Screening devices before sensitive operations
- **Security researchers** — Baseline tool for Android C2 behavioral studies

---

## Research Background

Inspired by:

- **arXiv:2609.27311** — *Multi-View Fusion for Encrypted C2 Detection: A Leakage-Controlled Measurement Study* (2026) — demonstrates timing + TLS metadata for C2 detection
- **INESC-ID Network Security Research** — Timing-based covert channel detection
- **Android AOSP Security Guidelines** — `/proc/net` access restrictions post Android 10

This implementation covers the **timing regularity** component as a field-deployable triage primitive.

---

## File Structure

```
C2BD_Software/
├── c2bd.py          # Main scanner — run this
├── validate.py      # Algorithm validation + fake beacon test
├── requirements.txt # pip dependencies (rich, reportlab)
├── LICENSE
└── README.md
```

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Disclaimer

This tool is intended for **authorized security auditing only**. Use only on devices you own or have explicit written permission to audit. Unauthorized interception of network communications may violate applicable laws including the **IT Act 2000 (India)** and similar legislation.

---

<p align="center">Built for Indian Government & Defence use · No root · No internet · No excuses</p>
