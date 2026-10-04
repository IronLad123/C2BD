#!/usr/bin/env python3
"""
C2BD_v2.py — Android Connection Timing Triage Tool
====================================================
Monitors TCP socket activity via ADB and /proc/net/tcp* to detect
endpoints with high timing regularity — a behavioral signal consistent
with periodic callback (beacon) patterns.

IMPORTANT: This is a behavioral triage tool, not a C2 probability estimator.
HIGH_REGULARITY does not mean malicious. It means: investigate further.

Fixes over C2BD.py (original):
  - Inode tracking: persistent sockets are NOT counted as repeated events
  - Monotonic timestamps: real intervals, not list-position artifacts
  - Preflight /proc/net visibility check: abort if unreadable (not false-clean)
  - No IP allowlist: malware uses AWS/CDN; no blind spots by default
  - Fixed IPv6 decoding: full 128-bit address, not truncated last 32 bits
  - Maps ALL UIDs including system (pm list -U, not -U -3)
  - Default 2s interval (not 10s) — catches short connections
  - Honest verdict labels: HIGH/MODERATE/LOW_REGULARITY + PERSISTENT_CONNECTION
  - SHA-256 sidecar file for integrity
  - Graceful Ctrl+C + ADB error reporting

Research note: Inspired by arXiv 2609.27311 (Multi-View Fusion for Encrypted C2
Detection, 2026), which uses flow statistics and TLS metadata — not just timing.
This tool implements only the timing component as a triage primitive.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, stdev
from typing import Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

# ─────────────────────────────────────────────────────────────────────────────
#  DEFAULTS (all overridable via CLI)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_DURATION       = 300     # seconds
DEFAULT_INTERVAL       = 2.0     # seconds between snapshots
DEFAULT_MIN_EVENTS     = 5       # minimum new-socket events to score
DEFAULT_HIGH_THRESH    = 0.85    # regularity score ≥ this → HIGH_REGULARITY
DEFAULT_MEDIUM_THRESH  = 0.65    # regularity score ≥ this → MODERATE_REGULARITY
REPORT_DIR             = Path.home() / "Desktop" / "C2BD_Reports"

# ─────────────────────────────────────────────────────────────────────────────
#  TERMINAL COLORS
# ─────────────────────────────────────────────────────────────────────────────

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def _c(code, t): return f"\033[{code}m{t}\033[0m" if _COLOR else t

def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def green(t):  return _c("92", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("97", t)
def dim(t):    return _c("2",  t)

BANNER = """
  C2BD v2.0 — Android Connection Timing Triage
  ─────────────────────────────────────────────
  Heuristic regularity index. NOT a C2 probability.
  HIGH_REGULARITY means: investigate further.
"""

# ─────────────────────────────────────────────────────────────────────────────
#  ADB LAYER
# ─────────────────────────────────────────────────────────────────────────────

DEVICE: Optional[str] = None

def adb_run(*args: str, timeout=20) -> subprocess.CompletedProcess:
    """Run adb with argument list (no shell=True). Returns CompletedProcess."""
    cmd = ["adb", "-s", DEVICE] + list(args)
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        # Return a fake failed result so callers can handle it
        return subprocess.CompletedProcess(cmd, returncode=1, stdout="", stderr="adb timeout")

def adb_shell(*args: str, timeout=20) -> tuple[str, bool]:
    """
    Run an adb shell command. Returns (stdout_text, success).
    Callers MUST check success — empty string is not the same as success.
    """
    result = adb_run("shell", *args, timeout=timeout)
    out    = result.stdout.strip()
    ok     = result.returncode == 0
    return out, ok

def connect_device(preferred: Optional[str]) -> bool:
    global DEVICE
    # Ensure server is running
    subprocess.run(["adb", "start-server"], capture_output=True, timeout=15)
    out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10).stdout
    lines   = out.strip().splitlines()[1:]
    ready   = [l.split("\t")[0] for l in lines if "\tdevice" in l]
    offline = [l.split("\t")[0] for l in lines if "offline" in l or "unauthorized" in l]

    if offline:
        print(yellow(f"  [!] Devices offline/unauthorized: {', '.join(offline)}"))
        print(yellow("      Unlock phone and tap 'Allow USB debugging'."))

    if preferred:
        if preferred in ready:
            DEVICE = preferred
        else:
            print(red(f"  [X] Requested device '{preferred}' not ready."))
            return False
    elif len(ready) == 1:
        DEVICE = ready[0]
    elif len(ready) > 1:
        print(cyan("  Multiple devices:"))
        for i, d in enumerate(ready):
            print(f"    {i+1}. {d}")
        try:
            DEVICE = ready[int(input("  Select: ")) - 1]
        except (ValueError, IndexError):
            print(red("  [X] Invalid selection."))
            return False
    else:
        print(red("  [X] No usable device found."))
        return False

    model,   ok1 = adb_shell("getprop", "ro.product.model")
    android, ok2 = adb_shell("getprop", "ro.build.version.release")
    if not (ok1 and ok2):
        print(yellow("  [!] Device responded but some properties unavailable."))
    print(green(f"  [+] Device  : {DEVICE}"))
    print(green(f"  [+] Model   : {model}  (Android {android})"))
    return True

# ─────────────────────────────────────────────────────────────────────────────
#  /proc/net PARSERS  (fixed IPv4 and IPv6)
# ─────────────────────────────────────────────────────────────────────────────

def decode_proc_ipv4(hex_addr: str) -> tuple[str, int]:
    """
    Decode little-endian hex address from /proc/net/tcp.
    'ABCDEF12:1F90' → ('18.222.239.171', 8080)
    """
    try:
        ip_hex, port_hex = hex_addr.split(":")
        ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
        return ip, int(port_hex, 16)
    except Exception:
        return "", 0

def decode_proc_ipv6(hex_addr: str) -> tuple[str, int]:
    """
    Decode little-endian hex address from /proc/net/tcp6.
    Full 128-bit, byte-swapped per 32-bit word.
    Handles IPv4-mapped addresses (::ffff:x.x.x.x).
    """
    try:
        ip_hex, port_hex = hex_addr.split(":")
        if len(ip_hex) != 32:
            return "", 0
        # Reverse each 4-byte (8 hex char) word
        words = [ip_hex[i:i+8] for i in range(0, 32, 8)]
        reordered = "".join(
            "".join(w[j:j+2] for j in (6, 4, 2, 0)) for w in words
        )
        raw = bytes.fromhex(reordered)
        addr = ipaddress.ip_address(raw)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped), int(port_hex, 16)
        return str(addr), int(port_hex, 16)
    except Exception:
        return "", 0

def parse_tcp_table(raw: str, ipv6: bool = False) -> list[dict]:
    """
    Parse /proc/net/tcp or /proc/net/tcp6 rows.
    Returns list of dicts with: remote_ip, remote_port, uid, inode.
    Only ESTABLISHED (state=01) connections are returned.
    """
    rows = []
    for line in raw.splitlines()[1:]:    # skip header
        parts = line.split()
        if len(parts) < 12:
            continue
        if parts[3] != "01":             # 01 = ESTABLISHED
            continue
        decode = decode_proc_ipv6 if ipv6 else decode_proc_ipv4
        rip, rport = decode(parts[2])
        if not rip or rip in ("0.0.0.0", "::"):
            continue
        inode = parts[9] if len(parts) > 9 else "0"
        rows.append({
            "remote_ip":   rip,
            "remote_port": rport,
            "uid":         parts[7],
            "inode":       inode,
        })
    return rows

# ─────────────────────────────────────────────────────────────────────────────
#  VISIBILITY PREFLIGHT
# ─────────────────────────────────────────────────────────────────────────────

def preflight_visibility() -> dict:
    """
    Check whether /proc/net/tcp and /proc/net/tcp6 are actually readable.
    Returns dict with 'tcp4', 'tcp6', 'usable' keys.
    Aborts with error if neither is readable.
    """
    raw4, ok4 = adb_shell("cat", "/proc/net/tcp")
    raw6, ok6 = adb_shell("cat", "/proc/net/tcp6")

    # Successful read but empty could mean no connections — that is fine.
    # Failure (returncode != 0) or 'Permission denied' in output = not visible.
    v4 = ok4 and "Permission denied" not in raw4
    v6 = ok6 and "Permission denied" not in raw6

    if not v4 and not v6:
        print(red("\n  [X] INSUFFICIENT VISIBILITY"))
        print(red("      Cannot read /proc/net/tcp or /proc/net/tcp6 on this device."))
        print(red("      This scanner cannot determine connection status."))
        print(red("      Do NOT interpret this as a clean result.\n"))
        sys.exit(2)

    print(dim(f"  Visibility: /proc/net/tcp={'ok' if v4 else 'NO'}  "
              f"/proc/net/tcp6={'ok' if v6 else 'NO'}"))
    return {"tcp4": v4, "tcp6": v6, "raw4": raw4 if v4 else "", "raw6": raw6 if v6 else ""}

# ─────────────────────────────────────────────────────────────────────────────
#  SNAPSHOT — get current connections
# ─────────────────────────────────────────────────────────────────────────────

def snapshot(vis: dict) -> list[dict]:
    """Return current ESTABLISHED connections from accessible tcp tables."""
    rows = []
    if vis["tcp4"]:
        raw, ok = adb_shell("cat", "/proc/net/tcp")
        if ok:
            rows += parse_tcp_table(raw, ipv6=False)
        else:
            vis["fail_count"] = vis.get("fail_count", 0) + 1
    if vis["tcp6"]:
        raw, ok = adb_shell("cat", "/proc/net/tcp6")
        if ok:
            rows += parse_tcp_table(raw, ipv6=True)
        else:
            vis["fail_count"] = vis.get("fail_count", 0) + 1
    return rows

# ─────────────────────────────────────────────────────────────────────────────
#  UID → PACKAGE MAPPING  (all UIDs, including system)
# ─────────────────────────────────────────────────────────────────────────────

_uid_map: dict[str, list[str]] = {}

def build_uid_map() -> None:
    """Build UID → [packages] map from pm list packages -U (all, not just -3)."""
    raw, ok = adb_shell("pm", "list", "packages", "-U", timeout=30)
    if not ok:
        print(yellow("  [!] Could not build UID map (pm list failed). UIDs will show as uid:N."))
        return
    for line in raw.splitlines():
        m = re.search(r"package:(\S+)\s+uid:(\d+)", line)
        if m:
            pkg, uid = m.group(1), m.group(2)
            _uid_map.setdefault(uid, []).append(pkg)

def uid_label(uid: str) -> str:
    pkgs = _uid_map.get(uid)
    if pkgs:
        return ", ".join(pkgs[:2]) + (" …" if len(pkgs) > 2 else "")
    sys_names = {"0": "root", "1000": "system", "1001": "radio",
                 "1002": "bluetooth", "2000": "shell"}
    return sys_names.get(uid, f"uid:{uid}")

# ─────────────────────────────────────────────────────────────────────────────
#  CIDR ALLOW-LIST
# ─────────────────────────────────────────────────────────────────────────────

_allowed_nets: list[ipaddress._BaseNetwork] = []

def load_allowed_cidrs(cidrs: list[str]) -> None:
    for cidr in cidrs:
        try:
            _allowed_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            print(yellow(f"  [!] Invalid CIDR ignored: {cidr}"))

def is_allowed(ip: str) -> bool:
    if not _allowed_nets:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _allowed_nets)
    except ValueError:
        return False

# ─────────────────────────────────────────────────────────────────────────────
#  REGULARITY SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def regularity_score(intervals: list[float]) -> float:
    """
    Heuristic regularity index in [0, 1]. Higher = more periodic.
    Combines Coefficient of Variation with median-deviation ratio.
    NOT a probability of C2.
    """
    if len(intervals) < 2:
        return 0.0
    m  = mean(intervals)
    md = median(intervals)
    if m == 0:
        return 0.0
    cv  = stdev(intervals) / m if len(intervals) > 1 else 1.0
    # Median-centered deviation reduces impact of single outliers
    mad = mean(abs(x - md) for x in intervals) / md if md > 0 else 1.0
    combined_jitter = (cv + mad) / 2.0
    return round(max(0.0, min(1.0, 1.0 - combined_jitter)), 4)

def classify(score: float, is_persistent: bool,
             high_t: float, mid_t: float) -> tuple[str, str]:
    if is_persistent:
        return "PERSISTENT_CONNECTION", "dim"
    if score >= high_t:
        return "HIGH_REGULARITY", "red"
    elif score >= mid_t:
        return "MODERATE_REGULARITY", "yellow"
    return "LOW_REGULARITY", "green"

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCAN LOOP
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(duration: float, interval: float, min_events: int,
             high_t: float, mid_t: float,
             include_udp: bool, vis: dict) -> dict:
    """
    Poll /proc/net/tcp* every `interval` seconds for `duration` seconds.
    Track new socket inodes per endpoint to avoid counting persistent conns.
    """
    # endpoint key → list of timestamps when a NEW inode was seen
    new_socket_times: dict[str, list[float]] = defaultdict(list)
    # endpoint key → set of inodes ever seen (to detect new vs persistent)
    seen_inodes:      dict[str, set]         = defaultdict(set)
    # endpoint key → count of persistent (never-new) appearances
    persist_count:    dict[str, int]         = defaultdict(int)

    snapshots_taken    = 0
    collection_failures = 0
    t_start = time.monotonic()
    t_end   = t_start + duration

    scheduled = int(duration / interval) + 1
    print(dim(f"  Baseline snapshot (not scored)... "), end="", flush=True)

    # --- Baseline snapshot: populate seen_inodes but don't score ---
    baseline = snapshot(vis)
    for row in baseline:
        key = f"{row['remote_ip']}:{row['remote_port']}|uid:{row['uid']}"
        if not is_allowed(row["remote_ip"]):
            seen_inodes[key].add(row["inode"])
    print(dim("done"))
    snapshots_taken += 1

    # --- Timed sampling loop ---
    print(f"\n{dim('  Scanning... (Ctrl+C to stop early)')}\n")
    i = 0
    while time.monotonic() < t_end:
        i += 1
        now  = time.monotonic()
        rows = snapshot(vis)
        fail = vis.pop("fail_count", 0)
        collection_failures += fail

        current_inodes: dict[str, set] = defaultdict(set)
        for row in rows:
            if is_allowed(row["remote_ip"]):
                continue
            key = f"{row['remote_ip']}:{row['remote_port']}|uid:{row['uid']}"
            current_inodes[key].add(row["inode"])

        for key, inodes in current_inodes.items():
            new = inodes - seen_inodes[key]
            if new:
                new_socket_times[key].append(now - t_start)
                seen_inodes[key].update(new)
            else:
                persist_count[key] += 1

        snapshots_taken += 1
        # Progress bar
        pct  = min(100, int(100 * (now - t_start) / duration))
        bar  = "█" * (pct // 2) + "░" * (50 - pct // 2)
        print(f"\r  [{bar}] {pct:>3}%  snap {snapshots_taken}/{scheduled}", end="", flush=True)

        # Precise sleep: account for processing time
        elapsed = time.monotonic() - now
        sleep   = max(0.0, interval - elapsed)
        time.sleep(sleep)

    print("\n")

    # --- Build results ---
    results = []
    for key, ts in new_socket_times.items():
        if len(ts) < min_events:
            continue
        intervals = [ts[j+1] - ts[j] for j in range(len(ts) - 1)]
        score     = regularity_score(intervals) if intervals else 0.0
        is_p      = (len(ts) < 2 and persist_count[key] > 3)
        label, col = classify(score, is_p, high_t, mid_t)

        ip, rest  = key.split(":")
        port      = int(rest.split("|")[0])
        uid       = key.split("uid:")[-1]

        results.append({
            "remote_ip":         ip,
            "remote_port":       port,
            "uid":               uid,
            "packages":          uid_label(uid),
            "new_socket_events": len(ts),
            "persist_snaps":     persist_count[key],
            "regularity_score":  score,
            "avg_interval_s":    round(mean(intervals), 2) if intervals else None,
            "label":             label,
            "_color":            col,
        })

    results.sort(key=lambda x: -x["regularity_score"])

    return {
        "snapshots_taken":      snapshots_taken,
        "collection_failures":  collection_failures,
        "failure_ratio":        round(collection_failures / max(1, snapshots_taken), 3),
        "results":              results,
    }

# ─────────────────────────────────────────────────────────────────────────────
#  GEOLOCATION (optional, no allowlist decisions)
# ─────────────────────────────────────────────────────────────────────────────

_geo: dict = {}

def geolocate(ip: str) -> dict:
    if ip in _geo:
        return _geo[ip]
    try:
        req  = Request(f"https://ipinfo.io/{ip}/json", headers={"User-Agent":"C2BD/2"})
        data = json.loads(urlopen(req, timeout=4).read())
        r    = {"country": data.get("country","?"),
                "org":     data.get("org","?"),
                "city":    data.get("city","?")}
    except Exception:
        r = {"country":"?","org":"?","city":"?"}
    _geo[ip] = r
    return r

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

# ─────────────────────────────────────────────────────────────────────────────
#  DISPLAY
# ─────────────────────────────────────────────────────────────────────────────

_CF = {"red": red, "yellow": yellow, "green": green, "dim": dim}

def print_results(data: dict) -> None:
    results = data["results"]
    fr      = data["failure_ratio"]
    if fr > 0.1:
        print(yellow(f"  [!] Collection failure ratio: {fr:.1%}  "
                     f"({data['collection_failures']}/{data['snapshots_taken']} snapshots had errors)"))

    if not results:
        print(green("  [✓] No endpoints met the minimum new-socket event threshold."))
        print(dim( "      If collection failures were high, this is NOT a clean result."))
        return

    print(bold(f"\n  {'IP':<20} {'Port':<7} {'Events':<8} {'Persist':<9} "
               f"{'Score':<8} {'AvgInt':<9} Label"))
    print(dim("  " + "─" * 90))

    for r in results:
        cf  = _CF.get(r["_color"], lambda x: x)
        avg = f"{r['avg_interval_s']}s" if r["avg_interval_s"] is not None else "—"
        print(cf(f"  {r['remote_ip']:<20} {r['remote_port']:<7} "
                 f"{r['new_socket_events']:<8} {r['persist_snaps']:<9} "
                 f"{r['regularity_score']:<8} {avg:<9} {r['label']}"))
        pkg = r.get("packages", "")
        if pkg:
            print(dim(f"    {'':>20} {pkg}"))
        geo  = r.get("geo", {})
        host = r.get("hostname", "")
        if geo and geo.get("country") != "?":
            print(dim(f"    {'':>20} [{geo.get('country')}] {geo.get('city')} / {geo.get('org')}"))
        if host and host != r["remote_ip"]:
            print(dim(f"    {'':>20} {host}"))

    print()
    h = sum(1 for r in results if r["label"] == "HIGH_REGULARITY")
    m = sum(1 for r in results if r["label"] == "MODERATE_REGULARITY")
    p = sum(1 for r in results if r["label"] == "PERSISTENT_CONNECTION")
    l = sum(1 for r in results if r["label"] == "LOW_REGULARITY")
    print(f"  {red(f'HIGH_REGULARITY: {h}')}  "
          f"{yellow(f'MODERATE: {m}')}  "
          f"{dim(f'PERSISTENT: {p}')}  "
          f"{green(f'LOW: {l}')}")

# ─────────────────────────────────────────────────────────────────────────────
#  REPORT
# ─────────────────────────────────────────────────────────────────────────────

def save_report(scan_data: dict, args_ns) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    dev  = hashlib.sha256(DEVICE.encode()).hexdigest()[:12]  # redact serial
    path = REPORT_DIR / f"C2BDv2_{dev}_{ts}.json"

    # Remove internal _color key before saving
    results_clean = [{k: v for k, v in r.items() if not k.startswith("_")}
                     for r in scan_data["results"]]

    payload = {
        "tool":            "C2BD v2.0",
        "disclaimer":      ("Heuristic triage tool. HIGH_REGULARITY is NOT "
                            "confirmation of C2 or malware activity."),
        "timestamp_utc":   datetime.now(timezone.utc).isoformat(),
        "device_serial_hash": dev,
        "scan_config": {
            "duration_s":       getattr(args_ns, "duration", DEFAULT_DURATION),
            "interval_s":       getattr(args_ns, "interval", DEFAULT_INTERVAL),
            "min_events":       getattr(args_ns, "min_events", DEFAULT_MIN_EVENTS),
            "high_threshold":   getattr(args_ns, "high_threshold", DEFAULT_HIGH_THRESH),
            "medium_threshold": getattr(args_ns, "medium_threshold", DEFAULT_MEDIUM_THRESH),
            "allowed_cidrs":    getattr(args_ns, "allow_cidr", []),
        },
        "scan_stats": {
            "snapshots_taken":      scan_data["snapshots_taken"],
            "collection_failures":  scan_data["collection_failures"],
            "failure_ratio":        scan_data["failure_ratio"],
        },
        "results": results_clean,
    }

    raw    = json.dumps(payload, indent=2, sort_keys=True)
    sha256 = hashlib.sha256(raw.encode()).hexdigest()
    payload["integrity_sha256"] = sha256
    final  = json.dumps(payload, indent=2, sort_keys=True)

    path.write_text(final, encoding="utf-8")
    os.chmod(path, 0o600)   # owner read/write only

    # SHA-256 sidecar
    sidecar = path.with_suffix(".sha256")
    sidecar.write_text(f"{sha256}  {path.name}\n", encoding="utf-8")
    os.chmod(sidecar, 0o600)

    return path

# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="c2bd_v2",
        description="Android connection timing triage via ADB.")
    p.add_argument("--device",           metavar="SERIAL",
                   help="ADB device serial (auto-detected if omitted)")
    p.add_argument("--duration",         type=float, default=DEFAULT_DURATION,
                   metavar="SEC",        help=f"Scan duration (default {DEFAULT_DURATION}s)")
    p.add_argument("--interval",         type=float, default=DEFAULT_INTERVAL,
                   metavar="SEC",        help=f"Poll interval (default {DEFAULT_INTERVAL}s)")
    p.add_argument("--min-events",       type=int,   default=DEFAULT_MIN_EVENTS,
                   metavar="N",          help=f"Min new-socket events to score (default {DEFAULT_MIN_EVENTS})")
    p.add_argument("--high-threshold",   type=float, default=DEFAULT_HIGH_THRESH,
                   metavar="0-1",        help=f"Regularity ≥ this → HIGH (default {DEFAULT_HIGH_THRESH})")
    p.add_argument("--medium-threshold", type=float, default=DEFAULT_MEDIUM_THRESH,
                   metavar="0-1",        help=f"Regularity ≥ this → MODERATE (default {DEFAULT_MEDIUM_THRESH})")
    p.add_argument("--allow-cidr",       action="append", default=[], metavar="CIDR",
                   help="CIDR to exclude from analysis (repeatable). Default: none excluded.")
    p.add_argument("--include-udp",      action="store_true",
                   help="Include connected UDP peers (very noisy; treat with extra caution)")
    p.add_argument("--no-geo",           action="store_true",
                   help="Skip geolocation lookup")
    return p

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print(BANNER)
    args = build_parser().parse_args()

    if not connect_device(args.device):
        sys.exit(1)

    if args.allow_cidr:
        load_allowed_cidrs(args.allow_cidr)
        print(dim(f"  Allowed CIDRs (excluded from analysis): {', '.join(args.allow_cidr)}"))

    print(dim(f"\n  Building UID → package map..."), end="", flush=True)
    build_uid_map()
    print(dim(f" {len(_uid_map)} UIDs mapped"))

    print(dim(f"\n  Checking /proc/net visibility..."))
    vis = preflight_visibility()

    print(f"\n  {bold('Scan parameters')}")
    print(dim(f"    Duration  : {args.duration}s"))
    print(dim(f"    Interval  : {args.interval}s"))
    print(dim(f"    Min events: {args.min_events}"))
    print(dim(f"    High thresh : {args.high_threshold}  |  "
              f"Mid thresh : {args.medium_threshold}"))
    print(dim(f"    Snapshots (approx): {int(args.duration / args.interval) + 1}"))

    try:
        scan_data = run_scan(
            duration    = args.duration,
            interval    = args.interval,
            min_events  = args.min_events,
            high_t      = args.high_threshold,
            mid_t       = args.medium_threshold,
            include_udp = args.include_udp,
            vis         = vis,
        )
    except KeyboardInterrupt:
        print(yellow("\n\n  [!] Scan interrupted."))
        scan_data = {"snapshots_taken": 0, "collection_failures": 0,
                     "failure_ratio": 0.0, "results": []}

    # Geolocation
    if not args.no_geo:
        notable = [r for r in scan_data["results"]
                   if r["label"] in ("HIGH_REGULARITY", "MODERATE_REGULARITY")]
        if notable:
            ips = {r["remote_ip"] for r in notable}
            print(dim(f"  Geolocating {len(ips)} notable endpoints..."))
            for ip in ips:
                geo  = geolocate(ip)
                host = resolve_hostname(ip)
                for r in scan_data["results"]:
                    if r["remote_ip"] == ip:
                        r["geo"]      = geo
                        r["hostname"] = host

    print(f"\n{bold('  ═══ RESULTS ═══')}\n")
    print_results(scan_data)

    report_path = save_report(scan_data, args)
    print(green(f"\n  [+] Report  : {report_path}"))
    print(green(f"  [+] Sidecar : {report_path.with_suffix('.sha256')}"))
    print(dim( f"      Report permissions: 600 (owner-only)"))

    high = sum(1 for r in scan_data["results"] if r["label"] == "HIGH_REGULARITY")
    if high:
        print(red(f"\n  [!] {high} endpoint(s) show HIGH_REGULARITY."))
        print(red( "      These require manual investigation — they are NOT"))
        print(red( "      confirmed C2 activity. Correlate with network logs."))
    else:
        print(green("\n  [✓] No high-regularity endpoints detected in this scan window."))

    if scan_data["failure_ratio"] > 0.2:
        print(yellow(f"\n  [!] High collection failure rate ({scan_data['failure_ratio']:.1%})."))
        print(yellow( "      Results may be incomplete. Do NOT treat this as a clean result."))


if __name__ == "__main__":
    main()
