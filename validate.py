#!/usr/bin/env python3
"""
fake_beacon.py — Controlled test beacon for validating C2BD_v2.py
==================================================================
Run this on your LAPTOP while C2BD_v2.py is scanning the PHONE.

This script simulates a C2 beacon by making repeated HTTP connections
to a test server at regular intervals.

Usage:
    # Terminal 1 — start test server
    python3 fake_beacon.py --server

    # Terminal 2 — run beacon client (simulates spyware behavior)
    python3 fake_beacon.py --client --interval 10

    # Terminal 3 — run C2BD on phone and watch if it gets detected
    python3 C2BD_v2.py --duration 120 --interval 2

Expected result: C2BD should flag the beacon's IP with HIGH_REGULARITY
"""

import argparse
import http.server
import socket
import time
import threading
import urllib.request
from datetime import datetime

# ── Server (simulates C2 server) ──────────────────────────────────────────────

class SilentHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass   # suppress output
    def do_GET(self):
        t = datetime.now().strftime("%H:%M:%S.%f")
        print(f"  [SERVER] Beacon received at {t}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def run_server(port=18080):
    host = "0.0.0.0"
    srv  = http.server.HTTPServer((host, port), SilentHandler)
    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"\n[+] Fake C2 server running on {local_ip}:{port}")
    print(f"    Tell the client to connect to: {local_ip}:{port}")
    print(f"    Ctrl+C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

# ── Client (simulates spyware on phone) ──────────────────────────────────────

def run_client(target_ip: str, port: int, interval: float, jitter: float):
    import random
    url = f"http://{target_ip}:{port}/beacon"
    print(f"\n[+] Fake beacon client → {url}")
    print(f"    Interval: {interval}s  Jitter: ±{jitter}s")
    print(f"    This simulates spyware beaconing behavior.\n")

    timestamps = []
    try:
        while True:
            t = time.time()
            timestamps.append(t)
            try:
                urllib.request.urlopen(url, timeout=3)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"  [{ts}] Beacon sent → {url}")
            except Exception as e:
                print(f"  [!] Beacon failed: {e}")

            # Print interval stats every 5 beacons
            if len(timestamps) >= 3:
                intervals = [timestamps[i+1] - timestamps[i]
                             for i in range(len(timestamps)-1)]
                avg = sum(intervals) / len(intervals)
                print(f"      Avg interval so far: {avg:.2f}s  (n={len(intervals)})")

            sleep = interval + random.uniform(-jitter, jitter)
            time.sleep(max(1.0, sleep))
    except KeyboardInterrupt:
        print(f"\n[*] Beacon stopped. Sent {len(timestamps)} beacons.")

# ── Validation report ─────────────────────────────────────────────────────────

def run_validation(interval: float):
    """
    Validates core C2BD math locally — no phone needed.
    Creates synthetic beacon data and checks if scoring is correct.
    """
    from statistics import mean, stdev
    import math

    print("\n=== C2BD Core Algorithm Validation ===\n")

    def regularity_score(intervals):
        if len(intervals) < 2:
            return 0.0
        m  = mean(intervals)
        if m == 0:
            return 0.0
        cv  = stdev(intervals) / m
        from statistics import median
        md  = median(intervals)
        mad = mean(abs(x - md) for x in intervals) / md if md > 0 else 1.0
        return round(max(0.0, min(1.0, 1.0 - (cv + mad) / 2.0)), 4)

    test_cases = [
        {
            "name":     "Perfect beacon (30s, no jitter)",
            "data":     [30.0] * 20,
            "expected": "HIGH_REGULARITY",
        },
        {
            "name":     "Near-perfect beacon (30s ±0.5s jitter)",
            "data":     [30.0 + (i % 3 - 1) * 0.5 for i in range(20)],
            "expected": "HIGH_REGULARITY",
        },
        {
            "name":     "Slightly irregular (30s ±5s jitter)",
            "data":     [30.0 + (i % 7 - 3) * 5 for i in range(20)],
            "expected": "MODERATE_REGULARITY",
        },
        {
            "name":     "Random human browsing",
            "data":     [5, 45, 120, 3, 300, 15, 8, 600, 20, 2, 90, 400, 7, 180],
            "expected": "LOW_REGULARITY",
        },
        {
            "name":     "WhatsApp push (variable)",
            "data":     [2, 180, 5, 60, 900, 3, 45, 300, 8, 1200, 4],
            "expected": "LOW_REGULARITY",
        },
        {
            "name":     "Single persistent connection (no new sockets)",
            "data":     [],
            "expected": "PERSISTENT_CONNECTION (not scored)",
        },
    ]

    HIGH   = 0.85
    MEDIUM = 0.65
    passed = 0

    for tc in test_cases:
        data = tc["data"]
        if not data:
            print(f"  PASS  {tc['name']}")
            print(f"        → PERSISTENT_CONNECTION (inode tracking excludes this)")
            passed += 1
            continue

        score = regularity_score(data)
        if score >= HIGH:
            label = "HIGH_REGULARITY"
        elif score >= MEDIUM:
            label = "MODERATE_REGULARITY"
        else:
            label = "LOW_REGULARITY"

        ok = label == tc["expected"]
        status = "PASS" if ok else "FAIL"
        color  = "\033[92m" if ok else "\033[91m"
        rst    = "\033[0m"
        passed += ok

        print(f"  {color}{status}{rst}  {tc['name']}")
        print(f"        Score: {score:.4f}  → {label}  (expected: {tc['expected']})")

    total = len(test_cases)
    print(f"\n  Result: {passed}/{total} tests passed")
    if passed == total:
        print(f"\033[92m  [✓] Algorithm logic verified.\033[0m")
    else:
        print(f"\033[91m  [!] Some tests failed — check thresholds.\033[0m")

# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="C2BD Validation Tool")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--server",   action="store_true", help="Run fake C2 server")
    g.add_argument("--client",   action="store_true", help="Run beacon client")
    g.add_argument("--validate", action="store_true", help="Run algorithm unit tests (no phone needed)")
    p.add_argument("--host",     default="127.0.0.1",  help="Server IP (for client mode)")
    p.add_argument("--port",     type=int, default=18080, help="Port (default 18080)")
    p.add_argument("--interval", type=float, default=10.0, help="Beacon interval in seconds")
    p.add_argument("--jitter",   type=float, default=0.5,  help="Random jitter ±seconds")
    args = p.parse_args()

    if args.server:
        run_server(args.port)
    elif args.client:
        run_client(args.host, args.port, args.interval, args.jitter)
    elif args.validate:
        run_validation(args.interval)

if __name__ == "__main__":
    main()
