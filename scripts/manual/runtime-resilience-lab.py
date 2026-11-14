#!/usr/bin/env python3
"""Bounded, non-root WSL2 sensor exercise. It never contacts a non-loopback peer."""

import argparse
import json
import os
import pathlib
import platform
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

CONFIRMATION = "runtime-resilience"
METRICS_URL = "http://127.0.0.1:2112/metrics"
CANARY = b"SENTINEL_LAB_SYNTHETIC_CANARY_NO_CREDENTIALS\n"


def require_lab():
    if os.environ.get("SENTINEL_LAB_CONFIRM") != CONFIRMATION:
        raise SystemExit(f"Set SENTINEL_LAB_CONFIRM={CONFIRMATION} to run this bounded lab.")
    if sys.platform != "linux":
        raise SystemExit("This manual lab is supported only inside Linux/WSL2.")
    if os.geteuid() == 0:
        raise SystemExit("Run as an unprivileged workload account, never as root.")
    release = platform.release().lower()
    if "microsoft" not in release and "wsl" not in release:
        raise SystemExit("This script is restricted to the local WSL2 lab kernel.")


def read_counter_snapshot():
    try:
        request = urllib.request.Request(METRICS_URL, headers={"Accept": "text/plain"})
        with urllib.request.urlopen(request, timeout=2) as response:
            body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            return {"state": "REJECTED_OVER_4_MIB"}
        counters = {}
        for raw_line in body.decode("utf-8", "replace").splitlines():
            if not raw_line or raw_line.startswith("#"):
                continue
            name_and_labels, separator, value = raw_line.partition(" ")
            if not separator or not any(word in name_and_labels.lower() for word in ("drop", "miss", "overflow", "lost")):
                continue
            try:
                counters[name_and_labels] = float(value.strip().split()[0])
            except (ValueError, IndexError):
                continue
        return {"state": "AVAILABLE", "counters": counters}
    except Exception as error:  # Metrics can be disabled; absence is unknown, never zero.
        return {"state": "UNAVAILABLE", "reason": type(error).__name__}


def run_read_burst(path, count):
    for _ in range(count):
        with path.open("rb") as source:
            source.read()


def run_relative_path_read(directory):
    previous_directory = os.getcwd()
    try:
        os.chdir(directory)
        with open("synthetic-canary.txt", "rb") as source:
            source.read(1)
    finally:
        os.chdir(previous_directory)


def run_argv0_spoof(children):
    pids = []
    for _ in range(children):
        child_pid = os.fork()
        if child_pid == 0:
            try:
                # Use a no-op executable to keep the child short-lived while
                # still exposing the spoofed argv[0] to process sensors.
                # dash ignores argv[0] for this non-login `-c` invocation,
                # unlike coreutils' multi-call binary which dispatches by name.
                os.execve("/usr/bin/dash", ["sshd", "-c", "exit 0"], {})
            except OSError:
                os._exit(127)
        pids.append(child_pid)
        _, status = os.waitpid(child_pid, 0)
        if os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("argv[0] spoof child exited unsuccessfully")
    return pids


def run_loopback_transfers(count):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(2)
        address = server.getsockname()
        for _ in range(count):
            with socket.create_connection(address, timeout=2) as client:
                client.sendall(CANARY)
                connection, _ = server.accept()
                with connection:
                    connection.recv(256)


def main():
    require_lab()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reads", type=int, default=2000, help="file open/read cycles; max 10000")
    parser.add_argument("--spoofed-execs", type=int, default=16, help="short-lived argv[0] spoof attempts; max 64")
    parser.add_argument("--loopback-transfers", type=int, default=16, help="loopback-only sends; max 64")
    args = parser.parse_args()
    if not 1 <= args.reads <= 10000 or not 0 <= args.spoofed_execs <= 64 or not 0 <= args.loopback_transfers <= 64:
        raise SystemExit("Bounds exceeded: reads 1..10000, spoofed execs 0..64, loopback transfers 0..64.")

    release = platform.release()
    before = read_counter_snapshot()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="sentinel-runtime-lab-") as directory:
        root = pathlib.Path(directory)
        os.chmod(root, 0o700)
        canary = root / "synthetic-canary.txt"
        canary.write_bytes(CANARY)
        os.chmod(canary, 0o600)
        alias = root / "benign-alias.txt"
        alias.symlink_to(canary.name)

        run_read_burst(canary, args.reads)
        run_relative_path_read(root)
        with alias.open("rb") as source:
            source.read()
        spoofed_exec_pids = run_argv0_spoof(args.spoofed_execs)
        run_loopback_transfers(args.loopback_transfers)

    elapsed = time.monotonic() - started
    after = read_counter_snapshot()
    deltas = {}
    if before.get("state") == "AVAILABLE" and after.get("state") == "AVAILABLE":
        for name, value in after["counters"].items():
            prior = before["counters"].get(name)
            deltas[name] = None if prior is None or value < prior else value - prior

    print(json.dumps({
        "report_type": "SENTINEL_RUNTIME_BOUNDED_WSL_LAB_V1",
        "test_marker": "SR-RT-001-LOCAL-RESILIENCE",
        "mode": "LIVE_LOCAL_SENSOR_EXERCISE",
        "kernel": release,
        "run_as_uid": os.geteuid(),
        "orchestrator_pid": os.getpid(),
        "argv0_spoof_child_pids": spoofed_exec_pids,
        "external_network": "NONE",
        "network_scope": "127.0.0.1 only",
        "file_scope": "temporary synthetic canary under /tmp; removed on exit",
        "activities": {
            "file_open_read_cycles": args.reads,
            "relative_path_open_reads": 1,
            "symlink_alias_reads": 1,
            "argv0_spoof_execs": args.spoofed_execs,
            "short_lived_child_execs": args.spoofed_execs,
            "loopback_transfers": args.loopback_transfers,
            "canary_contains_credentials": False,
        },
        "elapsed_seconds": round(elapsed, 3),
        "tetragon_loss_counters_before": before,
        "tetragon_loss_counters_after": after,
        "tetragon_loss_counter_deltas": deltas if deltas else "UNKNOWN_OR_NO_COUNTER_CHANGE",
        "interpretation_limit": "No observed counter delta does not prove zero loss in unavailable telemetry domains.",
    }, indent=2))


if __name__ == "__main__":
    main()
