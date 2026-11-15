#!/usr/bin/env python3
"""Bounded enterprise-style red-team exercise for a disposable WSL2 lab.

The script runs as an unprivileged application account. It uses only synthetic
canaries, loopback traffic, bounded subprocesses, and non-destructive marker
files. It is not a malware sample, an exploit, or an external C2 client.
"""

import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

CONFIRMATION = "sentinel-enterprise-redteam"
LAB_ROOT = pathlib.Path("/srv/sentinel-enterprise-lab")
MARKER_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")


def require_lab():
    if os.environ.get("SENTINEL_ENTERPRISE_LAB_CONFIRM") != CONFIRMATION:
        raise SystemExit(f"Set SENTINEL_ENTERPRISE_LAB_CONFIRM={CONFIRMATION} to run this bounded lab.")
    if sys.platform != "linux":
        raise SystemExit("This manual lab is supported only inside Linux/WSL2.")
    if os.geteuid() == 0:
        raise SystemExit("Run as an unprivileged application account, never as root.")
    release = platform.release().lower()
    if "microsoft" not in release and "wsl" not in release:
        raise SystemExit("This script is restricted to the local WSL2 lab kernel.")
    if not LAB_ROOT.is_dir():
        raise SystemExit(f"Missing lab root: {LAB_ROOT}")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def read_bounded(path, limit):
    try:
        with path.open("rb") as source:
            data = source.read(limit)
        return {"status": "READ", "bytes": len(data), "sha256": sha256_bytes(data)}
    except PermissionError:
        return {"status": "DENIED"}
    except FileNotFoundError:
        return {"status": "MISSING"}
    except OSError as error:
        return {"status": "ERROR", "error": type(error).__name__}


def run_command(argv, timeout=5):
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "status": "COMPLETED",
            "returncode": result.returncode,
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
        }
    except FileNotFoundError:
        return {"status": "MISSING"}
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT"}
    except OSError as error:
        return {"status": "ERROR", "error": type(error).__name__}


def loopback_transfer(marker, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(3)
        address = server.getsockname()
        sent = f"SENTINEL_ENTERPRISE_EXFIL {marker}\n".encode("ascii") + payload
        with socket.create_connection(address, timeout=3) as client:
            client.sendall(sent)
            connection, _ = server.accept()
            with connection:
                connection.settimeout(3)
                received = connection.recv(8192)
        return {
            "status": "RECEIVED" if received else "EMPTY",
            "target": f"{address[0]}:{address[1]}",
            "bytes": len(received),
            "sha256": sha256_bytes(received),
        }


def write_marker(marker):
    directory = pathlib.Path.home() / ".config" / "sentinel-lab"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / "persistence.marker"
    target.write_text(f"{marker}\n", encoding="utf-8")
    os.chmod(target, 0o600)
    return {"status": "CREATED", "path": str(target), "active_persistence": False}


def main():
    require_lab()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("compromised-app", "unprivileged"), required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--app-canary", default=str(LAB_ROOT / "app-secret.txt"))
    parser.add_argument("--root-canary", default=str(LAB_ROOT / "root-secret.txt"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--sensitive-path", default="/etc/passwd")
    args = parser.parse_args()

    if not MARKER_PATTERN.fullmatch(args.marker):
        raise SystemExit("Marker must match [A-Za-z0-9_.:-]{8,128}.")
    app_canary = pathlib.Path(args.app_canary)
    root_canary = pathlib.Path(args.root_canary)
    sensitive_path = pathlib.Path(args.sensitive_path)
    if app_canary.parent != LAB_ROOT or root_canary.parent != LAB_ROOT:
        raise SystemExit(f"Canaries must be direct children of {LAB_ROOT}.")
    if sensitive_path != pathlib.Path("/etc/passwd"):
        raise SystemExit("This bounded lab only permits /etc/passwd as the sensitive-path marker.")

    started = time.monotonic()
    identity = run_command(["/usr/bin/id"])
    sudo_probe = run_command(["/usr/bin/sudo", "-n", "true"])
    shell = run_command(["/bin/sh", "-c", f"printf '%s\\n' {args.marker}; /usr/bin/id"])
    app_read = read_bounded(app_canary, 4096)
    root_read = read_bounded(root_canary, 4096)
    passwd_read = read_bounded(sensitive_path, 1)
    persistence = write_marker(args.marker)

    if app_read.get("status") == "READ":
        with app_canary.open("rb") as source:
            canary_payload = source.read(4096)
        exfil = loopback_transfer(args.marker, canary_payload)
    else:
        exfil = {"status": "SKIPPED_NO_CANARY"}

    compromise = (
        app_read.get("status") == "READ"
        and exfil.get("status") == "RECEIVED"
        and persistence.get("status") == "CREATED"
        and root_read.get("status") == "DENIED"
    )
    result = {
        "schema": "sentinel-enterprise-redteam-lab/v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "marker": args.marker,
        "mode": args.mode,
        "host": platform.node(),
        "kernel": platform.release(),
        "uid": os.geteuid(),
        "identity": identity,
        "sudo_probe": sudo_probe,
        "shell_exec": shell,
        "app_canary": app_read,
        "root_canary": root_read,
        "sensitive_path": {**passwd_read, "path": str(sensitive_path)},
        "loopback_exfil": exfil,
        "persistence_marker": persistence,
        "compromise_observed": compromise,
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
    }
    output = pathlib.Path(args.out)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(output, 0o600)
    print(json.dumps({"marker": args.marker, "mode": args.mode, "compromise": compromise, "out": str(output)}))


if __name__ == "__main__":
    main()
