# Sentinel Runtime: Configuration & Environment Guide

This guide details all environment variables, CLI runtime options, security flags, socket paths, and systemd parameters for deploying and operating **Sentinel Runtime**.

---

## 1. Environment Variables

Sentinel Runtime is designed to operate 100% autonomously and air-gapped without external dependencies. Optional environment variables configure cloud fleet intelligence and default database locations.

| Variable | Type | Default | Description |
|---|---|---|---|
| `SENTINEL_RUNTIME_API_KEY` | String | *(None / Unconfigured)* | Sentinel Cloud authentication key for runtime fleet telemetry. Must begin with the dedicated `snt_rt_` prefix. CLI tokens (`sntl_`) are rejected. |
| `SENTINEL_CLOUD_URL` | URL | `https://sentinel-security.up.railway.app` | Target Sentinel Cloud fleet aggregation endpoint. |
| `SENTINEL_DB_PATH` | File Path | `~/.sentinel/runtime.sqlite` | Default storage path for the cryptographic SQLite evidence ledger. |
| `NODE_ENV` | String | `production` | Node.js execution environment (`production`, `development`, `test`). |

---

## 2. CLI Commands & Global Options

Sentinel Runtime commands are invoked via `sentinel-runtime <command> [options]`:

### Commands Overview

- `collect-tetragon`: Connects to Cilium Tetragon gRPC stream and ingests real-time events.
- `ingest-tetragon`: Replays and processes an immutable Tetragon JSONL export file.
- `learn-profile`: Analyzes observed Tetragon activity and synthesizes a hardened `WorkloadProfile`.
- `export-custody`: Generates a tamper-evident forensic custody bundle with SHA-256 and HMAC manifests.
- `verify-custody`: Verifies the cryptographic integrity and provenance of an exported custody bundle.
- `verify-ledger`: Verifies the SHA-256 hash chain and structural integrity of the local SQLite database.
- `validate-v2`: Compiles and tests Event Contract v2 candidate schemas against local fixtures.
- `status`: Reports host runtime identity, ledger sequence, and collector readiness.

---

## 3. CLI Command Options & Flags

### Collection & Ingestion Options

| Flag | Type | Default | Description |
|---|---|---|---|
| `--address` | String | `unix:///run/sentinel-runtime/tetragon-readonly.sock` | Target Tetragon gRPC endpoint. Accepts `unix://<path>` on Linux, or `host:port` / `[IPv6]:port` for TCP. |
| `--host-id` | String | *(Required)* | Stable identity of the host node (e.g., node name, machine UUID). |
| `--boot-id` | UUID String | *(Required unless file)* | Host boot UUID. Must match canonical 36-character UUID format. |
| `--boot-id-file` | File Path | `/proc/sys/kernel/random/boot_id` | Absolute path to a regular file containing the host boot UUID. |
| `--db` | File Path | `~/.sentinel/runtime.sqlite` | Path to the SQLite evidence ledger file. |
| `--intelligence` | Boolean | `false` | Enables the real-time Intelligence Engine (CEP Sequence Detector, EWMA/CUSUM Anomaly Engine, and Decision Engine). |
| `--batch-size` | Integer | `128` | Number of events committed atomically in each SQLite transaction (1–4096). |
| `--flush-interval-ms` | Integer | `1000` | Maximum millisecond delay before flushing uncommitted pending events. |
| `--workload-id` | String | `unassigned` | Workload identifier associated with the ingested stream. |
| `--profiles` | File Path | *(None)* | Path to JSON file defining deterministic `WorkloadProfile` policies. |
| `--capture-process-arguments` | Boolean | `false` | Opts in to bounded string capture of process CLI arguments (default is policy-redacted). |
| `--expected-node-name` | String | *(None)* | Pin expected Tetragon `node_name`; drops or rejects mismatches. |
| `--max-events` | Integer | *(Unlimited)* | Terminates collector gracefully after processing $N$ events. |

### TLS & Network Security Options

Plaintext TCP gRPC is disabled by default for security.

| Flag | Type | Description |
|---|---|---|
| `--tls-ca` | File Path | Path to PEM-encoded root CA certificate. Required for TCP Tetragon endpoints. |
| `--tls-client-cert` | File Path | Path to PEM-encoded client certificate for mutual TLS (mTLS). |
| `--tls-client-key` | File Path | Path to PEM-encoded client private key for mTLS. Permissions must be 0600 on Linux. |
| `--metrics-url` | URL | Prometheus metrics scrape URL (e.g., `http://127.0.0.1:2112/metrics`). Loopback only or verified TLS. |

---

## 4. Real-Time Intelligence & Safety Invariants

When `--intelligence` is enabled, the runtime pipeline enforces the following strict defaults:

1. **Observe-Only & Dry-Run by Default**:
   `autoContain` is strictly `false` and `ContainmentDispatcher` defaults to `dryRun: true`. No process signals (`SIGSTOP`, `SIGKILL`) are sent to host processes without explicit operator configuration.
2. **Durability Before Action**:
   The triggering event and its SHA-256 cryptographic hash are committed to the SQLite hash chain prior to dispatching any containment decision.
3. **Attribution Safety Gate**:
   Destructive actions (R3/R4) are strictly blocked for any process lacking verified `host_id + boot_id + exec_id` lineage (such as Profile D or unverified PIDs).
4. **Observability Loss Gate**:
   If sensor drops or queue overflows occur (`loss_metrics` reported as `MEASURED`), destructive containment is prohibited.
5. **Human Approval Gate for Suspension (R2)**:
   Statistical rate anomalies alone cannot trigger process suspension. R2 recommendations require human operator authorization.

---

## 5. Systemd Deployment Architecture

For Linux host deployments, two decoupled service units are provided in [`docs/DEPLOYMENT_SYSTEMD.md`](DEPLOYMENT_SYSTEMD.md):

1. **`sentinel-tetragon-gateway.service`**:
   - Runs as a constrained gateway process.
   - Connects to privileged Tetragon socket (`/var/run/tetragon/tetragon.sock`).
   - Exposes a restricted, read-only Unix socket (`/run/sentinel-runtime/tetragon-readonly.sock`) exposing only `GetVersion` and `GetEvents`.
   - Socket ownership: `sentinel-gateway:sentinel-runtime`, permissions `0660`.
2. **`sentinel-runtime.service`**:
   - Runs as an unprivileged service account (`sentinel-runtime`).
   - Connects only to the read-only proxy socket.
   - Enforces Event Contract v2 validation, hash chaining, and local behavioral correlation.
   - Has zero access to Tetragon administrative RPCs or sensor reconfiguration.
