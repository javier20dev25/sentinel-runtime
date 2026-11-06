# Sentinel Runtime: eBPF Workload Security & Process Lineage Verification

[![CI](https://github.com/javier20dev25/sentinel-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/javier20dev25/sentinel-runtime/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.5.0-brightgreen)](package.json)
[![eBPF: Cilium Tetragon v1.8](https://img.shields.io/badge/eBPF-Cilium%20Tetragon%20v1.8-purple.svg)](https://tetragon.io)
[![Event Contract: v2](https://img.shields.io/badge/Event%20Contract-v2%20Candidate-orange.svg)](docs/specs/SENTINEL_RUNTIME_ENGINE_V1_SPEC.md)

**Sentinel Runtime** is a verifiable runtime security, process behavioral correlation, and tamper-evident audit ledger for Linux and Kubernetes workloads. It ingests eBPF telemetry from [Cilium Tetragon](https://tetragon.io), validates telemetry against formal event contracts (Event Contract v2), tracks process execution lineage across fork/exec/exit boundaries, and anchors cryptographic evidence trails in an immutable SQLite hash chain.

Sentinel Runtime provides deterministic runtime behavioral correlation, complex event processing (CEP), streaming anomaly detection, and tamper-evident audit ledger capabilities for Linux and Kubernetes workloads. It ingests eBPF telemetry from [Cilium Tetragon](https://tetragon.io), validates telemetry against formal event contracts (Event Contract v2), tracks process execution lineage across fork/exec/exit boundaries, and anchors cryptographic evidence trails in an immutable SQLite hash chain.

The engine operates by default in **observe-only** mode (R1) with strict attribution gates. Active containment (R2–R4) requires explicit opt-in policy authorization and verified process lineage.


## Architectural Comparison: Sentinel Runtime vs. Cilium Tetragon, Falco & Sysdig

When evaluating runtime security tools for Linux and Kubernetes environments, teams frequently compare **Cilium Tetragon**, **Falco**, and **Sysdig**. Sentinel Runtime occupies a complementary, contract-first layer above raw sensors:

| Capability | Cilium Tetragon | Falco (CNCF) | Sysdig Secure | Sentinel Runtime |
|---|---|---|---|---|
| **Primary Role** | In-kernel eBPF sensor & enforcement | Rule-based syscall anomaly detection | Commercial runtime & cloud security | Verifiable process lineage & evidence custody |
| **Architecture** | Kernel eBPF probes + user-space daemon | Kernel module / eBPF + rule engine | Agent + SaaS control plane | Local correlation engine + tamper-evident chain |
| **Event Contract** | Protobuf / JSON (sensor-specific) | Falco JSON / gRPC stream | Proprietary telemetry format | Strictly validated Event Contract v1 & v2 schemas |
| **Process Lineage** | `exec_id` tracking (sensor-scoped) | Syscall-correlated PID tracking | Agent-correlated container trees | Deterministic `host_id + boot_id + exec_id` state machine |
| **PID Reuse Defense** | Handled via kernel exec identity | Susceptible to rapid PID recycling | Agent-side correlation | Cryptographic event keys with domain-separated UTF-8 lengths |
| **Evidence Custody** | Standard syslog / JSON logs | Syslog / Webhook / File alerts | Cloud SaaS storage | Tamper-evident SHA-256 SQLite hash chain on-host |
| **Loss Transparency** | BPF ring buffer loss counters | Drops logged if buffer fills | Dropped events accounted by agent | Measured loss counters required for provenance certification |
| **Air-Gap Capable** | Yes (local sensor) | Yes (local daemon) | No (requires SaaS connectivity) | 100% Autonomous & Air-Gap Capable |
| **Cloud Synergy** | Cilium / Hubble integration | CNCF ecosystem plugins | Native SaaS dashboard | Zero-knowledge cloud fleet intel (optional `snt_rt_` API key) |

> **Why Sentinel Runtime alongside Tetragon or Falco?**  
> Tetragon is an extraordinary low-level eBPF sensor, and Falco provides extensive community rule engines. However, enterprise compliance, regulatory audits, and forensic investigation require **verifiable contracts**, **tamper-evident evidence chains**, and **deterministic process state machines**. Sentinel Runtime acts as the trust and arbitration layer: it consumes Tetragon's raw eBPF telemetry, normalizes it through strict contracts, and guarantees that incident evidence cannot be silently rewritten or repudiated. Read the detailed [Tetragon, Falco & Sentinel Architecture Comparison](docs/COMPARISON_TETRAGON_FALCO_SYSDIG.md).
## What works today

- Deterministic process correlation keyed by `host_id + boot_id + exec_id`, with time-window expiry, duplicate suppression, and bounded in-memory state.
- Exact executable path or SHA-256 allowlists, path-boundary checks, and normalized hostname/IPv4 CIDR destination rules.
- Tetragon JSONL ingestion with optional atomic checkpoints, plus a version-pinned v1.8.0 gRPC collector. Unsupported event families are recorded rather than guessed.
- Optional Linux read-only gRPC proxy that exposes only `GetVersion` and `GetEvents` over a permission-controlled Unix socket; it preserves exact upstream protobuf bytes, including unknown fields, while policy and sensor administration RPCs are not registered downstream.
- Native `PROCESS_EXEC`, `PROCESS_EXIT`, and supported kprobe events are materialized as complete, validated Event Contract v2 records with transport-aware cursors, source hashes, separate source/observation timestamps, workload metadata, and explicit unknown loss states.
- Hardened [systemd units](docs/DEPLOYMENT_SYSTEMD.md) for separate single-host gateway and collector accounts. Installation, upgrades, and fleet management remain operator-managed.
- JSONL framing with byte offsets, UTF-8 validation, a 16 MiB per-frame limit, and duplicate-key rejection before `JSON.parse`.
- Event Contract v1 validator is frozen (SHA-256: `8c58cd9661eb3e192d89a3480572486fd96fe24f5bdb3219e3053a807515cfe9`). Event Contract v2 candidate (SHA-256: `40ff2d683cb3efd81376cc136af6e4d8afc0ea4d934a9745dec4f2c479a838fa`) provides strict validation for RAW (Profile A), DERIVED (Profile B), SYNTHETIC (Profile C), and provisional RAW_PARTIAL (Profile D) keys. v2 remains an unapproved candidate; schema conformance does not authenticate the sensor.
- The production v2 validator recomputes and verifies domain-separated event keys, requires provenance for measured loss counters, enforces canonical uint64 decimal strings without `Number` precision loss, and separates `FILE_BYTES` from `GRPC_SEQUENCE` cursors.
- SQLite evidence records linked with a SHA-256 hash chain, full synchronous commits, and an integrity verifier.
- Automated baseline discovery via `learn-profile` that synthesizes hardened `WorkloadProfile` definitions from observed Tetragon JSONL activity.
- Real-time Threat Intelligence Engine with zero external runtime dependencies:
  - Complex Event Processing (CEP) and sliding-window Finite State Machine (`SequenceDetector`) tracking multi-step attack sequences across time (e.g. sensitive credential access followed by network egress, outbound reverse shells, privilege escalation attempts).
  - Online streaming anomaly detection (`AnomalyEngine`) using Exponentially Weighted Moving Average (EWMA) and Cumulative Sum (CUSUM) control charts evaluating streaming time-normalized rate metrics with bounded memory under workload churn and IEEE 754 precision.
  - Multi-signal Behavioral Fusion (`BehaviorEngine`) combining deterministic policy allowlists, CEP state machines, and statistical drift metrics.
  - Automated Decision Engine (`DecisionEngine`) scoring threats, computing decision confidence, and orchestrating policy-authorized containment actions.
- Containment & Response Dispatcher (`ContainmentDispatcher`) supporting graduated containment levels (R1 Observe Only, R2 Process Suspension via `SIGSTOP`, R3 Process Termination via `SIGKILL`, R4 Container/Network Isolation) with strict transactional pre-commitment (`ACTION_PLANNED` committed to the SQLite hash chain prior to signal dispatch) and strict attribution gates that prevent destructive actions against Profile D or unverified identities.
- Cryptographic chain custody and forensic bundle export (`export-custody`, `verify-custody`) with immutable SHA-256 / HMAC manifests for external audit and incident response.

## Explicit product limits

- There is no managed resident daemon, Kubernetes controller, fleet health plane, or eBPF sensor in this repository. A systemd unit template is provided for operator-managed single-host deployment.
- There is no host enforcement provider. Decisions are observations and recommendations only.
- Direct access to Tetragon's gRPC API is privileged. The optional local proxy filters its client-facing API to `GetVersion` and `GetEvents`, but the proxy process itself still needs access to Tetragon's full API and must be treated as a privileged gateway. Protect its Unix socket and parent directory with OS ownership/modes; remote upstreams still require server-enforced TLS/mTLS and network controls.
- The Tetragon adapter normalizes process exec/exit and selected exact `PROCESS_KPROBE` hook shapes (`do_sys_openat2`, `vfs_read`, `tcp_v4_connect`, `tcp_v6_connect`, `tcp_sendmsg`, and return-only `cap_capable`). Those hooks require a compatible operator-supplied TracingPolicy with unique `sentinel_*` argument labels; all other hooks and incomplete argument shapes remain explicitly unsupported. `tcp_sendmsg` return events retain raw provider identity and report local stack acceptance only. When Tetragon omits `exec_id`, Sentinel preserves the raw event with an explicitly partial PID/start-time identity and a separate domain-separated key; the event is not correlated as a strong process identity. Process arguments and environment variables are omitted from persisted v2 events by default; `--capture-process-arguments` opts into bounded raw-string capture. An optional, version-gated Prometheus poller ingests five pinned v1.8.0 observer/BPF loss counters when the operator enables Tetragon's metrics endpoint.
- SQLite hash chaining detects accidental or unsophisticated edits when checked against the chain. A host administrator can rewrite the database and recompute the chain. There is no external signed anchor or remote evidence service.
- Workload policies must be supplied by the operator. Without a matching profile, events are recorded and no baseline judgment is made.

## Requirements

- Node.js 22.5 or later (`node:sqlite` is used by the evidence ledger).
- Linux is the intended deployment platform for Tetragon JSONL collection. The validator, engine, ledger, and tests also run on Windows with a supported Node.js version.

## Commands

```bash
# Run the test suite
npm test

# See the exact implemented capabilities
node bin/sentinel-runtime.js status

# Validate one v2 event
node bin/sentinel-runtime.js validate-v2 --input event.json

# Ingest a Tetragon JSONL export (requires stable host identity)
node bin/sentinel-runtime.js ingest-tetragon \
  --input /var/log/tetragon/tetragon.log \
  --host-id host-prod-01 \
  --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --db /var/lib/sentinel/runtime.sqlite

# Opt in to bounded raw process-argument capture when incident policy requires it
node bin/sentinel-runtime.js ingest-tetragon \
  --input /var/log/tetragon/tetragon.log \
  --host-id host-prod-01 \
  --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --capture-process-arguments \
  --db /var/lib/sentinel/runtime.sqlite

# Make a fixed export restartable; repeat with --resume after an interrupted run
node bin/sentinel-runtime.js ingest-tetragon \
  --input /srv/tetragon/incident-2026-11-02.jsonl \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --checkpoint-id incident-2026-11-02 --db /var/lib/sentinel/runtime.sqlite
node bin/sentinel-runtime.js ingest-tetragon \
  --input /srv/tetragon/incident-2026-11-02.jsonl \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --checkpoint-id incident-2026-11-02 --resume --db /var/lib/sentinel/runtime.sqlite

# Direct upstream access (privileged); the CLI/systemd production default uses the read-only proxy below.
node bin/sentinel-runtime.js collect-tetragon \
  --address unix:///var/run/tetragon/tetragon.sock \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --expected-node-name worker-17 --db /var/lib/sentinel/runtime.sqlite

# Optional: run this gateway under a dedicated OS identity with Tetragon socket access.
# Give the collector account access only to this 0660 client socket and its parent directory.
node bin/sentinel-runtime.js tetragon-readonly-proxy \
  --upstream-address unix:///var/run/tetragon/tetragon.sock \
  --listen-address unix:///run/sentinel-runtime/tetragon-readonly.sock --socket-mode 0660

# Point the collector at the filtered socket instead of Tetragon's administrative socket.
node bin/sentinel-runtime.js collect-tetragon \
  --address unix:///run/sentinel-runtime/tetragon-readonly.sock \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --expected-node-name worker-17 --db /var/lib/sentinel/runtime.sqlite

# Also poll Tetragon v1.8.0 Prometheus health/loss counters (enable its metrics server first)
node bin/sentinel-runtime.js collect-tetragon \
  --address unix:///var/run/tetragon/tetragon.sock \
  --metrics-url http://127.0.0.1:2112/metrics --metrics-interval-ms 5000 \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --expected-node-name worker-17 --db /var/lib/sentinel/runtime.sqlite

# Remote Tetragon endpoint with server-authenticated TLS (add client cert/key for mTLS)
node bin/sentinel-runtime.js collect-tetragon \
  --address tetragon.internal:54321 --tls-ca /etc/sentinel/tetragon-ca.pem \
  --tls-client-cert /etc/sentinel/collector.pem --tls-client-key /etc/sentinel/collector-key.pem \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)" \
  --expected-node-name worker-17 --db /var/lib/sentinel/runtime.sqlite

# Verify the local evidence hash chain
node bin/sentinel-runtime.js verify-ledger --db /var/lib/sentinel/runtime.sqlite

# Inspect recent ledger records after integrity verification
node bin/sentinel-runtime.js audit-log --db /var/lib/sentinel/runtime.sqlite --limit 1000

# Export immutable, certified evidence bundle with SHA-256 manifest for forensic custody
node bin/sentinel-runtime.js export-custody \
  --db /var/lib/sentinel/runtime.sqlite \
  --out-dir /var/lib/sentinel/exports/incident-2026-11-05 \
  --host-id host-prod-01 --boot-id "$(cat /proc/sys/kernel/random/boot_id)"

# Independently verify cryptographic integrity of an exported custody bundle
node bin/sentinel-runtime.js verify-custody \
  --manifest /var/lib/sentinel/exports/incident-2026-11-05/custody-manifest.json

# Automatically synthesize a hardened WorkloadProfile from an observed JSONL event baseline
node bin/sentinel-runtime.js learn-profile \
  --input /var/log/tetragon/baseline-72h.jsonl \
  --name web-api-service \
  --out /etc/sentinel/profiles/web-api.json

# Run the bounded, deterministic offline ingestion benchmark against a pinned HEAD SHA
node bench/runtime-ingest.js --revision <40-hex-git-sha> --events 2000 --warmup 250 --repetitions 3 --batch-size 128 --output bench/results/SR-INGEST-001.json
node bench/runtime-ingest.js --verify bench/results/SR-INGEST-001.json
```

The sealed benchmark runs, environment, methodology, and limitations are documented in [`docs/benchmarks/SR-INGEST-001.md`](docs/benchmarks/SR-INGEST-001.md). They measure synthetic offline ingestion only, not live sensor capacity or detection quality.

The version-pinned Tetragon gRPC collector has a separate synthetic loopback benchmark in [`docs/benchmarks/SR-GRPC-002.md`](docs/benchmarks/SR-GRPC-002.md). It exercises the real collector-to-ledger path, but does not measure kernel/eBPF generation or production sensor loss.

Manual integration and fixture-generation scripts live under `scripts/manual/` so generic `node --test` discovery cannot execute them. These scripts may change sensor configuration or overwrite generated fixtures; invoke them only by explicit path and in a disposable test environment.

The live `tcp_sendmsg` check is [`scripts/manual/tetragon-kprobe-smoke.js`](scripts/manual/tetragon-kprobe-smoke.js). It requires Tetragon v1.8.0 and privileged local gRPC access; it loads a temporary `Post`-only policy scoped to its own PID and exact Node binary, sends one loopback HTTP request, validates the full v2 result, and deletes the policy.

The live capability check is [`scripts/manual/tetragon-capability-smoke.js`](scripts/manual/tetragon-capability-smoke.js). It uses a temporary `Post`-only policy scoped to a child Node process, triggers `cap_capable` by dropping that child from uid 0 to 65534, validates a `CAP_SETUID` `CAPABILITY_CHECK` v2 event, and verifies policy cleanup.

The non-mutating live proxy check is [`scripts/manual/tetragon-readonly-proxy-smoke.js`](scripts/manual/tetragon-readonly-proxy-smoke.js). It forwards up to five frames through the local gateway, verifies Tetragon v1.8.0, checks that `GetHealth` is denied, and prints only frame hashes and lengths.

The JSONL command consumes an exported file and writes validated v2 objects for supported native events; unsupported records are recorded explicitly. Process arguments and environment variables remain private by default. Without `--checkpoint-id`, it commits bounded transactions of 128 records by default. With a checkpoint ID, each event batch and its byte offset are committed atomically in the same SQLite hash-chain transaction. The ledger also suppresses repeated valid 64-hex `source_event_key` values across batches and process restarts; the first stored projection remains authoritative, and CLI/collector counters report suppressed duplicates. This is local idempotent persistence for equal source keys, not upstream replay, delivery acknowledgement, or exactly-once stream delivery. The source must be a regular, non-symlink file; the runtime fingerprints its resolved path, device, inode, size, and full SHA-256 before ingest, verifies the content again before completion, and refuses resume if the fingerprint differs. `--resume` is required to continue an existing checkpoint; a completed checkpoint is a no-op.

`collect-tetragon` uses the vendored upstream protobuf definitions pinned to Tetragon v1.8.0. It verifies `GetVersion` before subscribing and rejects other versions until their API semantics are reviewed. The default transport is the local Unix socket; TCP requires a CA-verified TLS connection, with client credentials accepted for mTLS. `--expected-node-name` checks the sensor identity before event persistence. Process execution/exit and the selected exact kprobe hook shapes listed above are materialized as full v2 objects; all other native families and incomplete hook records are preserved as explicitly unsupported. Each observed `RateLimitInfo` frame is retained as raw evidence and mapped to `sensor_throttle` with unknown window semantics. Tetragon v1.8.0 does not guarantee that this frame is emitted on the gRPC stream, so absence of a frame is not evidence of zero loss.

Optional `--metrics-url` starts a Prometheus poller only after gRPC has verified the sensor reports v1.8.0. Plain HTTP is restricted to loopback; HTTPS uses verified server TLS and can use a client certificate. The collector hashes exact response bytes, caps responses at 4 MiB, and atomically commits metrics events with the poll checkpoint. It reads five pinned v1.8.0 loss counters: kernel ring-buffer loss, BPF send misses, listener overflow, field-filter drops, and observer queue drops. Counter deltas require the same observed `process_start_time_seconds`; process/counter resets and missing telemetry remain unknown. Aggregation-buffer drops are `NOT_APPLICABLE` while Sentinel requests no Tetragon aggregation. If aggregation is enabled later, that domain needs a counter before it can be reported as measured. Sentinel's gRPC gap, local queue, parser, and storage domains are not inferred from this endpoint. The non-Kubernetes Tetragon metrics server is disabled by default; enable it on loopback before using this option. Both `host-id` and `boot-id` are required trusted values from the monitored host; the runtime does not guess them from the collector's machine.


## Sentinel Cloud connection (optional)

Sentinel Runtime can report incidents and send heartbeats to Sentinel Cloud when a `snt_rt_` API key is configured. All cloud features are optional Ã¢â‚¬â€ the engine operates fully offline and air-gapped without them.

### Prerequisites

- An active Sentinel Production subscription (annual plan).
- A Runtime host token generated from the Sentinel Cloud admin panel (Runtime Fleet tab).

### Configuration

Set the environment variable before starting the runtime daemon:

```bash
export SENTINEL_RUNTIME_API_KEY="snt_rt_<your-token>"
export SENTINEL_RUNTIME_API_URL="https://your-sentinel-cloud-instance.com"  # optional override
```

Or pass it at startup:

```bash
SENTINEL_RUNTIME_API_KEY="snt_rt_..." node bin/sentinel-runtime.js ingest-tetragon ...
```

### Token isolation

Runtime tokens (`snt_rt_` prefix) are stored and authenticated separately from CLI tokens (`sntl_`). A runtime token cannot authenticate on scan, billing, or admin endpoints. A CLI token is explicitly rejected on runtime endpoints.

### Offline resilience

If Sentinel Cloud is unreachable, the cloud client buffers the incident envelope and continues. The local engine and SQLite evidence ledger continue to operate normally. Reconnection is automatic on the next report cycle.

### Module usage

```js
const { SentinelRuntimeCloudClient } = require('./src/cloud/cloud-client');

const client = new SentinelRuntimeCloudClient({
  apiKey: process.env.SENTINEL_RUNTIME_API_KEY,
  apiUrl: process.env.SENTINEL_RUNTIME_API_URL,
});

await client.sendHeartbeat({ hostId: 'host-prod-01', status: 'healthy' });
await client.sendIncidentEnvelope({ hostId: 'host-prod-01', incidents: [...] });
```
## Workload profile format

The engine API accepts profiles using exact absolute binary paths or SHA-256 digests. Bare executable names such as `node` are rejected. Network entries can be exact hostnames, `host:port`, or IPv4 CIDRs.

```js
const { WorkloadProfile, BehavioralSequenceEngine } = require('sentinel-runtime');

const engine = new BehavioralSequenceEngine();
engine.registerProfile('payments-api', new WorkloadProfile({
  allowedBinaries: ['/usr/bin/node'],
  allowedBinaryDigests: ['<64-hex-sha256>'],
  allowedReadPrefixes: ['/app', '/etc/ssl/certs'],
  allowedDestinations: ['payments.internal:443', '10.40.0.0/16']
}));
```

Treat profiles as security policy: generate them from trusted deployment manifests and pin binary digests where practical. Path matching is lexical because a remote sensor path cannot be resolved with the collector's filesystem; it does not certify symlink targets.

## Repository map

```text
bin/sentinel-runtime.js          CLI
src/engine.js                    bounded deterministic correlation
src/profiler.js                  workload baseline rules
src/evidence.js                  local SQLite evidence hash chain
src/ingest/jsonl.js               bounded JSONL framer and duplicate-key scanner
src/adapters/tetragon-json.js    Tetragon JSON adapter (exec/exit and selected kprobes)
src/contracts/materialize-tetragon-v2.js  Native Tetragon-to-v2 mapping and validation
src/contracts/                   v1/v2 validators, materializer, and event-key profiles
schemas/                         event contract schemas
test/                            contract, integration, and hardening tests
scripts/manual/                  explicit live sensor checks and fixture generation; never auto-run as tests
docs/specs/                      provenance and architecture specifications
docs/IMPLEMENTATION_STATUS.md    implemented scope and production gates
```

## Current validation & release posture

This repository is an early-stage, observe-only runtime published as an **unapproved development candidate (Phase 001C)**. It is **not** enterprise-ready, production-certified, or fully validated:

- **Test suite results:** 226 total tests ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â **224 passed, 2 skipped** (Linux-only tests for TLS client key permissions and read-only Unix proxy) on Windows.
- **Linux execution status:** Under the local host environment, WSL2 invokes Windows `node.exe` through binary interop (`process.platform === 'win32'`); it does not constitute native Linux validation. Native Linux validation (`process.platform === 'linux'`) remains pending native guest Node.js provisioning or GitHub Actions CI execution.
- **Contract status:** Event Contract v1 is frozen (`8c58cd96...`). Event Contract v2 is an unapproved candidate (`40ff2d68...`). Profile D (`RAW_PARTIAL_PROCESS_EVENT`) remains `PROVISIONAL ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â REQUIRES NORMATIVE REVIEW`. The provenance matrix status is `REOPENED ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â BLOCKED`.
- **Sensor telemetry:** Exploratory observations (`tcp_sendmsg` and `cap_capable` on one Tetragon v1.8.0 WSL2 kernel) are micro-benchmark checks under `scripts/manual/` and do NOT constitute formal L3 sensor evidence. Phases 001D (live sensor validation) and 001E (durable queue architecture) are not started and remain unauthorized.
- **Deployment & Gateway limits:** The read-only proxy filters downstream RPCs to `GetVersion` and `GetEvents` while preserving exact upstream protobuf bytes, but the proxy process itself requires privileged upstream socket access. Installation compatibility of the systemd unit templates across production Linux distributions is not yet established. Enterprise rollout still requires managed install/upgrade, fleet health monitoring, external ledger signing/anchoring, key custody, tenant RBAC, and signed policy distribution. Active enforcement is not implemented.
- **License:** Licensed under Business Source License 1.1 (BUSL-1.1).
