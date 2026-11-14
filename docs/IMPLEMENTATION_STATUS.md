# Sentinel Runtime implementation status

**Review date:** 2026-11-14
**Release status:** development candidate; not production-certified
**Authority:** source and tests describe implementation. Specs and historical reports do not establish shipped behavior.

## Implemented

- Observe-only Node.js CLI and library for Linux runtime telemetry.
- Tetragon v1.8.0 gRPC collector with explicit host/workload event subscriptions, pinned protobuf definitions, bounded message sizes, bounded event/byte queue, event validation, and explicit stream-gap state.
- JSONL ingestion with bounded frame size, UTF-8 validation, duplicate-key rejection, immutable-source fingerprinting, optional atomic resume checkpoints, and explicit unsupported-event records.
- Supported Tetragon process lifecycle records and selected, explicitly labeled kprobe shapes. Incomplete or unsupported shapes are not guessed.
- Event Contract v2 candidate materializer and validator. Native open hooks preserve raw absolute, relative, or empty pathname operands and dirfd. The candidate schema is not frozen.
- Process correlation, allowlist checks, sequence detection, and rate anomaly signals. Profiles are operator-supplied; event names and rule labels alone do not prove malicious intent.
- SQLite local evidence hash chain with verification. A privileged host administrator can rewrite the database and recompute a local chain.
- Bounded Cloud incident outbox, optional outbound heartbeat/publishing, and a fixed L0 read-only investigation task interface. Task execution does not use shell or arbitrary commands.
- Linux systemd unit templates that separate the collector from a read-only Tetragon proxy. The collector has no Linux capabilities and writes only to its state directory under the unit’s filesystem view.
- SQLite temporary-path configuration needed under ProtectSystem=strict.

## Validated in this review

- Full Node test suite on Windows under the required runtime guard: 304 total, 299 passed, 5 skipped, 0 failed. Skips are Linux-only process metadata (2), private-key permissions (1), and proxy integration (2). Focused Linux collector, Cloud client, and proxy suites passed 29/29 in WSL2.
- Focused adapter/materializer/schema/engine regression suites passed after raw relative-path support was added.
- Local WSL2 service recovery: a controlled SIGKILL of the Runtime process was followed by a systemd restart and a valid local ledger check across 6,877 records.
- Local WSL2 permissions: the active install tree was found world-writable, corrected, and then confirmed non-writable by the sentinel-runtime account. A temporary 203/EXEC failure during mode normalization was corrected; details are in the [lab report](labs/SR-RT-001-LOCAL-RESILIENCE.md).
- A bounded event-flood exercise increased Tetragon observer-overflow/queue-loss counters and Runtime recorded EVENT_LOSS. Exact matching of every generated child event was not established.
- The updated proxy rejected a second live `GetEvents` subscription with `RESOURCE_EXHAUSTED` and accepted a replacement after cancellation. Under bounded load, the updated collector stopped cleanly in about 11 seconds, recorded a 158-event / 104,553-byte shutdown-queue discard lower bound, and restarted with observability degraded/unknown. Active WSL2 systemd units reported their configured resource ceilings.
- A controlled benign `dash` execution with a deceptive `argv[0]` did not add a `PROCESS_EXEC` ledger record (564 records and maximum sequence 21,508 before and after). Exporter execution counters were cumulative and could not be mapped to this invocation; end-to-end execution capture remains unresolved.
- Cloud heartbeat after process restart timed out in that run. Cloud-side heartbeat recovery is not validated.

## Not implemented or not proven

- No kernel-level self-protection, BPF link/policy integrity attestation, tamper-resistant host root of trust, or protection from root/kernel compromise.
- No automatic containment, process kill, network isolation, or counterattack. Current response mode is observe-only.
- No independent local watchdog that can attest the Runtime process while it is stopped.
- No Cloud stale-heartbeat SLA verified in this lab.
- No remote signed ledger anchor, immutable remote storage, or reliable host non-repudiation.
- No built-in ledger retention, disk quota, or disk-exhaustion guarantee.
- No cross-distribution production certification, managed installer, signed upgrade system, or fleet policy management.
- No guarantee that gRPC events missed during disconnect can be replayed; gaps remain unknown without provider replay.
- No independent proof that the local sensor, kernel, agent credential, or Runtime binary was uncompromised when an event was produced.

## Current release gates

1. Enforce root-owned non-writable installation modes through a supported installer and upgrade path.
2. Validate systemd sandbox behavior on supported native Linux distributions.
3. Resolve the reproducible `PROCESS_EXEC` sensor-to-ledger gap; then repeat overload/deception testing and prove exact event-to-lab-process matches, latency, and loss accounting.
4. Define ledger retention, disk-exhaustion behavior, signed external checkpoints, and Cloud stale-agent alerting.
5. Complete independent Event Contract v2 review and freeze only after producer conformance.
6. Review read-only task authorization, privacy, and tenant scoping with the Cloud service owner.
7. Keep host enforcement disabled until separate policy authorization, rollback, and failure-mode reviews pass.

See [Runtime self-protection threat model](threat-model/RUNTIME_SELF_PROTECTION.md), [Linux deployment](DEPLOYMENT_SYSTEMD.md), and [documentation index](README.md).
