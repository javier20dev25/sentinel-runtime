# Sentinel Runtime self-protection threat model

**Status:** current implementation boundary and lab review
**Review date:** 2026-11-14
**Scope:** local Linux Runtime process, Tetragon proxy boundary, event pipeline, host-installed files, outbound Cloud heartbeat and incident receipt client

## Security objective

A low-privilege attacker should not be able to replace Runtime files, use the collector to administer Tetragon, or exhaust unbounded in-memory queues without Sentinel exposing degraded coverage. Runtime should preserve local evidence across ordinary process failures and report only what its telemetry supports.

Runtime is not a kernel reference monitor. It cannot protect itself from root, a compromised kernel, or an attacker who controls the Tetragon daemon or its policies. It does not retaliate against an attacker.

## Threat model

| Attacker capability | Defensive control in this build | Evidence / limit |
|---|---|---|
| Unprivileged local account | Run collector as dedicated non-root user; no Linux capabilities; systemd NoNewPrivileges and strict filesystem view; installation/configuration must be root-owned and non-writable by group/other | WSL2 lab found the active install tree at 0777. It was corrected; the service account then failed write checks for the install directory and Runtime code. The permission check is an operator/deployment control, not a Runtime tamper detector. |
| Abuse of collector-to-Tetragon connection or local socket | Separate proxy process/account; downstream gRPC surface registers only GetVersion and GetEvents; one active GetEvents stream; eight concurrent gRPC streams maximum | The proxy still has the site-specific upstream socket access needed to read from Tetragon. A proxy compromise inherits that access. |
| Flood supported event stream | Core-event request by default; probe event families require explicit policy names; gRPC messages capped at 16 MiB; collector queue bounded to 512 events / 64 MiB by default; collector and proxy have systemd CPU/memory/task/file limits; loss is surfaced as degraded observability | Policy filtering does not disable upstream probes or recover Tetragon drops. A cgroup memory limit can restart the service. Local SQLite has no built-in retention or disk quota. |
| Compromised Cloud account | Runtime exposes no inbound Cloud-to-host task channel in this release | The host token authenticates outbound Runtime requests; it does not attest the host, kernel, installed binary, or local ledger to Cloud. |
| Kill or crash the Runtime process | systemd Restart=on-failure restarts unexpected process failure; collector records a new stream epoch and marks the prior stream gap unknown | A process cannot report its own SIGKILL. Runtime has no independent local watchdog or signed health anchor. Cloud must independently alert on stale heartbeat. |
| Root or kernel compromise | Report measured loss and local ledger verification results; use OS service isolation to reduce attack surface | Root can stop or replace Runtime, alter systemd and Tetragon configuration, read host credentials, tamper with the kernel, or rewrite the local hash chain. External anchoring and separate control plane are required. |

## Implemented defenses

### Service isolation

The systemd collector template uses a dedicated unprivileged user, empty CapabilityBoundingSet, NoNewPrivileges, ProtectSystem=strict, protected kernel surfaces, restricted address families, and bounded CPU/memory/tasks/file descriptors. Runtime code and configuration are read-only in the unit; only /var/lib/sentinel-runtime is writable for the ledger and SQLite temporary files. The proxy has a distinct account, one active upstream event subscription, resource ceilings, and the Runtime user receives only access to the client-facing Unix socket.

At install time, /opt/sentinel-runtime and /etc/sentinel-runtime must be root-owned and not group/world writable. A writable installation directory lets another local user replace files even when individual files are read-only. Audit permissions after every install or upgrade.

### Bounded ingestion and loss reporting

The gRPC client caps individual messages at 16 MiB. Collector event and byte queues are bounded. Queue overflow is counted and transitions observability to degraded; a degraded Runtime must not claim complete coverage. Cloud delivery uses a separate bounded outbox so network failure cannot grow that queue without limit. SQLite remains the durable local evidence store, not a retention policy.

### Cloud channel boundary

In this master release, Runtime sends heartbeats and incident receipts to Cloud. No Cloud-to-host task channel is shipped, so Cloud cannot use Runtime to request host inspection or response actions. The outbound client does not attest the kernel or Runtime binary; receipts remain agent-reported evidence.

### Evidence and recovery

The local ledger verifies a SHA-256 record chain. This detects many accidental or direct edits when a verifier has a trusted head, but a privileged attacker can rewrite the database and recompute the chain. No remote signed anchor is implemented. Tetragon gRPC does not provide replay from a Runtime checkpoint; a reconnect is therefore a gap with unknown completeness.

## Observed local validation

The separate [SR-RT-001 lab report](../labs/SR-RT-001-LOCAL-RESILIENCE.md) records the 2026-11-13 and 2026-11-14 WSL2 tests. The material observations are:

- A bounded event-flood workload increased Tetragon observer-overflow and queue-loss counters. Runtime wrote EVENT_LOSS records and marked observability degraded.
- The flood run did not find reliable event-key/PID matches for every synthetic child process, so do not state that the attack sequence was fully detected. A later controlled run that waited for `STREAM_CONNECTED` matched five marked executions; the earlier mismatch is attributed to test sequencing.
- After a controlled SIGKILL of the Runtime main process, systemd restarted it and the local ledger verified valid. The post-restart Cloud heartbeat timed out in that run.
- The active install tree was found world-writable and corrected to root-owned, non-writable permissions. That exposed a real deployment weakness. The deployment guide now requires a permission audit.
- The live proxy test verifies that a second event subscription receives `RESOURCE_EXHAUSTED` and that cancellation releases the single stream slot. The active WSL2 systemd units reported the configured memory, CPU, task, descriptor, and OOM limits; this does not certify enforcement on other distributions.
- Under a bounded 5,000-read / 16-child lab load, the updated collector stopped cleanly in about 11 seconds, recorded 158 queued events and 104,553 bytes as a discard lower bound, and marked the stream gap degraded/unknown. This is explicit loss accounting, not complete telemetry recovery.
- A follow-up on the published `master` build waited for `STREAM_CONNECTED` before starting five marked executions with a deceptive `argv[0]`. The ledger captured those children (PIDs 11717-11721) and 13 `PROCESS_EXEC` records in the window, with `rejected: 0` and a shutdown-loss lower bound of 2 events (1,976 bytes). This resolves the earlier sensor-to-Runtime reconciliation discrepancy as test sequencing, but it does not prove capture before connection, exact argument boundaries, or complete execution visibility. `--capture-process-arguments` yields `RAW_STRING_ONLY` with `argv: null`.
- The published `master` build rejects `FILE_OPEN_RESULT` records whose open operand is relative, because the materializer requires an absolute pathname. The unpublished feature branch adds `path_form` and `dirfd` handling and was verified live (8 relative records persisted with `path_form: RELATIVE`, `rejected: 0`). Relative-path open evidence must not be treated as covered on `master` until that correction is ported and revalidated.

## Response behavior

Runtime's current host response is **observe, record, degrade, and report**. The systemd manager may restart a crashed process. This master release only publishes heartbeats and incident receipts; it has no inbound task interface. Runtime does not kill, isolate, block, or counterattack an adversary. Any future enforcement must be a separate, explicitly authorized, independently tested capability.

## Remaining security gates

1. Add a supported installer/upgrade path that enforces root ownership and rejects writable installation trees.
2. Add signed remote ledger checkpoints and explicit disk-retention/exhaustion handling.
3. Add an independent heartbeat watchdog and validate Cloud behavior for process death and prolonged host isolation.
4. Extend live execution validation beyond WSL2: prove capture completeness, argument fidelity, and loss thresholds on native supported Linux distributions. Port and validate the relative-path correction before relying on relative-path open evidence.
5. Add supported policy provenance and sensor-policy drift checks; the current agent does not cryptographically attest loaded Tetragon policies.
6. Before adding Cloud-to-host tasks, review authorization and data minimization with the Cloud service owner.
