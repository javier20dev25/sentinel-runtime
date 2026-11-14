# Sentinel Runtime

[![CI](https://github.com/javier20dev25/sentinel-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/javier20dev25/sentinel-runtime/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22.5.0-brightgreen)](package.json)

Sentinel Runtime is an early-stage Linux runtime telemetry and evidence service. It consumes selected events from Cilium Tetragon, validates and normalizes supported event shapes, correlates process activity, records a local hash-chained ledger, and can send bounded incident receipts to Sentinel Cloud.

> **Release posture:** development candidate. This repository is not a certified EDR/MDR product. Runtime is observe-only: it does not block, kill, quarantine, or retaliate against an attacker. Event Contract v2 is still a candidate. Read the implementation status and threat model before deployment.

## Architecture

~~~mermaid
flowchart LR
  subgraph Host["Customer Linux host"]
    T["Tetragon eBPF sensor"]
    P["Read-only gRPC proxy<br/>GetVersion + GetEvents"]
    R["Sentinel Runtime<br/>unprivileged systemd account"]
    V["Normalize + validate<br/>bounded event queue"]
    L[("SQLite hash-chain ledger")]
    H["Health and loss metrics"]
    T --> P --> R --> V --> L
    V --> H
    R -->|"optional outbound HTTPS"| C
    L -->|"bounded incident receipts"| C
  end
  C["Sentinel Cloud"]
  A["Local unprivileged attacker"] -. "cannot write a root-owned install" .-> R
  K["root / kernel compromise"] -. "outside the agent trust boundary" .-> T
~~~

The proxy separates the collector from Tetragon’s administrative RPC surface and permits one active event stream for the collector. The collector is constrained by systemd, has no Linux capabilities, and writes only to its private state directory. Both services have CPU, memory, task, and file-descriptor ceilings. The installation and configuration trees must be root-owned and non-writable by group or other users. The local SQLite chain detects some edits when verified; it is not immutable against a host administrator.

## What is implemented

- Tetragon v1.8.0 gRPC collection and bounded JSONL ingestion for documented native events and selected kprobes.
- The default gRPC request asks for core process events only. Policy-driven event families are opt-in by exact `--tetragon-policy-name`; this reduces unrelated probe traffic without claiming that Tetragon generated no other events or that upstream drops are impossible.
- Strict Event Contract v2 candidate validation, raw provider provenance, source-time preservation, and explicit unsupported/rejected records.
- Bounded in-memory event queues and Cloud incident outbox; overload is surfaced as degraded observability instead of being reported as healthy.
- Read-only proxy limits all clients to one active Tetragon event stream and eight concurrent gRPC streams per client connection; the systemd templates bound service CPU, memory, tasks, and open files.
- Process correlation, deterministic profile checks, sequence rules, and statistical anomaly signals. A finding is an observation or hypothesis, not proof that a file was read, a connection succeeded, or data left the host.
- SQLite evidence ledger with local SHA-256 hash chaining and a verifier.
- Optional outbound Cloud heartbeats and incident receipts. This release has no Cloud-to-host task channel.
- Linux systemd templates for separate collector and read-only Tetragon proxy accounts.

## Self-protection: controls and limits

~~~mermaid
flowchart TD
  E["Tetragon event stream"] --> Q["Bounded queue"]
  Q -->|capacity exceeded| D["Record loss / mark observability DEGRADED"]
  Q -->|within limits| DB["Commit to local hash chain"]
  DB --> OUT["Bounded Cloud incident outbox"]
  OUT -->|Cloud unavailable| LOCAL["Keep local evidence; report delivery failure"]
  S["Runtime process exits unexpectedly"] --> SD["systemd Restart=on-failure"]
  SD --> RESUME["Reconnect to Tetragon; record stream gap as UNKNOWN"]
  ROOT["root or kernel attacker"] --> LIMIT["Can still stop/replace the agent, sensor, key, or local ledger"]
  LIMIT --> EXT["Requires an independent external heartbeat and evidence anchor"]
~~~

| Threat | Current control | What it does not prove |
|---|---|---|
| Unprivileged user replaces Runtime files | Root-owned install with no group/other write; systemd read-only filesystem | A root user can change the install or service policy |
| Collector or local socket client abuses Tetragon API | Separate proxy registers only GetVersion and GetEvents; one active GetEvents stream; gRPC streams capped; dedicated socket group | The proxy itself still has upstream sensor access |
| Event flood / large frame / resource exhaustion | Core-event default; policy event families are filtered by explicit policy name; 16 MiB gRPC limit, bounded queue, and systemd CPU/memory/task/file limits; loss makes coverage degraded | Filtering does not disable Tetragon probes or recover upstream drops; hitting the hard memory limit can restart the service |
| Cloud outage / incident burst | Bounded outbox with local ledger as primary record | Local disk usage is not capped; retention and anchoring remain operator work |
| Runtime process crash or SIGKILL | systemd restart policy | It cannot report its own death while stopped; Cloud needs a stale-heartbeat monitor |
| Compromised Cloud account | Runtime exposes no inbound Cloud-to-host task channel in this release | The host token authenticates outbound Runtime requests; it does not attest the host kernel or Runtime binary |
| Root/kernel compromise | No in-agent prevention claim | Root can alter Tetragon, Runtime, keys, service units, and local evidence |

The current service template is observe-only. Runtime does not “attack back.” Its defensive response is to preserve evidence, expose loss and health state, request bounded read-only inspection where enabled, and leave containment decisions to an independently authorized response system.

## Lab evidence

The reproducible lab and its limits are in [SR-RT-001 Local Resilience Lab](docs/labs/SR-RT-001-LOCAL-RESILIENCE.md).

- A bounded WSL2 stress exercise generated measurable Tetragon observer-overflow and queue-loss counter increases. Runtime recorded loss evidence and marked observability degraded.
- The exact synthetic child processes from that exercise were not reliably matched in the Runtime ledger. This run does **not** prove the agent detected every generated action.
- A controlled SIGKILL of the Runtime main process was followed by systemd restart and a valid local ledger check. Cloud heartbeat delivery after that restart timed out, so Cloud recovery was not verified in the same exercise.
- The lab install originally had mode 0777. It was corrected to root-owned, non-writable modes; the service account could no longer write its install tree. This is a deployment finding, not an automatic tamper alarm in Runtime.
- The proxy stream-limit regression test passed on Linux: a second `GetEvents` stream is rejected with `RESOURCE_EXHAUSTED`, and the slot becomes available after the first stream disconnects. Deployment-specific testing remains required for each customer systemd/Tetragon setup.
- Follow-up checks still found no Runtime record for a controlled shell invocation whose reported process name differed from the executable (564 execution records, maximum ledger sequence 21,508 before and after). Tetragon's exporter showed cumulative execution metrics that cannot be attributed to that invocation. End-to-end execution capture remains an open gate; the lab does not claim that the process was detected.

These are observations from one WSL2 laboratory, not a production certification or a benchmark against other products.

## Run and inspect

Requirements: Linux for live Tetragon collection, Node.js 22.5 or later, and Tetragon v1.8.0. For the systemd setup, follow [Linux deployment](docs/DEPLOYMENT_SYSTEMD.md). Packaging notes are in [the systemd directory](packaging/systemd/README.md).

~~~sh
npm ci
npm test
node bin/sentinel-runtime.js status
node bin/sentinel-runtime.js verify-ledger --db /var/lib/sentinel-runtime/runtime.sqlite
~~~

For the explicitly bounded local resilience exercise, see its guide and the guarded runner in scripts/manual. Do not run it on a production host.

## Documentation map

| Area | Document |
|---|---|
| Current code and validation status | [Implementation status](docs/IMPLEMENTATION_STATUS.md) |
| Security boundary and self-protection | [Runtime self-protection threat model](docs/threat-model/RUNTIME_SELF_PROTECTION.md) |
| Linux installation, permissions, systemd | [Deployment guide](docs/DEPLOYMENT_SYSTEMD.md) |
| Systemd unit packaging | [Packaging notes](packaging/systemd/README.md) |
| Specifications, reports, and operational docs | [Documentation index](docs/README.md) |
| Event source mappings | [Tetragon v1.8.0 field mapping](docs/specs/TETRAGON_V1_8_0_FIELD_MAPPING.md) |
| Local resilience exercise | [SR-RT-001 lab report](docs/labs/SR-RT-001-LOCAL-RESILIENCE.md) |

## Open enterprise gates

- Validate the installer, file ownership, upgrades, and systemd sandbox across supported Linux distributions.
- Demonstrate event capture and end-to-end latency under load with quantified loss and no unreported gaps.
- Add remote signed ledger checkpoints, retention controls, disk-exhaustion handling, and independent heartbeat alerting.
- Validate and freeze Event Contract v2 and its producer implementations.
- Define signed policy updates, key enrollment/rotation, tenant isolation, and incident response authorization.
- Keep host enforcement disabled until separate safety, authorization, rollback, and failure-mode reviews pass.

Sentinel Runtime is licensed under BUSL-1.1. Its present code and lab evidence should not be represented as a managed incident-response service or as prevention against a privileged host compromise.
