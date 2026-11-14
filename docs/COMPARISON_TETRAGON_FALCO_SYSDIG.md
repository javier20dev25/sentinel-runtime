# Comparative Architecture Study: Sentinel Runtime vs. Cilium Tetragon, Falco & Sysdig

## Abstract

Runtime security in Linux and Kubernetes environments has evolved rapidly from user-space polling (`auditd`) to in-kernel instrumentation via eBPF. However, engineering teams face significant architectural tradeoffs between **kernel observability sensors**, **syscall rule engines**, and **cryptographically verifiable evidence ledgers**.

This document outlines the comparative positioning of **Sentinel Runtime** alongside three industry references: **Cilium Tetragon**, **Falco (CNCF)**, and **Sysdig Secure**.

---

## 1. Executive Matrix

| Architectural Dimension | Cilium Tetragon | Falco (CNCF) | Sysdig Secure | Sentinel Runtime |
|---|---|---|---|---|
| **Core Technology** | In-kernel eBPF kprobes/tracepoints | Kernel module or modern eBPF driver | Host Agent + Cloud SaaS platform | eBPF event ingestion + State Machine |
| **Primary Design Goal** | Low-overhead kernel observation & filter | Heuristic syscall rule evaluation | Compliance, vulnerability & runtime suite | Tamper-evident evidence & process lineage |
| **Telemetry Format** | Protobuf / JSON (sensor-specific) | JSON / gRPC event stream | Proprietary cloud telemetry | Strict Event Contract v2 candidate validation (v1 validator retained) |
| **Process Tracking** | Sensor-scoped `exec_id` | Syscall-correlated PID tracking | Agent container namespace tracking | Compound `host_id + boot_id + exec_id`, with PID/start-time fallback |
| **PID Recycling Defense** | In-kernel execution lifetime | Vulnerable to fast PID reuse in containers | Correlated by user-space agent | Compound host + boot + exec identity |
| **Loss Transparency** | BPF ring buffer loss counters | Drop counters logged upon buffer fill | Aggregated drops reported via SaaS | Provenance required for loss counter deltas |
| **Forensic Evidence** | Ephemeral system logs / stdout | Ephemeral alert streams / webhooks | Centralized cloud retention | Local tamper-evident SHA-256 SQLite chain |
| **Air-Gap Capability** | Fully autonomous | Fully autonomous | Requires persistent SaaS connection | Fully autonomous & air-gap capable |
| **Code-to-Runtime Link** | None (pure runtime) | None (pure runtime) | SaaS repository integration | No shipped code-to-runtime link |

---

## 2. In-Depth Comparative Analysis

### 2.1 Cilium Tetragon: The In-Kernel Sensor

**Strengths:**
- Unmatched kernel-level execution and kprobe visibility.
- Minimal CPU overhead due to in-kernel filtering before passing events to user space.
- Native Kubernetes metadata enrichment and Cilium CNI integration.
- Ability to perform in-kernel synchronous blocking (`sigkill`) via eBPF on supported kernels.

**Architectural Gaps addressed by Sentinel Runtime:**
- **No Evidence Immutability:** Tetragon emits a stream of events to stdout or gRPC. If an attacker gains host root access, syslog or JSON files can be modified or deleted without detection.
- **Contract Ambiguity:** Upstream Tetragon protobuf definitions evolve across versions; without strict schema validation, downstream consumers can silently misinterpret fields or miss unknown drops.
- **Sentinel Runtime Role:** Sentinel Runtime acts as a **verifiable arbitration consumer** above Tetragon. It runs Tetragon as a pinned v1.8.0 sensor, consumes events via a read-only gRPC proxy, validates them against the Event Contract v2 candidate, and commits them to a hash-chained SQLite ledger.

---

### 2.2 Falco: The Rule-Based Syscall Engine

**Strengths:**
- Broad community ruleset covering common MITRE ATT&CK techniques.
- Flexible rule syntax based on syscall arguments and container metadata.
- Large ecosystem of notification outputs (Slack, Webhooks, SIEM).

**Architectural Gaps addressed by Sentinel Runtime:**
- **PID Reuse Vulnerabilities:** Falco tracks processes predominantly through Linux PIDs. In high-density container environments where hundreds of short-lived processes are spawned per second, PID recycling can lead to race conditions and inaccurate process lineage attribution.
- **Syscall Noise:** Syscall-level evaluation often yields high false positive rates, requiring extensive manual tuning of exception lists.
- **Sentinel Runtime Role:** Sentinel Runtime does not rely solely on transient PIDs. It uses a compound identity: `host_id + boot_id + exec_id`, with an explicit PID/start-time fallback when the sensor omits `exec_id`. This reduces false attribution caused by process recycling, but it is not infallible.

---

### 2.3 Sysdig Secure: The Commercial SaaS Platform

**Strengths:**
- End-to-end commercial suite combining image scanning, CSPM, and runtime detection.
- Enterprise management dashboard, SSO, and compliance reporting frameworks (SOC 2, PCI-DSS).

**Architectural Gaps addressed by Sentinel Runtime:**
- **SaaS Dependency & Air-Gap Incompatibility:** Sysdig requires outbound Internet connectivity to the Sysdig backend. In highly restricted environments (defense, banking, isolated OT/ICS networks), SaaS dependencies are non-viable.
- **Proprietary Custody:** Evidence is stored in proprietary cloud databases, making independent on-premises cryptographic verification complex.
- **Sentinel Runtime Role:** Sentinel Runtime is designed to be **air-gap capable**. Evidence is stored locally in a tamper-evident SQLite ledger with SHA-256 hash chaining. Connection to Sentinel Cloud is strictly optional and outbound-only: heartbeats and bounded incident receipts may leave the host, and this release has no Cloud-to-host task channel. The local chain can detect many edits when a trusted head is available, but a host administrator can rewrite it.

---

## 3. Recommended Deployment Topology

Sentinel Runtime does not compete to replace Tetragon; **it adds validation, correlation, and local evidence custody above the sensor**:

```
+-------------------------------------------------------------------+
| Linux Host / Kubernetes Worker Node                               |
|                                                                   |
|   +--------------------------+                                    |
|   |   Linux Kernel (eBPF)    |                                    |
|   +------------+-------------+                                    |
|                |                                                  |
|   +------------v-------------+                                    |
|   |  Cilium Tetragon v1.8    |  (Kernel Sensor & Filtering)       |
|   +------------+-------------+                                    |
|                | Unix Domain Socket                               |
|   +------------v-------------+                                    |
|   |  Sentinel Read-Only Proxy|  (Enforces GetEvents / GetVersion) |
|   +------------+-------------+                                    |
|                |                                                  |
|   +------------v----------------------------------------------+   |
|   |                 Sentinel Runtime Engine                   |   |
|   |                                                           |   |
|   |  1. Event Contract v2 Validation (Ajv Schema Strictness)  |   |
|   |  2. Process Lineage & PID Reuse Defense (exec_id hash)    |   |
|   |  3. Behavioral Allowlist & Deviation Detection            |   |
|   |  4. Tamper-Evident SHA-256 Hash-Chained SQLite Ledger  |   |
|   +---------------------------+-------------------------------+   |
|                               |                                   |
+-------------------------------|-----------------------------------+
                                | (Optional: TLS / snt_rt_ Token)
                                v
               +----------------------------------+
               |      Sentinel Cloud Fleet        |
               | (Incident Analytics & Telemetry) |
               +----------------------------------+
```

---

## 4. Conclusion

For infrastructure operators requiring:
1. **Tamper-Evident Local Evidence** that detects many edits when a trusted head is available; a root administrator can still rewrite the ledger,
2. **Compound Process Lineage** that resists PID reuse through `host_id + boot_id + exec_id`, with an explicit fallback when `exec_id` is unavailable,
3. **Strict Event Contract v2 Candidate Validation** with domain-separated event identity keys,
4. **Autonomous Air-Gap Execution** with no mandatory SaaS dependency,

**Sentinel Runtime** provides the verification, custody, and contract layer that raw eBPF sensors and alerting engines omit.