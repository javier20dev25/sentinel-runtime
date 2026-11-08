# Sentinel Compliance & Standards Readiness Matrix (V1)
**Document ID:** MAT-CMP-2026-V1  
**Status:** APPROVED / NORMATIVE  
**Scope:** Regulatory, Legal, and Forensic Audit Compliance for Sentinel Cloud & Sentinel Runtime  

---

## 1. Executive Summary

This matrix outlines how the Sentinel ecosystem (Sentinel Cloud + Sentinel Runtime) satisfies technical and operational requirements across major international security, privacy, and incident management standards.

It provides enterprise customers and auditors with verifiable evidence mappings to justify deployment in regulated environments (SOC 2, ISO 27001, HIPAA, PCI-DSS, FedRAMP).

---

## 2. Standards Cross-Reference Matrix

| Standard & Control ID | Control Description | Sentinel Technical Implementation | Implementation Status |
| :--- | :--- | :--- | :--- |
| **ISO/IEC 27001:2022 A.5.24** | Information security incident management planning and preparation | Formal incident schema, Universal Investigation Case File v2, automated classification taxonomy | **FULL COMPLIANCE** |
| **ISO/IEC 27001:2022 A.5.28** | Collection of digital evidence | Local SQLite SHA-256 chained ledger, eBPF tracepoint capture, signed API envelope ingestion | **FULL COMPLIANCE** |
| **ISO/IEC 27001:2022 A.8.16** | Monitoring activities | Kernel eBPF (Tetragon) continuous observation of process, socket, and file activity with drop counters | **FULL COMPLIANCE** |
| **ISO/IEC 27035-1 / 27035-2** | Incident management principles & process | 4-Tier Case File architecture (Executive Summary, Security Investigation, Evidence Proof, Raw JSON) | **FULL COMPLIANCE** |
| **ISO/IEC 27037:2012** | Digital evidence identification, collection, acquisition, preservation | SHA-256 evidence record hashing, client-side secret redaction, immutable storage in Cloud Evidence Vault | **FULL COMPLIANCE** |
| **ISO/IEC 27041:2015** | Method validation in digital investigations | Deterministic FSM detection rules, reproducible adversarial test scripts (`audit-adversarial-scenarios.js`) | **FULL COMPLIANCE** |
| **ISO/IEC 27042:2015** | Analysis and interpretation of digital evidence | Mandatory Epistemic Boundary Audit (Observed Facts separated from Unconfirmed Inferences) | **FULL COMPLIANCE** |
| **NIST SP 800-61 Rev. 3** | Incident Response Recommendations | Phase-aligned lifecycle: Detection $\to$ Ingestion $\to$ Triage $\to$ Epistemic Audit $\to$ Containment Gate | **FULL COMPLIANCE** |
| **NIST SP 800-86** | Integrating Forensic Techniques into IR | Strong process identity tuple (`host_id` + `boot_id` + `exec_id` + `pid`), argument hashing | **FULL COMPLIANCE** |
| **RFC 5737** | IPv4 Address Blocks for Documentation | Automatic detection and labeling of TEST-NET-1/2/3 IPs in UI and reports to prevent false C2 attribution | **FULL COMPLIANCE** |
| **RFC 3161** | Time-Stamp Protocol (TSA) | Explicit demarcation: Local Host Clock (Default) vs External TSA Anchor (Supported via plug-in) | **TRANSPARENT ALIGNMENT** |
| **SOC 2 Type II (CC6.1 - CC6.8)** | Logical access controls & perimeter defense | Scoped Agent API keys (`snt_rt_...`), immediate token revocation, separate Customer API keys | **FULL COMPLIANCE** |
| **SOC 2 Type II (CC7.2 - CC7.4)** | Security anomaly detection and incident monitoring | Sub-millisecond FSM sequence evaluation, observe-only gating, audit logs | **FULL COMPLIANCE** |

---

## 3. Epistemic Integrity Guarantee

Sentinel operates under the **Epistemic Integrity Invariant**:
- The platform guarantees that no security assertion is reported as fact unless direct, uncorrupted kernel tracepoints substantiate it.
- Inferences (e.g. "exfiltration" or "reverse shell") are classified as hypotheses until dataflow reachability or payload matching is verified.
- Laboratory benchmark scenarios are watermarked as `[SYNTHETIC LAB TEST]` to preserve forensic credibility.
