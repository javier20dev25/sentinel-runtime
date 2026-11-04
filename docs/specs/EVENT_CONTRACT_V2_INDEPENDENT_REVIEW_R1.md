# Sentinel Runtime — Event Contract v2 Independent Review

**Document ID:** `REPORT-EVENT-V2-INDEPENDENT-REVIEW-R1`  
**Review gate:** `EVENT-V2-PROVENANCE-REVIEW-R2`  
**Reviewed artifact:** `EVENT_CONTRACT_PROVENANCE_MATRIX.md` (R1)  
**Date:** 2026-11-02  
**Verdict:** `NOT APPROVED FOR SCHEMA FREEZE — 2 P0 and 6 P1 findings remain`

## Scope and result

This review independently checked the R1 provenance claims against the pinned Tetragon v1.8.0 protobuf API, Tetragon v1.8.0 package documentation, Tetragon tracing-policy documentation, and Linux v6.12 kernel sources. The event enum numbers and `GetEventsResponse` oneof names in R1 are correct. The protobuf also says `Process.uid` maps to `ProcessCredentials.euid`, and the corrected `do_sys_openat2` rule correctly treats every nonnegative return as a successful file descriptor.

The review found two P0 blockers and six P1 issues. The schema must remain a candidate until the P0 items are corrected and all hook semantics are versioned and validated. This review did not modify the schema or runtime implementation.

No Sentinel CLI code scan or test suite was run for this review. The supplied 132/132 result is treated as prior reported evidence, not as a result reproduced here.

## Findings

### P0 — `CAPABILITY_CHECK` uses the wrong kernel prototype and argument index

=== SENTINEL FINDING ===
[P0] KPROBE_ARGUMENT_MISMATCH in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:299`
Snippet: `cap_capable(struct task_struct *t, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)`
Description: The documented hook signature adds a `task_struct *` parameter that is not present in Linux v6.12 `cap_capable`; it also places `cap` at zero-based argument index 3 instead of index 2.

=== AGENT INTERPRETATION ===
Linux v6.12 declares `cap_capable(const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts)`. Tetragon tracing-policy argument indexes are zero-based. The current policy would read `opts` as the capability number, so `capability_value`, `capability_name`, and any derived GRANTED/DENIED record would be untrustworthy. Correct the prototype/index and pin supported kernel variants; prefer a stable tracepoint if it provides the required process and return context. Sources: [Linux v6.12 `commoncap.c`](https://raw.githubusercontent.com/torvalds/linux/v6.12/security/commoncap.c), [Tetragon tracing-policy reference](https://tetragon.io/docs/reference/tracing-policy/).

### P0 — Loss accounting is incomplete and cannot support a “lossless” claim

=== SENTINEL FINDING ===
[P0] INCOMPLETE_LOSS_TELEMETRY in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:114`
Snippet: `Three independent Tetragon mechanisms produce countable loss, each mapped to a specific loss_metrics domain:`
Description: The matrix omits documented event drops in Tetragon queues, BPF event emission, listener buffers, aggregation buffers, filters, and export paths.

=== AGENT INTERPRETATION ===
Tetragon v1.8.0 exposes distinct loss/error counters, including failed BPF event sends, ring-buffer losses, listener-buffer overflows, and field-filter drops. The pinned protobuf also says the aggregation channel can drop incoming events when its buffer fills. A contract that counts only ring-buffer loss and `RATE_LIMIT_INFO` can report zero loss while upstream has discarded events. The schema additionally permits `payload.loss_source = storage_drop`, but R1 defines no producer or corresponding `loss_metrics` mapping for it. Inventory each stage and counter, record its enablement and scrape health, and represent unavailable counters as unknown/degraded rather than zero. Source: [Tetragon v1.8.0 metrics package](https://pkg.go.dev/github.com/cilium/tetragon@v1.8.0/pkg/metrics/eventmetrics), [Tetragon v1.8.0 observer package](https://pkg.go.dev/github.com/cilium/tetragon@v1.8.0/pkg/observer), [pinned `events.proto`](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/api/v1/tetragon/events.proto).

### P1 — `open_how.flags` is specified as a scalar capture from a pointer

=== SENTINEL FINDING ===
[P1] POINTER_FIELD_CAPTURE_UNSPECIFIED in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:205`
Snippet: `struct open_how __user *how — flags and mode (type size_arg for how->flags)`
Description: `how` is a pointer to a structure; the matrix does not specify a BTF field-resolution path that reads `how->flags`.

=== AGENT INTERPRETATION ===
The proposed mapping does not establish that the kernel structure is safely dereferenced or that the correct field is captured. Specify and validate a BTF-backed `open_how.flags` resolution for each supported kernel, or mark `open_flags` unavailable. Do not treat the pointer value as the flags bitmask. Source: [Tetragon tracing-policy reference](https://tetragon.io/docs/reference/tracing-policy/).

### P1 — Synthetic identity collides after producer restart or host reboot

=== SENTINEL FINDING ===
[P1] SYNTHETIC_KEY_REUSE in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:396`
Snippet: `Resets on producer restart. Combined with host_id and producer_id, uniquely identifies each emission.`
Description: The key formula includes neither a producer epoch nor a boot identifier, while the sequence is allowed to reset.

=== AGENT INTERPRETATION ===
After a restart, the same host and producer can reuse a sequence number; if the payload also matches, Profile C produces the same key for a new emission. The formula also lacks the boot identifier that defines the stated per-boot sequence scope. Persist a monotonic counter across restarts or add a durable producer epoch and define what happens if its state is lost. Specify replay behavior against the persisted sequence.

### P1 — Profile A does not identify its source host or transport canonically

=== SENTINEL FINDING ===
[P1] SOURCE_IDENTITY_AND_ENCODING_AMBIGUOUS in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:321`
Snippet: `K = SHA-256(LP("RAW") || LP(host_id) || LP(boot_id) || LP(exec_id) || LP(event_type) || LP(source_timestamp) || LP(raw_payload_sha256))`
Description: The inputs do not define a stable remote host identity or a byte representation shared by JSONL and gRPC ingestion.

=== AGENT INTERPRETATION ===
R1 derives `host_id` from `node_name` or config and reads `boot_id` from the collector host. For a remote Tetragon node, that can bind the event to the collector's boot, and node names may be reused across clusters. The payload hash is defined over raw JSONL bytes although Tetragon supports gRPC and JSON output; no equivalent gRPC byte source or canonical serializer is defined. Use an immutable sensor/host identity scoped by cluster, obtain the monitored node's boot ID, and define an encoding-aware, deterministic identity input for each transport. Source: [pinned `tetragon.proto`](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/api/v1/tetragon/tetragon.proto), [Tetragon events documentation](https://tetragon.io/docs/concepts/events/).

### P1 — Connect and send events overstate what their hooks observe

=== SENTINEL FINDING ===
[P1] NETWORK_OUTCOME_OVERCLAIM in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:259`
Snippet: `connected = (return_code == 0)`
Description: A return from `tcp_v4_connect`/`tcp_v6_connect` establishes the result of that kernel routine, not that the TCP handshake completed.

=== AGENT INTERPRETATION ===
Separate the connect-call outcome from an established connection. Use the socket-state event for the later handshake state and retain the originating attempt key. Also, a `tcp_sendmsg` return reports local stack acceptance/bytes, not remote delivery; a transition to a closing socket state cannot confirm a send result. Rename or define these families as local call-return observations and do not infer peer receipt. Source: [Tetragon v1.8.0 protobuf API](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/api/v1/tetragon/tetragon.proto).

### P1 — `source_cursor` mixes file offsets and gRPC streams

=== SENTINEL FINDING ===
[P1] SOURCE_CURSOR_TRANSPORT_MISMATCH in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:485`
Snippet: `anchors each event to a specific byte range in the physical input stream (typically a Tetragon JSONL log file or gRPC response)`
Description: Device, inode, and byte-offset fields describe a file cursor; a gRPC message stream needs different cursor semantics.

=== AGENT INTERPRETATION ===
Define a discriminated cursor by transport: file generation/device/inode/offset for JSONL, and stream/session ID plus monotonically increasing message sequence for gRPC. The `device_id` string representation may remain canonical, but its stated JavaScript precision rationale is unsupported by the documented 12:20 major/minor packing; remove or replace that rationale. Source: [Linux v6.12 `kdev_t.h`](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/kdev_t.h).

### P1 — The uint64 safe-range example is outside the stated range

=== SENTINEL FINDING ===
[P1] UINT64_BOUNDARY_EXAMPLE_INVALID in `docs/specs/EVENT_CONTRACT_PROVENANCE_MATRIX.md:505`
Snippet: `0 ≤ v ≤ 2⁵³ - 1 (= 9007199254740991) ... 1793662267642869315`
Description: The example value is greater than the maximum safe integer shown in the same row.

=== AGENT INTERPRETATION ===
`1793662267642869315` is above `9007199254740991` and belongs in the string-only range. Replace the example with the actual boundary `9007199254740991` (or a smaller value), and add explicit boundary fixtures for `2^53-1`, `2^53`, and `2^64-1` before claiming uint64 conformance.

## Recommended corrective contract decisions

These are concrete changes for the next matrix/schema revision:

1. **Loss state:** model loss by pipeline stage and producer counter. Keep actual dropped counts separate from intentionally filtered events. Include the upstream counter name, counter reset/monotonicity rules, collection freshness, and whether the value is `KNOWN`, `LOWER_BOUND`, or `UNKNOWN`. If aggregation drops are not countable in the pinned Tetragon build, report telemetry as degraded; do not serialize zero.
2. **Raw identity:** define a stable monitored-node identity and the monitored node's boot ID, plus a transport-aware canonical event representation. Keep a separate hash of the exact source bytes for forensic integrity. Define `LP` lengths in UTF-8 bytes.
3. **Synthetic identity:** persist a monotonically increasing producer epoch and sequence across process restarts; include cluster, host, host boot ID, producer ID, producer epoch, sequence, and canonical payload hash in the key. If durable identity state is unavailable, expose that limitation instead of claiming uniqueness.
4. **Transport cursor:** use a tagged cursor object: file identity plus byte range for JSONL, or stream/session identity plus message sequence for gRPC.
5. **Hook semantics:** capture capability argument index 2 for the pinned Linux v6.12 prototype; mark `open_how.flags` unavailable until BTF-backed user-pointer resolution is demonstrated on each supported kernel; distinguish connect-call return from established TCP state and local send return from peer delivery.
6. **Numeric boundaries:** correct the uint64 example and keep integer JSON values within the safe range; serialize larger values as canonical decimal strings.

## Benchmark and validation plan

Static syscall datasets are useful for replay/model research but do not prove correctness of Tetragon protobuf provenance, loss accounting, or kernel hook coverage. The product needs a versioned corpus captured from a live, pinned Linux/Tetragon setup, then checked into a replayable sanitized fixture set with expected normalized events and source hashes.

| Lane | Corpus/workload | What it measures | Guardrails |
|---|---|---|---|
| Contract conformance | Tetragon v1.8.0 official end-to-end outputs plus Sentinel golden fixtures for every supported family | Mapping accuracy, missing-field states, identity stability, uint64 boundaries, malformed/unknown events, replay determinism | Pin Tetragon tag, kernel, architecture, policy hash, and raw fixture hashes |
| Behavior coverage | A selected Linux subset of [Atomic Red Team](https://atomicredteam.io/) plus Tetragon’s own e2e policy scenarios | Recall by technique and event family, false positives, time-to-observation, evidence lineage | Run only in a disposable Linux VM; preserve test IDs and cleanup results |
| High-rate load | [Falco event-generator](https://github.com/falcosecurity/event-generator) benchmark actions and controlled file/process/network workloads | Events/s, p50/p95/p99 ingest latency, CPU, RSS, loss by pipeline stage, recovery after backpressure | Use its benchmark mode as a workload generator, not as a Sentinel score; run identical workloads and capture all Tetragon loss counters |
| Resilience | Rotation, `copytruncate`, collector restart, producer restart, gRPC reconnect, clock skew, queue saturation, truncated records | Cursor continuity, duplicate/missing-event detection, synthetic-key reuse, health-state transitions | Inject one fault at a time and verify the expected degraded state |
| Compatibility | Pinned Linux kernel/architecture matrix for every claimed Tetragon policy hook | Hook availability, BTF resolution, argument correctness, behavior across kernel versions | Do not mark a hook supported based only on schema coverage |

Report results with a reproducibility manifest: source commit/tag, schema hash, policy hash, kernel build, architecture, workload and test IDs, repetitions, warm-up duration, collection settings, Tetragon counters, and raw result hashes. Publish detection precision/recall and false positives separately from performance; do not collapse them into one score.

The host in this task is Windows and no Linux runtime benchmark was run or downloaded in this review. Running eBPF and behavior benchmarks requires a disposable Linux VM or node with the target kernel and Tetragon v1.8.0 installed.

## Required closeout before freeze

1. Correct the `cap_capable` prototype and zero-based index, and add a kernel/version support matrix.
2. Expand `EVENT_LOSS` to cover every observable Tetragon and Sentinel drop stage; distinguish known counts from unavailable telemetry.
3. Resolve the `open_how.flags` pointer read and define source-specific cursor/identity inputs.
4. Make Profile C sequence identity collision-safe across process restarts and host reboots.
5. Separate connect-call return, connection-established, and local send-return semantics.
6. Apply the schema changes already listed as S-1 through S-6 plus the new identity, cursor, and loss-state requirements.
7. Correct the uint64 boundary example and include boundary fixtures.
8. Capture a live Linux corpus and run the benchmark lanes above before calling the v2 contract frozen.

## Sources

- [Tetragon v1.8.0 `events.proto`](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/api/v1/tetragon/events.proto)
- [Tetragon v1.8.0 `tetragon.proto`](https://raw.githubusercontent.com/cilium/tetragon/v1.8.0/api/v1/tetragon/tetragon.proto)
- [Tetragon v1.8.0 metrics package](https://pkg.go.dev/github.com/cilium/tetragon@v1.8.0/pkg/metrics/eventmetrics)
- [Tetragon v1.8.0 observer package](https://pkg.go.dev/github.com/cilium/tetragon@v1.8.0/pkg/observer)
- [Linux v6.12 capability implementation](https://raw.githubusercontent.com/torvalds/linux/v6.12/security/commoncap.c)
- [Linux v6.12 device-number encoding](https://raw.githubusercontent.com/torvalds/linux/v6.12/include/linux/kdev_t.h)
- [Tetragon tracing-policy reference](https://tetragon.io/docs/reference/tracing-policy/)
- [Tetragon event-generator benchmark](https://github.com/falcosecurity/event-generator)
- [Atomic Red Team](https://atomicredteam.io/)
