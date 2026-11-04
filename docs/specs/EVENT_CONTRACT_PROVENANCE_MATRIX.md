# Sentinel Runtime — Event Contract v2 Provenance Matrix

**Document ID:** `SPEC-EVENT-V2-PROVENANCE-R1.4` (partial process identity and capability-check amendment)
**Supersedes:** `SPEC-EVENT-V2-PROVENANCE-R1.3` (provenance corrections retained; amendments below supersede stale statements)
**Gate:** `EVENT-V2-PROVENANCE-REVIEW-R1`
**Status:** `DRAFT R1.4 — NOT FROZEN; INDEPENDENT SCHEMA REVIEW AND PLATFORM MATRIX PENDING`
**Phase:** `PHASE 001B-2`
**Tetragon Reference:** Tag `v1.8.0` — `api/v1/tetragon/events.proto` + `api/v1/tetragon/tetragon.proto`
**Schema Under Review:** `schemas/runtime-event-v2.schema.json`
**Schema:** `schemas/runtime-event-v2.schema.json` — R1.4 draft; hash is recorded in the implementation closeout.

---

## Implementation Amendment R1.2 — 2026-11-03

This amendment supersedes the R1.1 claims about `NETWORK_SEND_RESULT` provenance and descriptor capture. In the pinned Tetragon v1.8.0 implementation, a return-probe event retains the matching entry arguments so the provider emits one `ProcessKprobe` containing arguments and return. Sentinel therefore normalizes a `tcp_sendmsg` return directly from one raw provider frame using Profile A; no second Sentinel correlation or Profile B key is required. See the pinned [generic kprobe implementation](https://github.com/cilium/tetragon/blob/v1.8.0/pkg/sensors/tracing/generickprobe.go) and the [v1.8.0 gRPC API](https://tetragon.io/docs/reference/grpc-api/).

The protobuf `KprobeFile` and `KprobeSock` messages contain no file-descriptor field. A path or socket tuple must never be used to infer an fd. This implementation stores `fd`/`socket_fd` as unavailable (`null`) and preserves the explicit path, tuple, requested size, and return value only.

The adapter implements selected, exact-symbol kprobe mappings for `do_sys_openat2`, `vfs_read`, `tcp_v4_connect`, `tcp_v6_connect`, `tcp_sendmsg`, and return-only `cap_capable`. These mappings require a TracingPolicy with the expected argument types and labels listed in §5. The adapter resolves arguments by label because Tetragon serializes the policy's argument list, which is not necessarily the kernel function's argument-index order. Other symbols, duplicate labels, and incomplete/unlabeled argument shapes remain unsupported. This follows Tetragon's [`TracingPolicy` argument definition](https://tetragon.io/docs/reference/tracing-policy/), which exposes argument labels in events and evaluates `argN` in policy-list order.

This amendment supersedes contradictory statements below where noted. The v2 candidate schema and production validator now implement: `CAPABILITY_CHECK`; unresolved credential collisions with both raw UID values; transport-specific file/gRPC/in-memory cursors; file `device_id`; distinct RAW/RAW_PID_START/DERIVED/SYNTHETIC event-key verification using 8-byte big-endian UTF-8 length prefixes; synthetic producer epoch and sequence; expanded loss domains including `storage_drop`; and warning states for unknown or lower-bound loss. The fixtures are explicitly synthetic and make no claim to be captured Tetragon events.

## Implementation Amendment R1.3 — 2026-11-03

`src/contracts/materialize-tetragon-v2.js` now builds and validates complete Event Contract v2 records for native `PROCESS_EXEC`, `PROCESS_EXIT`, and the selected kprobe mappings in §5. The gRPC collector and JSONL CLI both use this materializer and persist the v2 object as the event record. Each record carries the exact raw provider SHA-256 and the transport cursor, verifies the Profile A RAW key, records separate source/observation/ingest timestamps, and expresses unavailable identity and loss data without inventing values. Unsupported and contract-rejected events remain explicit evidence records.

The v2 payload schema now retains the open-result path, directory file descriptor for open attempts, read request size, and complete network tuple on connection/send results. A Tetragon socket descriptor is still `null` because the pinned provider message contains none. `container_id_capture_status` distinguishes full IDs from Tetragon's 15-character `docker` prefix. `FILE_READ` requires an observed return; an entry-only `vfs_read` hook stays unsupported because no result can be asserted.

Process arguments default to `REDACTED_BY_POLICY`; `--capture-process-arguments` opts into a bounded raw argument string and never claims an exact `argv`. Environment variables remain omitted, with a redaction status when Tetragon supplied them. RAW hashes identify the original frame but the ledger does not retain the full protobuf/JSON source bytes.

The materializer is covered by direct family tests, a gRPC wire-to-ledger test, and a JSONL CLI-to-ledger test. On 2026-11-03, the live WSL2 smoke captured a `tcp_sendmsg` result with 170 requested / 170 locally accepted bytes, validated the complete v2 object, and removed its temporary policy. Contract freeze remains blocked on independent schema/crypto review and supported kernel/policy validation.

The following items remain gates before contract freeze: run the kprobe normalizer against captured Tetragon v1.8.0 records; poll supported loss counters on a live sensor and provide freshness/source evidence; validate the proposed TracingPolicy argument shapes on supported Linux kernels; and obtain an independent review of R1.2.

## Implementation Amendment R1.4 — 2026-11-03

`cap_capable` return events are now normalized as `CAPABILITY_CHECK`; the adapter requires the labeled capability argument and the raw kretprobe return, maps return 0 to `GRANTED`, negative return to `DENIED`, and rejects positive or absent returns. The production Event Contract v2 materializer preserves `capability_value`, optional provider `capability_name`, `return_code`, and the derived result. This event proves an authorization check only.

Tetragon v1.8.0 can emit a process object for a kprobe without `exec_id` or `binary`. Sentinel preserves these frames only when PID and process start time are present. The v2 schema marks the missing values `UNAVAILABLE_IN_SENSOR`, sets `identity_quality: PARTIAL_RECONSTRUCTED`, and leaves them null. Profile D `RAW_PID_START` keys domain-separate this fallback using host, boot, PID, process start time, event type, source timestamp, and the exact frame hash. The behavioral engine does not correlate the event as a strong process identity.

On 2026-11-03, a scoped WSL2 live policy observed a `cap_capable` kretprobe from a child Node process dropping uid 0 to 65534. The raw `CAP_SETUID` value 7 and return 0 materialized as a schema-valid v2 `CAPABILITY_CHECK`; Tetragon reported `STATUS_LOADED`, and the script deleted the temporary policy and confirmed cleanup. A separate live frame previously showed Tetragon omitting `exec_id` and `binary`; the fallback profile now retains that shape without fabricating either value.

### Corrections to hook and network claims

- Linux v6.12 `cap_capable` has signature `cap_capable(const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts)`. In Tetragon's zero-based kprobe argument list, `cap` is **argument 2**, not argument 3.
- `do_sys_openat2` argument 2 is a pointer to `struct open_how`. Tetragon's `size_arg` captures the pointer value, not `how->flags`. `open_flags` must be unavailable unless the active TracingPolicy demonstrably resolves that pointer through supported BTF-aware access.
- `tcp_v4_connect`/`tcp_v6_connect` return values describe the local connect call. Return `0` does not prove the TCP handshake completed or the peer received anything. Preserve `return_code`; do not emit `connected=true` as a peer-state claim.
- `tcp_sendmsg`'s return value describes bytes accepted by the local networking stack. A socket state transition is not a per-send acknowledgement and must not be used as the secondary key for that send. `NETWORK_SEND_RESULT` is a local send-call result; it cannot by itself establish delivery, transfer to a peer, or exfiltration.
- Synthetic producer identity includes `boot_id` and a durable/random-per-start `producer_epoch`; sequence numbers reset only inside a new epoch. Epoch must be retained across replay. A new producer start gets a new epoch.

## Corrections Applied in This Revision

| Finding | Severity | Description | Resolution |
|---------|----------|-------------|------------|
| **R2-A / P01** | P0 BLOCKER | `EVENT_TYPE_KPROBE (4)` is a reserved number; `SOCKET_STATE_CHANGE` used wrong enum value (9). Payload paths used `.kprobe` and `.tracepoint` (not valid oneof field names). | Corrected to `PROCESS_KPROBE = 9`, `PROCESS_TRACEPOINT = 10`; payload paths corrected to `process_kprobe` and `process_tracepoint` per the `GetEventsResponse` oneof definition. |
| **R2-B / P02** | P0 BLOCKER | `EVENT_LOSS` was incorrectly attributed to `TEST = 40000`. Mixed three independent Tetragon loss mechanisms (ringbuf, rate-limit, throttle) into a single erroneous source. | `TEST (40000)` removed as loss source. Each `loss_metrics` domain now has its own verified producer documented in §3. |
| **R2-C / P03** | P0 BLOCKER | `CAPABILITY_CHANGE` was backed by `kprobe:cap_capable`, which checks authorization (returns 0/error) — it does NOT modify capabilities. | Family renamed to `CAPABILITY_CHECK`; v2 schema and fixture now require capability number, audit result, and raw return code. |
| **R2-D / P07** | P1 | Hook trazability was incomplete — no argument indices, types, or return value semantics. | Hook detail tables added for all TracingPolicy-dependent families in §5. |
| **R2-E / P05** | P0 BLOCKER | `source_event_key` formula required `exec_id` and `raw_payload_sha256`, which do not exist for `EVENT_LOSS` or `SENSOR_HEALTH`. | RAW keys cover direct provider frames, including kretprobe results; DERIVED remains reserved for future genuinely multi-source events; SYNTHETIC covers observability events. |
| **R2-F / P04** | P0 BLOCKER | Case C4 declared automatic precedence of `ProcessCredentials.euid` over `Process.uid` without code-level justification. If values conflict, eliminating one destroys evidence. | Precedence claim removed. C4 now preserves **both** raw values, marks collision, emits anomaly, and prohibits enforcement use of the conflicted identity. |
| **R2-G / P04** | P1 | Report claimed `tid: 0` certifies the `swapper/0` kernel thread identity. The proto does not assert this. | Clarified: `tid: 0` is a structurally valid wrapper value. Semantic interpretation as `swapper/0` requires additional event-context evidence not provided by Tetragon alone. |
| **R2-H / P06** | P1 | `FILE_OPEN_RESULT` modeled `fd = -1` on error, conflating libc's `open(2)` convention with the actual kernel `do_sys_openat2` return. | Corrected to preserve `return_code` as the raw kernel return; `fd` is null on any negative return; `errno = -return_code` is a derived field. |
| **Additional / P08** | P1 | `source_cursor.device_id` domain was undocumented. `uint64` dual representation (integer vs string) lacked a canonical rule. | File, gRPC, and in-memory cursors are discriminated in schema. `device_id` uses canonical decimal string form; `uint64` representation is defined in §11. |
| **R3-A** | P1 | `NETWORK_SEND_RESULT` was incorrectly treated as a Sentinel-derived join even though Tetragon's return-probe event carries the entry args and return together. The matrix also claimed that `KprobeFile`/`KprobeSock` expose an fd. | `NETWORK_SEND_RESULT` is now a RAW `PROCESS_KPROBE` event; Profile B is reserved. File and socket descriptor fields remain unavailable because the pinned protobuf messages contain no fd. |

---

## 1. Authoritative EventType Enum (Tetragon v1.8.0 — `events.proto`)

The following values are the **exact** names and numbers from the `EventType` enum in the official `events.proto` at tag `v1.8.0`. Numbers 2–4 and 6–8 and 13–26 are **reserved** and must not be assigned.

```
enum EventType {
  reserved 2 to 4, 6 to 8, 13 to 26;
  UNDEF             =     0;
  PROCESS_EXEC      =     1;
  PROCESS_EXIT      =     5;
  PROCESS_KPROBE    =     9;
  PROCESS_TRACEPOINT =   10;
  PROCESS_LOADER    =    11;
  PROCESS_UPROBE    =    12;
  PROCESS_THROTTLE  =    27;
  PROCESS_LSM       =    28;
  PROCESS_USDT      =    29;
  TEST              = 40000;   // internal test event — uint64 fields arg0–arg3
  RATE_LIMIT_INFO   = 40001;   // rate limiter notification
}
```

`GetEventsResponse` is a `oneof event` whose field names and numbers map 1:1 to `EventType`:

| EventType name | Number | oneof field in `GetEventsResponse` | Message type |
|---|---|---|---|
| `PROCESS_EXEC` | 1 | `process_exec` | `ProcessExec` |
| `PROCESS_EXIT` | 5 | `process_exit` | `ProcessExit` |
| `PROCESS_KPROBE` | 9 | `process_kprobe` | `ProcessKprobe` |
| `PROCESS_TRACEPOINT` | 10 | `process_tracepoint` | `ProcessTracepoint` |
| `PROCESS_LOADER` | 11 | `process_loader` | `ProcessLoader` |
| `PROCESS_UPROBE` | 12 | `process_uprobe` | `ProcessUprobe` |
| `PROCESS_THROTTLE` | 27 | `process_throttle` | `ProcessThrottle` |
| `PROCESS_LSM` | 28 | `process_lsm` | `ProcessLsm` |
| `PROCESS_USDT` | 29 | `process_usdt` | `ProcessUsdt` |
| `TEST` | 40000 | `test` | `Test` (uint64 arg0–arg3) |
| `RATE_LIMIT_INFO` | 40001 | `rate_limit_info` | `RateLimitInfo` |

> [!CAUTION]
> Numbers 2–4 are reserved in both the enum and the `oneof`. Any mapping that uses the number 4 for a kprobe event is architecturally incorrect. The previous revision of this document contained this error for families 3–12 (all kprobe-backed events were labeled `EVENT_TYPE_KPROBE (4)`).

---

## 2. Corrected 14-Family Provenance Matrix

For each family the matrix documents: Sentinel canonical type, correct Tetragon `EventType` name and number, correct payload `oneof` field path in `GetEventsResponse`, derivation class, and L1/L2/L3 evidence status.

Evidence level definitions:
- **L1 Schema:** JSON Schema Draft 2020-12 formally defines the family.
- **L2 Adapter:** Normalizer has deterministic, unit-tested conversion into the internal model and, for implemented native families, complete Event Contract v2 materialization. `IMPLEMENTED` does not imply live capture on every kernel/policy; unsupported symbols and mismatched argument shapes are rejected explicitly.
- **L3 Live Sensor:**
  - `OBSERVED_BASE_V1_8_0` — emitted without any custom TracingPolicy.
  - `REQUIRES_TRACING_POLICY` — requires an explicit Tetragon `TracingPolicy` CRD.
  - `OBSERVED_TRACING_POLICY_V1_8_0_WSL2` — observed with a temporary, scoped TracingPolicy on the recorded WSL2 kernel; this is not a supported-kernel matrix claim.
  - `DERIVED_CORRELATION` — synthesized by Sentinel Causal Core.
  - `SYNTHETIC_METRIC` — generated by Sentinel observability layer, not by Tetragon sensor.

> [!IMPORTANT]
> L3 status `REQUIRES_TRACING_POLICY` means the schema defines the shape of the event but no live telemetry for that family has been observed in this validation. Schema coverage (L1) does **not** imply sensor availability (L3). Family 9 is the sole kprobe exception recorded in the scoped WSL2 smoke test below.

| # | Sentinel `event_type` | Tetragon `EventType` | Number | `GetEventsResponse` oneof field | Derivation Class | L1 | L2 | L3 |
|---|---|---|---|---|---|---|---|---|
| 1 | `PROCESS_EXEC` | `PROCESS_EXEC` | 1 | `process_exec` | `DIRECT_SENSOR` | SUPPORTED | IMPLEMENTED | OBSERVED_BASE_V1_8_0 |
| 2 | `PROCESS_EXIT` | `PROCESS_EXIT` | 5 | `process_exit` | `DIRECT_SENSOR` | SUPPORTED | IMPLEMENTED | OBSERVED_BASE_V1_8_0 |
| 3 | `FILE_OPEN_ATTEMPT` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | REQUIRES_TRACING_POLICY |
| 4 | `FILE_OPEN_RESULT` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | REQUIRES_TRACING_POLICY |
| 5 | `FILE_READ` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | REQUIRES_TRACING_POLICY |
| 6 | `NETWORK_CONNECT_ATTEMPT` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | REQUIRES_TRACING_POLICY |
| 7 | `NETWORK_CONNECT_RESULT` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | REQUIRES_TRACING_POLICY |
| 8 | `NETWORK_SEND_ATTEMPT` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | REQUIRES_TRACING_POLICY |
| 9 | `NETWORK_SEND_RESULT` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | OBSERVED_TRACING_POLICY_V1_8_0_WSL2 |
| 10 | `SOCKET_STATE_CHANGE` | `PROCESS_TRACEPOINT` | 10 | `process_tracepoint` | `EXTENDED_TRACING_POLICY` | SUPPORTED | UNSUPPORTED | REQUIRES_TRACING_POLICY |
| 11 | `IDENTITY_CHANGE` | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | UNSUPPORTED | REQUIRES_TRACING_POLICY |
| 12 | `CAPABILITY_CHECK` ¹ | `PROCESS_KPROBE` | 9 | `process_kprobe` | `EXTENDED_TRACING_POLICY` | SUPPORTED | IMPLEMENTED | OBSERVED_TRACING_POLICY_V1_8_0_WSL2 |
| 13 | `EVENT_LOSS` | N/A (Sentinel synthetic) | — | Observer metrics + `rate_limit_info` | `SYNTHETIC_OBSERVABILITY` | SUPPORTED | IMPLEMENTED | SYNTHETIC_METRIC |
| 14 | `SENSOR_HEALTH` | N/A (Sentinel synthetic) | — | Collector heartbeat | `SYNTHETIC_OBSERVABILITY` | SUPPORTED | IMPLEMENTED | SYNTHETIC_METRIC |

¹ **Family #12 name change:** The event family was previously called `CAPABILITY_CHANGE`. This name is **incorrect** because the underlying kernel hook (`cap_capable`) checks whether a task holds a capability — it does not modify capabilities. The correct semantics are documented in §4.

**Materialization gate:** complete v2 objects are now built for supported `PROCESS_EXEC`, `PROCESS_EXIT`, and the selected kprobe shapes, then validated before persistence. L2 is closed for these source shapes. L3 remains limited to the base process events and one `tcp_sendmsg` WSL2 policy smoke; other kprobe families still require live policy validation.

---

## 3. EVENT_LOSS: Corrected Source Mapping (R2-B / P02)

The previous revision incorrectly attributed `EVENT_LOSS` to `TEST (40000)`. `TEST` is an internal testing artifact with four opaque `uint64` arguments; it carries no semantic information about event loss.

Tetragon v1.8.0 exposes several independently countable loss/error mechanisms, each mapped to a specific `loss_metrics` domain. Other throttling paths are transition-only or lack an interval contract and remain unknown unless a concrete count is observed:

### 3.1 Ringbuf Dropped Events → `loss_metrics.ebpf_kernel`

- **Mechanism:** The BPF ring buffer between kernel space and user space becomes full when the consumer (Tetragon observer) cannot drain it fast enough.
- **Tetragon v1.8.0 source:** Prometheus counter `tetragon_observer_ringbuf_events_lost_total`, registered by the observer metrics package. It is not carried by `GetEventsResponse`.
- **Sentinel production path:** `collect-tetragon --metrics-url http://127.0.0.1:2112/metrics` polls the Prometheus endpoint, stores the exact response SHA-256, and emits validated synthetic health/loss events in the SQLite evidence chain. The adapter supports loopback-only HTTP or TLS-verified HTTPS.
- **Delta rule:** Counters are aggregated by metric name across labels. Sentinel calculates deltas only while `process_start_time_seconds` proves the same Tetragon process remained up. On the first verified scrape it can report the cumulative total since the Tetragon process start. A process restart, counter decrease, missing baseline, or absent process-start gauge leaves that interval `UNKNOWN` and does not fabricate a zero.
- **Tetragon proto involvement:** None. The count comes from the Prometheus observer counter, not a protobuf event or a direct `ReadLostEvents()` call by Sentinel.

### 3.2 `RATE_LIMIT_INFO` Wire Frames → conditional `loss_metrics.sensor_throttle`

- **Tetragon source:** The pinned proto defines `GetEventsResponse.rate_limit_info` (`RATE_LIMIT_INFO = 40001`) and `uint64 number_of_dropped_process_events`, but it does not define a reporting interval, cumulative/reset semantics, or cgroup scope. The reviewed v1.8.0 `GetEvents` server path does not establish that this frame is emitted for the gRPC stream.
- **Sentinel handling:** If a frame is received, Sentinel preserves the original protobuf evidence and emits a validated Event Contract v2 `EVENT_LOSS` when its count is positive. A zero frame emits `SENSOR_HEALTH` with `sensor_throttle=ZERO_OBSERVED`. The event records `window_seconds=null` and `window_status=UNKNOWN`; values are never summed across frames or presented as an interval/cumulative total.
- **Production coverage:** Absence of this frame is not evidence that throttling loss is zero. `loss_metrics.sensor_throttle` remains `UNKNOWN` unless a concrete provider frame supplies a count.

### 3.3 PROCESS_THROTTLE Transitions → informational, not a loss count

- **Mechanism:** `--cgroup-rate` throttles base `PROCESS_EXEC`/`PROCESS_EXIT` publication per cgroup/CPU and produces `PROCESS_THROTTLE` start/stop transitions. The optional JSON exporter also has a separate output rate limiter.
- **Sentinel production path:** `PROCESS_THROTTLE` transitions do not carry dropped-event counts. Tetragon's `tetragon_export_ratelimit_events_dropped_total` / `tetragon_events_export_failed_total` describe its JSON exporter, not Sentinel's gRPC capture stream, and are not mapped to its gRPC loss count.
- **Tetragon source:** `GetEventsResponse.process_throttle`.

### 3.4 gRPC Transport Losses → `loss_metrics.grpc_transport`

- **Mechanism:** gRPC stream disconnects, reconnects, or backpressure drops between Tetragon and Sentinel.
- **Source:** Sentinel transport layer; no Tetragon proto involvement.

### 3.5 Other Domains

| Domain | Source | Producer |
|---|---|---|
| `log_rotation` | File cursor lost during rotation | Sentinel file-stream adapter |
| `parser_reject` | JSON parse error or schema rejection | Sentinel normalizer |
| `runtime_queue` | Sentinel Causal Core ingress queue overflow | Sentinel Causal Core |
| `storage_drop` | Evidence database/write failure or explicit durability queue overflow | Sentinel evidence writer |
| `tetragon_bpf_missed_events` | `tetragon_bpf_missed_events_total` counter | Tetragon metrics adapter |
| `tetragon_listener_overflow` | `tetragon_notify_overflowed_events_total` counter | Tetragon listener metrics |
| `tetragon_field_filter_drops` | `tetragon_field_filter_failed_total` counter | Tetragon field-filter metrics |
| `tetragon_observer_queue_drops` | `tetragon_observer_ringbuf_queue_events_lost_total` counter | Tetragon observer queue metrics |
| `tetragon_aggregation_buffer_drops` | Optional per-GetEvents aggregation channel; Tetragon v1.8.0 says it is bypassed when request `aggregation_options` is unset | `NOT_APPLICABLE` while Sentinel requests no aggregation; if aggregation is enabled later, state becomes `UNAVAILABLE` until an upstream counter exists |

The pinned v1.8.0 metrics adapter polls the five counter names above plus `process_start_time_seconds`. `tetragon_observer_ringbuf_errors_total` is retained as sensor-health context and is **not** treated as a count of dropped events. The official v1.8.0 JSON exporter separately has `tetragon_export_ratelimit_events_dropped_total` and `tetragon_events_export_failed_total`; those counters describe its JSON export path and are not attributed to Sentinel's gRPC capture stream. Counter samples must be exactly representable non-negative integers; absent samples, malformed exposition, non-integral values, and scrape failures never become zero.

The non-Kubernetes Tetragon metrics server is disabled by default. It must be enabled on a loopback address (for example `127.0.0.1:2112`) or exposed over authenticated TLS before polling. Sentinel's current GetEvents request leaves `aggregation_options` unset, so the optional Tetragon aggregation queue is bypassed and its loss domain is `NOT_APPLICABLE` on this path. Enabling aggregation in a future collector version requires a verified drop counter first. `SENSOR_HEALTH` remains `DEGRADED` while Sentinel-side transport gaps and queue/storage/parser metrics are unobserved.

Every loss domain has a state, count, source, and observation time when measured. `ZERO_OBSERVED` is valid only when the source was polled successfully during the stated interval. A missing/unobservable counter is `UNAVAILABLE` or `UNKNOWN`, never zero. `MEASURED_LOWER_BOUND` means the true loss may be greater than the reported count.

> [!IMPORTANT]
> `GetEventsResponse.test` (`TEST = 40000`) must **never** be used as a loss-event source in Sentinel. Its payload (`uint64 arg0–arg3`) has no defined semantic relationship to dropped events.

---

## 4. CAPABILITY_CHECK Semantics (R2-C / P03)

**Decision:** Family #12 is formally named `CAPABILITY_CHECK`. The name `CAPABILITY_CHANGE` is withdrawn.

### 4.1 What `cap_capable` actually does

`cap_capable(struct task_struct *t, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts)` is called by the Linux kernel to check whether a task holds a specific capability in a given namespace. It returns `0` if the capability is granted and a negative error code (`-EPERM`) if not.

Consequences:
- A `cap_capable` invocation that returns `0` means the process **has** the capability and is being **allowed** to use it.
- A `cap_capable` invocation that returns `-EPERM` means the operation was **denied**.
- Neither case represents a change to the process's capability sets.

### 4.2 Normative event semantics for CAPABILITY_CHECK

The `CAPABILITY_CHECK` event records:

| Payload field | Source | Semantics |
|---|---|---|
| `capability` | `KprobeCapability.value` (int32) | Linux capability number (e.g., 21 = `CAP_SYS_ADMIN`) |
| `capability_name` | `KprobeCapability.name` (string) | Human-readable name (e.g., `"CAP_SYS_ADMIN"`) |
| `audit_result` | kretprobe return value | `GRANTED` (0) or `DENIED` (negative errno) |
| `ns_type` | User namespace context (from args) | Namespace in which the check was evaluated |

### 4.3 What CAPABILITY_CHECK does NOT represent

- It does **not** indicate that capabilities were added or removed.
- It does **not** indicate `setcap`, `prctl(PR_SET_SECUREBITS)`, or `commit_creds`.
- Sentinel **must not** emit a security alert stating "a process changed its privileges" based on a `CAPABILITY_CHECK` event.

### 4.4 Schema impact

The v2 draft schema now defines `CAPABILITY_CHECK` with `capability_value`, `audit_result`, and the raw `return_code`. The v1 contract retains its historic `CAPABILITY_CHANGE` spelling for compatibility; it must not be interpreted as evidence that capabilities changed.

The v2 schema is still a draft and is not frozen; the family rename itself is implemented.

---

## 5. Hook Traceability Matrix (R2-D / P07)

For each `EXTENDED_TRACING_POLICY` family, the following table documents the kernel hook, required TracingPolicy labels, return semantics, and known limitations. The adapter is implemented for selected kprobe symbols. A temporary policy smoke test now validates `tcp_sendmsg` on one WSL2 kernel; a production policy bundle and cross-kernel validation remain open.

### 5.1 FILE_OPEN_ATTEMPT — `do_sys_openat2`

| Attribute | Value |
|---|---|
| Symbol | `do_sys_openat2` (Linux ≥ 5.6); `do_sys_open` for older kernels |
| Hook type | `kprobe` (entry) |
| Arg 0 | `int dfd` — directory file descriptor (type `int_arg` in Tetragon). AT_FDCWD = -100 for current directory. |
| Arg 1 | `const char __user *filename` — path string (type `string_arg`) |
| Arg 2 | `struct open_how __user *how` — pointer only; `size_arg` does **not** decode `how->flags` |
| Required labels | arg 0: `sentinel_dfd`; arg 1: `sentinel_filename` |
| Return | Not captured on entry probe |
| Sentinel field mapping | `payload.path` ← arg1 string; `payload.open_flags` is unavailable unless a tested BTF-aware resolver reads `how->flags` |
| Unavailability | Path may be truncated if > 4096 bytes; AT_FDCWD expansion requires userspace resolution; a pointer value is not the flags bitmask |

### 5.2 FILE_OPEN_RESULT — `do_sys_openat2` (kretprobe) — CORRECTED (R2-H)

The kernel function `do_sys_openat2` returns a `long`. On success it returns the new file descriptor number (≥ 0). On failure it returns a negative error code (e.g., `-13` for `EACCES`, `-2` for `ENOENT`). This is **not** the same as the libc `open(2)` convention where `fd = -1` on any error.

| Attribute | Value |
|---|---|
| Symbol | `do_sys_openat2` |
| Hook type | `kretprobe` (exit) |
| Return value | `long` — raw kernel return code |
| Required labels | Merged entry args retain arg 1 as `sentinel_filename`; missing/duplicate label leaves the event unsupported |
| Sentinel payload | `return_code` = raw kernel return value (always preserved) |
| `fd` field | `fd = return_code` if `return_code >= 0`; `fd = null` if `return_code < 0` |
| `errno` field | `null` if `return_code >= 0`; `-return_code` if `return_code < 0` (derived) |
| Example success | `return_code: 7, fd: 7, errno: null` |
| Example failure | `return_code: -13, fd: null, errno: 13` |
| Unavailability | kretprobe may miss the return if the thread is preempted for too long |

> [!CAUTION]
> The previous revision modeled `fd: -1` on error, which conflates the libc convention with the kernel reality. Negative return codes from `do_sys_openat2` can be any errno value negated, not only -1.

### 5.3 FILE_READ — `vfs_read`

| Attribute | Value |
|---|---|
| Symbol | `vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)` |
| Hook type | `kprobe` (entry) + optional `kretprobe` |
| Arg 0 | `struct file *` → `file_arg` in Tetragon (yields `KprobeFile.path`, `KprobeFile.flags`) |
| Arg 1 | `char __user *buf` — not captured (user buffer pointer, unsafe) |
| Arg 2 | `size_t count` → `size_arg` — bytes requested |
| Required labels | arg 0: `sentinel_file`; arg 2: `sentinel_count` |
| Return (kretprobe) | `ssize_t` — bytes actually read (≥ 0) or negative errno |
| Sentinel fields | `fd` unavailable; `bytes_requested` ← arg2; `bytes_read` ← return value |
| Limitation | Very high-frequency hook; requires aggressive per-binary or per-path filtering in TracingPolicy to avoid ringbuf overflow contributing to `loss_metrics.ebpf_kernel`. |

### 5.4 NETWORK_CONNECT_ATTEMPT — `tcp_v4_connect` / `tcp_v6_connect`

| Attribute | Value |
|---|---|
| Symbol | `tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)` |
| Hook type | `kprobe` (entry) |
| Arg 0 | `struct sock *` → `sock_arg` → `KprobeSock` (family, saddr, daddr, sport, dport, protocol, state) |
| Arg 1 | `struct sockaddr *` → `sockaddr_arg` → `KprobeSockaddr` (family, addr, port) |
| Required labels | arg 0: `sentinel_socket`; arg 1: `sentinel_sockaddr` |
| Sentinel fields | `src_ip` ← `sock.saddr`; `dst_ip` ← `sockaddr.addr`; `dst_port` ← `sockaddr.port`; `protocol` = TCP |
| IPv6 | Same pattern via `tcp_v6_connect`; `daddr` is IPv6 string |

### 5.5 NETWORK_CONNECT_RESULT — `tcp_v4_connect` / `tcp_v6_connect` (kretprobe)

| Attribute | Value |
|---|---|
| Hook type | `kretprobe` (exit) |
| Return | `int` — 0 on success, negative errno on failure |
| Required labels | Merged entry args retain `sentinel_socket` and `sentinel_sockaddr` |
| Sentinel fields | `return_code` ← raw return; `errno` ← `-return_code` if negative; `call_result` may describe the local call only |
| Semantic limit | Return `0` does not prove handshake completion, peer acceptance, or data receipt. No `connected=true` assertion is allowed from this kretprobe alone. |

### 5.6 NETWORK_SEND_ATTEMPT — `tcp_sendmsg`

| Attribute | Value |
|---|---|
| Symbol | `tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)` |
| Hook type | `kprobe` (entry) |
| Arg 0 | `struct sock *` → `sock_arg` |
| Arg 2 | `size_t size` → `size_arg` — bytes to send |
| Required labels | arg 0: `sentinel_socket`; arg 2: `sentinel_size` |
| Sentinel fields | `socket_fd` unavailable; `bytes_requested` ← arg2; 4-tuple from `KprobeSock` |
| Limitation | `msg` (msghdr) is not directly extractable without BTF traversal. Buffer content is not captured. |

### 5.7 SOCKET_STATE_CHANGE — tracepoint `sock:inet_sock_set_state`

| Attribute | Value |
|---|---|
| Subsystem | `sock` |
| Event | `inet_sock_set_state` |
| Tetragon EventType | `PROCESS_TRACEPOINT (10)` |
| Payload field | `GetEventsResponse.process_tracepoint` |
| `ProcessTracepoint.subsys` | `"sock"` |
| `ProcessTracepoint.event` | `"inet_sock_set_state"` |
| Args (tracepoint format) | `oldstate` (int), `newstate` (int), `family` (int), `protocol` (int), `sport` (u16), `dport` (u16), `saddr`/`daddr` (u32/u128) |
| Sentinel fields | `old_state_name`, `new_state_name`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` |

### 5.8 IDENTITY_CHANGE — `commit_creds`

| Attribute | Value |
|---|---|
| Symbol | `commit_creds(struct cred *new)` |
| Hook type | `kprobe` (entry) |
| Arg 0 | `struct cred *` → `process_credentials_arg` (yields `ProcessCredentials` with uid, gid, euid, egid, suid, sgid, caps) |
| Limitation | `commit_creds` is called for **any** credential change including setuid, capset, and filesystem-related operations. Distinguishing the **previous** credentials requires either a kretprobe reading `current->cred` before the swap, or a paired kprobe on the caller. Without the previous state, the event only shows the **new** credentials; it cannot confirm the before→after transition. |
| Schema impact | `payload.previous_credentials` must be explicitly marked `UNAVAILABLE` if the hook does not capture the prior state. The event should not claim to record a diff if only the new state is available. |

### 5.9 CAPABILITY_CHECK — `cap_capable`

| Attribute | Value |
|---|---|
| Symbol | Linux v6.12: `cap_capable(const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts)` |
| Hook type | `kprobe` (entry) + `kretprobe` (exit) |
| Arg 2 | `int cap` → `int_arg` / `capability_arg` — capability number |
| Arg 2 name | Mapped via `KprobeCapability.value` / `.name` when the active policy captures that argument type |
| Return | `int` — 0 granted, negative denied |
| Sentinel fields | `capability_value`, `capability_name`, `audit_result` (`GRANTED`/`DENIED`) |
| Semantic constraint | Event represents a **permission check**, not a capability modification. Must not be surfaced to users as a privilege change. |

---

## 6. source_event_key Identity Profiles (R2-E / P05, R3-A)

The raw event formula applies to direct provider frames that include process context. A Tetragon kretprobe result is still one provider frame: its merged entry arguments and return value share one `ProcessKprobe`. `EVENT_LOSS` and `SENSOR_HEALTH` are synthetic.

Four identity profiles are defined. Each profile includes a **domain tag** in the hashed material to prevent cross-profile collisions.

### 6.1 Profile A — RAW_PROVIDER_EVENT

**Applies to:** Families 1–12 (all `DIRECT_SENSOR` and `EXTENDED_TRACING_POLICY` events backed by a single `GetEventsResponse` frame) when `Process.exec_id` is present, including `NETWORK_SEND_RESULT` from a `tcp_sendmsg` kretprobe.

**Formula:**
```
K = SHA-256(LP("RAW") || LP(host_id) || LP(boot_id) || LP(exec_id) || LP(event_type) || LP(source_timestamp) || LP(raw_payload_sha256))
```

Where `LP(x)` = an 8-byte unsigned big-endian length of the UTF-8 encoding of `x`, followed by those UTF-8 bytes. This is the encoding implemented in `src/contracts/event-keys.js`; character count is not used.

**Component availability requirements:**

| Component | Source | Must be present |
|---|---|---|
| `host_id` | Stable configured identity of the monitored host; a collector host or reusable node name is not substituted | Yes |
| `boot_id` | Boot ID of the monitored host, from that host or a trusted sensor field; collector boot ID is valid only when collector and target are the same host | Yes |
| `exec_id` | `Process.exec_id` from the event's `process` field | Yes |
| `event_type` | Sentinel canonical type string | Yes |
| `source_timestamp` | `GetEventsResponse.time` (nanoseconds since epoch as string) | Yes |
| `raw_payload_sha256` | SHA-256 of the exact source-frame bytes: original JSONL frame bytes for file ingestion or original protobuf wire bytes for gRPC | Yes |

**Idempotence:** Given identical inputs, the same key is always produced. Replay of the same raw line produces the same key.

**Certified test vector (unchanged from Review R2):**
```
Domain tag:        RAW
host_id:           sentinel-host-prod-01 (len 21)
boot_id:           8f5a2b1c-3d4e-5f6a-7b8c-9d0e1f2a3b4c (len 36)
exec_id:           REVTS1RPUC1LSTVBUFA0OjM4NjY4NTY2Mjk1OToxMzEw (len 44)
event_type:        PROCESS_EXEC (len 12)
source_timestamp:  1793662267642869315 (len 19)
raw_payload_sha256: 0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818 (len 64)
```

The production validator recomputes this key from event fields and rejects a mismatch. Test fixtures are labeled synthetic and are not Tetragon captures.

### 6.2 Profile B — DERIVED_CORRELATED_EVENT (Reserved)

**Applies to:** No current event family. Reserved for a future Sentinel event that truly combines multiple independently sourced provider frames.

`NETWORK_SEND_RESULT` does not use this profile. Tetragon v1.8.0 emits its `tcp_sendmsg` return event with the stored entry arguments and return in one `ProcessKprobe`, so the result has one raw frame and uses Profile A. A `SOCKET_STATE_CHANGE` is not a per-send result and cannot serve as a correlation input.

**Formula:**
```
K = SHA-256(LP("DERIVED") || LP(host_id) || LP(boot_id) || LP(correlation_rule_id) || LP(rule_version) || LP(primary_event_key) || LP(secondary_event_key))
```

**Component definitions:**

| Component | Description |
|---|---|
| `host_id` | Same as Profile A |
| `boot_id` | Same as Profile A |
| `correlation_rule_id` | Stable Sentinel identifier for a future multi-source derivation rule |
| `rule_version` | Rule version; ensures the key changes when correlation semantics change |
| `primary_event_key` | `source_event_key` of the first actual source event (Profile A key) |
| `secondary_event_key` | `source_event_key` of the second actual source event (Profile A key) |

**Idempotence:** Given the same source keys and rule version, the derived key is stable. Re-running the correlator on the same input events produces the same key.

**Known limitation:** The reserved profile must not be applied unless every source frame and correlation rule is explicitly represented. No current producer emits Profile B events.

### 6.3 Profile C — SYNTHETIC_OBSERVABILITY_EVENT

**Applies to:** Families 13 (`EVENT_LOSS`) and 14 (`SENSOR_HEALTH`).

These events are generated internally by Sentinel's collector/observability layer. They have no originating Tetragon event and no `exec_id`.

**Formula:**
```
K = SHA-256(LP("SYNTHETIC") || LP(host_id) || LP(boot_id) || LP(producer_id) || LP(producer_epoch) || LP(sequence_number) || LP(payload_sha256))
```

**Component definitions:**

| Component | Description |
|---|---|
| `host_id` | Sentinel host identifier |
| `boot_id` | Boot identity of the monitored host |
| `producer_id` | Stable identifier of the synthetic event producer (e.g., `"sentinel-ebpf-loss-monitor-v1"`, `"sentinel-health-beacon-v1"`) |
| `producer_epoch` | Random/persisted UUID created at producer start; a restart creates a new epoch |
| `sequence_number` | Monotonically increasing canonical decimal string within one producer epoch |
| `payload_sha256` | SHA-256 of the RFC 8785 canonical JSON representation of the event payload |

**Idempotence guarantee:** Exact idempotence is not achievable for synthetic events because `sequence_number` increments per emission. The key uniquely identifies each emission but does not guarantee that an identical metric observation at a different time produces the same key.

**Explicit limitation:** Unlike Profile A, Profile C keys do not guarantee replay-idempotence. Duplicate detection for synthetic events must be implemented at the consumer level using `sequence_number` windows, not by key equality alone.

> [!IMPORTANT]
> Profile C keys MUST NOT omit `boot_id` or `producer_epoch`, use an empty identity, or reset a sequence while reusing the old epoch. A UUID used as a producer epoch is allowed; a random UUID used as the event key itself is not. Payload hash is computed from the synthetic payload, not a fabricated raw provider frame.

### 6.4 Profile D — RAW_PARTIAL_PROCESS_EVENT (PID + start time)

**Applies to:** A raw provider event that includes `Process.pid` and `Process.start_time` but omits `Process.exec_id`. This profile does not create an `exec_id`; it preserves the event with `exec_id: null`, `exec_id_capture_status: UNAVAILABLE_IN_SENSOR`, and `identity_quality: PARTIAL_RECONSTRUCTED`. The runtime does not use this partial identity as a process-chain or exclusive enforcement identity.

**Formula:**
```
K = SHA-256(LP("RAW_PID_START") || LP(host_id) || LP(boot_id) || LP(pid) || LP(process_start_time) || LP(event_type) || LP(source_timestamp) || LP(raw_payload_sha256))
```

**Required inputs:** `pid` must be the observed uint32 value, `process_start_time` and `source_timestamp` must be exact nanosecond decimal strings, and `raw_payload_sha256` must hash the exact provider frame. The schema requires PID + start time and explicit capture-status fields before this key can validate. If both `exec_id` and PID are absent, the event stays unsupported.

**Identity limit:** PID + process start time distinguishes PID reuse for event identity when both are supplied, but it does not provide Tetragon's opaque execution identity or executable provenance. Sentinel preserves the event for evidence and leaves process correlation unassessed.

**Idempotence:** An exact replay of the same provider frame with the same host, boot, PID, and start time yields the same key. The separate domain tag prevents collision with Profile A keys.

---

## 7. EUID Collision Resolution — Corrected (R2-F / P04)

### 7.1 Protobuf field semantics (from `tetragon.proto` v1.8.0)

From the Process message documentation (field 3, `uid`):
> "The effective User identifier used for permission checks. This field maps to the `ProcessCredentials.euid` field. Run with the `--enable-process-cred` flag to enable `ProcessCredentials` and get all the User and Group identifiers."

From `ProcessCredentials`:
- `uid` (field 1, `UInt32Value`): "The real user ID of the process' owner."
- `euid` (field 3, `UInt32Value`): "The effective user ID used for permission checks."

**Confirmed mapping:** `Process.uid` ↔ `ProcessCredentials.euid` (both represent the effective UID).

### 7.2 Corrected collision matrix

**The previous Case C4 ("extended credentials take precedence") has been withdrawn.** No code evidence in Tetragon v1.8.0 demonstrates that `ProcessCredentials.euid` is captured at a different kernel time than `Process.uid`, or that one is more "atomic" than the other. Both are read from the kernel `cred` struct, but the timing of each read relative to any `commit_creds` call is not documented at the Proto level.

| Case | `Process.uid` | `ProcessCredentials.euid` | `ProcessCredentials.uid` | `euid` in event | `ruid` in event | `euid_capture_status` | `ruid_capture_status` | `credentials_capture_status` | Action |
|---|---|---|---|---|---|---|---|---|---|
| **C1: Base sensor only** | Present ($V_1$) | Absent | Absent | $V_1$ | null | `OBSERVED_PROCESS_UID` | `UNAVAILABLE_BASE_SENSOR` | `EFFECTIVE_ONLY` | Normal operation; `--enable-process-cred` not enabled. |
| **C2: Extended creds agree** | Present ($V_1$) | Present ($V_2 = V_1$) | Present ($V_3$) | $V_1$ | $V_3$ | `OBSERVED_EXTENDED_CRED` | `OBSERVED_EXTENDED_CRED` | `REAL_AND_EFFECTIVE` | Clean capture; both sources agree. |
| **C3: Base wrapper absent** | Absent | Present ($V_2$) | Present ($V_3$) | $V_2$ | $V_3$ | `OBSERVED_EXTENDED_CRED` | `OBSERVED_EXTENDED_CRED` | `REAL_AND_EFFECTIVE` | Extended credentials used as sole source. |
| **C4: EUID collision** | Present ($V_1$) | Present ($V_2 \ne V_1$) | Present ($V_3$) | **PRESERVED: both $V_1$ and $V_2$** | $V_3$ | `EUID_COLLISION_FLAGGED` | `OBSERVED_EXTENDED_CRED` | `COLLISION_UNRESOLVED` | **NEITHER value is discarded.** Both raw values stored. Anomaly emitted. Identity MUST NOT be used as the exclusive predicate for destructive enforcement. |
| **C5: Both absent** | Absent | Absent | Absent | null | null | `UNAVAILABLE_ABSENT_IN_SENSOR` | `UNAVAILABLE_ABSENT_IN_SENSOR` | `ABSENT_IN_SENSOR` | Valid in synthetic or degraded sensor scenarios. |

**Normative rules for C4:**
1. `euid` field in the event **must not** silently drop either raw value. Both `process_uid_raw` (from `Process.uid`) and `credentials_euid_raw` (from `ProcessCredentials.euid`) must be preserved as separate fields.
2. The event must carry `credentials_capture_status: "COLLISION_UNRESOLVED"` (not `"COLLISION_RESOLVED"` — resolution requires out-of-band investigation).
3. A causal anomaly record must be emitted.
4. Enforcement decisions that rely on `euid` for process identity must treat this event as **untrusted identity** and require secondary verification.

### 7.3 Schema impact for C4

The v2 draft now uses `credentials_capture_status: "COLLISION_UNRESOLVED"`, requires `process_uid_raw` and `credentials_euid_raw`, and requires canonical `euid` to be null in that state. The production validator also warns that the conflicting identity must not be used as an exclusive enforcement predicate.

---

## 8. TID = 0 Semantics (R2-G)

Protobuf `google.protobuf.UInt32Value` has explicit presence semantics:
- **Wrapper absent:** serializes to `null` in JSON; means the value was not observed.
- **Wrapper present, value = 0:** serializes to `0` in JSON; means the value was observed and is zero.

`tid: 0` is therefore a structurally valid value within the schema. The schema correctly accepts it.

**What `tid: 0` does NOT certify:**

The value `0` in `Process.tid` does not, by itself, identify the `swapper/0` idle thread. The Tetragon proto documentation states:
> "Thread ID, note that for the thread group leader, tid is equal to pid."

It does not state that `tid = 0` always corresponds to the idle thread. Interpretation of `tid: 0` as the swapper requires corroborating evidence such as:
- `pid: 0` present in the same event.
- `event_type` consistent with a kernel-internal execution context.
- Additional sensor metadata indicating a non-userspace origin.

**Policy:** Accept `tid: 0` as structurally valid. Do not emit a semantic annotation claiming the event originated from `swapper/0` without the corroborating evidence listed above.

---

## 9. FILE_OPEN_RESULT — Corrected Error Representation (R2-H / P06)

See §5.2 for the full hook specification.

The normative field mapping replaces the previous incorrect model:

| Condition | `return_code` | `fd` | `errno` |
|---|---|---|---|
| Success | raw kernel return (e.g., `7`) | `7` | `null` |
| Failure | raw kernel return (e.g., `-13`) | `null` | `13` (= `-return_code`) |

`errno` is always a **derived field**, not captured directly from the kernel. The raw `return_code` is the authoritative value and must always be preserved.

---

## 10. Source Cursor — Transport-Specific Position (P08)

`source_cursor.cursor_kind` discriminates the position model. File byte offsets must not be used as a substitute for a gRPC stream sequence.

| Field | Type | Domain | Representation | Notes |
|---|---|---|---|---|
| `cursor_kind` | enum | `FILE_BYTES`, `GRPC_SEQUENCE`, or `IN_MEMORY_SEQUENCE` | Exact string | Must match the configured transport |
| `device_id` | canonical decimal string | Linux `dev_t`, encoded as `major * 2^20 + minor` | **String only** for one cross-language representation; not because Linux `dev_t` exceeds JS safe integer range | Obtained from `stat(2).st_dev`; required for file cursor |
| `inode` | `$defs/uint64` | `ino_t` file identity | String or safe integer | Obtained from `stat(2).st_ino`; file cursor only |
| `byte_offset` | `$defs/uint64` | Byte position of the start of the JSONL line within the file | String or integer ≤ 2⁵³-1 | Monotonically increasing per `file_generation_id` |
| `byte_length` | `integer [0, 16777216]` | Total bytes consumed from the stream for this event | Plain integer | `payload_byte_length + delimiter_byte_length` |
| `payload_byte_length` | `integer [0, 16777216]` | Byte length of the JSON payload (excluding delimiter) | Plain integer | Used for SHA-256 scope |
| `delimiter_byte_length` | `integer {0, 1, 2}` | Byte length of the line delimiter: 0=EOF/none, 1=LF, 2=CRLF | Plain integer | |
| `file_generation_id` | `$defs/uint64` | Sentinel-managed monotonic file generation counter, incremented on each rotation | String or integer ≤ 2⁵³-1 | Resets are permissible only on full collector restart |
| `raw_payload_sha256` | `$defs/sha256` | SHA-256 of exactly `payload_byte_length` bytes starting at `byte_offset` | 64-char lowercase hex string | Used in Profile A key computation |
| `stream_epoch` | UUID | gRPC connection/stream generation | UUID string | Required for gRPC and in-memory cursors |
| `sequence_number` | `$defs/uint64` | Position within one gRPC stream epoch | Canonical decimal string preferred | Required for gRPC and in-memory cursors |

---

## 11. uint64 Canonical Representation Rule (P08)

A `uint64` value in the Sentinel event contract is represented as follows:

| Value range | JSON type | Format | Example |
|---|---|---|---|
| `0 ≤ v ≤ 2⁵³ - 1` (= 9007199254740991) | `integer` OR `string` | No leading zeros if string | `1793662267` or `"1793662267"` |
| `2⁵³ ≤ v ≤ 2⁶⁴ - 1` | **`string` only** | Canonical decimal, no leading zeros | `"18446744073709551615"` |

**Canonical rule:** When a `uint64` value is serialized, it MUST use the **string form** if it exceeds `Number.MAX_SAFE_INTEGER`. Both forms are accepted by the schema for values within the safe integer range, but producers SHOULD prefer the string form for all `uint64` fields to avoid consumer-side precision loss.

**Prohibition:** The following representations are non-conforming for `uint64`:
- Leading zeros (e.g., `"007"`) → rejected by the regex pattern.
- Scientific notation (e.g., `"1.8e19"`) → not a canonical decimal string.
- Negative values → `uint64` is unsigned.
- Floats (e.g., `1793662267642869300.0`) → precision loss.

---

## 12. NETWORK_SEND_RESULT — Local Send-Call Result

`NETWORK_SEND_RESULT` is normalized from one `PROCESS_KPROBE` frame when a compatible TracingPolicy captures `tcp_sendmsg` entry arguments and its kretprobe return:

- `args[0].sock_arg` supplies the socket tuple.
- `args[2].size_arg` supplies requested bytes.
- `return.long_arg` supplies the raw signed return code.
- The raw protobuf response hash and process execution identity produce a Profile A key.

Tetragon's v1.8.0 generic kprobe implementation stores entry events for return probes and merges their arguments when the return event is generated. This is provider-side pairing within one event, not a cross-event Sentinel correlation. If the active policy does not capture the required args and return, the event remains unsupported; Sentinel does not synthesize missing values.

This event proves only the local call result. A positive return means bytes were accepted by the local networking stack; it does not prove a completed handshake, peer acknowledgement, remote receipt, or exfiltration. `socket_fd` is unavailable in `KprobeSock` and is stored as `null`. A socket state transition is recorded separately and is not treated as the result of a specific send.

---

## 13. Schema R1.4 Status and Remaining Gates

The following R1 changes are present in the v2 draft schema and production validator. Their implementation does not constitute approval to freeze the contract; captured-provider conformance and independent review remain open.

| # | Schema field / enum | R1.2 candidate state | Gate |
|---|---|---|---|
| S-1 | `event_type` enum | `CAPABILITY_CHECK` | Implemented; verify provider mapping before freeze |
| S-2 | `credentials_capture_status` | `COLLISION_UNRESOLVED` | Implemented with null canonical EUID and preserved raw values |
| S-3 | `process_identity` | Raw provider UID fields present | Implemented; exercise collision fixture from real provider data |
| S-4 | `source_event_key` | RAW/RAW_PID_START/DERIVED/SYNTHETIC profiles and production verification | Implemented; independent cryptographic review pending |
| S-7 | Partial process identity | Explicit missing `exec_id`/binary capture status and PID + start-time identity | Implemented in draft R1.4; require independent collision and semantics review |
| S-5 | `source_cursor` | `device_id` and FILE/GRPC/IN_MEMORY cursor kinds | Implemented structurally; transport adapters must populate real cursors |
| S-6 | `uint64` representation | String required above 2⁵³-1; strings preferred below | Implemented and tested |
| L-1 | `loss_metrics` | Separate Tetragon stages plus storage; unknown and lower-bound states | Implemented structurally; polling and freshness adapter pending |
| N-1 | `NETWORK_SEND_RESULT` | Raw local call result from one merged kretprobe frame; no peer receipt claim | Adapter and one scoped WSL2 live policy smoke test passed; supported Linux kernel matrix remains pending |

---

## 14. Provenance Status Summary

| Family | Name | Mapping Correct | Semantics Complete | Hooks Documented | L3 Available |
|---|---|---|---|---|---|
| 1 | `PROCESS_EXEC` | ✅ | ✅ | N/A (direct) | ✅ |
| 2 | `PROCESS_EXIT` | ✅ | ✅ | N/A (direct) | ✅ |
| 3 | `FILE_OPEN_ATTEMPT` | ✅ | ✅ | ✅ §5.1 | ❌ TracingPolicy needed |
| 4 | `FILE_OPEN_RESULT` | ✅ | ✅ corrected | ✅ §5.2 | ❌ TracingPolicy needed |
| 5 | `FILE_READ` | ✅ | ⚠️ high-frequency risk | ✅ §5.3 | ❌ TracingPolicy needed |
| 6 | `NETWORK_CONNECT_ATTEMPT` | ✅ | ✅ | ✅ §5.4 | ❌ TracingPolicy needed |
| 7 | `NETWORK_CONNECT_RESULT` | ✅ | ✅ | ✅ §5.5 | ❌ TracingPolicy needed |
| 8 | `NETWORK_SEND_ATTEMPT` | ✅ | ⚠️ msghdr limitation | ✅ §5.6 | ❌ TracingPolicy needed |
| 9 | `NETWORK_SEND_RESULT` | ✅ | ✅ Profile A | ✅ §5.6, §12 | ✅* Scoped WSL2 policy smoke only |
| 10 | `SOCKET_STATE_CHANGE` | ✅ corrected | ✅ | ✅ §5.7 | ❌ TracingPolicy needed |
| 11 | `IDENTITY_CHANGE` | ✅ | ⚠️ before-state limitation | ✅ §5.8 | ❌ TracingPolicy needed |
| 12 | `CAPABILITY_CHECK` | ✅ | ✅ authorization-check semantics | ✅ §5.9 | ✅* Scoped WSL2 policy smoke only |
| 13 | `EVENT_LOSS` | ✅ corrected | ✅ Profile C defined | N/A (synthetic) | ✅ (Sentinel-generated) |
| 14 | `SENSOR_HEALTH` | ✅ | ✅ Profile C defined | N/A (synthetic) | ✅ (Sentinel-generated) |

Legend: ✅ Complete | ⚠️ Limitation documented | ❌ Not yet available

### 15. Scoped Live Kprobe Smoke Evidence

On 2026-11-03, the manual test in `scripts/manual/tetragon-kprobe-smoke.js` loaded a temporary Tetragon v1.8.0 policy for `tcp_sendmsg` with `return: true`, the labels `sentinel_socket` / `sentinel_size`, and a selector requiring both the test process's namespace PID and the exact test binary path. The policy used `Post` only. A local HTTP request to `127.0.0.1` produced a raw protobuf event with both labels, a return value, process `exec_id`, and `NETWORK_SEND_RESULT` normalization (170 requested / 170 locally accepted bytes). Tetragon reported the hook as loaded; the script deleted the policy and verified that it was absent from `ListTracingPolicies` afterward.

Also on 2026-11-03, `scripts/manual/tetragon-capability-smoke.js` loaded a PID- and binary-scoped `Post` policy for `cap_capable`, then triggered a real `setuid(65534)` from a root child process. Tetragon emitted `CAP_SETUID` (value 7) with return 0. Sentinel normalized the raw protobuf bytes, materialized `CAPABILITY_CHECK`, verified the full v2 key/schema, and removed the temporary policy. The captured frame had complete process identity; a separate test fixture exercises the partial PID/start-time profile when Tetragon omits `exec_id` and binary.

This confirms one hook on WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`. It does not validate the other kprobe hooks, other Linux distributions/kernels, production event rates, or complete loss accounting.

---

**End of `SPEC-EVENT-V2-PROVENANCE-R1.4`**
