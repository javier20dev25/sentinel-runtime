# Sentinel Runtime implementation status

**Status date:** 2026-11-04
**Authority:** describes behavior present in this repository. Design specifications describe intended behavior and do not establish that a feature is implemented. Event Contract v2 candidate SHA-256: `40ff2d683cb3efd81376cc136af6e4d8afc0ea4d934a9745dec4f2c479a838fa`; frozen Event Contract v1 SHA-256: `8c58cd9661eb3e192d89a3480572486fd96fe24f5bdb3219e3053a807515cfe9`.

## Implemented

- Observe-only Node.js library and CLI.
- Bounded deterministic process correlation keyed by host, boot, and opaque process execution ID.
- Exact path/digest binary rules, lexical sensitive-path checks, and hostname/IPv4 destination rules.
- Tetragon JSONL ingestion for `process_exec`, `process_exit`, and supported selected kprobes. Supported records are complete, schema-validated Event Contract v2 objects; unsupported and rejected records remain explicit.
- Optional immutable-file checkpointing. Event rows and byte offsets commit atomically in the SQLite evidence chain. Resume verifies source identity and full content hash; a completed source does not ingest twice.
- Persistent source-event-key deduplication inside the SQLite write transaction. Repeated valid 64-hex keys are suppressed across batches and process restarts; the first stored projection wins, and JSONL/gRPC report suppressed counts. This does not provide upstream replay or exactly-once delivery.
- Tetragon gRPC streaming using upstream protobuf files pinned to tag `v1.8.0`. The client checks `GetVersion`, accepts the default local Unix socket, and requires CA-verified TLS for TCP. Optional mTLS and pre-persistence node-name verification are supported.
- Optional Linux gRPC gateway connects upstream to Tetragon but registers only `GetVersion` and `GetEvents` downstream. Its client endpoint is an absolute Unix socket with owner read/write by default, optional owner/group access, no auto-removal of pre-existing paths, umask checks, and inode-checked cleanup. It forwards exact upstream protobuf bytes (including unknown fields) so evidence hashes remain tied to the provider frame. The gateway still requires privileged upstream socket access and is not an upstream Tetragon authorization policy.
- Raw protobuf response hashes, per-stream local sequence checkpoints, explicit unsupported native event records, and Tetragon `RateLimitInfo` mapping to `sensor_throttle` telemetry.
- Deterministic normalization for selected exact Tetragon v1.8.0 kprobe shapes: `do_sys_openat2` (attempt/result), `vfs_read`, `tcp_v4_connect`/`tcp_v6_connect` (attempt/result), `tcp_sendmsg` (attempt/result), and `cap_capable` (return result only). The adapter requires unique `sentinel_*` argument labels because Tetragon preserves TracingPolicy argument-list order rather than function index. Return probes use Tetragon's merged `ProcessKprobe` arguments and return as one raw provider event. Mapped values are bounded and conservative: no fd is inferred, `open_how` pointer contents are not guessed, positive send return means local stack acceptance only, and `cap_capable` is an authorization check rather than a privilege change.
- Shared v2 materialization for native `PROCESS_EXEC`, `PROCESS_EXIT`, and supported kprobe events on both JSONL and gRPC paths. Each event receives a verified source key, exact source payload hash/cursor, distinct source and observation timestamps, explicit workload/identity availability, and all 12 loss domains. Full Tetragon execution IDs use Profile A; events with missing `exec_id` use the explicit PID/start-time Profile D, remain `PARTIAL_RECONSTRUCTED`, and are not process-correlated. Event Contract v2 R1.4 remains a draft.
- Process arguments are redacted by default; the `--capture-process-arguments` opt-in preserves a bounded raw Tetragon string and never invents `argv`. Environment variables are never persisted by the current collectors. The contract marks provider-present fields as redacted.
- Explicit live kprobe and capability smoke scripts plus fixture generation live under `scripts/manual/`, outside Node test auto-discovery. The sensor smokes install temporary policies and require privileged Tetragon access; the fixture generator writes into `test/fixtures`.
- Non-mutating live proxy smoke under `scripts/manual/`: connected to Tetragon v1.8.0 via the gateway, forwarded up to five frames, and verified that `GetHealth` returned `UNIMPLEMENTED`.
- Optional Tetragon v1.8.0 Prometheus polling tied to a gRPC-verified sensor version. The parser verifies the pinned counter types, aggregates label series, hashes exact response bytes, bounds response size/time, and atomically commits `SENSOR_HEALTH`/positive-delta `EVENT_LOSS` events with checkpoints.
- Loopback-only unauthenticated HTTP and TLS-verified HTTPS metrics transports, optional mTLS client credentials, strict v2 event validation, and durable counter baselines. Counter resets, missing baselines, absent metrics, and scrape errors remain `UNKNOWN`/`UNAVAILABLE`, not zero.
- gRPC queue bounded by both message count and payload bytes, with backpressure and explicit lower-bound overflow reporting. Intentional `--max-events` termination reports any queued events it leaves behind.
- v1 compatibility validation and draft v2 event schema with provenance and semantic validation.
- Local SQLite evidence ledger with canonical JSON, SHA-256 hash chain, atomic event/checkpoint transactions, and local verification.
- Hardened systemd units for separate Linux proxy and collector accounts. The collector defaults to the filtered Unix socket and requires the proxy service; only the proxy account receives site-specific upstream Tetragon socket access. Both units restrict capabilities/address families and the collector uses a private writable state directory. Production distribution validation remains open.

## Explicitly not implemented

- Production Linux distribution/kernel/policy matrix validation. One actual Tetragon v1.8.0 WSL2 smoke run is recorded below; loopback gRPC tests exercise the client path but are not kernel integration tests.
- Upstream Tetragon server-side least-privilege authorization for its gRPC API. The local gateway restricts its downstream RPC surface, while its own process still has the upstream permissions it is granted. Remote endpoints still require server-enforced client authentication and network restrictions. See the [Tetragon threat model](https://tetragon.io/docs/threat-model/) and [gRPC TLS guidance](https://tetragon.io/docs/installation/grpc-tls/).
- Managed installation/upgrade, Kubernetes operator, fleet health monitor, or remote collector management. The two systemd templates are operator-installed and have not been production-validated across a supported distribution matrix.
- Upstream replay, delivery acknowledgements, or exactly-once semantics for a live gRPC stream. The local sequence is scoped to a stream epoch; gaps on reconnect remain `UNKNOWN`.
- Complete loss accounting across all Sentinel and Tetragon domains. While Sentinel requests no `aggregation_options`, the optional aggregation-buffer loss domain is `NOT_APPLICABLE`; enabling aggregation later requires a verified counter. Other Sentinel-side transport gaps, parser rejects, local queue overflow, and storage failures remain separately surfaced and are not inferred from the Tetragon metrics endpoint.
- Normalization of Tetragon tracepoints, identity hooks, and other kprobe symbols. Only the exact kprobe symbols listed above are currently normalized; compatible live TracingPolicy shapes and supported-kernel behavior still need validation.
- Live capture and conformance across all supported kprobe policies, kernels, Linux distributions, and Tetragon releases beyond the scoped v1.8.0 WSL2 smoke test. The current smoke covers one `tcp_sendmsg` return hook.
- External signing, protected key custody, remote ledger anchoring, multi-tenant access control, or an authenticated alert pipeline.
- Host prevention. Severity labels are observations; they do not signal, freeze, isolate, or kill anything.
- Cross-process taint propagation or proof that bytes read from a sensitive file reached a network peer.

## Evidence and limitations

On 2026-11-03, the collector connected to the running Tetragon v1.8.0 daemon in WSL2 over its Unix socket. The bounded live run received and committed 8 protobuf events, normalized all 8, and reported 0 unsupported events, 0 rejected events, and 0 local queue drops. The SQLite ledger was in-memory for this smoke run. This validates the tested WSL2 daemon and API path only; it does not validate other kernels, policies, transports, or loss-counter completeness. No `RateLimitInfo` report arrived in this short sample, which is not evidence that sensor or kernel loss was zero.

Also on 2026-11-03, the manual kprobe smoke test loaded a temporary Tetragon v1.8.0 `tcp_sendmsg` return policy on WSL2 kernel `6.18.54.1-microsoft-standard-WSL2`, captured loopback `ProcessKprobe` records with the expected labels and process execution ID, and materialized a schema-valid `NETWORK_SEND_RESULT` with 170 requested and 170 locally accepted bytes. Tetragon reported the hook `STATUS_LOADED`; the script deleted the temporary policy and confirmed no policy remained. This is one hook on one WSL2 kernel and does not close the supported-kernel or policy matrix.

The live read-only proxy smoke connected to the same Tetragon v1.8.0 daemon, returned the pinned version, forwarded five event frames with raw protobuf bytes retained, and rejected `GetHealth` with gRPC `UNIMPLEMENTED`. It did not invoke a mutating Tetragon RPC. A separate loopback integration test appends an unknown protobuf wire field and verifies byte-for-byte preservation through the proxy.

Following Phase 001C remediation and test-discovery hardening, the Windows test suite passes **224/226** with **2 Linux-only tests skipped** and no failures. Under the current host environment, WSL2 invokes Windows `node.exe` through interop (`process.platform === 'win32'`), which executes the same 224 passed and 2 skipped; native Linux execution (`process.platform === 'linux'`) remains pending native guest Node.js provisioning. `systemd-analyze verify` accepted both units using temporary placeholder executable and account values because WSL does not have `/usr/bin/node` or the dedicated service accounts; the production units have not been installed or started on a supported Linux distribution. The synthetic v1.8.0 throughput runs and their limits are recorded in [`SR-GRPC-002`](benchmarks/SR-GRPC-002.md).

Event Contract v2 remains an unapproved candidate (SHA-256: `40ff2d683cb3efd81376cc136af6e4d8afc0ea4d934a9745dec4f2c479a838fa`), pending independent review. Requirements S-1 through S-6, Profile D (`RAW_PARTIAL_PROCESS_EVENT` — strictly provisional), canonical uint64 decimal-string validation, and transport-separated cursors (`FILE_BYTES` vs `GRPC_SEQUENCE`) are implemented in the candidate schema and verified by the production validator. Native event materialization passes the strict v2 validator on both ingestion paths. Exploratory observations under `scripts/manual/` (`tcp_sendmsg` and `cap_capable` on one Tetragon v1.8.0 WSL2 kernel) are micro-benchmark checks only and do NOT constitute formal L3 sensor evidence. Provenance matrix gate remains `REOPENED — BLOCKED`. Phase 001D (live sensor validation) and Phase 001E (durable queue) have not started and remain unauthorized.

The live WSL2 Tetragon service currently has no metrics listener configured. The metrics poller is therefore covered by deterministic parser/ledger tests but has not yet been exercised against that live daemon. Tetragon's non-Kubernetes metrics server is disabled by default; this repository does not silently restart or reconfigure the running sensor.

The v2 family fixtures are synthetic contract examples, not captured kernel events. Passing schema tests proves only that the examples match the current schema and semantic checks. The loopback gRPC fixture verifies wire decoding, version gating, raw payload hashing, loss telemetry, bounded queue behavior, and ledger commits. The two WSL live kprobe smokes validate only `tcp_sendmsg` and `cap_capable` on one kernel; they do not prove that a target kernel and tracing policy emit every field in production.

JSONL checkpoint guarantees apply to one source fingerprint and one evidence ledger. The input is hashed before processing and verified again before marking the checkpoint complete. A mismatch is rejected and leaves the checkpoint incomplete. Local SQLite transactions protect each event batch and its cursor from diverging after a process crash. Equal valid source keys are transactionally deduplicated; the first persisted projection wins. Synthetic profile keys identify individual emissions, so equal observations emitted under distinct producer sequence values are not deduplicated by key equality. A privileged attacker can still alter the database and recompute its local hash chain.

The live gRPC collector checkpoints only the last locally committed receive sequence inside a stream epoch. Tetragon `GetEvents` provides no resume cursor or acknowledgement, so the checkpoint cannot recover events that the server never delivered. Any disconnect is therefore accompanied by an `UNKNOWN` stream-gap state. Queue overflow is separately counted as a lower bound.

The local hash chain detects edits that do not recompute the chain. A privileged host attacker can replace the database and recompute it. Evidence is not independently tamper-proof without an external anchor and protected key custody.

## Production gates

Before enterprise rollout, close and independently review at least these gates:

1. Package and install the systemd template on pinned Linux distributions, architectures, and supported kernels; validate the live gRPC fields and socket/TLS identity across the supported Tetragon v1.8.0 matrix.
2. Enable the pinned Tetragon metrics endpoint on loopback and run live counter-delta/restart tests. Keep Tetragon aggregation disabled for the current collector contract; if aggregation is introduced, first add and validate an upstream drop counter against a real v1.8.0 build.
3. Define and test a live-stream gap policy. The current gRPC API cannot replay or acknowledge events; the local checkpoint and new health events expose, but cannot recover, events missed before connection or during disconnect.
4. Add protected signing, key rotation/custody, external ledger anchoring, retention controls, and export verification.
5. Add tenant isolation, authenticated policy delivery, RBAC, and audited operator access.
6. Run adversarial E2E tests and resource-ceiling benchmarks on pinned hosts with sanitized, labeled real traces. Report false positives and false negatives separately from throughput.
7. Conduct a separate safety review before any active enforcement implementation; enforcement is outside this repository's current behavior.

## Historical specifications

`docs/specs/SPECIFICATION_CROSS_VALIDATION_001.md`, `CAUSAL_CORE_V1.md`, `EVENT_CONTRACT_V1.md`, and architecture/threat-model documents contain proposed target behavior. Tables that mention `ISOLATE_NETWORK`, `SUSPEND_PROCESS`, or `TERMINATE_PROCESS` describe design proposals; this runtime does not implement those actions. The Event Contract v2 provenance matrix remains a draft and needs live sensor validation.
