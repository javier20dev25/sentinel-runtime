# SR-RT-001 — Local Runtime resilience lab

**Date:** 2026-11-13
**Environment:** Ubuntu on WSL2, kernel 6.18.58.1-microsoft-standard-WSL2, Tetragon v1.8.0
**Purpose:** bounded, local validation of overload reporting and basic process self-recovery
**Result:** partial. The test demonstrated loss reporting and systemd restart behavior; it did not establish complete attack-event capture.

## Scope and safety

The exercise ran only on the local lab host, under an unprivileged Runtime account for the synthetic process load. It used a bounded temporary canary, process-execution argument spoofing via argv[0], and loopback connections only. It did not connect to an external host, execute a malware sample, change customer data, or attempt privilege escalation.

The host Runtime API key was left in place and not read, printed, rotated, or revoked. Cloud response after the forced restart was not confirmed because the heartbeat request timed out.

## Exercise record

### Bounded event load

The Runtime resilience runner generated 2,000 file-read operations, 16 child executions with a deceptive argv[0], and 16 loopback connection attempts. The exercise completed in approximately 0.697 seconds.

Tetragon counters changed during the run:

| Counter | Before | After | Delta |
|---|---:|---:|---:|
| notify overflowed events | 16,557,684 | 16,574,144 | +16,460 |
| observer ring-buffer queue events lost | 33,666 | 47,882 | +14,216 |
| observer ring-buffer events lost | 0 | 0 | 0 |
| exec-hook miss counter | unchanged | unchanged | 0 |

Runtime persisted EVENT_LOSS records and reported degraded observability. This confirms visibility of measured Tetragon loss counters; it does not mean Runtime recovered dropped events.

The script completed the argv[0] spoof child and loopback activity. However, querying the recent Runtime ledger did not produce reliable matches for all synthetic child PIDs or the temporary canary path. Therefore this run does not prove complete capture or detection of the generated process sequence. Counter totals also include the long-running lab host and are not attributable exclusively to this single exercise.

### Runtime process termination and restart

The Runtime main process was deliberately sent SIGKILL once. systemd Restart=on-failure started a new process. Tetragon v1.8.0 reconnected and Runtime preserved the previous observation state as degraded/unknown because the gRPC stream has no replay cursor.

After restart, the ledger verifier reported valid across 6,877 records. The result had no external timestamp anchor. A Cloud heartbeat attempt after restart timed out, so the test does not verify the Cloud-side stale-agent alert or heartbeat recovery.

### Installation permission audit

The active /opt/sentinel-runtime tree was root-owned but had mode 0777 directories and files. Any local account could replace or unlink Runtime files. The lab tree contained no symlinks during the check. Permissions were normalized to root-owned 0755 directories and 0644 files, with 0755 restored for the bundled Node binary and CLI entrypoint; the local state directory remained 0700 owned by sentinel-runtime. Running write checks as sentinel-runtime then failed for both the install directory and Runtime source.

A first blanket permission normalization also removed execute permission from the bundled Node binary and caused systemd start failures (203/EXEC). The binary execute bit was restored, the failed unit state reset, and Runtime returned to active. This was an operator correction during the lab, not a Runtime self-detection feature. The deployment guide now uses removal of group/other write bits while preserving executable bits and requires a post-install audit.

## Regression found and corrected in source

The live run produced 88 rejected FILE_OPEN_RESULT records because the materializer required an absolute pathname. Linux openat2 accepts relative operands interpreted with dirfd. The Event Contract v2 candidate on the feature branch (not the published `master` build used below) now retains the raw path, path_form (ABSOLUTE, RELATIVE, EMPTY), and dirfd without fabricating an absolute path. Runtime marks unresolved relative paths for review and does not learn or correlate them as confirmed sensitive-path access. Unit and contract tests cover this mapping. A new live sensor run with the updated feature-branch build is still required to verify those records end to end; the published `master` build still rejects relative open-result paths.

## Reproduction

Run only in a disposable WSL2/Linux laboratory. Review scripts/manual/runtime-resilience-lab.py and the systemd/proxy configuration first. The script requires an explicit confirmation environment variable and refuses unsafe bounds. Do not run it on production hosts.

After a run, compare Tetragon counters before/after, inspect Runtime EVENT_LOSS and SENSOR_HEALTH records, verify the ledger, and correlate each generated PID and canary path. Report unmatched actions as coverage gaps; do not infer detection from a process name, rule name, or nonzero event count.

## Limits and next steps

- No native Linux distribution was tested; WSL2 is not a certification target.
- No proof of external connectivity or data exfiltration was attempted; all network traffic stayed on loopback.
- The tests did not attempt kernel compromise, BPF program tampering, credential theft, or destructive containment.
- The local ledger has no external anchor, and local disk retention is not bounded.
- Repeat the lab after deploying the relative-path correction and require exact event/PID matching before calling the deception test detected.

## Follow-up — 2026-11-14: stream abuse and shutdown under load

This follow-up exercised the Runtime proxy and collector shutdown path on the same disposable WSL2 host. The Runtime API key file remained present with root ownership and mode `0600`; its contents were not read, printed, rotated, or changed.

### Read-only proxy stream exhaustion

With the updated proxy running, the Runtime service's existing Tetragon event stream stayed open while a second local `GetEvents` request was issued under the Runtime account. The proxy rejected the second request with gRPC `RESOURCE_EXHAUSTED` (code 8) and did not create another upstream Tetragon stream. After cancelling the first stream, a replacement stream was accepted. This verifies the one-active-event-stream gate in this local setup; it does not protect a compromised root account or prevent a process with the socket permission from repeatedly reconnecting and consuming the permitted slot.

### Service resource ceilings

The active systemd units reported these effective limits:

| Service | MemoryHigh | MemoryMax | CPUQuota | TasksMax | LimitNOFILE | OOMPolicy |
|---|---:|---:|---:|---:|---:|---|
| `sentinel-runtime.service` | 512 MiB | 768 MiB | 200% | 64 | 8192 | `stop` |
| `sentinel-runtime-proxy.service` | 256 MiB | 384 MiB | 100% | 32 | 2048 | `stop` |

These are resource containment ceilings, not a guarantee that the process remains available when a ceiling is reached. A memory kill or enforced CPU limit may interrupt telemetry; health and loss state must therefore be treated as part of the security signal.

### Bounded synthetic load and graceful stop

A local, unprivileged bounded run performed 5,000 canary-file reads, started 16 children with a deceptive `argv[0]`, and made no loopback transfer. It completed in about 0.629 seconds. This was synthetic activity only; there was no external destination, credential access, exploit payload, or privilege escalation.

While queued Tetragon events from the run were still being processed, the updated Runtime was stopped through systemd. The stop completed in approximately 11 seconds, below the 15-second unit timeout, and systemd reported a successful stop without SIGKILL. Runtime wrote `COLLECTOR_SHUTDOWN_QUEUE_DISCARD` for a lower bound of 158 queued events and 104,553 bytes, then `COLLECTOR_STOPPED`. It restarted successfully and reported observability as degraded because the non-replayable stream leaves a gap of unknown completeness.

The collector now yields to the event loop during sustained delivery so shutdown signals can be handled. On shutdown it persists already processed pending records, discards the remaining in-memory queue, and records the discard lower bound. The reported lower bound does not count events lost earlier in Tetragon or records still in flight outside Runtime's queue.

### Process-execution capture on the published master build

A follow-up run used the published `master` build (`35f1029`) against the direct Tetragon socket with `--capture-process-arguments` and the exact policy `sentinel-runtime-observability`. The collector was started first and the test waited for the ledger's `STREAM_CONNECTED` record before generating activity. On this host the stream took about 19.5 seconds to connect; activity generated before that point falls outside the documented `LIVE_EVENTS_AFTER_CONNECTION_ONLY` coverage.

After `STREAM_CONNECTED`, five `sleep 1` children were started with a deceptive `argv[0]` (`exec -a sentinel-diag-master-20261114-N /bin/sleep 1`). The ledger contains five `/bin/bash` `PROCESS_EXEC` records carrying the marker in `arguments_raw` (PIDs 11717-11721), five `/bin/sleep` `PROCESS_EXEC` records for the same PIDs with `arguments_raw` `"1"`, and 13 `PROCESS_EXEC` records in total for the window.

The collector summary reported `received 352`, `persisted 352`, `supported 341`, `unsupported 11`, `rejected 0`. The only shutdown loss was a lower bound of 2 queued events (1,976 bytes). A separate 100-exec burst did not increase `bpf_missed_events{Execve}` on this host, although those counters are host-wide and are not per-test proof.

This resolves the earlier execution-capture discrepancy as a test-sequencing error: the synthetic process had been generated before the collector's stream was connected. It does not prove capture before connection, does not establish exact argv boundaries, and has no external timestamp anchor. `--capture-process-arguments` yields `arguments_capture_status: RAW_STRING_ONLY` with `argv: null` because the pinned Tetragon gRPC field is a raw joined string; the deceptive `argv[0]` is preserved in the parent shell's `arguments_raw`, not in the final `sleep` record.

The remaining execution-coverage gate is therefore the documented live-only coverage window, argument-capture fidelity, and measured sensor-side loss, not a missing `PROCESS_EXEC` in the published build. Do not infer detection or evasion from exporter totals alone.

### Security behavior and remaining boundary

These changes make local stream multiplication and resource exhaustion harder, and make shutdown loss visible. Runtime's current response remains defensive and non-retaliatory: preserve available evidence, report degraded coverage, reconnect under systemd, and submit only fixed, bounded read-only investigation tasks when configured. It does not execute arbitrary attacker commands, kill the suspected process, isolate networking, or “attack back.” A root or kernel-level attacker can still stop/replace Runtime, Tetragon, their configuration, and local evidence; independent remote health monitoring and evidence custody are needed to detect that boundary being crossed.
