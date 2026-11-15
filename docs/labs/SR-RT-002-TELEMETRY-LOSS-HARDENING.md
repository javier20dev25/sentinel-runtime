# SR-RT-002 — Telemetry-loss hardening lab

**Date:** 2026-11-14
**Environment:** Ubuntu on WSL2, kernel `6.18.58.1-microsoft-standard-WSL2`, Node `v22.23.4`, Tetragon `v1.8.0`
**Result:** pass for the scoped telemetry-loss lab. This is not a production certification and does not prove complete event capture.

## Scope and safety

The exercise ran on a disposable WSL2 lab host. It generated bounded synthetic file opens only. No file content was printed, no external connection was made, no credential was read, and no containment or privilege-escalation action was attempted. The Runtime API key was not read or changed. Synthetic activity was limited to local files whose paths are already listed in the lab policy.

The host Runtime and Tetragon services remained in observe/monitor mode. Existing evidence and the service configuration were not reset. Event-loss conclusions apply only to the measured windows below.

## Changes under test

1. `src/evidence.js`
   - `verifyIntegrity()` now reads the ledger in `1000`-row pages instead of loading the whole table with `.all()`.
   - Source-checkpoint lookup uses an indexed `source_checkpoint` key and `LIMIT 1`.
   - Event deduplication uses separate indexed v2 and legacy key queries instead of a full scan with `OR`.
   - Added `evidence_source_checkpoint_source_id`.
2. `packaging/tetragon/sentinel-runtime-observability.yaml`
   - `do_sys_openat2` is filtered in-kernel to an explicit sensitive-path prefix set.
   - `vfs_read` is limited to `/usr/bin/python3`, `/usr/bin/python3.12`, `/usr/bin/dash` and the same sensitive-path set.
   - `tcp_sendmsg` is limited to the same interpreter binaries.
   - The policy remains monitor-only and does not authorize containment.
3. `test/engine.test.js`
   - Added a regression test that verifies a chain larger than one pagination window.

## Validation matrix

### Clean source test suite

A clean copy of the release candidate was created under `/tmp` with the repository's dependencies and no live state. `npm test` completed with:

| Metric | Result |
|---|---:|
| Tests | 284 |
| Passed | 284 |
| Failed | 0 |
| Skipped | 0 |
| Duration | ~6.3 s |

### Policy load

`tetra tracingpolicy list -o json` reported:

- policy `sentinel-runtime-observability`
- state `TP_STATE_ENABLED`
- mode `TP_MODE_MONITOR_ONLY`
- hooks `do_sys_openat2`, `vfs_read`, `tcp_v4_connect`, `tcp_v6_connect`, and `tcp_sendmsg` all `STATUS_LOADED`
- selector-indexed statistics present for `do_sys_openat2` and `tcp_sendmsg`

The policy is a static Tetragon `TracingPolicy`. Editing it requires a Tetragon restart; in this lab a delete/re-add attempt did not hot-reload the existing policy. Restart Tetragon only during a controlled maintenance window and re-check the loaded state afterward.

### Non-sensitive file-open control

Baseline ledger sequence was `269468`. A single `python3` process performed 5,000 opens of `/etc/hostname`, read one byte per descriptor, and closed it. The run completed in `0.085 s`.

| Observation | Result |
|---|---:|
| Synthetic non-sensitive opens | 5,000 |
| Ledger records in window | 69 |
| `FILE_OPEN_RESULT` records | 8 |
| New `EVENT_LOSS` records | 0 |

The eight file-open records are background host activity, not the 5,000 synthetic opens. The synthetic non-sensitive opens did not produce a corresponding 5,000-record flood.

### Sensitive file-open load

Baseline ledger sequence was `269537`. The same interpreter performed 1,000 opens/read-one-byte/close cycles on `/etc/passwd`; `dash` performed 500 redirection opens of `/etc/passwd`. The Python phase completed in `0.107 s`.

| Observation | Result |
|---|---:|
| Synthetic sensitive opens | 1,500 |
| Ledger records in window | 1,546 |
| `FILE_OPEN_RESULT` records | 1,506 |
| New `EVENT_LOSS` records | 0 |

The 1,506 file-open records include the 1,500 synthetic sensitive opens plus background activity. The filtered policy retained the sensitive-path operations instead of suppressing them.

### Tetragon counters

Counters were sampled before the load and after the load. Values are host-wide and include background activity.

| Counter | Before | After | Delta |
|---|---:|---:|---:|
| `tetragon_observer_ringbuf_events_received_total` | 2,358 | 9,108 | +6,750 |
| `tetragon_observer_ringbuf_events_lost_total` | 0 | 0 | 0 |
| `tetragon_observer_ringbuf_queue_events_lost_total` | 0 | 0 | 0 |
| `tetragon_notify_overflowed_events_total` | 0 | 0 | 0 |

No sensor-side loss or listener-buffer overflow was observed in this window.

### Ledger integrity

`verify-ledger` returned `valid: true` across `271,372` records after the load and restart. `external_anchor` was `false`, as expected for the local lab ledger.

### Restart and post-restart capture

`sentinel-runtime` was restarted through systemd. The command returned in `0.8 s`, but the collector emitted `COLLECTOR_STARTED` and `STREAM_CONNECTED` about `125 s` after the service start timestamp. Automation must wait for `COLLECTOR_STARTED`, not only for the systemd command to return.

After restart:

- the service was `active (running)`;
- the collector restored checkpoint sequence `271362` and reported `replay_supported: false`;
- observability remained `DEGRADED` with reason `COLLECTOR_RESTART_PRIOR_OBSERVABILITY_DEGRADED`, because the stream has no replay cursor;
- a 1,000-open sensitive-path run produced `1,006` `FILE_OPEN_RESULT` records in a 1,046-record window;
- the window contained `0` new `EVENT_LOSS` records;
- the service reported no OOM; memory was approximately `89.6 MiB` after restart, with a prior observed peak near `514 MiB` against `MemoryHigh=512 MiB` and `MemoryMax=768 MiB`.

The post-restart result confirms that the collector resumed live capture after the restart. It does not recover events produced during the gap.

## Interpretation

Within the measured lab window:

- the in-kernel path filter prevented the 5,000 non-sensitive opens from turning into a 5,000-event flood;
- sensitive-path opens remained observable;
- the collector did not record new `EVENT_LOSS` during the load or restart windows;
- the ledger remained verifiable after the load and restart;
- the paginated verifier avoided the earlier whole-table load pattern.

The lab does not establish:

- complete capture of every event on the host;
- detection or attribution of malicious intent;
- coverage for paths or binaries outside the configured sets;
- protection from root/kernel compromise or Tetragon policy tampering;
- replay of events lost during collector downtime;
- production behavior across native Linux distributions.

## Operational notes

- The path list in the policy is a lab baseline, not a complete sensitive-data inventory. Tune it to the workload before deployment.
- The binary allow-list for `vfs_read` and `tcp_sendmsg` is intentionally narrow. Other interpreters and file readers will not produce those records unless added.
- Static policy changes require a Tetragon restart and a post-restart check of `tetra tracingpolicy list`.
- Startup is not complete when `systemctl restart` returns. Wait for `COLLECTOR_STARTED` before sending validation traffic.
- The local ledger has no external anchor and no retention/quota guarantee.
- Keep the service in observe-only mode; no enforcement was tested or enabled.

## Rollback

The lab deployment backup is under `/var/backups/sentinel-runtime/hybrid-20261114T173520`. A rollback should restore the prior policy and Runtime source, restart Tetragon and `sentinel-runtime`, then verify the loaded policy and ledger. Do not delete the live evidence database in place; preserve it for custody review.

## Reproduction outline

1. Run the source test suite from a clean copy of the candidate tree.
2. Confirm the policy is enabled and all hooks are loaded with `tetra tracingpolicy list -o json`.
3. Record the current ledger maximum sequence and Tetragon loss counters.
4. Generate a bounded non-sensitive control load and a bounded sensitive-path load.
5. After allowing the collector to drain, query the new ledger window for event types and `EVENT_LOSS`.
6. Restart the collector, wait for `COLLECTOR_STARTED`, repeat a bounded sensitive load, and run `verify-ledger`.
7. Treat host-wide counters and background activity as context, not per-test attribution.
