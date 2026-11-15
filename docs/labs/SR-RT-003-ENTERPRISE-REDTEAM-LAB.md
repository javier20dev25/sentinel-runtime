# SR-RT-003 - Enterprise-style red-team lab

**Date:** 2026-11-14
**Environment:** Ubuntu on WSL2, kernel `6.18.58.1-microsoft-standard-WSL2`, Node `v22.23.4`, Tetragon `v1.8.0`, Sentinel Runtime `v0.2.0`
**Result:** partial. A simulated application-account compromise succeeded before and after Sentinel Runtime was enabled. Runtime produced a partial audit trail but did not prevent, block, or contain the action. This is expected for the current observe-only release.

## Scope and safety

The exercise was a controlled, disposable WSL2 lab. It did not use a real credential, malware, exploit chain, external C2, or non-loopback traffic. The test canaries were synthetic strings owned by dedicated lab accounts. The "compromise" is the ability of the compromised application account to read its own canary, send it to a loopback listener, and create a non-active marker file. It is not host root compromise.

The lab did not read, print, rotate, or revoke the Runtime Cloud API key. Existing evidence was not reset. Tetragon and Runtime remained in monitor/observe mode.

Runtime was already installed on the host. The baseline was produced with Tetragon, the read-only proxy, and Runtime stopped, so this is an enablement comparison rather than a pristine-machine install.

## Enterprise baseline before the attack

The baseline was treated as a small hardened server, not as a developer workstation. The following controls were checked.

| Control | Observed state | Action |
|---|---|---|
| Runtime install ownership | `/opt/sentinel-runtime` root-owned | retained |
| Runtime install write mode | 49 paths were group/other-writable, including `bin`, `src`, and package files | corrected to root-owned `0755` directories, `0644` files, executable bits only on `node` and the CLI entrypoint |
| Runtime source ownership | `src/evidence.js` was owned by `sentinel-runtime` | corrected to `root:root` |
| Service accounts | `sentinel-runtime` and `sentinel-tetragon-proxy` use `/usr/sbin/nologin` | retained |
| Privilege | Runtime collector has an empty capability set; proxy is separate | retained |
| systemd sandbox | `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `ProtectKernel*`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality` | retained |
| Resource bounds | collector `MemoryHigh=512M`, `MemoryMax=768M`, `TasksMax=64`, `CPUQuota=200%`; proxy lower limits | retained |
| Kernel hardening | ASLR `2`, `kptr_restrict=1`, `unprivileged_bpf_disabled=2`, `ptrace_scope=1`, protected hardlinks/symlinks enabled | retained |
| Kernel log access | `kernel.dmesg_restrict=0` | set to `1` in `/etc/sysctl.d/99-sentinel-enterprise-lab.conf` |
| SSH | no `sshd` service active | reduces remote surface; not a substitute for firewall policy |
| Host firewall | no `ufw` binary in this WSL2 image | not validated; enterprise gate |
| Synthetic canaries | application canary `0600` owned by `sentinel-lab-app`; root canary `0600` owned by root | created |
| Unprivileged account | `sentinel-lab-attacker`, no sudo group membership | created |
| Compromised application account | `sentinel-lab-app`, no sudo group membership | created |

The world-writable install was a deployment regression after the hybrid redeploy. It is a serious finding: an unprivileged local account could modify the CLI or source before the next service restart. The install was normalized before the attack.

## Attack scenario

The bounded runner is [scripts/manual/enterprise-redteam-lab.py](../../scripts/manual/enterprise-redteam-lab.py). Its environment gate is `SENTINEL_ENTERPRISE_LAB_CONFIRM=sentinel-enterprise-redteam`; it exits for system accounts, exits outside WSL2, and only treats `/etc/passwd` as the sensitive-path marker.

The simulated attacker performs:

1. Reads its own synthetic application canary.
2. Attempts to read a root-only synthetic canary.
3. Opens `/etc/passwd` and reads one byte.
4. Executes `/bin/sh -c` with the run marker in `argv`.
5. Probes `sudo -n true`.
6. Creates a marker file under the account's home directory. The file is not an active persistence mechanism.
7. Sends the application canary to a TCP listener bound to `127.0.0.1` on an ephemeral port.

The same runner was used as `sentinel-lab-app` (simulated compromised application) and as `sentinel-lab-attacker` (unprivileged local user).

## Baseline without Sentinel Runtime

Tetragon, the read-only proxy, and Runtime were stopped. The ledger was queried before and after the attack.

| Observation | Result |
|---|---:|
| Ledger maximum before stop | 274039 |
| Ledger maximum after stop | 274039 |
| Ledger maximum after attack | 274039 |
| New records after attack | 0 |
| Compromised application result | canary read, loopback transfer received, marker created |
| Root canary result | denied |
| Unprivileged attacker result | application and root canaries denied |
| `sudo -n true` | return code `1` |

This confirms the baseline condition: the hardened unprivileged account could not read the application or root canaries, but the simulated compromised application account could read its own canary and exfiltrate it over loopback. With the sensor and Runtime stopped, no audit record was produced.

## Sentinel Runtime enabled

Tetragon, the proxy, and Runtime were started. `COLLECTOR_STARTED` arrived about 110 seconds after the service start timestamp; `STREAM_CONNECTED` followed about one second later. The static policy reported:

- `sentinel-runtime-observability`
- `TP_STATE_ENABLED`
- `TP_MODE_MONITOR_ONLY`
- all five hooks `STATUS_LOADED`

The same simulated compromise was repeated with marker `ENT-SENTINEL-1794703397`.

### Attack outcome

| Observation | Result |
|---|---|
| Application canary | read, 50 bytes |
| Root canary | denied |
| `/etc/passwd` | read, one byte |
| `sudo -n true` | return code `1` |
| Loopback transfer | received 100 bytes on `127.0.0.1:40327` |
| Marker file | created; `active_persistence: false` |
| Attack compromise result | `true` |
| Runtime containment | none; requested action `OBSERVE_ONLY` |

Sentinel Runtime did not stop the attack. The compromise succeeded before and after enablement because this release has no enforcement path.

### Ledger window

The window was sequence `274231` through `274274`:

| Observation | Result |
|---|---:|
| Records in window | 43 |
| `PROCESS_EXEC` | 9 |
| `PROCESS_EXIT` | 13 |
| `FILE_OPEN_RESULT` | 8 |
| `NETWORK_CONNECT_RESULT` | 2 |
| `SENSOR_HEALTH` | 1 |
| `(none)` | 3 |
| `EVENT_CONTRACT_V2_REJECT` | 7 |
| New `EVENT_LOSS` | 0 |
| Marker matches | 4 `PROCESS_EXEC` |
| Threat level | `NORMAL` for all decisions |
| Requested action | `OBSERVE_ONLY` for all decisions |

Three records had no materialized event type (`(none)`); they are counted in the 43-record window. The marker appeared in four process-execution records: the `runuser` parent, `env`, `python3`, and `/bin/sh`. The ledger also recorded eight `/etc/passwd` file-open results and one loopback connection to `127.0.0.1:40327`, the exfiltration destination. The other network connect was the Runtime's local metrics scrape on `127.0.0.1:2112`.

No valid `NETWORK_SENDMSG` or `TCP_SENDMSG` record appeared in the window. Five `process_kprobe` source records were rejected at the contract boundary. The connect is audited; payload/send coverage is not proven.

### Contract rejection

All seven rejections had the same cause:

```text
/process_identity/ruid: must be null; #: must match "then" schema
```

Rejected source types:

| Source type | Rejected records |
|---|---:|
| `process_exec` | 1 |
| `process_exit` | 1 |
| `process_kprobe` | 5 |

This is a materializer/contract gap, not event loss. The rejected events were explicitly recorded as rejections, but their detailed action was not persisted in a valid Event Contract v2 record. The enterprise audit is therefore incomplete.

### Integrity and service state

- `verify-ledger`: `valid: true`, `checked: 274559`, `external_anchor: false`.
- Runtime service: active; `NRestarts=0`.
- Collector memory: about 511.9 MiB current, 514.0 MiB peak, close to `MemoryHigh=512M` and below `MemoryMax=768M`.
- Observability: `DEGRADED`, inherited from the prior collector restart; `replay_supported: false`.
- New `EVENT_LOSS` in the attack window: zero.

## Verdict

| Question | Answer |
|---|---|
| Was the hardened unprivileged account able to compromise the host? | No in this scope: both canaries were denied and sudo failed. |
| Was the simulated compromised application account able to act? | Yes: it read its canary, opened `/etc/passwd`, sent data over loopback, and created a marker. |
| Did Sentinel Runtime stop or contain it? | No. The policy is monitor-only and the decision is `OBSERVE_ONLY`. |
| Did Sentinel Runtime audit it? | Partially. Process execution, sensitive file opens, and the loopback connect were recorded; seven contract rejections and the missing send record leave gaps. |
| Did Runtime classify it as malicious? | No. The recorded decisions were `NORMAL` with no triggered rules. |
| Is the ledger valid? | Yes locally, with no external anchor. |

The correct enterprise description is **audit visibility with known coverage gaps**, not EDR prevention.

## Red-team tooling decision

No external red-team repository or attack framework was cloned for this run. Cloning and executing arbitrary GitHub red-team content would add a supply-chain and host-safety risk to a lab that already had a privileged sensor. The exercise used a first-party bounded runner with explicit confirmation, fixed timeouts, synthetic canaries, and loopback-only traffic.

If an operator later wants Atomic Red Team, CALDERA, or similar tooling, the safe sequence is:

1. Pin a reviewed commit and verify its hash.
2. Use a disposable VM or container with no production credentials.
3. Disable external egress and use a local listener only.
4. Start with one technique at a time and record the exact command.
5. Keep the host sensor in monitor mode until authorization and rollback are reviewed.
6. Treat every technique as untrusted code and scan the tool before execution.

This lab did not execute Atomic Red Team, CALDERA, Metasploit, Cobalt Strike, or a malware sample.

## Reproduce

The runner is intentionally not part of the automated test suite.

```sh
sudo install -d -o root -g root -m 0755 /srv/sentinel-enterprise-lab
sudo install -o root -g root -m 0755 \
  scripts/manual/enterprise-redteam-lab.py \
  /usr/local/sbin/sentinel-enterprise-redteam-lab.py

sudo runuser -u sentinel-lab-app -- \
  env HOME=/home/sentinel-lab-app \
  SENTINEL_ENTERPRISE_LAB_CONFIRM=sentinel-enterprise-redteam \
  python3 /usr/local/sbin/sentinel-enterprise-redteam-lab.py \
  --mode compromised-app --marker ENT-SENTINEL-EXAMPLE \
  --out /tmp/sentinel-enterprise-sentinel-app.json
```

Do not run this on a production host. The lab accounts, canaries, and marker files are disposable test fixtures.

## Limits

- WSL2 is not a production Linux distribution and does not validate SELinux, AppArmor, auditd, or a managed host firewall.
- No external C2, exploit chain, root escalation, credential dumping, or kernel attack was tested.
- No real secret was used.
- The "persistence" marker is not an active persistence mechanism.
- One application account and one attack run were exercised.
- The live-only collector window and the seven contract rejections limit completeness claims.
- The ledger has no external anchor; a privileged host administrator can rewrite it.
- Cloud incident delivery and analyst workflow were not exercised.
- No containment path exists to test.

## Follow-ups

1. Fix the Event Contract v2 `ruid` materialization mismatch so process and kprobe records are not rejected for observed credentials.
2. Decide whether `tcp_sendmsg` should be a supported audit event; if yes, add a conformance fixture and a live test.
3. Make the installer/upgrade path enforce root ownership and non-writable modes, then verify after every deployment.
4. Add a post-install audit to CI or the systemd deployment checklist.
5. Test on a native Linux VM with a host firewall, auditd, and a non-WSL2 kernel.
6. Add a Cloud stale-heartbeat and incident-delivery exercise.
7. Keep enforcement disabled until authorization, rollback, and failure-mode reviews pass.
