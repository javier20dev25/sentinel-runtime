# Sentinel Runtime Linux deployment and host investigation permissions

These units provide an observe-only Tetragon collector, a narrow gRPC proxy, optional local metrics polling, and an opt-in outbound Cloud task client. The task client accepts only fixed `L0_PASSIVE_READ` playbooks. It never invokes a shell, starts a subprocess, sends a signal, changes a file, reads process environment variables, or reads file/network payload content.

## What gets enabled

`sentinel-runtime.service` includes `--investigation-tasks` as an explicit deployment opt-in. Runtime polls Cloud over outbound HTTPS every 15 seconds, claims at most four leased tasks, runs registered procedures, and returns a bounded result to the authenticated Cloud API. No inbound host port is opened. Remove the flag to disable task dispatch; Runtime will advertise task execution as disabled.

Cloud currently dispatches only these host-side L0 playbooks:

| Playbook | Read performed | Important limit |
|---|---|---|
| `LINUX.PROCESS.IDENTITY` | `/proc/<pid>/status`, `stat`, `exe` link, namespace links | Current process snapshot; no argv/environment |
| `LINUX.PROCESS.TREE` | Bounded parent walk through `/proc` | Up to 16 current ancestors; exited parents may be absent |
| `LINUX.PROCESS.HISTORY` | Local Runtime ledger | Historical records retained locally; arguments are never returned |
| `LINUX.NETWORK.SOCKETS` | Target PID file descriptors and namespace socket tables | Current sockets only; no payload capture |
| `LINUX.NETWORK.CONNECTIONS` | Bounded `/proc/net` socket tables, optionally process namespace | Socket row is not proof of transfer or process ownership |
| `LINUX.NETWORK.CONNECTION_HISTORY` | Local Runtime ledger | Attempt/result semantics stay distinct |
| `LINUX.CONTAINER.NAMESPACES` | Namespace links compared with host PID 1 | Namespace differences alone do not prove escape |
| `LINUX.CONTAINER.MOUNTS` | Bounded `/proc/<pid>/mountinfo` | Risk indicators require human validation |
| `LINUX.FILE.METADATA` | `lstat()` on an evidence-derived absolute path | Metadata only; symlink targets are not followed as the final component |
| `LINUX.FILE.ACCESS_HISTORY` | Local Runtime ledger | Historical observations do not prove a successful read |
| `LINUX.SENSOR.HEALTH` | Recent locally recorded health/loss metrics and Runtime process health | Missing metrics remain `UNKNOWN`; no privileged Tetragon query |
| `LINUX.EVIDENCE.VERIFY` | Full local ledger hash-chain recomputation in a worker thread | Agent-reported result; Cloud still needs full custody records to verify independently |

Cloud rejects unknown playbooks, non-L0 governance, synthetic host dispatch, and PID/path/network scopes that are not present in the incident evidence. PID-bound tasks must match the host boot ID. Runtime independently checks the boot ID and confirms that a requested PID/path/destination exists in its own ledger before probing the host. A reboot, PID reuse, stale task, unsupported scope, or missing local evidence fails closed.

## Required Linux setup

1. Install a supported Tetragon release with eBPF enabled for the host kernel. This unit set does not replace Tetragon's vendor service, kernel/BTF requirements, or TracingPolicy deployment.
2. Create dedicated service identities: `sentinel-runtime`, `sentinel-tetragon-proxy`, and the socket access groups used by the proxy. Grant the proxy read access to Tetragon's Unix socket; grant Runtime access only to the proxy socket. Keep the collector away from Tetragon's privileged socket when the proxy is in use.
3. Keep `/etc/sentinel-runtime/sentinel-runtime.env` and `tetragon-proxy.env` root-owned, mode `0600`. Put the host token only in the Runtime environment file. Do not put secrets in unit `ExecStart` arguments.
4. Use `/var/lib/sentinel-runtime/runtime.sqlite` as a persistent, private ledger. The unit's `StateDirectory` creates a `sentinel-runtime`-owned directory with mode `0700`.
5. Keep the Tetragon metrics endpoint on loopback, for example `http://127.0.0.1:2112/metrics`. Runtime rejects plain HTTP metrics endpoints on routable interfaces.
6. Enable Tetragon `--enable-process-cred` and `--enable-process-ns` for credential and namespace context when the installed version supports those flags. Check that exact release's `tetragon --help`; do not replace its vendor unit or discard vendor arguments.
7. Apply the Cloud migration `20261111000001_runtime_investigation_tasks.sql` before expecting Cloud dispatch. Runtime reports executor capability on authenticated polling; Cloud displays dispatch as available only while that capability heartbeat is fresh.

Install the bounded socket permission helper and add it as a Tetragon systemd drop-in. This preserves the vendor unit and its arguments while allowing time for eBPF sensors to load:

```sh
sudo install -o root -g root -m 0755 packaging/systemd/sentinel-runtime-set-tetragon-proxy-access /usr/local/sbin/sentinel-runtime-set-tetragon-proxy-access
sudo install -d -o root -g root -m 0755 /etc/systemd/system/tetragon.service.d
sudo tee /etc/systemd/system/tetragon.service.d/50-sentinel-runtime-proxy-access.conf >/dev/null <<'EOF'
[Service]
TimeoutStartSec=120s
ExecStartPost=/usr/local/sbin/sentinel-runtime-set-tetragon-proxy-access /var/run/cilium/tetragon/tetragon.sock sentinel-tetragon-access 90
EOF
sudo systemctl daemon-reload
sudo systemctl restart tetragon.service
```

Tetragon can take tens of seconds to load eBPF programs before opening gRPC. The helper waits for up to 90 seconds, then gives the socket to the dedicated proxy group with mode `0660`; it never makes the socket world-readable. If the helper fails early, systemd marks Tetragon failed and stops its dependent proxy and Runtime collector. Adjust the socket path and group only to match the host's approved Tetragon socket and proxy account.

### Host credential and service setup

Create the environment file as root and keep the Runtime token out of unit arguments and shell history:

```sh
sudo install -d -o root -g root -m 0750 /etc/sentinel-runtime
sudo install -o root -g root -m 0600 /dev/null /etc/sentinel-runtime/sentinel-runtime.env
sudoedit /etc/sentinel-runtime/sentinel-runtime.env
```

Set the enrolled host values in that file (use the assigned host ID and endpoint; never paste a token into a ticket or log):

```ini
SENTINEL_RUNTIME_API_KEY=snt_rt_<issued-host-token>
SENTINEL_RUNTIME_CLOUD_ENDPOINT=https://<your-sentinel-cloud-host>
SENTINEL_RUNTIME_HOST_ID=<enrolled-host-id>
SENTINEL_RUNTIME_ADDRESS=unix:///run/sentinel-runtime/tetragon-readonly.sock
```

Install the reviewed unit files, then reload systemd. Enable the task-capable Runtime unit only after the Cloud migration is applied and the installed Runtime build contains the task executor; otherwise omit `--investigation-tasks` from `ExecStart` so a not-yet-deployed Cloud API is not polled:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-runtime-proxy.service
sudo systemctl enable --now sentinel-runtime.service
sudo systemctl status sentinel-runtime.service --no-pager
```

The shipped task-capable unit includes `--investigation-tasks`. Remove that argument and restart the service to disable remote investigation polling. Collection and local detection continue; Cloud can no longer request host-side L0 reads. A missing/failing task capability is visible in Cloud as “Runtime not ready”; it must not be repaired by granting broader Linux privileges.

## Permission profiles

### Baseline profile (recommended)

Keep Runtime as the dedicated unprivileged `sentinel-runtime` account with an empty `CapabilityBoundingSet`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, and `PrivateTmp=false` as in the service unit. `PrivateTmp=false` lets the bounded `lstat()` handler see an evidence-derived host `/tmp` path; the handler still reads no content and the service remains unprivileged. This is enough for the local ledger and whatever `/proc` fields the kernel exposes to that account. `EACCES`, exited processes, hidden PID namespaces, and files hidden by systemd protections become explicit partial/unknown fields; Cloud must not convert them to “no activity”.

The only host paths read by the investigation procedures are procfs entries under `/proc` and the exact incident-derived file path passed to `lstat()`. Runtime does not read content from that target. It does not collect `cmdline` or `environ` in a remote investigation task.

### Customer-approved expanded visibility

Do not grant `CAP_SYS_ADMIN`, broad root, unrestricted sudo, or shell execution to close an evidence gap. If an environment intentionally hides procfs entries, first review the host's `/proc` mount options (`hidepid`) and the unit's `ProtectProc`/`ProcSubset` settings. Prefer changing a customer-controlled procfs group or exposing only the required target path through a narrowly scoped read-only bind mount. Keep `ProtectHome=true`; if a required application path is under a protected directory, expose only that path with a reviewed systemd `BindReadOnlyPaths=` override and retain non-root ownership.

Some kernel fields such as `/proc/<pid>/exe` and another user's file descriptors are subject to ptrace access checks. The baseline intentionally does not add `CAP_SYS_PTRACE`; missing fields are reported as unavailable. A customer who elects to grant that capability must treat it as broad cross-process inspection authority, risk-assess the expanded agent attack surface, restrict it to the dedicated Runtime service, and record the exception. This release does not require or silently enable it.

`ProtectHome=true` hides `/home`, `/root`, and `/run/user` from the service. Do not disable it globally just to stat an artifact. Use a specific, approved `BindReadOnlyPaths=/srv/customer-app:/srv/customer-app` style override only for an incident evidence path that the operator has authorized. File contents remain outside the playbook contract; a separate, explicitly governed acquisition workflow would be needed to collect them.

## Tetragon tracing policy

`../tetragon/sentinel-runtime-observability.yaml` is a **lab-only** policy. Its `vfs_read` and `tcp_sendmsg` probes can generate high event volume. Install only on an isolated test host, measure event rates and all loss counters under representative load, and add workload filters before any production rollout. It is not required for the task channel itself.

Process argument capture is separate from task permission. It is disabled by default because arguments can contain credentials. To enable it for a lab, add `--capture-process-arguments` to the Runtime command, protect the local ledger, and verify the Cloud redaction behavior. It does not collect environment variables or file contents. Production should enable it only under a documented customer policy.

## Validation and operations

- `sentinel-runtime status` reports that enforcement remains unimplemented and task playbooks are fixed/read-only.
- `sentinel-runtime verify-ledger --db /var/lib/sentinel-runtime/runtime.sqlite` checks local chain integrity.
- Inspect logs with `journalctl -u sentinel-runtime.service`; task logs include task IDs and result status, never the host token.
- A Cloud task result is labeled agent-reported. A Runtime token authenticates the agent credential, not the integrity of the kernel, host, or agent binary.
- `OBSERVE_ONLY` applies to containment. It does not mean the collector, metrics polling, or explicitly enabled read-only investigations are off.
- No L1–L3 action is implemented or dispatchable by this task protocol.
