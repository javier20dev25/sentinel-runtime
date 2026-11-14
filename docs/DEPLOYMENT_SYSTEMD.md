# Linux systemd deployment template

The repository includes [`sentinel-runtime-proxy.service`](../packaging/systemd/sentinel-runtime-proxy.service) and [`sentinel-runtime.service`](../packaging/systemd/sentinel-runtime.service). The collector stores its evidence database under `/var/lib/sentinel-runtime`, reads the boot ID from the kernel at service start, restarts after transient failures, and writes operational status to the system journal. By default it depends on the local read-only gateway instead of connecting to Tetragon's administrative socket directly.

These are operator-installed templates, not a managed installer or fleet control plane. Both services have no Linux capabilities. The collector runs as `sentinel-runtime`; the gateway runs separately as `sentinel-tetragon-proxy` and is the only account that receives site-specific access to the upstream Tetragon socket.

## Install

1. Install the pinned Node.js runtime (22.5 or later) and production dependencies. Install this repository at `/opt/sentinel-runtime`; the templates expect Node at `/usr/bin/node`. The complete installation tree must be owned by `root:root` and must not be writable by group or other users. Never extract an archive that preserves permissive `0777` modes into the active installation path.
2. Create the shared client group and separate unprivileged service accounts, then install both units and root-owned configuration files:

   ```sh
   sudo groupadd --system sentinel-runtime
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid sentinel-runtime sentinel-runtime
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid sentinel-runtime sentinel-tetragon-proxy
   sudo install -d -o root -g root -m 0755 /opt/sentinel-runtime
   sudo chown -R root:root /opt/sentinel-runtime
   sudo chmod -R go-w /opt/sentinel-runtime
   if sudo find /opt/sentinel-runtime -xdev -perm /0022 -print -quit | grep -q .; then echo 'Runtime installation is group/world writable' >&2; exit 1; fi
   sudo install -o root -g root -m 0644 packaging/systemd/sentinel-runtime.service /etc/systemd/system/sentinel-runtime.service
   sudo install -o root -g root -m 0644 packaging/systemd/sentinel-runtime-proxy.service /etc/systemd/system/sentinel-runtime-proxy.service
   sudo install -d -o root -g root -m 0755 /etc/sentinel-runtime
   sudo install -o root -g root -m 0600 packaging/systemd/sentinel-runtime.env.example /etc/sentinel-runtime/sentinel-runtime.env
   sudo install -o root -g root -m 0644 packaging/systemd/tetragon-proxy.env.example /etc/sentinel-runtime/tetragon-proxy.env
   sudoedit /etc/sentinel-runtime/sentinel-runtime.env
   sudoedit /etc/sentinel-runtime/tetragon-proxy.env
   ```

   Set `SENTINEL_RUNTIME_HOST_ID` to a stable inventory identifier. The collector address defaults to `/run/sentinel-runtime/tetragon-readonly.sock`. Set `SENTINEL_TETRAGON_UPSTREAM_ADDRESS` to the host's Tetragon socket or TLS-protected TCP endpoint. Keep both environment files root-owned. The Runtime environment file is mode `0600` so it remains safe if it contains the host token; the proxy file should not contain private-key material.

3. Grant only `sentinel-tetragon-proxy` the narrowest available access to Tetragon's upstream socket. For a group-controlled socket, add its actual group in a proxy service drop-in; for example, use `SupplementaryGroups=tetragon` only if that is the group configured on the host. Do not add `sentinel-runtime` to that group. For remote gRPC, use a CA-verified TLS endpoint and a protected site-specific drop-in for certificate paths.
4. Start and inspect the service:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now sentinel-runtime-proxy.service sentinel-runtime.service
   sudo systemctl status sentinel-runtime-proxy.service
   sudo systemctl status sentinel-runtime.service
   sudo journalctl -u sentinel-runtime.service -f
   sudo -u sentinel-runtime /usr/bin/node /opt/sentinel-runtime/bin/sentinel-runtime.js verify-ledger --db /var/lib/sentinel-runtime/runtime.sqlite
   ```

The units use systemd environment expansion for configured endpoint values; an absent host ID causes the collector to fail closed. `ProtectSystem=strict` plus explicit `ReadOnlyPaths` prevents the Runtime service account from changing its code or configuration. Keep the installation root-owned and non-writable by group/other so a different unprivileged host account cannot replace files before systemd starts the service. The proxy service creates `/run/sentinel-runtime` as `sentinel-tetragon-proxy:sentinel-runtime` mode `0750`, then creates the client socket mode `0660`. The collector can traverse/connect through its primary group but has no access to the upstream Tetragon socket. For remote TLS, use a protected proxy unit drop-in and root-owned CA/client-key files; the gRPC connection rejects plaintext TCP and checks private-key permissions on Linux.

The collector unit sets `TMPDIR=/var/lib/sentinel-runtime`, which is writable through `StateDirectory`. Keep this private writable temp path when `ProtectSystem=strict` is enabled. SQLite may need temporary storage while processing a batch; if no writable temp directory is available, the collector can fail with `SQLITE_IOERR_GETTEMPPATH` and lose the uncommitted batch. Do not use a shared world-writable directory as a workaround.

## Resource and stream limits

The collector template uses `MemoryHigh=512M`, `MemoryMax=768M`, `CPUQuota=200%`, `TasksMax=64`, and `LimitNOFILE=8192`. The proxy template uses `MemoryHigh=256M`, `MemoryMax=384M`, `CPUQuota=100%`, `TasksMax=32`, and `LimitNOFILE=2048`. `OOMPolicy=stop` lets `Restart=on-failure` restart the affected service after a cgroup out-of-memory event. `MemoryHigh` throttles the service under pressure; `MemoryMax` is the hard cgroup limit. Tune these values against measured host capacity and event throughput before deployment. A memory-limit restart creates a telemetry gap and does not recover events lost upstream.

The local gateway permits one active `GetEvents` subscription globally and up to eight concurrent gRPC streams per client connection. The Runtime collector uses one persistent event stream. Additional event-stream clients receive gRPC `RESOURCE_EXHAUSTED`; keep the Unix socket and its group limited to the dedicated service identities. This prevents local clients from multiplying subscriptions to Tetragon through the gateway.

## Tetragon event scope

By default, Runtime requests core process lifecycle and sensor-throttle event types. It does not subscribe to every kprobe, tracepoint, uprobe, LSM, or USDT event. To receive policy-driven event families, pass one or more exact Tetragon policy names:

```sh
node /opt/sentinel-runtime/bin/sentinel-runtime.js collect-tetragon \
  --address unix:///run/sentinel-runtime/tetragon-readonly.sock \
  --host-id host-prod-01 --boot-id-file /proc/sys/kernel/random/boot_id \
  --tetragon-policy-name sentinel-runtime-observability
```

Repeat `--tetragon-policy-name` for each policy. The gRPC request uses separate allow-list entries: core events stand on their own; policy-generated event types must also match a configured policy name. Keep the policy set limited to reviewed Runtime TracingPolicies. This limits events delivered to Runtime, but does not disable Tetragon probes or prove that Tetragon did not drop events before delivery. Continue monitoring Tetragon loss metrics and Runtime observability state. Tetragon v1.8.0 field definitions are pinned in [`events.proto`](../vendor/tetragon/v1.8.0/api/v1/tetragon/events.proto).

## Read-only local gateway

The optional `tetragon-readonly-proxy` command opens an upstream Tetragon v1.8.0 connection and registers only `GetVersion` and `GetEvents` on its client-facing gRPC server. Policy mutation, debug, sensor control, and other RPCs return `UNIMPLEMENTED`. It allows one active event subscription and returns `RESOURCE_EXHAUSTED` to additional subscribers. The stream serializer forwards exact upstream protobuf bytes, preserving unknown fields and the evidence source hash. The proxy accepts only an absolute Unix-domain listener path, refuses an existing path or a group/world-writable parent directory, requires a umask that blocks group/world write during startup, defaults to mode `0600`, and removes only the socket inode it created. Use a protected runtime directory such as `/run/sentinel-runtime` and configure ownership/group access at the OS level.

Run the proxy under a dedicated gateway identity that can access the upstream sensor endpoint; run the collector as `sentinel-runtime`, and grant that account only access to the proxy socket. If using mode `0660`, configure the socket's group and parent-directory permissions deliberately. The proxy does not make the upstream Tetragon API itself read-only: a compromised proxy process can exercise whatever upstream rights its account has. Remote upstreams still require verified TLS and preferably mTLS.

Example command (the repository supplies a hardened systemd unit for this gateway):

```sh
node /opt/sentinel-runtime/bin/sentinel-runtime.js tetragon-readonly-proxy \
  --upstream-address unix:///var/run/tetragon/tetragon.sock \
  --listen-address unix:///run/sentinel-runtime/tetragon-readonly.sock --socket-mode 0660
```

Set the collector unit's `SENTINEL_RUNTIME_ADDRESS` to `unix:///run/sentinel-runtime/tetragon-readonly.sock`. Do not grant the collector account access to the upstream Tetragon socket. The proxy unit deliberately has no default supplementary group for the upstream socket; configure that access from the host's actual Tetragon socket ownership instead of assuming one group name across installations.

## Optional Prometheus polling

The template leaves metrics polling disabled because Tetragon's non-Kubernetes metrics listener is disabled by default. After enabling that endpoint on loopback and reviewing the Tetragon configuration, add `--metrics-url http://127.0.0.1:2112/metrics --metrics-interval-ms 5000` to the unit's `ExecStart` with `systemctl edit sentinel-runtime.service`. A drop-in that changes `ExecStart` must first clear the vendor command with an empty `ExecStart=` line, then provide the full replacement command. Remote metrics require HTTPS, certificate verification, and a metrics hostname matching the configured gRPC host.

## Operational limits

- **Permission separation & residual upstream privileges:** The gateway architecture strictly separates duties: the collector account has access only to the filtered client socket (`/run/sentinel-runtime/tetragon-readonly.sock`), with zero capabilities and no access to upstream Tetragon. However, the proxy process itself requires site-specific upstream access to Tetragon's administrative socket or TLS endpoint; a compromise of the proxy process can exercise whatever upstream access that account possesses. The gateway does not replace server-side upstream authorization.
- **Distribution compatibility not established:** The systemd unit templates are operator-managed references. Installation compatibility, security context enforcement, and service lifecycle have not been validated across production Linux distributions (e.g., Ubuntu 22.04/24.04, Debian 12, RHEL 9). The recorded WSL2 verification was performed with mock paths and does not constitute a production distribution certification.
- **No upstream stream replay:** gRPC has no upstream replay cursor, sequence offset, or delivery acknowledgement; stream reconnects remain an `UNKNOWN` gap and cannot recover events missed during downtime.
- **Local evidence ledger:** The evidence ledger is local SQLite and grows with event volume. Define and validate an external retention, export, and anchoring procedure before production rollout; do not delete records in place without an approved custody process.
- **Resource ceilings:** The unit limits bound Runtime and proxy resource consumption. An undersized memory ceiling can restart a process under legitimate peak load; monitor the cgroup and Tetragon loss counters, then tune for the measured workload.
- **No fleet or enforcement features:** The units do not implement tenant isolation, remote fleet management, signed policy distribution, automatic Tetragon installation, or host enforcement. Active prevention is not implemented.
