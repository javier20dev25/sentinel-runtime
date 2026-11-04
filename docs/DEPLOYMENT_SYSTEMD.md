# Linux systemd deployment template

The repository includes [`sentinel-runtime-proxy.service`](../packaging/systemd/sentinel-runtime-proxy.service) and [`sentinel-runtime.service`](../packaging/systemd/sentinel-runtime.service). The collector stores its evidence database under `/var/lib/sentinel-runtime`, reads the boot ID from the kernel at service start, restarts after transient failures, and writes operational status to the system journal. By default it depends on the local read-only gateway instead of connecting to Tetragon's administrative socket directly.

These are operator-installed templates, not a managed installer or fleet control plane. Both services have no Linux capabilities. The collector runs as `sentinel-runtime`; the gateway runs separately as `sentinel-tetragon-proxy` and is the only account that receives site-specific access to the upstream Tetragon socket.

## Install

1. Install the pinned Node.js runtime (22.5 or later) and production dependencies. Install this repository at `/opt/sentinel-runtime`; the templates expect Node at `/usr/bin/node`.
2. Create the shared client group and separate unprivileged service accounts, then install both units and root-owned configuration files:

   ```sh
   sudo groupadd --system sentinel-runtime
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid sentinel-runtime sentinel-runtime
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid sentinel-runtime sentinel-tetragon-proxy
   sudo install -o root -g root -m 0644 packaging/systemd/sentinel-runtime.service /etc/systemd/system/sentinel-runtime.service
   sudo install -o root -g root -m 0644 packaging/systemd/sentinel-runtime-proxy.service /etc/systemd/system/sentinel-runtime-proxy.service
   sudo install -d -o root -g root -m 0755 /etc/sentinel-runtime
   sudo install -o root -g root -m 0644 packaging/systemd/sentinel-runtime.env.example /etc/sentinel-runtime/sentinel-runtime.env
   sudo install -o root -g root -m 0644 packaging/systemd/tetragon-proxy.env.example /etc/sentinel-runtime/tetragon-proxy.env
   sudoedit /etc/sentinel-runtime/sentinel-runtime.env
   sudoedit /etc/sentinel-runtime/tetragon-proxy.env
   ```

   Set `SENTINEL_RUNTIME_HOST_ID` to a stable inventory identifier. The collector address defaults to `/run/sentinel-runtime/tetragon-readonly.sock`. Set `SENTINEL_TETRAGON_UPSTREAM_ADDRESS` to the host's Tetragon socket or TLS-protected TCP endpoint. Keep both environment files root-owned; they are configuration, not a secrets store.

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

The units use systemd environment expansion for configured endpoint values; an absent host ID causes the collector to fail closed. The proxy service creates `/run/sentinel-runtime` as `sentinel-tetragon-proxy:sentinel-runtime` mode `0750`, then creates the client socket mode `0660`. The collector can traverse/connect through its primary group but has no access to the upstream Tetragon socket. For remote TLS, use a protected proxy unit drop-in and root-owned CA/client-key files; the gRPC connection rejects plaintext TCP and checks private-key permissions on Linux.

## Read-only local gateway

The optional `tetragon-readonly-proxy` command opens an upstream Tetragon v1.8.0 connection and registers only `GetVersion` and `GetEvents` on its client-facing gRPC server. Policy mutation, debug, sensor control, and other RPCs return `UNIMPLEMENTED`. The stream serializer forwards exact upstream protobuf bytes, preserving unknown fields and the evidence source hash. The proxy accepts only an absolute Unix-domain listener path, refuses an existing path or a group/world-writable parent directory, requires a umask that blocks group/world write during startup, defaults to mode `0600`, and removes only the socket inode it created. Use a protected runtime directory such as `/run/sentinel-runtime` and configure ownership/group access at the OS level.

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
- **No fleet or enforcement features:** The units do not implement tenant isolation, remote fleet management, signed policy distribution, automatic Tetragon installation, or host enforcement. Active prevention is not implemented.
