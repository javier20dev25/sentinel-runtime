'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const { once } = require('node:events');
const { normalizeTetragonJson } = require('../../src/adapters/tetragon-json');
const { materializeTetragonEventV2 } = require('../../src/contracts/materialize-tetragon-v2');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');
const { getRawResponseBytes, loadTetragonApi } = require('../../src/collectors/tetragon-proto');

const SOCKET = 'unix:///var/run/cilium/tetragon/tetragon.sock';
const POLICY_NAME = `sentinel-runtime-smoke-${process.pid}`;
const POLICY = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: ${POLICY_NAME}
spec:
  kprobes:
    - call: tcp_sendmsg
      syscall: false
      return: true
      returnArg:
        index: 0
        type: int
      args:
        - index: 0
          type: sock
          label: sentinel_socket
        - index: 2
          type: size_t
          label: sentinel_size
      selectors:
        - matchPIDs:
            - operator: In
              values: [${process.pid}]
              isNamespacePID: true
          matchBinaries:
            - operator: In
              values: [${JSON.stringify(process.execPath)}]
              followChildren: false
          matchActions:
            - action: Post
`;

function rpc(client, method, request, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    client[method](request, { deadline: Date.now() + timeoutMs }, (error, response) => error ? reject(error) : resolve(response));
  });
}

async function main() {
  const api = loadTetragonApi();
  const client = new api.service(SOCKET, api.grpc.credentials.createInsecure());
  let added = false;
  let stream;
  let server;
  let eventTimer;
  let streamSequence = 0n;
  const streamEpoch = crypto.randomUUID();
  const collectorSessionId = crypto.randomUUID();
  try {
    const version = await rpc(client, 'getVersion', {});
    assert.equal(version.version, 'v1.8.0', `unexpected Tetragon version ${version.version}`);
    await rpc(client, 'addTracingPolicy', { yaml: POLICY, domain: '' });
    added = true;
    const policyState = await rpc(client, 'listTracingPolicies', {});
    const activePolicy = (policyState.policies || []).find(policy => policy.name === POLICY_NAME);
    assert.ok(activePolicy, 'Tetragon accepted the policy but did not list it');
    process.stderr.write(`${JSON.stringify({ policy_state: activePolicy.state, policy_error: activePolicy.error, policy_sensors: activePolicy.sensors, hook_statuses: activePolicy.hook_statuses })}\n`);

    server = http.createServer((_request, response) => response.end('sentinel-local-smoke'));
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();

    stream = client.getEvents({});
    const eventPromise = new Promise((resolve, reject) => {
      eventTimer = setTimeout(() => reject(new Error('Timed out waiting for a matching tcp_sendmsg kretprobe event')), 8000);
      stream.on('data', response => {
        streamSequence++;
        const kprobe = response.process_kprobe;
        if (kprobe?.function_name !== 'tcp_sendmsg') return;
        clearTimeout(eventTimer);
        try {
          const raw = getRawResponseBytes(response);
          assert.ok(raw?.length, 'protobuf wire bytes were not preserved by the decoder');
          const normalized = normalizeTetragonJson({ time: response.time, process_kprobe: kprobe }, raw, {
            hostId: 'sentinel-wsl-smoke', bootId: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim()
          });
          assert.equal(normalized.supported, true, `normalizer rejected live event: ${normalized.reason}`);
          assert.equal(normalized.eventType, 'NETWORK_SEND_RESULT');
          assert.equal(normalized.sourceFunction, 'tcp_sendmsg');
          assert.equal(normalized.policyName, POLICY_NAME);
          assert.equal(normalized.data.destination_ip, '127.0.0.1');
          assert.ok(normalized.data.destination_port > 0);
          assert.ok(normalized.data.return_code > 0);
          assert.ok(BigInt(normalized.data.bytes_accepted_by_kernel) <= BigInt(normalized.data.bytes_requested));
          const eventV2 = materializeTetragonEventV2(normalized, {
            hostId: 'sentinel-wsl-smoke',
            bootId: fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
            collectorSessionId,
            sensorVersion: version.version,
            transportProtocol: 'GRPC_UNIX_SOCKET',
            transportAuthentication: 'NONE_UNAUTHENTICATED',
            nodeName: response.node_name || null,
            nodeNameStatus: 'OBSERVED_IN_SENSOR',
            sourceCursor: {
              cursor_kind: 'GRPC_SEQUENCE', stream_epoch: streamEpoch,
              sequence_number: String(streamSequence), raw_payload_sha256: normalized.rawPayloadSha256
            },
            aggregationDisabled: true
          });
          assert.equal(validateEventV2(eventV2).valid, true);
          assert.equal(eventV2.event_type, 'NETWORK_SEND_RESULT');
          resolve({
            event_type: eventV2.event_type,
            schema_version: eventV2.schema_version,
            process_exec_id: normalized.processIdentity.execId,
            destination_ip: normalized.data.destination_ip,
            destination_port: normalized.data.destination_port,
            bytes_requested: normalized.data.bytes_requested,
            bytes_accepted_by_kernel: normalized.data.bytes_accepted_by_kernel,
            raw_payload_sha256: normalized.rawPayloadSha256,
            source_event_key: eventV2.source_event_key,
            event_v2_valid: true
          });
        } catch (error) {
          reject(error);
        }
      });
      stream.on('error', reject);
      stream.on('end', () => reject(new Error('Tetragon event stream ended before the matching kprobe event')));
    });

    await new Promise(resolve => setTimeout(resolve, 250));
    const requestPromise = fetch(`http://127.0.0.1:${address.port}/`).then(async response => {
      assert.equal(response.status, 200);
      await response.text();
    });
    const [observed] = await Promise.all([eventPromise, requestPromise]);
    process.stdout.write(`${JSON.stringify({ tetragon_version: version.version, policy_name: POLICY_NAME, pid_scope: process.pid, ...observed })}\n`);
  } finally {
    clearTimeout(eventTimer);
    try { stream?.cancel(); } catch { /* best-effort teardown */ }
    if (added) {
      await rpc(client, 'deleteTracingPolicy', { name: POLICY_NAME, namespace: '', domain: '' });
      const remainingPolicies = await rpc(client, 'listTracingPolicies', {});
      if ((remainingPolicies.policies || []).some(policy => policy.name === POLICY_NAME)) {
        throw new Error(`Temporary Tetragon policy ${POLICY_NAME} still exists after deletion`);
      }
    }
    if (server?.listening) await new Promise(resolve => server.close(resolve));
    client.close();
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
