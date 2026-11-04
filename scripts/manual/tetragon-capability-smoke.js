'use strict';

const assert = require('node:assert/strict');
const { fork } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { normalizeTetragonJson } = require('../../src/adapters/tetragon-json');
const { materializeTetragonEventV2 } = require('../../src/contracts/materialize-tetragon-v2');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');
const { getRawResponseBytes, loadTetragonApi } = require('../../src/collectors/tetragon-proto');

const SOCKET = 'unix:///var/run/cilium/tetragon/tetragon.sock';

function rpc(client, method, request, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    client[method](request, { deadline: Date.now() + timeoutMs }, (error, response) => error ? reject(error) : resolve(response));
  });
}

function policyYaml(name, pid, executable) {
  return `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: ${name}
spec:
  kprobes:
    - call: cap_capable
      syscall: false
      return: true
      returnArg:
        index: 0
        type: int
      args:
        - index: 2
          type: capability
          label: sentinel_capability
      selectors:
        - matchPIDs:
            - operator: In
              values: [${pid}]
              isNamespacePID: true
          matchBinaries:
            - operator: In
              values: [${JSON.stringify(executable)}]
              followChildren: false
          matchActions:
            - action: Post
`;
}

async function runChild() {
  if (typeof process.send !== 'function') throw new Error('Capability smoke child requires an IPC parent');
  if (process.getuid?.() !== 0) throw new Error('Capability smoke requires a root parent to exercise CAP_SETUID');
  process.on('message', message => {
    if (message !== 'TRIGGER') return;
    try {
      process.setuid(65534);
      process.send({ type: 'TRIGGERED', uid: process.getuid() });
      process.disconnect();
    } catch (error) {
      process.send({ type: 'CHILD_ERROR', message: String(error.message || error) });
      process.disconnect();
      process.exitCode = 1;
    }
  });
  process.send({ type: 'READY', uid: process.getuid() });
}

async function runParent() {
  const api = loadTetragonApi();
  const client = new api.service(SOCKET, api.grpc.credentials.createInsecure());
  const child = fork(__filename, ['--capability-smoke-child'], {
    execPath: process.execPath,
    stdio: ['ignore', 'ignore', 'inherit', 'ipc']
  });
  const policyName = `sentinel-runtime-capability-smoke-${process.pid}`;
  let added = false;
  let stream;
  let eventTimer;
  const streamEpoch = crypto.randomUUID();
  const collectorSessionId = crypto.randomUUID();
  const bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  try {
    const ready = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('message', message => message.type === 'READY' ? resolve(message) : reject(new Error(JSON.stringify(message))));
    });
    assert.equal(ready.uid, 0);
    const version = await rpc(client, 'getVersion', {});
    assert.equal(version.version, 'v1.8.0', `unexpected Tetragon version ${version.version}`);
    const policy = policyYaml(policyName, child.pid, process.execPath);
    await rpc(client, 'addTracingPolicy', { yaml: policy, domain: '' });
    added = true;
    const policyState = await rpc(client, 'listTracingPolicies', {});
    const activePolicy = (policyState.policies || []).find(item => item.name === policyName);
    assert.ok(activePolicy, 'Tetragon accepted the policy but did not list it');
    process.stderr.write(`${JSON.stringify({ policy_state: activePolicy.state, hook_statuses: activePolicy.hook_statuses })}\n`);

    stream = client.getEvents({});
    let sequence = 0n;
    const eventPromise = new Promise((resolve, reject) => {
      eventTimer = setTimeout(() => reject(new Error('Timed out waiting for the child CAP_SETUID check')), 10000);
      stream.on('data', response => {
        sequence++;
        const kprobe = response.process_kprobe;
        if (kprobe?.function_name !== 'cap_capable') return;
        const argument = (kprobe.args || []).find(item => item?.label === 'sentinel_capability');
        const rawCapability = argument?.capability_arg?.value?.value ?? argument?.capability_arg?.value;
        if (Number(rawCapability) !== 7) return;
        clearTimeout(eventTimer);
        try {
          const raw = getRawResponseBytes(response);
          assert.ok(raw?.length, 'protobuf wire bytes were not preserved by the decoder');
          const normalized = normalizeTetragonJson({ time: response.time, process_kprobe: kprobe }, raw, {
            hostId: 'sentinel-wsl-capability-smoke', bootId
          });
          assert.equal(normalized.supported, true,
            `normalizer rejected live event: ${normalized.reason}; process=${JSON.stringify(kprobe.process)}; args=${JSON.stringify(kprobe.args)}`);
          assert.equal(normalized.eventType, 'CAPABILITY_CHECK');
          assert.equal(normalized.data.capability_value, 7);
          assert.equal(normalized.data.capability_name, 'CAP_SETUID');
          assert.equal(normalized.data.return_code, 0);
          assert.equal(normalized.data.audit_result, 'GRANTED');
          const event = materializeTetragonEventV2(normalized, {
            hostId: 'sentinel-wsl-capability-smoke', bootId, collectorSessionId,
            sensorVersion: version.version, transportProtocol: 'GRPC_UNIX_SOCKET',
            transportAuthentication: 'NONE_UNAUTHENTICATED', nodeName: response.node_name || null,
            nodeNameStatus: 'OBSERVED_IN_SENSOR',
            sourceCursor: {
              cursor_kind: 'GRPC_SEQUENCE', stream_epoch: streamEpoch,
              sequence_number: String(sequence), raw_payload_sha256: normalized.rawPayloadSha256
            },
            aggregationDisabled: true
          });
          assert.equal(validateEventV2(event).valid, true);
          resolve({
            event_type: event.event_type,
            capability_value: event.payload.capability_value,
            capability_name: event.payload.capability_name,
            return_code: event.payload.return_code,
            audit_result: event.payload.audit_result,
            exec_id_capture_status: event.process_identity.exec_id_capture_status,
            executable_path_capture_status: event.process_identity.executable_path_capture_status,
            source_event_key: event.source_event_key,
            event_v2_valid: true
          });
        } catch (error) { reject(error); }
      });
      stream.on('error', reject);
    });

    await new Promise(resolve => setTimeout(resolve, 250));
    child.send('TRIGGER');
    const [observed] = await Promise.all([eventPromise]);
    process.stdout.write(`${JSON.stringify({
      tetragon_version: version.version,
      policy_name: policyName,
      pid_scope: child.pid,
      trigger: 'root Node child drops to uid 65534 via setuid',
      ...observed
    })}\n`);
  } finally {
    clearTimeout(eventTimer);
    try { stream?.cancel(); } catch { /* best-effort teardown */ }
    if (added) {
      await rpc(client, 'deleteTracingPolicy', { name: policyName, namespace: '', domain: '' });
      const remainingPolicies = await rpc(client, 'listTracingPolicies', {});
      if ((remainingPolicies.policies || []).some(item => item.name === policyName)) {
        throw new Error(`Temporary Tetragon policy ${policyName} still exists after deletion`);
      }
    }
    if (child.connected) child.kill('SIGKILL');
    client.close();
  }
}

if (process.argv[2] === '--capability-smoke-child') {
  runChild().catch(error => { process.stderr.write(`${error.stack || error.message}\n`); process.exitCode = 1; });
} else {
  runParent().catch(error => { process.stderr.write(`${error.stack || error.message}\n`); process.exitCode = 1; });
}
