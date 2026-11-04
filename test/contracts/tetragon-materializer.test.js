'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeTetragonJson } = require('../../src/adapters/tetragon-json');
const { materializeTetragonEventV2 } = require('../../src/contracts/materialize-tetragon-v2');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');
const { BehavioralSequenceEngine } = require('../../src/engine');

const HOST = { hostId: 'host-materializer', bootId: 'boot-materializer', transportProtocol: 'GRPC_TCP', transportAuthentication: 'TLS_SERVER_AUTH' };
const PROCESS = {
  exec_id: 'exec-materializer', parent_exec_id: 'parent-materializer',
  pid: { value: 41 }, tid: { value: 41 }, start_time: '2026-11-03T01:02:03.000000004Z',
  binary: '/usr/bin/worker', arguments: 'worker --safe', flags: 'execve clone'
};

function normalize(record) {
  const raw = Buffer.from(JSON.stringify(record));
  const normalized = normalizeTetragonJson(record, raw, HOST);
  assert.equal(normalized.supported, true, normalized.reason);
  return { normalized, raw };
}

function materialize(record, options = {}) {
  const { normalized, raw } = normalize(record);
  const event = materializeTetragonEventV2(normalized, {
    ...HOST,
    sensorVersion: 'v1.8.0',
    collectorSessionId: 'c9bb0a5c-6137-4fc2-8f80-39a746fb756b',
    nodeName: 'node-a',
    nodeNameStatus: 'OBSERVED_IN_SENSOR',
    providerObservationTimestamp: '1793670000000000000',
    ingestTimestamp: '1793670000000000001',
    sourceCursor: {
      cursor_kind: 'GRPC_SEQUENCE', stream_epoch: '5e721996-0035-46d7-a441-578f61bdb67f',
      sequence_number: '1', raw_payload_sha256: normalized.rawPayloadSha256
    },
    aggregationDisabled: true,
    ...options
  });
  assert.equal(validateEventV2(event).valid, true);
  assert.equal(event.source_cursor.raw_payload_sha256, normalized.rawPayloadSha256);
  assert.equal(raw.length > 0, true);
  return { event, normalized };
}

function kprobe(functionName, args, returnValue) {
  const process_kprobe = { process: structuredClone(PROCESS), function_name: functionName, policy_name: 'sentinel-test-policy', args };
  if (returnValue !== undefined) process_kprobe.return = returnValue;
  return { time: '2026-11-03T01:02:04.000000005Z', process_kprobe };
}

test('Tetragon PROCESS_EXEC materializes with separate source/observation times and private-by-default arguments', () => {
  const { event } = materialize({
    time: '2026-11-03T01:02:04.000000005Z', process_exec: { process: structuredClone(PROCESS) }
  });
  assert.equal(event.event_type, 'PROCESS_EXEC');
  assert.equal(event.payload.arguments_raw, null);
  assert.equal(event.payload.arguments_capture_status, 'REDACTED_BY_POLICY');
  assert.equal(event.timestamps.provider_observation_timestamp, '1793670000000000000');
  assert.notEqual(event.timestamps.source_timestamp, event.timestamps.provider_observation_timestamp);
  assert.equal(event.sensor_metadata.transport_protocol, 'GRPC_TCP');
});

test('PROCESS_EXEC argument capture is explicit opt-in and preserves Tetragon raw-string semantics', () => {
  const { event } = materialize({
    time: '2026-11-03T01:02:04.000000005Z', process_exec: { process: structuredClone(PROCESS) }
  }, { captureProcessArguments: true });
  assert.equal(event.payload.arguments_raw, 'worker --safe');
  assert.equal(event.payload.argv, null);
  assert.equal(event.payload.arguments_capture_status, 'RAW_STRING_ONLY');
});

test('credential collision preserves both raw values and blocks a resolved effective identity', () => {
  const process = {
    ...structuredClone(PROCESS), uid: { value: 1000 },
    process_credentials: { uid: { value: 1001 }, euid: { value: 2000 } }
  };
  const { event } = materialize({ time: '2026-11-03T01:02:04Z', process_exec: { process } });
  assert.equal(event.process_identity.credentials_capture_status, 'COLLISION_UNRESOLVED');
  assert.equal(event.process_identity.euid, null);
  assert.equal(event.process_identity.process_uid_raw, 1000);
  assert.equal(event.process_identity.credentials_euid_raw, 2000);
  assert.equal(event.process_identity.ruid, 1001);
});

test('partial Tetragon process identity preserves raw hooks without fabricating exec_id or executable path', () => {
  const record = kprobe('cap_capable', [
    { capability_arg: { value: { value: 19 }, name: 'CAP_SYS_PTRACE' }, label: 'sentinel_capability' }
  ], { int_arg: 0 });
  delete record.process_kprobe.process.exec_id;
  delete record.process_kprobe.process.binary;
  record.process_kprobe.process.pid = { value: 1987 };
  record.process_kprobe.process.flags = 'unknown';
  const { normalized, event } = materialize(record);
  assert.equal(event.process_identity.exec_id, null);
  assert.equal(event.process_identity.exec_id_capture_status, 'UNAVAILABLE_IN_SENSOR');
  assert.equal(event.process_identity.executable_path, null);
  assert.equal(event.process_identity.executable_path_capture_status, 'UNAVAILABLE_IN_SENSOR');
  assert.equal(event.process_identity.identity_quality, 'PARTIAL_RECONSTRUCTED');
  assert.match(event.source_event_key, /^[a-f0-9]{64}$/);
  assert.equal(validateEventV2(event).valid, true);

  const engine = new BehavioralSequenceEngine();
  const decision = engine.processEvent(normalized);
  assert.equal(decision.reason, 'Event family is not analyzed by this engine: CAPABILITY_CHECK');
  assert.equal(engine.processChains.size, 0);

  const identityEngine = new BehavioralSequenceEngine();
  const identityDecision = identityEngine.processEvent({
    ...normalized, eventType: 'PROCESS_EXEC', sourceEventKey: null, eventId: null, data: { binary: '' }
  });
  assert.equal(identityDecision.reason, 'Stable process identity unavailable; event not correlated');
  assert.equal(identityEngine.processChains.size, 0);

  const changedPid = structuredClone(event);
  changedPid.process_identity.pid++;
  assert.equal(validateEventV2(changedPid).valid, false);
  const missingStatus = structuredClone(event);
  delete missingStatus.process_identity.exec_id_capture_status;
  assert.equal(validateEventV2(missingStatus).valid, false);
});

test('Tetragon exit records preserve signal semantics and do not infer an exit code for signals', () => {
  const { event } = materialize({
    time: '2026-11-03T01:02:04Z', process_exit: {
      process: structuredClone(PROCESS), signal: 'SIGKILL', status: 0,
      time: '2026-11-03T01:02:04.000000006Z'
    }
  });
  assert.equal(event.event_type, 'PROCESS_EXIT');
  assert.deepEqual(event.payload.termination, {
    kind: 'SIGNALED', exit_status: null, signal_name: 'SIGKILL', status_origin: 'NOT_APPLICABLE_SIGNALED'
  });
  assert.equal(event.timestamps.provider_event_timestamp, '1793667724000000006');
});

test('supported Tetragon kprobe hooks materialize complete provenance-aware v2 payloads', () => {
  const openAttempt = materialize(kprobe('do_sys_openat2', [
    { int_arg: -100, label: 'sentinel_dfd' }, { string_arg: '/etc/shadow', label: 'sentinel_filename' }
  ])).event;
  assert.equal(openAttempt.event_type, 'FILE_OPEN_ATTEMPT');
  assert.equal(openAttempt.payload.dfd, -100);
  assert.equal(openAttempt.payload.flags, null);

  const openResult = materialize(kprobe('do_sys_openat2', [
    { int_arg: -100, label: 'sentinel_dfd' }, { string_arg: '/etc/shadow', label: 'sentinel_filename' }
  ], { long_arg: '-13' })).event;
  assert.equal(openResult.event_type, 'FILE_OPEN_RESULT');
  assert.equal(openResult.payload.path, '/etc/shadow');
  assert.equal(openResult.payload.return_code, -13);
  assert.equal(openResult.payload.fd, null);
  assert.equal(openResult.payload.errno, 13);

  const readResult = materialize(kprobe('vfs_read', [
    { file_arg: { path: '/srv/secrets/key.pem' }, label: 'sentinel_file' },
    { size_arg: '8192', label: 'sentinel_count' }
  ], { long_arg: '-13' })).event;
  assert.equal(readResult.event_type, 'FILE_READ');
  assert.equal(readResult.payload.bytes_requested, '8192');
  assert.equal(readResult.payload.bytes_read, '0');
  assert.equal(readResult.payload.return_code, -13);

  const connectResult = materialize(kprobe('tcp_v4_connect', [
    { sock_arg: { saddr: '192.0.2.10', sport: 4567, state: 'SYN_SENT' }, label: 'sentinel_socket' },
    { sockaddr_arg: { family: 'AF_INET', addr: '198.51.100.20', port: 443 }, label: 'sentinel_sockaddr' }
  ], { int_arg: '-115' })).event;
  assert.equal(connectResult.event_type, 'NETWORK_CONNECT_RESULT');
  assert.equal(connectResult.payload.family, 'AF_INET');
  assert.equal(connectResult.payload.destination_ip, '198.51.100.20');
  assert.equal(connectResult.payload.errno, 115);

  const sendAttempt = materialize(kprobe('tcp_sendmsg', [
    { size_arg: '4096', label: 'sentinel_size' },
    { sock_arg: { family: 'AF_INET', saddr: '192.0.2.10', daddr: '198.51.100.20', sport: 4567, dport: 443, state: 'ESTABLISHED' }, label: 'sentinel_socket' }
  ])).event;
  assert.equal(sendAttempt.event_type, 'NETWORK_SEND_ATTEMPT');
  assert.equal(sendAttempt.payload.destination_port, 443);
  assert.equal(sendAttempt.payload.socket_fd, null);

  const sendResult = materialize(kprobe('tcp_sendmsg', [
    { size_arg: '4096', label: 'sentinel_size' },
    { sock_arg: { family: 'AF_INET', saddr: '192.0.2.10', daddr: '198.51.100.20', sport: 4567, dport: 443, state: 'ESTABLISHED' }, label: 'sentinel_socket' }
  ], { long_arg: '2048' })).event;
  assert.equal(sendResult.event_type, 'NETWORK_SEND_RESULT');
  assert.equal(sendResult.payload.bytes_accepted_by_kernel, '2048');
  assert.equal(sendResult.payload.evidence_semantics, 'LOCAL_STACK_ACCEPTED_BYTES');

  const capabilityCheck = materialize(kprobe('cap_capable', [
    { capability_arg: { value: 21, name: 'CAP_SYS_ADMIN' }, label: 'sentinel_capability' }
  ], { int_arg: -1 })).event;
  assert.equal(capabilityCheck.event_type, 'CAPABILITY_CHECK');
  assert.deepEqual(capabilityCheck.payload, {
    capability_value: 21, capability_name: 'CAP_SYS_ADMIN', audit_result: 'DENIED', return_code: -1
  });
});

test('materializer rejects unsupported attempt-only reads and cursor/hash mismatches', () => {
  const attempt = kprobe('vfs_read', [
    { file_arg: { path: '/srv/data.db' }, label: 'sentinel_file' },
    { size_arg: '16', label: 'sentinel_count' }
  ]);
  const attemptRaw = Buffer.from(JSON.stringify(attempt));
  const unsupported = normalizeTetragonJson(attempt, attemptRaw, HOST);
  assert.equal(unsupported.supported, false);
  assert.equal(unsupported.reason, 'KPROBE_READ_RETURN_UNAVAILABLE');

  const { normalized } = normalize({ time: '2026-11-03T01:02:04Z', process_exec: { process: structuredClone(PROCESS) } });
  assert.throws(() => materializeTetragonEventV2(normalized, {
    ...HOST, sourceCursor: { cursor_kind: 'GRPC_SEQUENCE', stream_epoch: '5e721996-0035-46d7-a441-578f61bdb67f', sequence_number: '1', raw_payload_sha256: '0'.repeat(64) }
  }), /must match the exact provider payload bytes/);
});
