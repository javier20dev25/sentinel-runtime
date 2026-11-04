'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeTetragonJson, summarizeEventData } = require('../../src/adapters/tetragon-json');
const { rawProviderEventKey } = require('../../src/contracts/event-keys');

const context = { hostId: 'host-kprobe', bootId: 'boot-kprobe', workloadId: 'workload-a' };

function event(functionName, args, returnValue) {
  const process_kprobe = {
    process: {
      exec_id: 'opaque-exec-id', parent_exec_id: 'opaque-parent-id',
      pid: { value: 42 }, tid: { value: 42 },
      start_time: '2026-11-03T00:00:00.000000001Z', binary: '/usr/bin/worker'
    },
    function_name: functionName,
    policy_name: 'sentinel-observe-v1',
    args
  };
  if (returnValue !== undefined) process_kprobe.return = returnValue;
  return { time: '2026-11-03T00:00:01.123456789Z', process_kprobe };
}

function normalize(record) {
  return normalizeTetragonJson(record, Buffer.from(JSON.stringify(record)), context);
}

test('Tetragon open hooks preserve the path and derive the kernel return without inventing flags or fd errors', () => {
  const path = '/etc/shadow';
  const attempt = normalize(event('do_sys_openat2', [
    { int_arg: -100, label: 'sentinel_dfd' }, { string_arg: path, label: 'sentinel_filename' }, { size_arg: '140730000000000' }
  ]));
  assert.equal(attempt.supported, true);
  assert.equal(attempt.eventType, 'FILE_OPEN_ATTEMPT');
  assert.deepEqual(attempt.data, {
    path, dfd: -100, flags: null, mode: null,
    flags_capture_status: 'UNAVAILABLE_POINTER_NOT_DEREFERENCED'
  });

  const result = normalize(event('do_sys_openat2', [
    { int_arg: -100, label: 'sentinel_dfd' }, { string_arg: path, label: 'sentinel_filename' }
  ], { long_arg: '-13' }));
  assert.equal(result.supported, true);
  assert.equal(result.eventType, 'FILE_OPEN_RESULT');
  assert.deepEqual(result.data, { path, return_code: -13, fd: null, errno: 13 });
});

test('Tetragon vfs_read records exact requested and returned sizes without claiming an fd', () => {
  const normalized = normalize(event('vfs_read', [
    { size_arg: '128', label: 'sentinel_count' },
    { file_arg: { path: '/srv/secrets/key.pem', flags: 'O_RDONLY' }, label: 'sentinel_file' }
  ], { long_arg: '37' }));
  assert.equal(normalized.supported, true);
  assert.equal(normalized.eventType, 'FILE_READ');
  assert.deepEqual(normalized.data, {
    path: '/srv/secrets/key.pem', bytes_requested: '128', bytes_read: '37',
    return_code: 37, errno: null, read_status: 'RETURN_OBSERVED'
  });
  assert.equal(Object.hasOwn(normalized.data, 'fd'), false);
});

test('Tetragon TCP connect hooks use the explicit sockaddr target and keep return semantics local', () => {
  const args = [
    { sock_arg: { family: 'AF_INET', saddr: '192.0.2.10', sport: 4567, state: 'SYN_SENT' }, label: 'sentinel_socket' },
    { sockaddr_arg: { family: 'AF_INET', addr: '198.51.100.20', port: 443 }, label: 'sentinel_sockaddr' },
    { int_arg: 16 }
  ];
  const attempt = normalize(event('tcp_v4_connect', args));
  assert.equal(attempt.supported, true);
  assert.equal(attempt.eventType, 'NETWORK_CONNECT_ATTEMPT');
  assert.equal(attempt.data.destination_ip, '198.51.100.20');
  assert.equal(attempt.data.destination_port, 443);
  assert.equal(attempt.data.socket_fd, null);

  const result = normalize(event('tcp_v4_connect', args, { int_arg: '-115' }));
  assert.equal(result.supported, true);
  assert.equal(result.eventType, 'NETWORK_CONNECT_RESULT');
  assert.equal(result.data.return_code, -115);
  assert.equal(result.data.errno, 115);
  assert.equal(Object.hasOwn(result.data, 'connected'), false);
});

test('Tetragon tcp_sendmsg return event is a verifiable raw event with bounded evidence fields', () => {
  const args = [
    { size_arg: '4096', label: 'sentinel_size' },
    { sock_arg: { family: 'AF_INET', protocol: 'TCP', saddr: '192.0.2.10', daddr: '198.51.100.20', sport: 4567, dport: 443, state: 'ESTABLISHED' }, label: 'sentinel_socket' }
  ];
  const rawRecord = event('tcp_sendmsg', args, { long_arg: '4096' });
  const rawBytes = Buffer.from(JSON.stringify(rawRecord));
  const normalized = normalizeTetragonJson(rawRecord, rawBytes, context);
  assert.equal(normalized.supported, true);
  assert.equal(normalized.eventType, 'NETWORK_SEND_RESULT');
  assert.equal(normalized.data.bytes_requested, '4096');
  assert.equal(normalized.data.bytes_accepted_by_kernel, '4096');
  assert.equal(normalized.data.evidence_semantics, 'LOCAL_STACK_ACCEPTED_BYTES');
  assert.equal(normalized.data.socket_fd, null);
  assert.equal(normalized.sourceFunction, 'tcp_sendmsg');
  assert.equal(normalized.policyName, 'sentinel-observe-v1');
  assert.equal(normalized.sourceEventKey, rawProviderEventKey({
    hostId: context.hostId,
    bootId: context.bootId,
    execId: 'opaque-exec-id',
    eventType: 'NETWORK_SEND_RESULT',
    sourceTimestamp: normalized.timestamp,
    rawPayloadSha256: normalized.rawPayloadSha256
  }));
  assert.deepEqual(summarizeEventData({ ...normalized.data, argumentsRaw: 'must-not-persist' }).argumentsRaw, undefined);
});

test('Tetragon cap_capable return maps an authorization check without claiming a privilege change', () => {
  const args = [{ capability_arg: { value: 21, name: 'CAP_SYS_ADMIN' }, label: 'sentinel_capability' }];
  const granted = normalize(event('cap_capable', args, { int_arg: 0 }));
  assert.equal(granted.supported, true);
  assert.equal(granted.eventType, 'CAPABILITY_CHECK');
  assert.deepEqual(granted.data, {
    capability_value: 21, capability_name: 'CAP_SYS_ADMIN', return_code: 0, audit_result: 'GRANTED'
  });

  const denied = normalize(event('cap_capable', args, { int_arg: '-1' }));
  assert.equal(denied.supported, true);
  assert.equal(denied.data.audit_result, 'DENIED');
  assert.equal(denied.data.return_code, -1);
  assert.equal(normalize(event('cap_capable', args)).reason, 'KPROBE_CAPABILITY_RETURN_UNAVAILABLE');
  assert.equal(normalize(event('cap_capable', [{ int_arg: 64, label: 'sentinel_capability' }], { int_arg: 0 })).reason,
    'KPROBE_CAPABILITY_VALUE_UNAVAILABLE');
  assert.equal(normalize(event('cap_capable', args, { int_arg: 1 })).reason, 'KPROBE_CAPABILITY_RETURN_INVALID');
});

test('Tetragon process events without exec_id use an explicit PID/start-time source key profile', () => {
  const record = event('cap_capable', [
    { capability_arg: { value: { value: 19 }, name: 'CAP_SYS_PTRACE' }, label: 'sentinel_capability' }
  ], { int_arg: 0 });
  delete record.process_kprobe.process.exec_id;
  record.process_kprobe.process.pid = { value: 1987 };
  delete record.process_kprobe.process.binary;
  const normalized = normalize(record);
  assert.equal(normalized.supported, true);
  assert.equal(normalized.processIdentity.execId, null);
  assert.equal(normalized.processIdentity.pid, 1987);
  assert.equal(normalized.processIdentity.executablePath, null);
  assert.match(normalized.sourceEventKey, /^[a-f0-9]{64}$/);
  assert.equal(normalize({ ...record, process_kprobe: { ...record.process_kprobe, process: { ...record.process_kprobe.process, pid: null } } }).supported, false);
});

test('Unknown symbols and incomplete required hook arguments remain unsupported', () => {
  const unknown = normalize(event('vendor_private_hook', [], { long_arg: '0' }));
  assert.equal(unknown.supported, false);
  assert.equal(unknown.reason, 'UNSUPPORTED_KPROBE_FUNCTION');

  const missingAddress = normalize(event('tcp_v4_connect', [{ sock_arg: { daddr: '198.51.100.20', dport: 443 } }]));
  assert.equal(missingAddress.supported, false);
  assert.equal(missingAddress.reason, 'KPROBE_CONNECT_DESTINATION_UNAVAILABLE');
});

test('Kprobe normalization requires explicit TracingPolicy labels and never treats array position as argument index', () => {
  const unlabeled = normalize(event('vfs_read', [
    { file_arg: { path: '/srv/data.db' } },
    { size_arg: '4096' },
    { size_arg: '8192' }
  ], { long_arg: '2048' }));
  assert.equal(unlabeled.supported, false);
  assert.equal(unlabeled.reason, 'KPROBE_FILE_PATH_UNAVAILABLE');

  const mislabeled = normalize(event('tcp_sendmsg', [
    { sock_arg: { family: 'AF_INET', daddr: '198.51.100.20', dport: 443 }, label: 'sentinel_size' },
    { size_arg: '4096', label: 'sentinel_socket' }
  ], { long_arg: '2048' }));
  assert.equal(mislabeled.supported, false);
  assert.equal(mislabeled.reason, 'KPROBE_SOCKET_DESTINATION_UNAVAILABLE');

  const duplicateLabel = normalize(event('tcp_sendmsg', [
    { sock_arg: { family: 'AF_INET', daddr: '198.51.100.20', dport: 443 }, label: 'sentinel_socket' },
    { sock_arg: { family: 'AF_INET', daddr: '203.0.113.8', dport: 8443 }, label: 'sentinel_socket' },
    { size_arg: '4096', label: 'sentinel_size' }
  ], { long_arg: '2048' }));
  assert.equal(duplicateLabel.supported, false);
  assert.equal(duplicateLabel.reason, 'KPROBE_SOCKET_DESTINATION_UNAVAILABLE');
});
