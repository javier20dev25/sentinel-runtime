'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  InvestigationTaskExecutor,
  inspectProcessIdentity,
  inspectProcessTree,
  inspectFileMetadata,
  parseSocketTable,
  decodeProcAddress,
  queryLedger,
  fitOutputToLimit,
} = require('../../src/runtime/investigation-task-executor');

function executor(ledger = {}) {
  return new InvestigationTaskExecutor({
    client: { pollInvestigationTasks: async () => ({ ok: true, data: { tasks: [], state: 'NO_PENDING_TASKS' } }), sendInvestigationTaskResult: async () => ({ ok: true }) },
    ledger: { append() {}, getRecords: () => [], path: ':memory:', ...ledger },
    hostId: 'host-test', bootId: 'c31528b0-ab61-4f13-9b8d-bf7ee47b0b87', enabled: true,
  });
}

test('Runtime advertises only fixed L0 playbooks and no arbitrary command capability', () => {
  const caps = executor().capabilities();
  assert.equal(caps.investigation_tasks, true);
  assert.ok(caps.playbooks.includes('LINUX.PROCESS.IDENTITY'));
  assert.ok(caps.playbooks.includes('LINUX.EVIDENCE.VERIFY'));
  assert.equal(caps.playbooks.some((id) => id.includes('SHELL') || id.includes('EXEC')), false);
});

test('Runtime rejects a task from another boot before procfs access', () => {
  const runner = executor();
  assert.throws(() => runner.validateTask({
    task_id: 'inv_task_0123456789abcdef01234567', nonce: 'a'.repeat(32), playbook_id: 'LINUX.PROCESS.IDENTITY',
    governance_level: 'L0_PASSIVE_READ', expected_boot_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    expires_at: new Date(Date.now() + 60_000).toISOString(), scope: { pid: 7 }, timeout_ms: 5000, max_output_bytes: 8192,
  }), (error) => error.code === 'HOST_BOOT_ID_MISMATCH');
});

test('ledger verification accepts only full-chain scope and caps output to its local registry', () => {
  const runner = executor();
  assert.throws(() => runner.validateTask({
    task_id: 'inv_task_0123456789abcdef01234567', nonce: 'a'.repeat(32), playbook_id: 'LINUX.EVIDENCE.VERIFY',
    governance_level: 'L0_PASSIVE_READ', expires_at: new Date(Date.now() + 60_000).toISOString(),
    scope: { from_sequence: 10 }, timeout_ms: 15000, max_output_bytes: 16384,
  }), (error) => error.code === 'UNSUPPORTED_SCOPE_FIELD');
  assert.throws(() => runner.validateTask({
    task_id: 'inv_task_0123456789abcdef01234567', nonce: 'a'.repeat(32), playbook_id: 'LINUX.EVIDENCE.VERIFY',
    governance_level: 'L0_PASSIVE_READ', expires_at: new Date(Date.now() + 60_000).toISOString(),
    scope: {}, timeout_ms: 15000, max_output_bytes: 65536,
  }), (error) => error.code === 'INVALID_OUTPUT_LIMIT');
});

test('procfs process identity and ancestry never return argv or environment', { skip: process.platform !== 'linux' }, async () => {
  const identity = await inspectProcessIdentity(process.pid);
  assert.equal(identity.observation_status, 'OBSERVED');
  assert.equal(identity.pid, process.pid);
  assert.equal(Object.hasOwn(identity, 'cmdline'), false);
  assert.equal(Object.hasOwn(identity, 'environment'), false);
  assert.equal(identity.capture_limits.includes('No argv or environment variables were read.'), true);
  const tree = await inspectProcessTree(process.pid);
  assert.equal(tree.ancestors[0].pid, process.pid);
  assert.ok(tree.ancestors.length <= 16);
});

test('L0 process identity task reads the evidence-scoped PID and submits a bounded result', { skip: process.platform !== 'linux' }, async () => {
  const bootId = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
  const rows = [{
    sequence: 1,
    record_type: 'event',
    payload_json: JSON.stringify({
      host_identity: { boot_id: bootId },
      process_identity: { pid: process.pid },
    }),
    record_hash: '1'.repeat(64),
    timestamp: new Date().toISOString(),
  }];
  const submitted = [];
  let sequence = 2;
  const runner = executor({
    getRecords: () => rows,
    append: (recordType, payload) => {
      const row = {
        sequence: sequence++, record_type: recordType, payload_json: JSON.stringify(payload),
        record_hash: String(sequence).padStart(64, '0'), timestamp: payload.timestamp,
      };
      rows.push(row);
      return row;
    },
    path: ':memory:',
  });
  runner.bootId = bootId;
  runner.hostId = 'host-test';
  runner.client.sendInvestigationTaskResult = async (payload) => { submitted.push(payload); return { ok: true }; };

  await runner.executeAndSubmit({
    task_id: 'inv_task_0123456789abcdef01234567',
    incident_id: 'incident-test',
    nonce: 'a'.repeat(32),
    expected_boot_id: bootId,
    playbook_id: 'LINUX.PROCESS.IDENTITY',
    playbook_version: '1.0.0',
    governance_level: 'L0_PASSIVE_READ',
    scope: { pid: process.pid },
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    timeout_ms: 5000,
    max_output_bytes: 16 * 1024,
  }, new AbortController().signal);

  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].status, 'COMPLETED');
  assert.equal(submitted[0].output_data.pid, process.pid);
  assert.equal(submitted[0].output_data.observation_status, 'OBSERVED');
  assert.match(submitted[0].result_hash, /^[a-f0-9]{64}$/);
  assert.ok(submitted[0].evidence_record_hash);
});

test('file metadata uses lstat semantics and never reads target contents', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-task-'));
  const filename = path.join(dir, 'evidence.txt');
  fs.writeFileSync(filename, 'sensitive content must not leave the host');
  try {
    const result = await inspectFileMetadata(filename);
    assert.equal(result.exists, true);
    assert.equal(result.type, 'REGULAR_FILE');
    assert.equal(result.content_read, false);
    assert.equal(Object.hasOwn(result, 'contents'), false);
    assert.equal(result.size_bytes, String(Buffer.byteLength('sensitive content must not leave the host')));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('procfs socket decoding distinguishes loopback and TCP state without packet capture', () => {
  assert.equal(decodeProcAddress('0100007F', false), '127.0.0.1');
  assert.equal(decodeProcAddress('00000000000000000000000001000000', true), '::1');
  const table = [
    '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode',
    '   0: 0100007F:1F90 0100007F:46A0 02 00000000:00000000 00:00000000 00000000 1000 0 4242',
  ].join('\n');
  const [socket] = parseSocketTable(table, 'tcp');
  assert.equal(socket.local.ip, '127.0.0.1');
  assert.equal(socket.remote.port, 18080);
  assert.equal(socket.state, 'SYN_SENT');
  assert.equal(socket.inode, '4242');
});

test('historical task queries are boot-scoped and preserve attempt semantics', () => {
  const event = {
    event_type: 'NETWORK_CONNECT_ATTEMPT',
    host_identity: { boot_id: 'c31528b0-ab61-4f13-9b8d-bf7ee47b0b87' },
    process_identity: { pid: 17601, exec_id: 'exec-1' },
    payload: { network_endpoint: { protocol: 'TCP', destination_ip: '127.0.0.1', destination_port: 18080 } },
  };
  const wrongBoot = { ...event, host_identity: { boot_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' } };
  const rows = [event, wrongBoot].map((item, index) => ({ sequence: index + 1, timestamp: new Date().toISOString(), record_type: 'event', payload_json: JSON.stringify(item), record_hash: String(index + 1).repeat(64) }));
  const result = queryLedger({ getRecords: () => rows }, { scope: { pid: 17601, destination_ip: '127.0.0.1' } }, 'NETWORK', 'c31528b0-ab61-4f13-9b8d-bf7ee47b0b87');
  assert.equal(result.returned, 1);
  assert.equal(result.records[0].event_semantics, 'ATTEMPT_OBSERVED_SUCCESS_NOT_ESTABLISHED');
  assert.equal(result.records[0].network_endpoint.destination_ip, '127.0.0.1');
});

test('large procfs results are shortened deterministically before Cloud submission', () => {
  const output = fitOutputToLimit({ observation_status: 'OBSERVED', sockets: Array.from({ length: 80 }, (_, index) => ({ index, detail: 'x'.repeat(128) })), socket_count: 80 }, 2048);
  assert.ok(Buffer.byteLength(JSON.stringify(output)) <= 2048);
  assert.equal(output.truncated_by_playbook_output_limit, true);
  assert.ok(output.sockets.length < 80);
});
