'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { WorkloadProfile } = require('../src/profiler');
const { JsonlFramer, parseJsonRejectDuplicateKeys } = require('../src/ingest/jsonl');
const { normalizeTetragonJson, timestampNs } = require('../src/adapters/tetragon-json');
const { rawProviderEventKey, derivedCorrelatedEventKey, syntheticObservabilityEventKey, lengthPrefix } = require('../src/contracts/event-keys');
const { validateEventV2, validateCursor } = require('../src/contracts/validate-event-v2');
const { canonicalJson } = require('../src/contracts/canonical-json');
const { BehavioralSequenceEngine } = require('../src/engine');
const { EvidenceLedger } = require('../src/evidence');
const { main: runCli, resolveBootId } = require('../bin/sentinel-runtime');

const fixturesDir = path.join(__dirname, 'fixtures/events/v2');

test('Binary policy requires exact absolute paths or a pinned SHA-256 digest', () => {
  const profile = new WorkloadProfile({ allowedBinaries: ['/usr/bin/node', `sha256:${'a'.repeat(64)}`] });
  assert.equal(profile.isBinaryAllowed('/usr/bin/node'), true);
  assert.equal(profile.isBinaryAllowed('/tmp/node'), false);
  assert.equal(profile.isBinaryAllowed('node'), false);
  assert.equal(profile.isBinaryAllowed('/tmp/renamed', 'A'.repeat(64)), true);
  assert.throws(() => new WorkloadProfile({ allowedBinaries: ['node'] }), /absolute paths or sha256/);
});

test('Path decisions use normalized segment boundaries and treat unknown paths as untrusted', () => {
  const profile = new WorkloadProfile({ allowedReadPrefixes: ['/app'] });
  assert.equal(profile.isPathRestricted('/etc/shadow'), true);
  assert.equal(profile.isPathRestricted('/etc/shadow/child'), true);
  assert.equal(profile.isPathRestricted('/app/etc/shadow-copy'), false);
  assert.equal(profile.isPathRestricted('/app/../etc/shadow'), true);
  assert.equal(profile.isPathRestricted('proc/self/environ'), true);
});

test('Network allowlist normalizes names and supports IPv4 CIDR rules', () => {
  const profile = new WorkloadProfile({ allowedDestinations: ['API.INTERNAL.:443', '10.16.0.0/16'] });
  assert.equal(profile.isNetworkDestinationAllowed('api.internal', 443), true);
  assert.equal(profile.isNetworkDestinationAllowed('api.internal', 444), false);
  assert.equal(profile.isNetworkDestinationAllowed('10.16.4.9', 22), true);
  assert.equal(profile.isNetworkDestinationAllowed('10.17.4.9', 22), false);
});

test('JSONL framer preserves UTF-8 byte offsets and CRLF framing across chunks', () => {
  const framer = new JsonlFramer();
  assert.deepEqual(framer.push(Buffer.from('{"label":"á"}\r', 'utf8')), []);
  const first = framer.push(Buffer.from('\n{"n":2}', 'utf8'));
  assert.equal(first.length, 1);
  assert.deepEqual(JSON.parse(first[0].text), { label: 'á' });
  assert.equal(first[0].delimiterByteLength, 2);
  assert.equal(first[0].byteLength, Buffer.byteLength(first[0].text) + 2);
  const final = framer.finish();
  assert.equal(final.length, 1);
  assert.equal(final[0].byteOffset, first[0].byteLength);
  assert.equal(final[0].delimiterByteLength, 0);
});

test('JSONL framer handles blank frames and an input chunk containing many records', () => {
  const framer = new JsonlFramer({ maxFrameBytes: 8 });
  const frames = framer.push(Buffer.from('\n1\n2\n3\n4\n5\n6\n7\n8\n9\n'));
  assert.deepEqual(frames.map(frame => frame.text), ['1', '2', '3', '4', '5', '6', '7', '8', '9']);
  assert.equal(framer.offset, 19);
  assert.deepEqual(framer.finish(), []);
});

test('JSON parser rejects duplicate keys after escape decoding, including nested keys', () => {
  assert.throws(() => parseJsonRejectDuplicateKeys('{"a":1,"\\u0061":2}'), /Duplicate JSON object key/);
  assert.throws(() => parseJsonRejectDuplicateKeys('{"outer":{"x":1,"x":2}}'), /Duplicate JSON object key/);
  assert.deepEqual(parseJsonRejectDuplicateKeys('{"outer":{"x":1},"items":[true,null]}'), { outer: { x: 1 }, items: [true, null] });
  assert.throws(() => parseJsonRejectDuplicateKeys('{"x":1} trailing'), /Trailing content/);
});

test('Canonical evidence JSON rejects sparse arrays, symbol keys, and accessors', () => {
  const sparse = [];
  sparse.length = 1;
  assert.throws(() => canonicalJson(sparse), /sparse arrays/);
  assert.throws(() => canonicalJson({ [Symbol('hidden')]: 1 }), /symbol keys/);
  const accessor = {};
  Object.defineProperty(accessor, 'value', { enumerable: true, get() { throw new Error('getter executed'); } });
  assert.throws(() => canonicalJson(accessor), /accessor properties/);
  const cycle = [];
  cycle.push(cycle);
  assert.throws(() => canonicalJson(cycle), /cyclic values/);
});

test('JSONL framer enforces per-frame byte limit', () => {
  const framer = new JsonlFramer({ maxFrameBytes: 4 });
  assert.throws(() => framer.push(Buffer.from('12345')), /exceeds maxFrameBytes/);
});

test('JSONL framer isolates invalid UTF-8 frames and continues with the next line', () => {
  const framer = new JsonlFramer();
  const frames = framer.push(Buffer.from([0xff, 0x0a, 0x7b, 0x22, 0x78, 0x22, 0x3a, 0x31, 0x7d, 0x0a]));
  assert.equal(frames.length, 2);
  assert.match(frames[0].decodeError, /encoded data/i);
  assert.deepEqual(parseJsonRejectDuplicateKeys(frames[1].text), { x: 1 });
});

test('Tetragon protobuf timestamps retain all nanosecond digits', () => {
  assert.equal(timestampNs('2026-11-02T12:34:56.123456789Z'), '1793622896123456789');
  assert.equal(timestampNs({ seconds: 2, nanos: 3 }), '2000000003');
  assert.equal(timestampNs({ seconds: '9007199254740992', nanos: 3 }), '9007199254740992000000003');
  assert.equal(timestampNs({ seconds: 9007199254740992, nanos: 3 }), null);
  assert.equal(timestampNs('not-a-time'), null);
});

test('Tetragon timestamp parser rejects normalized impossible calendar dates', () => {
  assert.equal(timestampNs('2026-02-31T12:34:56.123456789Z'), null);
  assert.equal(timestampNs('2026-11-02T25:34:56Z'), null);
});

test('Tetragon process_exec normalization preserves opaque exec IDs and raw arguments', () => {
  const raw = Buffer.from(JSON.stringify({
    time: '2026-11-02T12:34:56.123456789Z',
    process_exec: {
      process: {
        exec_id: 'OPAQUE+/==', parent_exec_id: 'PARENT/opaque', pid: { value: 41 }, tid: { value: 41 },
        start_time: '2026-11-02T12:34:56.120000001Z', binary: '/usr/bin/node', arguments: 'node "two words" --flag'
      }
    }
  }));
  const event = normalizeTetragonJson(JSON.parse(raw), raw, { hostId: 'host-a', bootId: 'boot-a' });
  assert.equal(event.supported, true);
  assert.equal(event.processIdentity.execId, 'OPAQUE+/==');
  assert.equal(event.processIdentity.parentExecId, 'PARENT/opaque');
  assert.equal(event.processIdentity.pid, 41);
  assert.equal(event.data.argumentsRaw, 'node "two words" --flag');
  assert.match(event.sourceEventKey, /^[0-9a-f]{64}$/);
  assert.equal(event.sourceEventKey, rawProviderEventKey({
    hostId: 'host-a', bootId: 'boot-a', execId: 'OPAQUE+/==', eventType: 'PROCESS_EXEC',
    sourceTimestamp: event.timestamp, rawPayloadSha256: event.rawPayloadSha256
  }));
});

test('Unsupported Tetragon event families are explicit and do not masquerade as normalized', () => {
  const raw = Buffer.from('{"process_tracepoint":{}}');
  const result = normalizeTetragonJson(JSON.parse(raw), raw, { hostId: 'h', bootId: 'b' });
  assert.equal(result.supported, false);
  assert.equal(result.reason, 'UNSUPPORTED_NATIVE_EVENT');
});

test('V2 production validator checks fixtures and cursor transport semantics without mutation', () => {
  const event = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8'));
  const before = JSON.stringify(event);
  const result = validateEventV2(event);
  assert.equal(result.valid, true, JSON.stringify(result.errors));
  assert.equal(JSON.stringify(event), before);
  const errors = [];
  validateCursor(event.source_cursor, 'GRPC_TCP', errors);
  assert.ok(errors.some(error => error.keyword === 'cursorTransportMismatch'));
});

test('V2 production validator verifies all RAW, DERIVED, and SYNTHETIC event keys', () => {
  const files = [
    ...fs.readdirSync(fixturesDir).filter(file => file.endsWith('.json')).map(file => path.join(fixturesDir, file)),
    ...fs.readdirSync(path.join(fixturesDir, 'families')).filter(file => file.endsWith('.json')).map(file => path.join(fixturesDir, 'families', file))
  ];
  for (const file of files) {
    const event = JSON.parse(fs.readFileSync(file, 'utf8'));
    const result = validateEventV2(event);
    assert.equal(result.valid, true, `${path.basename(file)}: ${JSON.stringify(result.errors)}`);
  }
  const changed = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8'));
  changed.source_event_key = 'f'.repeat(64);
  assert.ok(validateEventV2(changed).errors.some(error => error.keyword === 'eventKeyMismatch'));
});

test('V2 production validator rejects unsafe uint64 Numbers and unresolved credential loss', () => {
  const event = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8'));
  event.source_cursor.byte_offset = 9007199254740992;
  const result = validateEventV2(event);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some(error => error.keyword === 'precisionRisk'));
});

test('V2 production validator rejects measured loss without provenance and zero lower bounds', () => {
  const event = JSON.parse(fs.readFileSync(path.join(fixturesDir, 'families/13_event_loss.json'), 'utf8'));
  event.loss_metrics.ebpf_kernel = { state: 'MEASURED', count: 1 };
  assert.equal(validateEventV2(event).valid, false);
  event.loss_metrics.ebpf_kernel = { state: 'MEASURED_LOWER_BOUND', count: '0', source: 'counter-a', observed_at: '1793662267650000000' };
  assert.equal(validateEventV2(event).valid, false);
  event.loss_metrics.ebpf_kernel = { state: 'UNKNOWN', count: null };
  const unknown = validateEventV2(event);
  assert.equal(unknown.valid, true);
  assert.ok(unknown.warnings.some(warning => warning.includes('ebpf_kernel is UNKNOWN')));
});

test('Event identity profiles are domain separated and use UTF-8 byte lengths', () => {
  const framed = lengthPrefix('á');
  assert.equal(framed.readBigUInt64BE(0), 2n);
  const rawArgs = { hostId: 'h', bootId: 'b', execId: 'e', eventType: 'PROCESS_EXEC', sourceTimestamp: '1', rawPayloadSha256: 'a'.repeat(64) };
  const raw = rawProviderEventKey(rawArgs);
  assert.equal(rawProviderEventKey({ ...rawArgs, rawPayloadSha256: 'A'.repeat(64) }), raw);
  assert.throws(() => lengthPrefix(1), /canonical strings/);
  assert.throws(() => rawProviderEventKey({ ...rawArgs, sourceTimestamp: {} }), /exact non-negative integer/);
  assert.throws(() => syntheticObservabilityEventKey({ hostId: 'h', bootId: 'b', producerId: 'p', producerEpoch: 'e', sequenceNumber: '18446744073709551616', payloadSha256: 'c'.repeat(64) }), /uint64 range/);
  const derived = derivedCorrelatedEventKey({ hostId: 'h', bootId: 'b', correlationRuleId: 'r', ruleVersion: '1', primaryEventKey: raw, secondaryEventKey: 'b'.repeat(64) });
  const synthetic = syntheticObservabilityEventKey({ hostId: 'h', bootId: 'b', producerId: 'p', producerEpoch: 'epoch-2', sequenceNumber: '1', payloadSha256: 'c'.repeat(64) });
  assert.equal(new Set([raw, derived, synthetic]).size, 3);
  assert.notEqual(syntheticObservabilityEventKey({ hostId: 'h', bootId: 'b', producerId: 'p', producerEpoch: 'epoch-1', sequenceNumber: '1', payloadSha256: 'c'.repeat(64) }), synthetic);
});

test('Process exit closes the stable process chain', () => {
  const engine = new BehavioralSequenceEngine();
  const profile = new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] });
  engine.registerProfile('w', profile);
  engine.processEvent({ workloadId: 'w', eventType: 'PROCESS_EXEC', hostIdentity: { hostId: 'h', bootId: 'b' }, processIdentity: { execId: 'e' }, data: { binary: '/usr/bin/node' } });
  assert.equal(engine.processChains.size, 1);
  engine.processEvent({ workloadId: 'w', eventType: 'PROCESS_EXIT', hostIdentity: { hostId: 'h', bootId: 'b' }, processIdentity: { execId: 'e' } });
  assert.equal(engine.processChains.size, 0);
});

test('CLI ingests real-shaped Tetragon JSONL in memory and reports supported scope', async () => {
  const output = [];
  const originalLog = console.log;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-jsonl-v2-'));
  const db = path.join(directory, 'runtime.sqlite');
  console.log = value => output.push(value);
  try {
    const code = await runCli([
      'ingest-tetragon', '--input', path.join(__dirname, 'fixtures/tetragon/process_exec_exit.jsonl'),
      '--host-id', 'unit-host', '--boot-id', 'unit-boot', '--db', db
    ]);
    assert.equal(code, 0);
  } finally {
    console.log = originalLog;
  }
  try {
    const result = JSON.parse(output[0]);
    assert.deepEqual(result.counts, { frames: 2, processed: 2, unsupported: 0, rejected: 0, unassessed: 2, decisions: 0, persisted_records: 2, duplicates_suppressed: 0 });
    assert.equal(result.batch_size, 128);
    assert.equal(result.mode, 'observe-only');
    const ledger = new EvidenceLedger(db);
    try {
      const events = ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'event')
        .map(row => JSON.parse(row.payload_json).event);
      assert.deepEqual(events.map(event => event.event_type).sort(), ['PROCESS_EXEC', 'PROCESS_EXIT']);
      for (const event of events) {
        assert.equal(validateEventV2(event).valid, true);
        assert.equal(event.source_cursor.cursor_kind, 'FILE_BYTES');
        assert.match(event.source_cursor.device_id, /^(0|[1-9][0-9]*)$/);
      }
      assert.equal(events.find(event => event.event_type === 'PROCESS_EXEC').payload.arguments_capture_status, 'REDACTED_BY_POLICY');
      assert.equal(ledger.verifyIntegrity().valid, true);
    } finally { ledger.close(); }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('boot-id-file reads a bounded canonical UUID and rejects ambiguous or unsafe inputs', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-boot-id-'));
  const input = path.join(directory, 'boot_id');
  const expected = '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c';
  try {
    fs.writeFileSync(input, `${expected.toUpperCase()}\n`);
    assert.equal(resolveBootId({ bootIdFile: input }), expected);
    assert.throws(() => resolveBootId({ bootId: 'inline', bootIdFile: input }), /either --boot-id or --boot-id-file/);
    assert.throws(() => resolveBootId({ bootIdFile: 'relative/boot_id' }), /absolute path/);
    fs.writeFileSync(input, 'not-a-uuid\n');
    assert.throws(() => resolveBootId({ bootIdFile: input }), /canonical UUID/);
    fs.writeFileSync(input, 'x'.repeat(4097));
    assert.throws(() => resolveBootId({ bootIdFile: input }), /exceeds 4096 bytes/);
    if (process.platform !== 'win32') {
      const link = path.join(directory, 'boot_id_link');
      fs.symlinkSync(input, link);
      assert.throws(() => resolveBootId({ bootIdFile: link }), /Cannot read --boot-id-file/);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon offline ingestion requires trusted host and boot identity', async () => {
  await assert.rejects(() => runCli([
    'ingest-tetragon', '--input', path.join(__dirname, 'fixtures/tetragon/process_exec_exit.jsonl'),
    '--host-id', 'unit-host', '--db', ':memory:'
  ]), /--boot-id is required/);
});

test('Tetragon JSONL checkpoint resumes after an atomic batch failure without duplicating committed events', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-file-resume-'));
  const input = path.join(directory, 'events.jsonl');
  const db = path.join(directory, 'runtime.sqlite');
  const first = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/tetragon/process_exec_exit.jsonl'), 'utf8').split('\n')[0]);
  const second = structuredClone(first);
  second.time = '2026-11-02T12:35:03.000000001Z';
  second.process_exec.process.exec_id = 'TETRAGON-EXEC-42';
  fs.writeFileSync(input, `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`);
  const initialOffset = Buffer.byteLength(`${JSON.stringify(first)}\n`);
  let ledger = new EvidenceLedger(db);
  ledger.db.exec("CREATE TRIGGER reject_second_event BEFORE INSERT ON evidence_records WHEN NEW.record_type = 'event' AND NEW.payload_json LIKE '%TETRAGON-EXEC-42%' BEGIN SELECT RAISE(ABORT, 'injected event write failure'); END;");
  ledger.close();

  const args = ['ingest-tetragon', '--input', input, '--host-id', 'unit-host', '--boot-id', 'unit-boot', '--db', db, '--checkpoint-id', 'retry-case', '--batch-size', '1'];
  const originalLog = console.log;
  console.log = () => {};
  try {
    await assert.rejects(() => runCli(args), /injected event write failure/);
  } finally { console.log = originalLog; }

  ledger = new EvidenceLedger(db);
  const partial = ledger.getLatestSourceCheckpoint('file:retry-case');
  assert.equal(partial.byte_offset, String(initialOffset));
  assert.equal(partial.complete, false);
  assert.equal(ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'event').length, 1);
  ledger.db.exec('DROP TRIGGER reject_second_event');
  ledger.close();

  const output = [];
  console.log = value => output.push(value);
  try {
    const code = await runCli([...args, '--resume']);
    assert.equal(code, 0);
  } finally { console.log = originalLog; }
  const result = JSON.parse(output[0]);
  assert.equal(result.resumed_from_offset, initialOffset);
  assert.equal(result.counts.processed, 1);
  assert.equal(result.counts.persisted_records, 1);
  ledger = new EvidenceLedger(db);
  try {
    assert.equal(ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'event').length, 2);
    assert.equal(ledger.getLatestSourceCheckpoint('file:retry-case').complete, true);
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon JSONL resume refuses changed content and skips an already complete immutable source', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-file-fingerprint-'));
  const input = path.join(directory, 'events.jsonl');
  const db = path.join(directory, 'runtime.sqlite');
  fs.copyFileSync(path.join(__dirname, 'fixtures/tetragon/process_exec_exit.jsonl'), input);
  const args = ['ingest-tetragon', '--input', input, '--host-id', 'unit-host', '--boot-id', 'unit-boot', '--db', db, '--checkpoint-id', 'immutable-case'];
  const originalLog = console.log;
  let output = [];
  console.log = value => output.push(value);
  try {
    assert.equal(await runCli(args), 0);
    output = [];
    assert.equal(await runCli([...args, '--resume']), 0);
    assert.equal(JSON.parse(output[0]).already_complete, true);
    assert.equal(JSON.parse(output[0]).counts.persisted_records, 0);
  } finally { console.log = originalLog; }

  fs.appendFileSync(input, '\n');
  try {
    await assert.rejects(() => runCli([...args, '--resume']), /fingerprint does not match/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
