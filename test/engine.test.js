'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventType, ThreatLevel, EnforcementAction, RecommendationAction } = require('../src/types');
const { WorkloadProfile } = require('../src/profiler');
const { BehavioralSequenceEngine } = require('../src/engine');
const { EvidenceLedger } = require('../src/evidence');

function event(execId, eventType, data = {}, overrides = {}) {
  return {
    eventId: `${execId}:${eventType}:${overrides.n || 0}`,
    workloadId: 'workload-app-1',
    hostIdentity: { hostId: 'host-1', bootId: 'boot-1' },
    processIdentity: { execId, pid: 2002 },
    eventType,
    timestamp: Date.now(),
    data,
    ...overrides
  };
}

test('Sentinel Runtime observes baseline behavior with exact executable and destination rules', () => {
  const engine = new BehavioralSequenceEngine();
  const profile = new WorkloadProfile({
    name: 'api-service',
    allowedBinaries: ['/usr/bin/node'],
    allowedDestinations: ['api.internal.corp:443']
  });
  engine.registerProfile('workload-app-1', profile);

  assert.equal(engine.processEvent(event('exec-1', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' })).threatLevel, ThreatLevel.NORMAL);
  assert.equal(engine.processEvent(event('exec-1', EventType.FILE_READ, { path: '/app/package.json' })).threatLevel, ThreatLevel.NORMAL);
  assert.equal(engine.processEvent(event('exec-1', EventType.NETWORK_CONNECT, { host: 'API.INTERNAL.CORP.', port: 443 })).threatLevel, ThreatLevel.NORMAL);
});

test('Suspicious sequence raises observation only and records a verifiable evidence chain', () => {
  const ledger = new EvidenceLedger(':memory:');
  const enforcements = [];
  const engine = new BehavioralSequenceEngine({ onDecision: decision => enforcements.push(decision) });
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));

  const decisions = [
    engine.processEvent(event('exec-2', EventType.PROCESS_EXEC, { binary: '/bin/bash' })),
    engine.processEvent(event('exec-2', EventType.FILE_READ, { path: '/proc/self/environ' }, { n: 1 })),
    engine.processEvent(event('exec-2', EventType.NETWORK_CONNECT, { host: 'malicious-c2.attacker.com', port: 8080 }, { n: 2 })),
    engine.processEvent(event('exec-2', EventType.NETWORK_SEND_ATTEMPT, { bytes_accepted_by_kernel: 128 }, { n: 3 }))
  ];

  for (const decision of decisions) ledger.recordIncident(decision);
  assert.equal(decisions[0].threatLevel, ThreatLevel.ELEVATED_WATCH);
  assert.equal(decisions[0].action, RecommendationAction.REQUEST_MORE_TELEMETRY);
  assert.equal(decisions[1].threatLevel, ThreatLevel.SUSPICIOUS);
  assert.equal(decisions[2].threatLevel, ThreatLevel.SUSPICIOUS);
  assert.equal(decisions[3].threatLevel, ThreatLevel.SUSPICIOUS);
  assert.ok(decisions.every(decision => decision.action !== 'TERMINATE_PROCESS' && decision.action !== 'SUSPEND_PROCESS'));
  assert.ok(decisions.every(decision => decision.enforcementMode === 'OBSERVE_ONLY'));
  assert.equal(enforcements.length, 4);
  assert.ok(enforcements.every(decision => decision.action === RecommendationAction.REQUEST_MORE_TELEMETRY));
  assert.equal(ledger.getIncidents().length, 4);
  assert.equal(ledger.verifyIntegrity().valid, true);
  ledger.close();
});

test('Process identity uses host, boot, and exec ID, so PID reuse cannot merge chains', () => {
  const engine = new BehavioralSequenceEngine();
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  const first = engine.processEvent(event('exec-a', EventType.PROCESS_EXEC, { binary: '/bin/bash' }));
  const second = engine.processEvent(event('exec-b', EventType.FILE_READ, { path: '/app/data' }, { n: 1 }));
  assert.deepEqual(first.stages, ['UNEXPECTED_EXECUTABLE']);
  assert.deepEqual(second.stages, []);
  assert.equal(engine.processChains.size, 2);
});

test('Events without stable process identity are never correlated', () => {
  const engine = new BehavioralSequenceEngine();
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  const result = engine.processEvent({ workloadId: 'workload-app-1', pid: 44, eventType: EventType.PROCESS_EXEC, data: { binary: '/usr/bin/node' } });
  assert.equal(result.threatLevel, ThreatLevel.ELEVATED_WATCH);
  assert.equal(engine.processChains.size, 0);
});

test('Missing profiles and unimplemented event families are unassessed, not normal', () => {
  const engine = new BehavioralSequenceEngine();
  const noProfile = engine.processEvent(event('unprofiled', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' }));
  assert.equal(noProfile.threatLevel, ThreatLevel.UNASSESSED);
  const unimplemented = engine.processEvent(event('unprofiled', EventType.FILE_WRITE, { path: '/app/data' }, { n: 1 }));
  assert.equal(unimplemented.threatLevel, ThreatLevel.UNASSESSED);
  assert.equal(engine.processChains.size, 0);
});

test('Duplicate IDs are idempotent and expired process state is bounded', () => {
  let now = Date.now();
  const engine = new BehavioralSequenceEngine({ clock: () => now, windowMs: 100, maxChains: 2 });
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  const first = event('exec-dedupe', EventType.PROCESS_EXEC, { binary: '/bin/bash' }, { eventId: 'same', timestamp: now });
  const result = engine.processEvent(first);
  const duplicate = engine.processEvent(first);
  assert.equal(duplicate.reason, 'Duplicate source event ignored');
  assert.equal(duplicate.action, EnforcementAction.RECORD_ONLY);
  assert.equal(duplicate.threatLevel, ThreatLevel.UNASSESSED);
  assert.equal(engine.processChains.size, 1);
  now += 200;
  engine.processEvent(event('exec-new', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' }, { eventId: 'new', timestamp: now }));
  assert.equal(engine.processChains.size, 1);
});

test('Stable source keys take precedence over local payload IDs for dedupe', () => {
  const engine = new BehavioralSequenceEngine();
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  engine.processEvent(event('exec-key', EventType.PROCESS_EXEC, { binary: '/bin/bash' }, { eventId: 'same-payload', sourceEventKey: 'source-a' }));
  engine.processEvent(event('exec-key', EventType.FILE_READ, { path: '/app/data' }, { eventId: 'same-payload', sourceEventKey: 'source-b', n: 1 }));
  assert.equal(engine.processChains.get(JSON.stringify(['host-1', 'boot-1', 'exec-key'])).eventCount, 2);
});

test('Process exit closes state without a profile and remains unassessed', () => {
  const engine = new BehavioralSequenceEngine();
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  engine.processEvent(event('exec-exit', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' }));
  engine.profiles.delete('workload-app-1');
  const exit = engine.processEvent(event('exec-exit', EventType.PROCESS_EXIT, {}, { n: 1 }));
  assert.equal(exit.threatLevel, ThreatLevel.UNASSESSED);
  assert.equal(exit.action, EnforcementAction.RECORD_ONLY);
  assert.equal(engine.processChains.size, 0);
});

test('Expiry queues preserve recently touched state without scanning every retained key', () => {
  let now = 0;
  const engine = new BehavioralSequenceEngine({ clock: () => now, windowMs: 100, maxChains: 10, maxEventIds: 10 });
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  engine.processEvent(event('proc-a', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' }, { timestamp: now, eventId: 'a-1' }));
  now = 50;
  engine.processEvent(event('proc-b', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' }, { timestamp: now, eventId: 'b-1' }));
  now = 75;
  engine.processEvent(event('proc-a', EventType.FILE_READ, { path: '/app/data' }, { timestamp: now, eventId: 'a-2' }));
  now = 151;
  engine.processEvent(event('proc-c', EventType.PROCESS_EXEC, { binary: '/usr/bin/node' }, { timestamp: now, eventId: 'c-1' }));
  assert.equal(engine.processChains.has(JSON.stringify(['host-1', 'boot-1', 'proc-b'])), false);
  assert.equal(engine.processChains.has(JSON.stringify(['host-1', 'boot-1', 'proc-a'])), true);
  assert.equal(engine.eventIds.has('b-1'), false);
  assert.equal(engine.eventIds.has('a-2'), true);
});

test('Send attempts never claim accepted bytes; only a positive send result can do so', () => {
  const engine = new BehavioralSequenceEngine();
  engine.registerProfile('workload-app-1', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'], allowedDestinations: ['api.internal:443'] }));
  const attempt = engine.processEvent(event('exec-send', EventType.NETWORK_SEND_ATTEMPT,
    { bytes_requested: '8192', destination_host: 'api.internal', destination_port: 443 }));
  assert.equal(attempt.eventClass, 'OUTBOUND_ATTEMPT');
  assert.equal(attempt.stages.includes('LOCAL_STACK_ACCEPTED_BYTES'), false);
  const result = engine.processEvent(event('exec-send', EventType.NETWORK_SEND_RESULT,
    { return_code: 4096, bytes_accepted_by_kernel: '4096', destination_host: 'api.internal', destination_port: 443 }, { n: 1 }));
  assert.equal(result.stages.includes('LOCAL_STACK_ACCEPTED_BYTES'), true);
  assert.match(result.reason, /peer receipt is not established/);
});

test('Corrupted ledger payload is detected', () => {
  const ledger = new EvidenceLedger(':memory:');
  ledger.recordIncident({ workloadId: 'w', pid: 10, action: EnforcementAction.RECORD_ONLY, reason: 'test' });
  assert.equal(ledger.verifyIntegrity().valid, true);
  ledger.db.prepare("UPDATE evidence_records SET payload_json = ? WHERE sequence = 1").run('{"tampered":true}');
  assert.equal(ledger.verifyIntegrity().reason, 'TIMESTAMP_MISMATCH');
  ledger.close();
});

test('Ledger detects timestamp-column tampering and preserves prototype-shaped JSON keys', () => {
  const ledger = new EvidenceLedger(':memory:');
  const decision = JSON.parse('{"__proto__":{"polluted":true},"action":"RECORD_ONLY"}');
  ledger.recordIncident(decision);
  const stored = JSON.parse(ledger.db.prepare('SELECT payload_json FROM evidence_records WHERE sequence = 1').get().payload_json);
  assert.equal(Object.hasOwn(stored.decision, '__proto__'), true);
  assert.equal(Object.getPrototypeOf(stored.decision), Object.prototype);
  assert.equal({}.polluted, undefined);
  assert.equal(ledger.verifyIntegrity().valid, true);
  ledger.db.prepare("UPDATE evidence_records SET timestamp = '2000-01-01T00:00:00.000Z' WHERE sequence = 1").run();
  assert.equal(ledger.verifyIntegrity().reason, 'TIMESTAMP_MISMATCH');
  ledger.close();
});

test('Evidence event batches preserve input order and verify as one continuous chain', () => {
  const ledger = new EvidenceLedger(':memory:');
  const records = ledger.recordEvents([
    { event: { sourceEventKey: 'event-a' }, decision: { action: EnforcementAction.RECORD_ONLY }, evidence: { offset: 1 } },
    { event: { sourceEventKey: 'event-b' }, decision: { action: EnforcementAction.RECORD_ONLY }, evidence: { offset: 2 } }
  ]);
  assert.deepEqual(records.map(record => record.sequence), [1, 2]);
  assert.equal(ledger.verifyIntegrity().checked, 2);
  assert.deepEqual(ledger.getRecords().map(record => record.sequence), [2, 1]);
  ledger.close();
});

test('Evidence checkpoints commit atomically with events and remain hash-chain verifiable', () => {
  const ledger = new EvidenceLedger(':memory:');
  try {
    const checkpoint = {
      source_id: 'file:nightly-export', source_fingerprint: 'a'.repeat(64),
      cursor_kind: 'FILE_BYTES', byte_offset: 120, complete: false
    };
    const committed = ledger.recordEventsWithCheckpoint([{ event: { sourceEventKey: 'event-a' } }], checkpoint);
    assert.equal(committed.events.length, 1);
    assert.equal(committed.checkpoint.sequence, 2);
    assert.deepEqual(ledger.getLatestSourceCheckpoint('file:nightly-export'), { sequence: 2, ...checkpoint });
    assert.equal(ledger.verifyIntegrity().checked, 2);

    ledger.db.exec("CREATE TRIGGER reject_source_checkpoint BEFORE INSERT ON evidence_records WHEN NEW.record_type = 'source_checkpoint' BEGIN SELECT RAISE(ABORT, 'checkpoint fault'); END;");
    assert.throws(() => ledger.recordEventsWithCheckpoint([{ event: { sourceEventKey: 'event-b' } }], { ...checkpoint, byte_offset: 240 }), /checkpoint fault/);
    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
    assert.equal(integrity.checked, 2);
    assert.deepEqual(ledger.getLatestSourceCheckpoint('file:nightly-export'), { sequence: 2, ...checkpoint });
  } finally { ledger.close(); }
});

test('Evidence ledger suppresses duplicate source event keys across batches and restarts', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-idempotency-'));
  const dbPath = path.join(directory, 'evidence.sqlite');
  const keyA = 'a'.repeat(64);
  const keyB = 'b'.repeat(64);
  try {
    let ledger = new EvidenceLedger(dbPath);
    try {
      const first = ledger.recordEvents([
        { event: { source_event_key: keyA, value: 'first' } },
        { event: { source_event_key: keyA.toUpperCase(), value: 'duplicate-in-batch' } },
        { event: { value: 'without-source-key' } }
      ]);
      assert.deepEqual(first.map(record => record.sequence), [1, 2]);
      assert.equal(ledger.verifyIntegrity().checked, 2);
    } finally { ledger.close(); }

    ledger = new EvidenceLedger(dbPath);
    try {
      const checkpointed = ledger.recordEventsWithCheckpoint([
        { event: { source_event_key: keyA, value: 'replayed-after-restart' } },
        { event: { sourceEventKey: keyB, value: 'new-event' } }
      ], {
        source_id: 'replay-test', cursor_kind: 'FILE_BYTES', byte_offset: '200', complete: false
      });
      assert.equal(checkpointed.events.length, 1);
      assert.equal(checkpointed.duplicates, 1);
      assert.equal(checkpointed.checkpoint.sequence, 4);
      assert.equal(ledger.verifyIntegrity().checked, 4);
      const storedEvents = ledger.db.prepare("SELECT payload_json FROM evidence_records WHERE record_type = 'event' ORDER BY sequence").all();
      assert.equal(storedEvents.length, 3);
      assert.equal(JSON.parse(storedEvents[0].payload_json).event.value, 'first');
      assert.equal(JSON.parse(storedEvents[1].payload_json).event.value, 'without-source-key');
      assert.equal(JSON.parse(storedEvents[2].payload_json).event.value, 'new-event');
    } finally { ledger.close(); }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('Evidence ledger does not deduplicate malformed or non-cryptographic source keys', () => {
  const ledger = new EvidenceLedger(':memory:');
  try {
    const records = ledger.recordEvents([
      { event: { source_event_key: 'not-a-hash' } },
      { event: { source_event_key: 'not-a-hash' } },
      { event: { source_event_key: 'f'.repeat(63) } },
      { event: { source_event_key: 'f'.repeat(63) } }
    ]);
    assert.equal(records.length, 4);
    assert.equal(ledger.verifyIntegrity().checked, 4);
  } finally { ledger.close(); }
});

test('Evidence ledger can reopen a database with malformed payloads and report corruption', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-corrupt-index-'));
  const dbPath = path.join(directory, 'evidence.sqlite');
  try {
    let ledger = new EvidenceLedger(dbPath);
    ledger.recordEvent({ source_event_key: 'c'.repeat(64) });
    ledger.db.exec('DROP INDEX evidence_events_source_key_v2; DROP INDEX evidence_events_source_key_legacy;');
    ledger.db.prepare('UPDATE evidence_records SET payload_json = ? WHERE sequence = 1').run('{invalid-json');
    ledger.close();

    ledger = new EvidenceLedger(dbPath);
    try {
      assert.deepEqual(ledger.verifyIntegrity(), {
        valid: false, checked: 0, sequence: 1, reason: 'INVALID_PAYLOAD_JSON'
      });
    } finally { ledger.close(); }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
