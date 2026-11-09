'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EvidenceLedger } = require('../../src/evidence');
const { RuntimeIncidentPublisher } = require('../../src/cloud/incident-publisher');

function sampleEntry() {
  return {
    event: {
      event_type: 'FILE_OPEN_ATTEMPT',
      source_event_key: 'a'.repeat(64),
      timestamps: { source_timestamp: '2026-11-08T12:00:00.000Z' },
      process_identity: { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-1', pid: 42, arguments: '--password=secret' },
      payload: { path: '/etc/shadow', password: 'never-upload-this' }
    },
    decision: {
      threatLevel: 'HIGH', confidence: 0.82, reason: 'Restricted file access observed',
      triggeredRules: ['RESTRICTED_PATH_ACCESS'], requestedAction: 'REQUEST_MORE_TELEMETRY',
      safetyGatingReasons: ['Observation only']
    },
    evidence: { raw_arguments_preserved: false }
  };
}

function createLedgerWithEvent(entry) {
  const ledger = new EvidenceLedger(':memory:');
  ledger.recordEventsWithCheckpoint([entry], {
    source_id: 'test-source', provider: 'tetragon', sequence_number: '1'
  });
  return ledger;
}

test('publisher builds a factual envelope from committed evidence and redacts command material', () => {
  const entry = sampleEntry();
  const ledger = createLedgerWithEvent(entry);
  const sent = [];
  const publisher = new RuntimeIncidentPublisher({
    ledger, hostId: 'host-1', bootId: 'boot-1',
    client: { sendIncidentEnvelope: async envelope => { sent.push(envelope); return { ok: true, data: {} }; } }
  });

  assert.equal(publisher.consider(entry, 'HEALTHY'), true);
  const pending = JSON.parse(ledger.getCloudDeliveryRecords().find(row => row.record_type === 'cloud_delivery_pending').payload_json);
  assert.equal(pending.envelope.severity, 'HIGH');
  assert.equal(pending.envelope.containment_status, 'OBSERVED');
  assert.equal(pending.envelope.sanitized_envelope.analysis_status, 'NOT_REQUESTED');
  assert.equal(pending.envelope.sanitized_envelope.observations.length, 1);
  assert.equal(pending.envelope.sanitized_envelope.evidence.verification_status, 'AGENT_REPORTED_NOT_CLOUD_VERIFIED');
  const json = JSON.stringify(pending.envelope);
  assert.equal(json.includes('never-upload-this'), false);
  assert.equal(json.includes('--password=secret'), false);

  ledger.close();
});

test('pending delivery survives restart and acknowledged incident is not resent', async () => {
  const entry = sampleEntry();
  const ledger = createLedgerWithEvent(entry);
  let attempts = 0;
  const client = { sendIncidentEnvelope: async () => {
    attempts++;
    return attempts === 1 ? { ok: false, error: 'OFFLINE' } : { ok: true, data: { incident_id: 'cloud-1', duplicate: false } };
  } };
  const retryOptions = { retryBaseMs: 25, retryMaxMs: 25 };
  const first = new RuntimeIncidentPublisher({ ledger, client, hostId: 'host-1', bootId: 'boot-1', ...retryOptions });
  first.consider(entry, 'HEALTHY');
  assert.deepEqual(await first.flushPending(), { sent: 0, failed: 1, queued: 1 });
  first.close();

  const restarted = new RuntimeIncidentPublisher({ ledger, client, hostId: 'host-1', bootId: 'boot-1', ...retryOptions });
  assert.deepEqual(await restarted.flushPending(), { sent: 0, failed: 0, queued: 1 });
  await new Promise(resolve => setTimeout(resolve, 35));
  assert.equal(attempts, 2);
  assert.deepEqual(await restarted.flushPending(), { sent: 0, failed: 0, queued: 0 });
  const afterAck = new RuntimeIncidentPublisher({ ledger, client, hostId: 'host-1', bootId: 'boot-1' });
  assert.deepEqual(await afterAck.flushPending(), { sent: 0, failed: 0, queued: 0 });
  assert.equal(attempts, 2);
  ledger.close();
});

test('low severity and events without a stable source key do not enqueue Cloud cases', () => {
  const entry = sampleEntry();
  const ledger = createLedgerWithEvent(entry);
  const publisher = new RuntimeIncidentPublisher({ ledger, hostId: 'host-1', bootId: 'boot-1', client: { sendIncidentEnvelope: async () => ({ ok: true }) } });
  assert.equal(publisher.consider({ ...entry, decision: { threatLevel: 1 } }, 'HEALTHY'), false);
  assert.equal(publisher.consider({ ...entry, event: { event_type: 'FILE_OPEN_ATTEMPT' } }, 'HEALTHY'), false);
  assert.equal(publisher.pendingCount(), 0);
  ledger.close();
});
