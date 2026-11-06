'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { EvidenceLedger } = require('../../src/evidence');
const {
  ContainmentDispatcher,
  ContainmentLevel,
  ContainmentStatus,
  LocalProcessContainmentAdapter
} = require('../../src/containment');

describe('ContainmentDispatcher - Safety & Transactional Lifecycle', () => {
  it('enforces R1_OBSERVE_ONLY without process interruption', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const dispatcher = new ContainmentDispatcher({ ledger, dryRun: false });

    const result = await dispatcher.dispatch({
      incidentId: 'inc-001',
      ruleId: 'SEC_UNEXPECTED_EXEC',
      requestedLevel: ContainmentLevel.R1_OBSERVE_ONLY,
      targetIdentity: { pid: 12345, exec_id: 'host-01:boot-01:12345:1000' }
    });

    assert.equal(result.status, ContainmentStatus.EXECUTED);
    assert.ok(result.plannedRecordHash);
    assert.ok(result.resultRecordHash);

    // Verify ledger sequence (getRecords returns DESC, reverse to chronological ASC)
    const records = ledger.getRecords().reverse();
    assert.equal(records.length, 2);
    assert.equal(records[0].record_type, 'containment_planned');
    assert.equal(records[1].record_type, 'containment_result');
    assert.equal(records[1].previous_hash, records[0].record_hash);

    const payloadResult = JSON.parse(records[1].payload_json);
    assert.equal(payloadResult.planned_record_hash, records[0].record_hash);

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('blocks destructive R3_PROCESS_TERMINATE when target lacks strong exec_id lineage', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const dispatcher = new ContainmentDispatcher({ ledger, dryRun: false });

    // Target with Profile D / missing exec_id (transient PID only)
    const result = await dispatcher.dispatch({
      incidentId: 'inc-002',
      ruleId: 'SEC_MALICIOUS_C2',
      requestedLevel: ContainmentLevel.R3_PROCESS_TERMINATE,
      targetIdentity: { pid: 9999, profile: 'D', attribution: 'UNKNOWN' }
    });

    assert.equal(result.status, ContainmentStatus.BLOCKED_UNSAFE);
    assert.match(result.reason, /lacks strong exec_id lineage/);

    const records = ledger.getRecords();
    assert.equal(records.length, 1);
    assert.equal(records[0].record_type, 'containment_blocked');

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('executes R3_PROCESS_TERMINATE with simulated adapter in dryRun mode', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const dispatcher = new ContainmentDispatcher({ ledger, dryRun: true });

    const result = await dispatcher.dispatch({
      incidentId: 'inc-003',
      ruleId: 'SEC_REVERSE_SHELL',
      requestedLevel: ContainmentLevel.R3_PROCESS_TERMINATE,
      targetIdentity: { pid: 4567, exec_id: 'host-01:boot-01:4567:2000' }
    });

    assert.equal(result.status, ContainmentStatus.SKIPPED_DRY_RUN);
    assert.equal(result.outcome.success, true);
    assert.match(result.outcome.actionTaken, /DRY_RUN/);

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('dispatches live signals through LocalProcessContainmentAdapter with signal capture', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const signalsSent = [];
    const mockSender = (pid, sig) => {
      signalsSent.push({ pid, sig });
    };

    const adapter = new LocalProcessContainmentAdapter({
      dryRun: false,
      signalSender: mockSender
    });

    const dispatcher = new ContainmentDispatcher({
      ledger,
      adapter,
      dryRun: false
    });

    // R2: Suspend
    const resSuspend = await dispatcher.dispatch({
      incidentId: 'inc-004',
      ruleId: 'SUSPICIOUS_MEMORY_BURST',
      requestedLevel: ContainmentLevel.R2_PROCESS_SUSPEND,
      targetIdentity: { pid: 7890, exec_id: 'host-01:boot-01:7890:3000' }
    });

    assert.equal(resSuspend.status, ContainmentStatus.EXECUTED);
    assert.equal(signalsSent.length, 1);
    assert.equal(signalsSent[0].pid, 7890);
    assert.equal(signalsSent[0].sig, 'SIGSTOP');

    // R3: Terminate
    const resKill = await dispatcher.dispatch({
      incidentId: 'inc-005',
      ruleId: 'CRITICAL_DATA_EXFILTRATION',
      requestedLevel: ContainmentLevel.R3_PROCESS_TERMINATE,
      targetIdentity: { pid: 7890, exec_id: 'host-01:boot-01:7890:3000' }
    });

    assert.equal(resKill.status, ContainmentStatus.EXECUTED);
    assert.equal(signalsSent.length, 2);
    assert.equal(signalsSent[1].pid, 7890);
    assert.equal(signalsSent[1].sig, 'SIGKILL');

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('handles ESRCH gracefully if target process terminated prior to signal', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const mockSender = () => {
      const err = new Error('No such process');
      err.code = 'ESRCH';
      throw err;
    };

    const adapter = new LocalProcessContainmentAdapter({
      dryRun: false,
      signalSender: mockSender
    });

    const dispatcher = new ContainmentDispatcher({
      ledger,
      adapter,
      dryRun: false
    });

    const result = await dispatcher.dispatch({
      incidentId: 'inc-006',
      ruleId: 'PROCESS_ANOMALY',
      requestedLevel: ContainmentLevel.R3_PROCESS_TERMINATE,
      targetIdentity: { pid: 8888, exec_id: 'host-01:boot-01:8888:4000' }
    });

    assert.equal(result.status, ContainmentStatus.EXECUTED);
    assert.equal(result.outcome.actionTaken, 'ALREADY_EXITED');

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('protects PID 1 and self-PID from accidental targeting', async () => {
    const adapter = new LocalProcessContainmentAdapter({ dryRun: false });

    // Target PID 1
    await assert.rejects(
      () => adapter.execute({ level: ContainmentLevel.R3_PROCESS_TERMINATE, targetIdentity: { pid: 1 } }),
      /PID 1 and non-positive PIDs are protected/
    );

    // Target self PID
    await assert.rejects(
      () => adapter.execute({ level: ContainmentLevel.R3_PROCESS_TERMINATE, targetIdentity: { pid: process.pid } }),
      /Self-containment blocked/
    );
  });
});