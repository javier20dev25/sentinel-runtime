'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { EvidenceLedger } = require('../../src/evidence');
const { ContainmentDispatcher, ContainmentStatus } = require('../../src/containment');
const {
  SequenceDetector,
  ChainType,
  StreamingStatTracker,
  AnomalyEngine,
  BehaviorEngine,
  DecisionEngine
} = require('../../src/intelligence');

describe('SequenceDetector - Complex Event Processing (CEP) & Kill Chains', () => {
  it('detects an exfiltration sequence: sensitive file read followed by network outbound', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity = { hostId: 'h1', bootId: 'b1', execId: 'exec-101', pid: 501 };

    // Step 1: Process initialized
    detector.evaluate({ eventType: 'PROCESS_EXEC', data: { binary: '/usr/bin/worker' } }, identity);

    // Step 2: Read sensitive shadow file
    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' } }, identity);

    // Step 3: Network outbound attempt
    const detections = detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5', destination_port: 4444 } },
      identity
    );

    assert.ok(detections);
    assert.equal(detections.length, 1);
    assert.equal(detections[0].chainType, ChainType.EXFILTRATION);
    assert.equal(detections[0].severity, 'CRITICAL');
    assert.equal(detections[0].confidence, 0.95);
  });

  it('detects a reverse shell sequence: network outbound followed by interactive shell spawn', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity = { hostId: 'h1', bootId: 'b1', execId: 'exec-102', pid: 502 };

    // Step 1: Network socket connected to external peer
    detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '203.0.113.8', destination_port: 1337 } },
      identity
    );

    // Step 2: Shell spawned
    const detections = detector.evaluate(
      { eventType: 'PROCESS_EXEC', data: { binary: '/bin/bash' } },
      identity
    );

    assert.ok(detections);
    assert.equal(detections.length, 1);
    assert.equal(detections[0].chainType, ChainType.REVERSE_SHELL);
    assert.equal(detections[0].severity, 'CRITICAL');
  });
});

describe('AnomalyEngine - Streaming EWMA & CUSUM Outlier Detection', () => {
  it('detects sudden statistical burst using StreamingStatTracker', () => {
    const tracker = new StreamingStatTracker({ alpha: 0.2, thresholdZ: 2.5 });

    // Establish normal baseline around 5-7 events
    for (let i = 0; i < 20; i++) {
      tracker.update(5 + Math.sin(i) * 0.5);
    }

    // Inject sudden massive spike
    const outlierResult = tracker.update(100);
    assert.equal(outlierResult.isAnomaly, true);
    assert.ok(outlierResult.zScore > 2.5);
  });

  it('evaluates anomalous bursts across workloads in real-time', () => {
    const engine = new AnomalyEngine();

    // Baseline executions
    for (let i = 0; i < 15; i++) {
      engine.evaluate({ eventType: 'PROCESS_EXEC' }, 'api-worker');
    }

    // Heavy burst
    let triggered = null;
    for (let i = 0; i < 30; i++) {
      const res = engine.evaluate({ eventType: 'PROCESS_EXEC' }, 'api-worker');
      if (res) {
        triggered = res;
        break;
      }
    }

    assert.ok(triggered);
    assert.equal(triggered[0].type, 'ANOMALOUS_PROCESS_BURST');
    assert.equal(triggered[0].severity, 'HIGH');
  });
});

describe('DecisionEngine - Fused Signals & Automated Containment Lifecycle', () => {
  it('fuses kill-chain sequence into a CRITICAL decision and triggers authorized dry-run containment', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const dispatcher = new ContainmentDispatcher({ ledger, dryRun: true });
    const decisionEngine = new DecisionEngine({ dispatcher, autoContain: true });

    const analysis = {
      workloadId: 'payment-svc',
      identity: { pid: 9001, exec_id: 'host-1:boot-1:9001:1000' },
      deterministicDeviation: null,
      sequenceDetections: [
        {
          chainType: ChainType.EXFILTRATION,
          severity: 'CRITICAL',
          confidence: 0.95,
          title: 'Exfiltration sequence detected'
        }
      ],
      anomalyDetections: null
    };

    const decision = await decisionEngine.decide(analysis);

    assert.equal(decision.threatLevel, 'CRITICAL');
    assert.equal(decision.confidence, 0.95);
    assert.equal(decision.requestedAction, 'PROCESS_TERMINATE');
    assert.ok(decision.containmentOutcome);
    assert.equal(decision.containmentOutcome.status, ContainmentStatus.SKIPPED_DRY_RUN);

    // Verify ledger persistence
    const records = ledger.getRecords();
    assert.equal(records.length, 2);
    assert.equal(records[0].record_type, 'containment_result');
    assert.equal(records[1].record_type, 'containment_planned');

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });

  it('blocks destructive containment when target identity lacks verified lineage', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const dispatcher = new ContainmentDispatcher({ ledger, dryRun: true });
    const decisionEngine = new DecisionEngine({ dispatcher, autoContain: true });

    const analysis = {
      workloadId: 'payment-svc',
      // Profile D / transient unverified target
      identity: { pid: 9002, profile: 'D', attribution: 'UNKNOWN' },
      deterministicDeviation: null,
      sequenceDetections: [
        {
          chainType: ChainType.EXFILTRATION,
          severity: 'CRITICAL',
          confidence: 0.95,
          title: 'Exfiltration sequence detected'
        }
      ],
      anomalyDetections: null
    };

    const decision = await decisionEngine.decide(analysis);

    assert.equal(decision.threatLevel, 'CRITICAL');
    assert.equal(decision.containmentOutcome.status, ContainmentStatus.BLOCKED_UNSAFE);

    const integrity = ledger.verifyIntegrity();
    assert.equal(integrity.valid, true);
  });
});