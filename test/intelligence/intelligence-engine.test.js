'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EvidenceLedger } = require('../../src/evidence');
const { ContainmentDispatcher, ContainmentStatus, ContainmentLevel } = require('../../src/containment');
const {
  SequenceDetector,
  ChainType,
  StreamingStatTracker,
  ChannelRateWindow,
  AnomalyEngine,
  BehaviorEngine,
  DecisionEngine
} = require('../../src/intelligence');
const { TetragonGrpcCollector } = require('../../src/collectors/tetragon-grpc');
const { loadTetragonApi } = require('../../src/collectors/tetragon-proto');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');

function tempLedger() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-intel-test-'));
  const ledger = new EvidenceLedger(path.join(directory, 'runtime.sqlite'));
  return { directory, ledger };
}

describe('SequenceDetector - Strict Attribution & Chronological Ordering', () => {
  // Test 1: Correct chronological ordering triggers sequence
  it('1. Correct chronological ordering triggers suspicious exfiltration sequence', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-101', pid: 501 };

    const t0 = 100000;
    detector.evaluate({ eventType: 'PROCESS_EXEC', data: { binary: '/usr/bin/worker' }, sourceEventKey: 'key-exec' }, identity, t0);
    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' }, sourceEventKey: 'key-file' }, identity, t0 + 100);

    const detections = detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5', destination_port: 4444 }, sourceEventKey: 'key-net' },
      identity,
      t0 + 200
    );

    assert.ok(detections);
    assert.equal(detections.length, 1);
    assert.equal(detections[0].chainType, ChainType.SUSPICIOUS_EXFILTRATION);
    assert.equal(detections[0].severity, 'HIGH');
    assert.equal(detections[0].stageTimestamps.fileAccess < detections[0].stageTimestamps.networkAttempt, true);
    assert.deepEqual(detections[0].sourceEventKeys, ['key-file', 'key-net']);
  });

  // Test 2: Reverse ordering must NOT trigger a sequence
  it('2. Reverse ordering (network outbound before sensitive file read) must NOT trigger exfiltration', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-102', pid: 502 };

    const t0 = 200000;
    // Step 1: Network connect happens first at t0
    detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5', destination_port: 4444 }, sourceEventKey: 'key-net' },
      identity,
      t0
    );

    // Step 2: Sensitive file read happens AFTER at t0 + 500
    const detections = detector.evaluate(
      { eventType: 'FILE_READ', data: { path: '/etc/shadow' }, sourceEventKey: 'key-file' },
      identity,
      t0 + 500
    );

    // Reverse order must not trigger exfiltration kill-chain
    assert.equal(detections, null);
  });

  // Test 3: PID reuse must NOT correlate separate executions
  it('3. PID reuse with distinct exec_id does NOT merge FSM chains', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity1 = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-aaa', pid: 999 };
    const identity2 = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-bbb', pid: 999 };

    const t0 = 300000;
    // First process (exec-aaa) reads sensitive file
    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' }, sourceEventKey: 'key-file-1' }, identity1, t0);

    // Second process (exec-bbb) with reused PID 999 connects to network
    const detections = detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5', destination_port: 80 }, sourceEventKey: 'key-net-2' },
      identity2,
      t0 + 100
    );

    // Must NOT correlate across distinct exec_id values
    assert.equal(detections, null);
  });

  // Test 4: Missing exec_id must NEVER create strong attribution
  it('4. Missing exec_id must never create strong causal attribution', () => {
    const detector = new SequenceDetector();
    // Only PID, no exec_id
    const identityPartial = { host_id: 'host-1', boot_id: 'boot-1', pid: 555 };

    const res1 = detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' } }, identityPartial, 1000);
    const res2 = detector.evaluate({ eventType: 'NETWORK_CONNECT', data: { destination_host: '1.2.3.4' } }, identityPartial, 2000);

    assert.equal(res1, null);
    assert.equal(res2, null);
    // Ensure no state was stored
    assert.equal(detector.processFsm.size, 0);
  });

  // Test 5: Missing identity must NOT collapse into pid:0 or default strings
  it('5. Missing identity must not collapse into pid:0 or default strings', () => {
    const detector = new SequenceDetector();
    assert.equal(detector.processKey(null), null);
    assert.equal(detector.processKey({}), null);
    assert.equal(detector.processKey({ pid: 0 }), null);
    assert.equal(detector.processKey({ host_id: 'h1', boot_id: '', exec_id: 'e1' }), null);
    assert.equal(detector.processKey({ host_id: '', boot_id: 'b1', exec_id: 'e1' }), null);
    assert.equal(detector.processKey({ host_id: 'h1', boot_id: 'b1', exec_id: '' }), null);
  });

  // Test 6: Duplicate detections must be suppressed (deterministic incident keys)
  it('6. Duplicate detections are suppressed by deterministic incident keys', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-dup-1', pid: 777 };

    const t0 = 400000;
    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' }, sourceEventKey: 'key-file-dup' }, identity, t0);

    // First network connect -> fires detection
    const detections1 = detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5' }, sourceEventKey: 'key-net-dup' },
      identity,
      t0 + 100
    );
    assert.ok(detections1);
    assert.equal(detections1.length, 1);

    // Subsequent event for the same process should NOT re-emit the same incident
    const detections2 = detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5' }, sourceEventKey: 'key-net-dup' },
      identity,
      t0 + 200
    );
    assert.equal(detections2, null);
  });

  // Test 7: Exit closes live processing but keeps bounded file evidence for parent correlation
  it('7. Process exit retains only bounded sensitive-file evidence and rejects later child events', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-exit-1', pid: 888 };

    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' } }, identity, 500000);
    assert.equal(detector.processFsm.size, 1);

    // Process exit retains evidence for a direct parent event inside the short correlation window.
    detector.evaluate({ eventType: 'PROCESS_EXIT' }, identity, 500500);
    assert.equal(detector.processFsm.size, 1);
    assert.equal(detector.processFsm.values().next().value.exitedAt, 500500);
    assert.equal(detector.evaluate({ eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.1' } }, identity, 501000), null);
    detector.prune(511000);
    assert.equal(detector.processFsm.size, 0);
  });

  // Test 8: Conservative labeling: file read + network egress is attempt, not confirmed transfer
  it('8. Exfiltration sequence is labeled as suspicious attempt, not confirmed transfer', () => {
    const detector = new SequenceDetector();
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-cons-1', pid: 889 };

    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' } }, identity, 1000);
    const detections = detector.evaluate(
      { eventType: 'NETWORK_CONNECT', data: { destination_host: '10.0.0.1' } },
      identity,
      2000
    );

    assert.ok(detections);
    assert.equal(detections[0].chainType, 'SUSPICIOUS_EXFILTRATION_SEQUENCE');
    assert.ok(detections[0].title.includes('unconfirmed'));
    assert.ok(detections[0].confidence <= 0.75);
  });

  // Test 9: Capability check is marked as capability check observed, not confirmed privilege change
  it('9. cap_capable check is labeled as capability check observed, not confirmed privilege escalation', () => {
    const detector = new SequenceDetector();
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-cap-1', pid: 890 };

    detector.evaluate({ eventType: 'CAPABILITY_CHECK', data: { capability_name: 'CAP_SYS_ADMIN' } }, identity, 1000);
    const detections = detector.evaluate(
      { eventType: 'PROCESS_EXEC', data: { binary: '/bin/bash' } },
      identity,
      2000
    );

    assert.ok(detections);
    assert.equal(detections[0].chainType, 'CAPABILITY_CHECK_OBSERVED');
    assert.equal(detections[0].severity, 'MEDIUM');
    assert.ok(detections[0].title.includes('Capability Check Observed'));
  });

  // Test 10: Reverse shell sequence correlation requirements
  it('10. Reverse shell sequence requires network connection before interpreter execution', () => {
    const detector = new SequenceDetector();
    const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-sh-1', pid: 891 };

    detector.evaluate({ eventType: 'NETWORK_CONNECT', data: { destination_host: '192.0.2.1', destination_port: 4444 } }, identity, 1000);
    const detections = detector.evaluate({ eventType: 'PROCESS_EXEC', data: { binary: '/bin/sh' } }, identity, 1500);

    assert.ok(detections);
    assert.equal(detections[0].chainType, 'SUSPICIOUS_NETWORK_AND_SHELL_SEQUENCE');
    assert.equal(detections[0].severity, 'HIGH');
    assert.ok(detections[0].title.includes('socket inheritance unconfirmed'));
  });

  it('11. Proc root aliases do not bypass sensitive path matching', () => {
    for (const alias of ['/proc/self/root/etc/shadow', '/proc/4242/root/etc/shadow']) {
      const detector = new SequenceDetector();
      const identity = { host_id: 'host-1', boot_id: 'boot-1', exec_id: `exec-alias-${alias.length}`, pid: 892 };

      detector.evaluate({ eventType: 'FILE_OPEN_ATTEMPT', data: { path: alias }, sourceEventKey: `key-file-${alias}` }, identity, 1000);
      const detections = detector.evaluate(
        { eventType: 'NETWORK_CONNECT', data: { destination_host: '198.51.100.5', destination_port: 443 }, sourceEventKey: `key-net-${alias}` },
        identity,
        2000
      );

      assert.ok(detections);
      assert.equal(detections[0].chainType, 'SUSPICIOUS_EXFILTRATION_SEQUENCE');
      assert.equal(detections[0].details.fileAccessed, alias);
      assert.equal(detections[0].details.fileAccessType, 'FILE_OPEN_ATTEMPT');
      assert.match(detections[0].title, /file-open attempt/i);
    }
  });

  it('12. Carries outbound activity across an execve in the same PID and start time', () => {
    const detector = new SequenceDetector();
    const python = {
      host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-python', pid: 3691,
      process_start_time: '1794209205908984122'
    };
    const shell = { ...python, exec_id: 'exec-shell' };

    detector.evaluate({ eventType: 'PROCESS_EXEC', data: { binary: '/usr/bin/python3' } }, python, 1000);
    detector.evaluate({ eventType: 'NETWORK_CONNECT_ATTEMPT', data: { destination_ip: '127.0.0.1', destination_port: 18080 } }, python, 1100);
    const detections = detector.evaluate({ eventType: 'PROCESS_EXEC', data: { binary: '/bin/sh' } }, shell, 1200);

    assert.ok(detections);
    assert.equal(detections[0].chainType, 'SUSPICIOUS_NETWORK_AND_SHELL_SEQUENCE');
    assert.equal(detections[0].details.interpreter, '/bin/sh');
  });

  it('13. Replays the observed proc-root open and loopback connect as a gated incident', async () => {
    const behavior = new BehaviorEngine();
    const decisionEngine = new DecisionEngine();
    decisionEngine.setObservabilityState('DEGRADED', true, 'NO_SENSOR_REPLAY');
    const processIdentity = {
      exec_id: 'exec-procpath', pid: 3690, process_start_time: '1794209205908984122',
      executable_path: '/usr/bin/python3'
    };
    const host_identity = { host_id: 'host-lab', boot_id: 'boot-lab' };
    const openEvent = {
      event_type: 'FILE_OPEN_ATTEMPT', host_identity, process_identity: processIdentity,
      timestamps: { source_timestamp: '1794209206366192192' },
      source_event_key: 'a'.repeat(64), payload: { path: '/proc/self/root/etc/shadow' }
    };
    const networkEvent = {
      event_type: 'NETWORK_CONNECT_ATTEMPT', host_identity, process_identity: processIdentity,
      timestamps: { source_timestamp: '1794209206448894816' },
      source_event_key: 'b'.repeat(64), payload: { destination_ip: '127.0.0.1', destination_port: 18080 }
    };

    assert.equal(behavior.analyzeEvent(openEvent).sequenceDetections, null);
    const analysis = behavior.analyzeEvent(networkEvent);
    assert.equal(analysis.sequenceDetections[0].chainType, 'SUSPICIOUS_EXFILTRATION_SEQUENCE');
    assert.deepEqual(analysis.sequenceDetections[0].sourceEventKeys, ['a'.repeat(64), 'b'.repeat(64)]);
    const decision = await decisionEngine.decide(analysis, networkEvent);
    assert.equal(decision.threatLevel, 'HIGH');
    assert.equal(decision.requestedAction, ContainmentLevel.R1_OBSERVE_ONLY);
    assert.match(decision.safetyGatingReasons.join(' '), /observability degraded/i);
  });

  it('14. Separates PID reuse from execve using process start time', () => {
    const detector = new SequenceDetector();
    const first = { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-old', pid: 777, process_start_time: '1000' };
    const reusedPid = { ...first, exec_id: 'exec-new', process_start_time: '2000' };

    detector.evaluate({ eventType: 'FILE_READ', data: { path: '/etc/shadow' } }, first, 1000);
    const detections = detector.evaluate({ eventType: 'NETWORK_CONNECT_ATTEMPT', data: { destination_ip: '198.51.100.2' } }, reusedPid, 1100);

    assert.equal(detections, null);
    assert.equal(detector.processFsm.size, 2);
  });

  it('15. Correlates sensitive file-open in an exited child to a later direct-parent network attempt', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const parentExec = 'exec-python-parent';
    const child = {
      host_id: 'host-lab', boot_id: 'boot-lab', exec_id: 'exec-cat-child', parent_exec_id: parentExec,
      pid: 3689, process_start_time: '1794209205833196248', executable_path: '/bin/cat'
    };
    const parent = {
      host_id: 'host-lab', boot_id: 'boot-lab', exec_id: parentExec,
      pid: 3687, process_start_time: '1794209205176586375', executable_path: '/usr/bin/python3'
    };

    detector.evaluate({ eventType: 'FILE_OPEN_ATTEMPT', data: { path: '/etc/shadow' }, sourceEventKey: 'child-file-key' }, child, 1000);
    detector.evaluate({ eventType: 'PROCESS_EXIT' }, child, 1100);
    const detections = detector.evaluate({
      eventType: 'NETWORK_CONNECT_ATTEMPT',
      data: { destination_ip: '127.0.0.1', destination_port: 18080 },
      sourceEventKey: 'parent-network-key'
    }, parent, 2100);

    assert.equal(detections.length, 1);
    assert.equal(detections[0].chainType, ChainType.SUSPICIOUS_EXFILTRATION);
    assert.equal(detections[0].confidence, 0.55);
    assert.match(detections[0].title, /direct parent-child/i);
    assert.match(detections[0].title, /transfer unconfirmed/i);
    assert.deepEqual(detections[0].sourceEventKeys, ['child-file-key', 'parent-network-key']);
    assert.equal(detections[0].details.fileProcess.pid, 3689);
    assert.equal(detections[0].details.networkProcess.pid, 3687);
    assert.equal(detections[0].attribution.relationship, 'DIRECT_PARENT_CHILD');
  });

  it('16. Does not correlate child activity to an unrelated process without an exact parent exec id', () => {
    const detector = new SequenceDetector({ windowMs: 10000 });
    const child = { host_id: 'host-lab', boot_id: 'boot-lab', exec_id: 'exec-cat-child', parent_exec_id: 'exec-real-parent', pid: 3689 };
    const unrelated = { host_id: 'host-lab', boot_id: 'boot-lab', exec_id: 'exec-other-parent', pid: 3687 };

    detector.evaluate({ eventType: 'FILE_OPEN_ATTEMPT', data: { path: '/etc/shadow' }, sourceEventKey: 'child-file-key' }, child, 1000);
    detector.evaluate({ eventType: 'PROCESS_EXIT' }, child, 1100);
    const detections = detector.evaluate({ eventType: 'NETWORK_CONNECT_ATTEMPT', data: { destination_ip: '198.51.100.9' }, sourceEventKey: 'other-net-key' }, unrelated, 2100);
    assert.equal(detections, null);
  });
});

describe('AnomalyEngine - Real Time Rates, Warm-up & Churn Bounding', () => {
  // Test 11: Constant-rate traffic versus true burst
  it('11. Constant-rate traffic does not trigger an anomaly, sudden rate spike triggers', () => {
    const tracker = new StreamingStatTracker({ alpha: 0.15, thresholdZ: 3.5, warmupObservations: 15 });

    // Establish normal baseline: 10 events/sec constant rate for 20 observations
    for (let i = 0; i < 20; i++) {
      const res = tracker.update(10.0 + (i % 2 === 0 ? 0.2 : -0.2));
      assert.equal(res.isAnomaly, false);
      assert.equal(res.warmedUp, i >= 14);
    }

    // Normal variation should not trigger
    const normalRes = tracker.update(10.5);
    assert.equal(normalRes.isAnomaly, false);

    // Sudden massive rate burst (100 events/sec vs 10 events/sec baseline)
    const burstRes = tracker.update(100.0);
    assert.equal(burstRes.isAnomaly, true);
    assert.ok(burstRes.zScore > 3.5);
  });

  // Test 12: Stationary traffic versus abrupt drift
  it('12. Stationary traffic maintains baseline without false alert; abrupt jump triggers CUSUM', () => {
    const tracker = new StreamingStatTracker({ alpha: 0.1, thresholdZ: 4.0, cusumH: 4.0, warmupObservations: 15 });

    // Stationary traffic with natural variation: 5.0 +/- 0.3 over 25 steps
    for (let i = 0; i < 25; i++) {
      const rate = 5.0 + (Math.sin(i) * 0.3);
      const res = tracker.update(rate);
      assert.equal(res.isAnomaly, false);
    }

    // Now inject abrupt sustained shift to 25.0
    let cusumFired = false;
    for (let i = 0; i < 5; i++) {
      const res = tracker.update(25.0);
      if (res.cusumAlert || res.isAnomaly) {
        cusumFired = true;
        break;
      }
    }
    assert.equal(cusumFired, true);
  });

  // Test 13: Event timestamp regression handling
  it('13. Event timestamp regression is handled safely without corrupting time window', () => {
    const window = new ChannelRateWindow({ windowMs: 1000 });

    window.recordEvent(5000);
    window.recordEvent(5100);

    // Out of order / regressing timestamp: should be safely ignored
    const regressionResult = window.recordEvent(4500);
    assert.equal(regressionResult, null);

    // Normal forward timestamp: continues window tracking cleanly
    window.recordEvent(5200);
    const flushResult = window.recordEvent(6050);
    assert.ok(flushResult !== null || window.eventCountInWindow >= 1);
  });

  // Test 14: Workload churn and bounded memory
  it('14. Workload churn maintains bounded memory through tracker capacity limit and TTL', () => {
    const engine = new AnomalyEngine({ maxTrackers: 5, trackerTtlMs: 1000 });

    const now = 100000;
    // Generate 15 distinct short-lived workload IDs
    for (let i = 0; i < 15; i++) {
      engine.evaluate({ eventType: 'PROCESS_EXEC', timestamp: now + i * 10 }, `workload-churn-${i}`, now + i * 10);
    }

    // Trackers must never exceed maxTrackers (5)
    assert.ok(engine.workloadTrackers.size <= 5);

    // Advance time beyond TTL and prune
    engine.pruneTrackers(now + 50000);
    assert.equal(engine.workloadTrackers.size, 0);
  });
});

describe('DecisionEngine - Strict Safety Gates & Evidence Retention', () => {
  // Test 15: Observability loss blocks destructive response
  it('15. Observability degradation strictly blocks destructive containment (R3/R4)', async () => {
    const ledger = new EvidenceLedger(':memory:');
    const dispatcher = new ContainmentDispatcher({ ledger, dryRun: true });
    const decisionEngine = new DecisionEngine({
      dispatcher,
      autoContain: true,
      allowAutomatedTermination: true
    });

    const analysis = {
      workloadId: 'prod-api',
      identity: { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-loss-1', pid: 1234 },
      deterministicDeviation: null,
      sequenceDetections: [
        {
          chainType: 'SUSPICIOUS_EXFILTRATION_SEQUENCE',
          severity: 'HIGH',
          confidence: 0.70,
          title: 'Suspicious exfiltration detected',
          sourceEventKeys: ['key-1', 'key-2']
        }
      ],
      anomalyDetections: null,
      // Degraded observability: telemetry dropped by sensor
      observabilityStatus: 'DEGRADED',
      telemetryLoss: { domain: 'sensor_throttle', count: '15' }
    };

    const decision = await decisionEngine.decide(analysis);

    assert.equal(decision.threatLevel, 'HIGH');
    // Must be gated to R1_OBSERVE_ONLY due to observability degradation
    assert.equal(decision.requestedAction, ContainmentLevel.R1_OBSERVE_ONLY);
    assert.ok(decision.safetyGatingReasons.some(r => r.includes('Observability degraded')));
    assert.deepEqual(decision.evidenceReferences, ['key-1', 'key-2']);
  });

  // Test 16: R2 requires explicit human authorization
  it('16. Process suspension (R2) requires explicit operator authorization and blocks automated R2 by default', async () => {
    const decisionEngineDefault = new DecisionEngine();

    const analysis = {
      workloadId: 'worker-1',
      identity: { host_id: 'host-1', boot_id: 'boot-1', exec_id: 'exec-r2-1', pid: 4321 },
      deterministicDeviation: null,
      sequenceDetections: [
        {
          chainType: 'SUSPICIOUS_NETWORK_AND_SHELL_SEQUENCE',
          severity: 'HIGH',
          confidence: 0.65,
          title: 'Suspicious network and shell sequence'
        }
      ],
      anomalyDetections: null,
      observabilityStatus: 'NORMAL'
    };

    const decision = await decisionEngineDefault.decide(analysis);

    // By default, automated suspension is disabled and requires human authorization
    assert.equal(decision.requestedAction, ContainmentLevel.R1_OBSERVE_ONLY);
    assert.ok(decision.safetyGatingReasons.some(r => r.includes('human operator authorization')));
  });

  // Test 17: Real collector-to-BehaviorEngine integration using version-pinned Tetragon fixtures
  it('17. Real collector-to-BehaviorEngine integration with Tetragon gRPC stream commits validated decisions', async () => {
    const api = loadTetragonApi();
    const server = new api.grpc.Server();

    const responses = [
      {
        node_name: 'test-node',
        time: { seconds: '1793603690', nanos: 100000000 },
        process_exec: {
          process: {
            exec_id: 'exec-integ-1',
            pid: { value: 101 },
            tid: { value: 101 },
            start_time: { seconds: '1793603680', nanos: 0 },
            binary: '/usr/bin/node',
            arguments: 'node worker.js'
          }
        }
      },
      {
        node_name: 'test-node',
        time: { seconds: '1793603695', nanos: 0 },
        process_exit: {
          process: {
            exec_id: 'exec-integ-1',
            pid: { value: 101 },
            start_time: { seconds: '1793603680', nanos: 0 },
            binary: '/usr/bin/node'
          },
          status: 0,
          signal: ''
        }
      }
    ];

    server.addService(api.service.service, {
      getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
      getEvents(call) {
        for (const resp of responses) call.write(resp);
        call.end();
      }
    });

    const port = await new Promise((resolve, reject) => {
      server.bindAsync('127.0.0.1:0', api.grpc.ServerCredentials.createInsecure(), (err, p) => err ? reject(err) : resolve(p));
    });

    const { directory, ledger } = tempLedger();
    let clientConnection;
    try {
      clientConnection = new api.service(`127.0.0.1:${port}`, api.grpc.credentials.createInsecure());
      const behaviorEngine = new BehaviorEngine();
      const decisionEngine = new DecisionEngine();

      const collector = new TetragonGrpcCollector({
        ledger,
        hostId: 'host-integ',
        bootId: 'boot-integ',
        maxEvents: 2,
        batchSize: 2,
        flushIntervalMs: 50,
        expectedNodeName: 'test-node',
        behaviorEngine,
        decisionEngine,
        connectionFactory: async () => ({
          client: clientConnection,
          close: () => clientConnection.close(),
          transportProtocol: 'GRPC_TCP',
          transportAuthentication: 'TLS_SERVER_AUTH'
        })
      });

      const result = await collector.run();
      assert.equal(result.supported, 2);

      // Verify that ledger records received decisions from BehaviorEngine & DecisionEngine
      const records = ledger.getRecords({ limit: 10 }).map(r => ({ ...r, payload: JSON.parse(r.payload_json) }));
      const eventRecords = records.filter(r => r.record_type === 'event');
      assert.equal(eventRecords.length, 2);

      for (const rec of eventRecords) {
        assert.ok(rec.payload.decision);
        assert.equal(rec.payload.decision.threatLevel, 'NORMAL');
        assert.equal(rec.payload.decision.requestedAction, ContainmentLevel.R1_OBSERVE_ONLY);
        assert.equal(validateEventV2(rec.payload.event).valid, true);
      }
    } finally {
      ledger.close();
      server.forceShutdown();
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
});
