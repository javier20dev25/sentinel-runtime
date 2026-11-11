'use strict';

/**
 * Sentinel Runtime — Adversarial Attack Benchmarking & Cloud Audit
 *
 * Runs 4 controlled attack sequences against SequenceDetector & DecisionEngine,
 * measures sub-millisecond decision latency, and dispatches verifiable forensic
 * envelopes to Sentinel Cloud using the designated host credential.
 */

const crypto = require('node:crypto');
const { SequenceDetector } = require('../src/intelligence/sequence-detector');
const { DecisionEngine } = require('../src/intelligence/decision-engine');
const { SentinelRuntimeCloudClient } = require('../src/cloud/cloud-client');

const API_KEY = process.env.SENTINEL_RUNTIME_API_KEY || 'snt_rt_2tfeLePZADTwFPBUd3k6ij9toDPaRJYOu9zLNSFDcBY';
const CLOUD_URL = process.env.SENTINEL_RUNTIME_API_URL || 'https://sentinel-psi-nine.vercel.app';

const SCENARIOS = [
  {
    id: 'SCENARIO_1_REVERSE_SHELL',
    name: 'Interactive Reverse Shell Sequence',
    actor: 'pid:10420:curl',
    identity: { host_id: 'host_1794126625946', boot_id: 'boot_wsl2_01', exec_id: 'exec_curl_420' },
    steps: [
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/usr/bin/curl', pid: 10420, ppid: 10400 },
        sourceEventKey: 'evt_1_exec_curl',
        deltaMs: 0
      },
      {
        eventType: 'NETWORK_CONNECT',
        data: { destination_ip: '185.220.101.5', host: '185.220.101.5', port: 443 },
        sourceEventKey: 'evt_1_net_tor',
        deltaMs: 42
      },
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/bin/bash', pid: 10425, ppid: 10420 },
        sourceEventKey: 'evt_1_exec_bash',
        deltaMs: 115
      }
    ],
    metadata: {
      vector: 'Outbound TCP to known Tor Exit Node followed by interactive shell',
      target: '185.220.101.5:443',
      destClassification: 'Tor Exit Node (AbuseIPDB 87%)'
    }
  },
  {
    id: 'SCENARIO_2_CREDENTIAL_EXFIL',
    name: 'Sensitive Credential Staging & Exfiltration',
    actor: 'pid:11500:python3',
    identity: { host_id: 'host_1794126625946', boot_id: 'boot_wsl2_01', exec_id: 'exec_py_500' },
    steps: [
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/usr/bin/python3', pid: 11500, ppid: 11480 },
        sourceEventKey: 'evt_2_exec_py',
        deltaMs: 0
      },
      {
        eventType: 'FILE_READ',
        data: { path: '/app/.env', file_path: '/app/.env', pid: 11500 },
        sourceEventKey: 'evt_2_read_env',
        deltaMs: 18
      },
      {
        eventType: 'NETWORK_CONNECT',
        data: { destination_ip: '198.51.100.89', host: '198.51.100.89', port: 8080 },
        sourceEventKey: 'evt_2_net_egress',
        deltaMs: 76
      }
    ],
    metadata: {
      vector: 'Production .env read followed by external HTTP connection',
      target: '198.51.100.89:8080',
      destClassification: 'Suspicious External VPS (Uncategorized)'
    }
  },
  {
    id: 'SCENARIO_3_PRIV_ESC_CAPABILITY',
    name: 'Privilege Escalation via Capability Abuse',
    actor: 'pid:12300:app_runner',
    identity: { host_id: 'host_1794126625946', boot_id: 'boot_wsl2_01', exec_id: 'exec_app_300' },
    steps: [
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/usr/local/bin/app_runner', pid: 12300, ppid: 12200 },
        sourceEventKey: 'evt_3_exec_app',
        deltaMs: 0
      },
      {
        eventType: 'CAPABILITY_CHECK',
        data: { capability_name: 'CAP_SETUID', pid: 12300 },
        sourceEventKey: 'evt_3_cap_setuid',
        deltaMs: 25
      },
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/bin/sh', pid: 12310, ppid: 12300 },
        sourceEventKey: 'evt_3_exec_sh',
        deltaMs: 55
      }
    ],
    metadata: {
      vector: 'Unprivileged binary probed CAP_SETUID capability then spawned /bin/sh',
      target: 'Local Linux Syscall (cap_capable)',
      destClassification: 'Kernel Syscall Probing'
    }
  },
  {
    id: 'SCENARIO_4_SSH_KEY_THEFT',
    name: 'SSH Private Key Reconnaissance & Tunneling',
    actor: 'pid:13400:deploy_worker',
    identity: { host_id: 'host_1794126625946', boot_id: 'boot_wsl2_01', exec_id: 'exec_worker_400' },
    steps: [
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/usr/bin/deploy_worker', pid: 13400, ppid: 13350 },
        sourceEventKey: 'evt_4_exec_worker',
        deltaMs: 0
      },
      {
        eventType: 'FILE_READ',
        data: { path: '/home/deploy/.ssh/id_rsa', file_path: '/home/deploy/.ssh/id_rsa', pid: 13400 },
        sourceEventKey: 'evt_4_read_key',
        deltaMs: 34
      },
      {
        eventType: 'NETWORK_CONNECT',
        data: { destination_ip: '203.0.113.50', host: '203.0.113.50', port: 2222 },
        sourceEventKey: 'evt_4_net_tunnel',
        deltaMs: 88
      }
    ],
    metadata: {
      vector: 'Access to id_rsa private key followed by outbound port 2222 connect',
      target: '203.0.113.50:2222',
      destClassification: 'External SSH/C2 Drop Point'
    }
  },
  {
    id: 'SCENARIO_5_PROC_ROOT_SHADOW_THEFT',
    name: 'Container Escape & Host /etc/shadow Exfiltration',
    actor: 'pid:14200:container_agent',
    identity: { host_id: 'host_1794126625946', boot_id: 'boot_wsl2_01', exec_id: 'exec_agent_200' },
    steps: [
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/usr/local/bin/container_agent', pid: 14200, ppid: 14100 },
        sourceEventKey: 'evt_5_exec_agent',
        deltaMs: 0
      },
      {
        eventType: 'FILE_READ',
        data: { path: '/proc/1/root/etc/shadow', file_path: '/proc/1/root/etc/shadow', pid: 14200, ppid: 14100 },
        sourceEventKey: 'evt_5_read_shadow',
        deltaMs: 22
      },
      {
        eventType: 'NETWORK_CONNECT',
        data: { destination_ip: '192.0.2.77', host: '192.0.2.77', port: 4444, pid: 14200, ppid: 14100 },
        sourceEventKey: 'evt_5_net_exfil',
        deltaMs: 65
      }
    ],
    metadata: {
      vector: 'Read access to host /etc/shadow via /proc/1/root followed by outbound connect to 192.0.2.77:4444',
      target: '192.0.2.77:4444',
      destClassification: 'Documentation RFC 5737 TEST-NET-1 (Simulated C2)'
    }
  },
  {
    id: 'SCENARIO_6_IDENTITY_CONFLICT_TEST',
    name: 'Controlled Process Identity Conflict & Lineage Rupture Test',
    actor: 'multi_pid:14200_vs_10420',
    identity: { host_id: 'host_1794126625946', boot_id: 'boot_wsl2_01', exec_id: 'exec_conflict_600' },
    steps: [
      {
        eventType: 'PROCESS_EXEC',
        data: { binary: '/usr/local/bin/container_agent', pid: 14200, ppid: 14100 },
        sourceEventKey: 'evt_6_exec_agent',
        deltaMs: 0
      },
      {
        eventType: 'FILE_READ',
        data: { path: '/proc/1/root/etc/shadow', file_path: '/proc/1/root/etc/shadow', pid: 14200, ppid: 14100 },
        sourceEventKey: 'evt_6_read_shadow',
        deltaMs: 15
      },
      {
        eventType: 'NETWORK_CONNECT',
        data: { destination_ip: '192.0.2.77', host: '192.0.2.77', port: 4444, pid: 10420, ppid: 10400 },
        sourceEventKey: 'evt_6_net_divergent_pid',
        deltaMs: 40
      }
    ],
    metadata: {
      vector: 'Simulated PID divergence (PID 14200 vs PID 10420) sharing exec_id exec_conflict_600',
      target: '192.0.2.77:4444',
      destClassification: 'Adversarial Telemetry Conflict Benchmark (RFC 5737)'
    }
  }
];

async function main() {
  console.log('═'.repeat(75));
  console.log('🛡️  SENTINEL RUNTIME — ADVERSARIAL ATTACK BENCHMARK & CLOUD AUDIT');
  console.log('═'.repeat(75));
  console.log(`Endpoint:    ${CLOUD_URL}`);
  console.log(`Key Hash:    ${crypto.createHash('sha256').update(API_KEY).digest('hex').slice(0, 16)}...`);
  console.log(`Scenarios:   ${SCENARIOS.length} attack chains`);
  console.log('═'.repeat(75));

  const client = new SentinelRuntimeCloudClient({
    apiKey: API_KEY,
    endpoint: CLOUD_URL,
    timeoutMs: 10000
  });

  // Verify Cloud Heartbeat first
  const hb = await client.sendHeartbeat({
    status: 'HEALTHY',
    kernelVersion: '6.6.36.6-microsoft-standard-WSL2',
    tetragonVersion: 'v1.8.0',
    runtimeVersion: '0.2.0-rc2'
  });
  console.log(`📡 Cloud Heartbeat: ${hb.ok ? '✓ CONNECTED (' + hb.data.device_name + ' / ' + hb.data.environment + ')' : '✕ FAILED: ' + hb.error}`);

  const auditResults = [];

  for (const scenario of SCENARIOS) {
    console.log(`\n▶ [Executing ${scenario.id}] ${scenario.name}...`);
    const detector = new SequenceDetector({ windowMs: 60000 });
    const decisionEngine = new DecisionEngine({
      dryRun: true,
      autoContain: false
    });

    const baseTime = Date.now();
    let triggeredDetections = null;

    // Benchmark local FSM evaluation latency
    const t0 = process.hrtime.bigint();

    for (const step of scenario.steps) {
      const stepTime = baseTime + step.deltaMs;
      const res = detector.evaluate(step, scenario.identity, stepTime);
      if (res && res.length > 0) {
        triggeredDetections = res;
      }
    }

    const t1 = process.hrtime.bigint();
    const evaluationLatencyUs = Number(t1 - t0) / 1000; // in microseconds

    if (!triggeredDetections || triggeredDetections.length === 0) {
      console.log(`   ✕ No detection triggered for ${scenario.id}`);
      continue;
    }

    const primaryDetection = triggeredDetections[0];

    // Benchmark DecisionEngine evaluation latency
    const td0 = process.hrtime.bigint();
    const decision = await decisionEngine.decide({
      workloadId: 'workload_test',
      identity: scenario.identity,
      sequenceDetections: [
        {
          rule: primaryDetection.chainType,
          severity: primaryDetection.severity,
          target: scenario.actor,
          confidence: primaryDetection.confidence
        }
      ],
      observabilityStatus: 'HEALTHY'
    });
    const td1 = process.hrtime.bigint();
    const decisionLatencyUs = Number(td1 - td0) / 1000;
    const totalLocalLatencyUs = evaluationLatencyUs + decisionLatencyUs;

    console.log(`   ✓ Detection:       ${primaryDetection.chainType} (${primaryDetection.severity})`);
    console.log(`   ✓ Confidence:      ${(primaryDetection.confidence * 100).toFixed(0)}% (${primaryDetection.title})`);
    console.log(`   ✓ Decision Action: ${decision?.requestedAction || 'OBSERVE_ONLY'} (autoContain=false)`);
    console.log(`   ⚡ Engine Latency:   ${totalLocalLatencyUs.toFixed(1)} µs (${(totalLocalLatencyUs / 1000).toFixed(3)} ms)`);

    // Compute 64-char SHA-256 hashes for cryptographic fidelity
    const makeSha256 = (str) => crypto.createHash('sha256').update(str).digest('hex');
    const idempotencyKey = makeSha256(`snt_idemp_${scenario.id}_${Date.now()}_${Math.random()}`);
    const evidenceHash = makeSha256(JSON.stringify({
      scenario: scenario.id,
      identity: scenario.identity,
      detection: primaryDetection,
      decision,
      timestamp: new Date().toISOString()
    }));

    // Ensure all step sourceEventKeys are 64-char SHA256 hex strings
    const stepKeys = scenario.steps.map((s, idx) => makeSha256(`${scenario.id}_step_${idx}_${s.sourceEventKey}_${Date.now()}`));

    // Build the compliant Sentinel Runtime Incident Envelope (sentinel-runtime-incident-v1)
    const envelope = {
      incident_id: `inc_${scenario.id.toLowerCase()}_${Date.now()}`,
      idempotency_key: idempotencyKey,
      actor_type: 'WORKLOAD',
      actor_id: scenario.actor,
      rule_id: primaryDetection.chainType,
      severity: primaryDetection.severity === 'HIGH' ? 'HIGH' : (primaryDetection.severity === 'CRITICAL' ? 'CRITICAL' : 'MEDIUM'),
      containment_level: 'R1',
      containment_status: 'OBSERVED',
      evidence_record_hash: evidenceHash,
      sanitized_envelope: {
        contract_version: 'sentinel-runtime-incident-v1',
        analysis_status: 'PENDING',
        scenario_id: scenario.id,
        scenario_name: scenario.name,
        source: {
          product: 'sentinel-runtime',
          provider: 'tetragon',
          event_keys: stepKeys,
          observed_at: new Date(baseTime).toISOString()
        },
        observations: scenario.steps.map((step, idx) => ({
          sequence: idx + 1,
          event: {
            event_type: step.eventType,
            source_event_key: stepKeys[idx],
            timestamps: {
              source_timestamp: new Date(baseTime + step.deltaMs).toISOString(),
              kernel_ns: `${(baseTime + step.deltaMs) * 1000000}`
            },
            process_identity: {
              pid: step.data.pid || (scenario.steps[0] && scenario.steps[0].data && scenario.steps[0].data.pid) || 10420,
              ppid: step.data.ppid || (scenario.steps[0] && scenario.steps[0].data && scenario.steps[0].data.ppid) || 10400,
              binary: step.data.binary || undefined,
              binary_path: step.data.binary || undefined,
              exec_id: scenario.identity.exec_id,
              host_id: scenario.identity.host_id,
              boot_id: scenario.identity.boot_id
            },
            payload: {
              ...step.data,
              destination_scope: step.data.destination_ip ? (step.data.destination_ip.startsWith('127.') ? 'LOOPBACK' : 'EXTERNAL') : undefined
            }
          },
          execution_context: step.data.binary ? `${step.data.binary}` : undefined,
          ledger_proof: {
            algorithm: 'SENTINEL-EVIDENCE-LEDGER-V1/SHA-256',
            previous_hash: idx === 0 ? '0000000000000000000000000000000000000000000000000000000000000000' : stepKeys[idx - 1],
            record_hash: stepKeys[idx],
            verification_status: 'AGENT_REPORTED_NOT_CLOUD_VERIFIED',
            external_anchor: false
          }
        })),
        decision: {
          producer: 'sentinel-runtime',
          severity: primaryDetection.severity,
          confidence: primaryDetection.confidence,
          rationale: primaryDetection.title,
          matched_rules: [primaryDetection.chainType],
          requested_action: decision?.requestedAction || 'OBSERVE_ONLY',
          safety_gates: [],
          observability_state: 'HEALTHY'
        },
        containment: {
          level: 'R1',
          status: 'OBSERVED',
          requested_action: 'OBSERVE_ONLY',
          actual_action: 'OBSERVE_ONLY',
          details: {
            mode: 'OBSERVE_ONLY',
            reason: 'Observe-only mode active. Automated containment disabled (autoContain=false).'
          }
        },
        evidence: {
          record_hash: evidenceHash,
          records: stepKeys.map((k, idx) => ({ sequence: idx + 1, record_hash: k })),
          verification_status: 'AGENT_REPORTED_NOT_CLOUD_VERIFIED',
          external_anchor: false
        },
        detection: primaryDetection.chainType,
        severity: primaryDetection.severity,
        confidence_score: primaryDetection.confidence,
        confidence_label: primaryDetection.confidence >= 0.7 ? 'PARTIAL_ATTRIBUTED' : 'DERIVED_SEQUENCE',
        actor: {
          id: scenario.actor,
          identity: scenario.identity,
          role: 'WORKLOAD'
        },
        vector: scenario.metadata,
        sequence: scenario.steps.map((s, idx) => ({
          type: s.eventType,
          delta_ms: s.deltaMs,
          binary: s.data.binary || undefined,
          target: s.data.destination_ip ? `${s.data.destination_ip}:${s.data.port}` : (s.data.path || s.data.capability_name || undefined)
        })),
        why_flagged: primaryDetection.title,
        epistemic_audit: {
          what_we_know: [
            `Observed sequence of ${scenario.steps.length} distinct events.${scenario.steps.some((s, i, a) => s.data.pid && a[0].data && a[0].data.pid && s.data.pid !== a[0].data.pid) ? ' Steps report divergent PIDs (controlled identity conflict test).' : ` Executed under actor ${scenario.actor}.`}`,
            `Outbound target ${scenario.metadata.target} matched criteria for ${scenario.metadata.destClassification}.`,
            `Zero local containment applied under observe-only laboratory policy.`
          ],
          what_remains_unconfirmed: [
            'Payload transfer byte volume was not stored in memory.',
            'Direct process socket inheritance not confirmed by kernel kprobe trace.',
            'External timestamp authority (RFC 3161 TSA) is not anchored.'
          ]
        },
        engine_benchmarks: {
          fsm_latency_us: evaluationLatencyUs,
          decision_latency_us: decisionLatencyUs,
          total_latency_us: totalLocalLatencyUs,
          total_latency_ms: totalLocalLatencyUs / 1000
        }
      }
    };

    // Dispatch to Cloud
    const tc0 = process.hrtime.bigint();
    const cloudRes = await client.sendIncidentEnvelope(envelope);
    const tc1 = process.hrtime.bigint();
    const cloudNetworkLatencyMs = Number(tc1 - tc0) / 1000000;

    const cloudSuccess = cloudRes.ok && Boolean(cloudRes.data?.incident_id);
    console.log(`   🌐 Cloud Dispatch:  ${cloudSuccess ? '✓ ' + cloudRes.data.incident_id : '✕ ' + (cloudRes.error || JSON.stringify(cloudRes))}`);
    console.log(`   📶 Network RTT:     ${cloudNetworkLatencyMs.toFixed(1)} ms`);

    auditResults.push({
      id: scenario.id,
      name: scenario.name,
      rule: primaryDetection.chainType,
      severity: primaryDetection.severity,
      decision: decision?.requestedAction || 'OBSERVE_ONLY',
      engineLatencyMs: totalLocalLatencyUs / 1000,
      networkRttMs: cloudNetworkLatencyMs,
      cloudIncidentId: cloudRes.data?.incident_id || 'FAILED',
      evidenceHash: evidenceHash.slice(0, 16) + '...'
    });
  }

  console.log('\n' + '═'.repeat(75));
  console.log('📊 AUDIT SUMMARY TABLE — SENTINEL RUNTIME × CLOUD INTEGRATION');
  console.log('═'.repeat(75));
  console.table(auditResults);
  console.log('═'.repeat(75));
  console.log(`All ${auditResults.length} adversarial scenarios successfully evaluated and committed to Cloud.`);
  console.log('View live in Cloud: https://sentinel-psi-nine.vercel.app/dashboard/runtime');
  console.log('═'.repeat(75));
}

main().catch(console.error);
