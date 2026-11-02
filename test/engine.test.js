'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { EventType, ThreatLevel, EnforcementAction } = require('../src/types');
const { WorkloadProfile } = require('../src/profiler');
const { BehavioralSequenceEngine } = require('../src/engine');
const { EvidenceLedger } = require('../src/evidence');

test('Sentinel Runtime — Escenario Benigno: 0 Falsos Positivos', () => {
  const engine = new BehavioralSequenceEngine();
  const profile = new WorkloadProfile({
    name: 'api-service',
    type: 'nodejs',
    allowedBinaries: ['node'],
    allowedDestinations: ['api.internal.corp:443']
  });

  engine.registerProfile('workload-app-1', profile);

  // Evento 1: Inicio de app node normal
  const ev1 = engine.processEvent({
    workloadId: 'workload-app-1',
    pid: 1001,
    ppid: 1,
    eventType: EventType.PROCESS_EXEC,
    timestamp: Date.now(),
    data: { binary: '/usr/bin/node' }
  });
  assert.strictEqual(ev1.threatLevel, ThreatLevel.NORMAL);
  assert.strictEqual(ev1.action, EnforcementAction.RECORD_ONLY);

  // Evento 2: Lectura de archivo de configuracion normal
  const ev2 = engine.processEvent({
    workloadId: 'workload-app-1',
    pid: 1001,
    ppid: 1,
    eventType: EventType.FILE_READ,
    timestamp: Date.now(),
    data: { path: '/app/package.json' }
  });
  assert.strictEqual(ev2.threatLevel, ThreatLevel.NORMAL);

  // Evento 3: Conexión interna normal
  const ev3 = engine.processEvent({
    workloadId: 'workload-app-1',
    pid: 1001,
    ppid: 1,
    eventType: EventType.NETWORK_CONNECT,
    timestamp: Date.now(),
    data: { host: 'api.internal.corp', port: 443 }
  });
  assert.strictEqual(ev3.threatLevel, ThreatLevel.NORMAL);
});

test('Sentinel Runtime — Escenario Malicioso Causal: Detección y Contención Graduada', () => {
  const ledger = new EvidenceLedger(':memory:');
  const enforcements = [];

  const engine = new BehavioralSequenceEngine({
    onEnforce: (dec) => {
      enforcements.push(dec);
      ledger.recordIncident(dec);
    }
  });

  const profile = new WorkloadProfile({
    name: 'api-service',
    type: 'nodejs',
    allowedBinaries: ['node']
  });

  engine.registerProfile('workload-app-1', profile);

  // 1. Spawning inesperado de bash
  const ev1 = engine.processEvent({
    workloadId: 'workload-app-1',
    pid: 2002,
    ppid: 1001,
    eventType: EventType.PROCESS_EXEC,
    timestamp: Date.now(),
    data: { binary: '/bin/bash' }
  });
  assert.strictEqual(ev1.threatLevel, ThreatLevel.ELEVATED_WATCH);
  assert.strictEqual(ev1.action, EnforcementAction.INCREASE_LOGGING);

  // 2. Intento de lectura de credenciales /proc/self/environ
  const ev2 = engine.processEvent({
    workloadId: 'workload-app-1',
    pid: 2002,
    ppid: 1001,
    eventType: EventType.FILE_READ,
    timestamp: Date.now(),
    data: { path: '/proc/self/environ' }
  });
  assert.strictEqual(ev2.threatLevel, ThreatLevel.SUSPICIOUS);
  assert.strictEqual(ev2.action, EnforcementAction.SUSPEND_PROCESS);

  // 3. Intento de conexión C2 externa no autorizada
  const ev3 = engine.processEvent({
    workloadId: 'workload-app-1',
    pid: 2002,
    ppid: 1001,
    eventType: EventType.NETWORK_CONNECT,
    timestamp: Date.now(),
    data: { host: 'malicious-c2.attacker.com', port: 8080 }
  });
  assert.strictEqual(ev3.threatLevel, ThreatLevel.CONFIRMED_VIOLATION);
  assert.strictEqual(ev3.action, EnforcementAction.TERMINATE_PROCESS);

  // Verificar que el ledger forense registró la evidencia
  const incidents = ledger.getIncidents();
  assert.strictEqual(incidents.length, 3);
  assert.strictEqual(incidents[0].action, EnforcementAction.TERMINATE_PROCESS);
});
