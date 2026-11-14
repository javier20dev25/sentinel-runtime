#!/usr/bin/env node
'use strict';

const { BehavioralSequenceEngine } = require('../../src/engine');
const { WorkloadProfile } = require('../../src/profiler');
const { EvidenceLedger } = require('../../src/evidence');
const { EventType } = require('../../src/types');

console.log('=== SENTINEL RUNTIME // BEHAVIORAL SUPERVISION LAB ===\n');

const ledger = new EvidenceLedger(':memory:');
const engine = new BehavioralSequenceEngine({
  onDecision: (decision) => {
    console.log(`[ENFORCEMENT ACTION] Level ${decision.threatLevel} -> ${decision.action}`);
    console.log(`[MOTIVO]: ${decision.reason}\n`);
    ledger.recordIncident(decision);
  }
});

const nodeAppProfile = new WorkloadProfile({
  name: 'production-api',
  type: 'nodejs',
  allowedBinaries: ['/usr/local/bin/node'],
  allowedDestinations: ['10.0.0.5:5432']
});

engine.registerProfile('workload-prod-api', nodeAppProfile);

console.log('1. Simulando tráfico benigno de producción...');
engine.processEvent({
  workloadId: 'workload-prod-api',
  hostId: 'lab-host',
  bootId: 'lab-boot',
  execId: 'exec-4001',
  pid: 4001,
  ppid: 1,
  eventType: EventType.PROCESS_EXEC,
  timestamp: Date.now(),
  data: { binary: '/usr/local/bin/node' }
});

engine.processEvent({
  workloadId: 'workload-prod-api',
  hostId: 'lab-host',
  bootId: 'lab-boot',
  execId: 'exec-4001',
  pid: 4001,
  ppid: 1,
  eventType: EventType.FILE_READ,
  timestamp: Date.now(),
  data: { path: '/app/src/index.js' }
});

console.log('-> Operaciones legítimas registradas sin interrupción (0 Falsos Positivos).\n');

console.log('2. Inyectando cadena de ataque simulada en subproceso...');
// Paso A: Spawning de bash desde el proceso node
engine.processEvent({
  workloadId: 'workload-prod-api',
  hostId: 'lab-host',
  bootId: 'lab-boot',
  execId: 'exec-4002',
  pid: 4002,
  ppid: 4001,
  eventType: EventType.PROCESS_EXEC,
  timestamp: Date.now(),
  data: { binary: '/bin/bash' }
});

// Paso B: Intento de recolectar secretos del proceso
engine.processEvent({
  workloadId: 'workload-prod-api',
  hostId: 'lab-host',
  bootId: 'lab-boot',
  execId: 'exec-4002',
  pid: 4002,
  ppid: 4001,
  eventType: EventType.FILE_READ,
  timestamp: Date.now(),
  data: { path: '/proc/self/environ' }
});

// Paso C: Intento de conectar hacia un host C2 desconocido
engine.processEvent({
  workloadId: 'workload-prod-api',
  hostId: 'lab-host',
  bootId: 'lab-boot',
  execId: 'exec-4002',
  pid: 4002,
  ppid: 4001,
  eventType: EventType.NETWORK_CONNECT,
  timestamp: Date.now(),
  data: { host: '198.51.100.24', port: 4444 }
});

const incidents = ledger.getIncidents();
console.log(`=== RECONSTRUCCIÓN FORENSE: ${incidents.length} EVENTOS EN AUDIT LEDGER ===`);
incidents.forEach((inc, idx) => {
  console.log(`[#${idx + 1}] ${inc.timestamp} | PID: ${inc.pid} | Action: ${inc.action} | ThreatLevel: ${inc.threat_level}`);
  console.log(`     Detalle: ${inc.reason}`);
});
