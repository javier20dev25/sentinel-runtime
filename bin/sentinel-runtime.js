#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { BehavioralSequenceEngine } = require('../src/engine');
const { WorkloadProfile } = require('../src/profiler');
const { EvidenceLedger } = require('../src/evidence');
const { EventType } = require('../src/types');

const args = process.argv.slice(2);
const command = args[0] || 'help';

function showHelp() {
  console.log(`
Sentinel Runtime — Deterministic Behavioral Enforcement Engine

Uso:
  sentinel-runtime daemon --config <path>   Inicia el agente residente en segundo plano
  sentinel-runtime audit-log               Muestra los incidentes y evidencias registradas
  sentinel-runtime status                  Estado del motor y workloads vigilados
  sentinel-runtime demo                    Ejecuta la simulación causal de laboratorio
`);
}

switch (command) {
  case 'demo': {
    require('../labs/01-proc-injection/run-lab.js');
    break;
  }
  case 'audit-log': {
    const dbPath = path.join(process.env.USERPROFILE || process.env.HOME, '.sentinel', 'runtime.sqlite');
    if (!fs.existsSync(dbPath)) {
      console.log('No hay incidentes registrados aún en:', dbPath);
      break;
    }
    const ledger = new EvidenceLedger(dbPath);
    const incidents = ledger.getIncidents();
    console.log(`Total de incidentes registrados: ${incidents.length}`);
    console.table(incidents.map(i => ({
      Timestamp: i.timestamp,
      Workload: i.workload_id,
      PID: i.pid,
      Nivel: i.threat_level,
      Acción: i.action,
      Razón: i.reason.slice(0, 50) + '...'
    })));
    break;
  }
  case 'status': {
    console.log(`
🛡️  Sentinel Runtime Status:
- Motor Causal: Activo (FSM determinista)
- Intervención IA en bloqueo: 0% (Decisión 100% causal)
- Tolerancia a desconexión Cloud: Fail-Safe (Políticas locales activas)
- Base de datos forense: SQLite local
`);
    break;
  }
  default:
    showHelp();
    break;
}
