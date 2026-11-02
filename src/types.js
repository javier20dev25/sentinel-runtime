'use strict';

/**
 * Event Types emitidos por los sensores (Tetragon, Linux Audit, Proc, eBPF)
 */
const EventType = Object.freeze({
  PROCESS_EXEC: 'PROCESS_EXEC',
  PROCESS_EXIT: 'PROCESS_EXIT',
  FILE_READ: 'FILE_READ',
  FILE_WRITE: 'FILE_WRITE',
  NETWORK_CONNECT: 'NETWORK_CONNECT',
  NETWORK_SEND: 'NETWORK_SEND',
  CAPABILITY_CHANGE: 'CAPABILITY_CHANGE',
  IDENTITY_ACCESS: 'IDENTITY_ACCESS'
});

/**
 * Niveles de Contención y Respuesta Graduada
 */
const ThreatLevel = Object.freeze({
  NORMAL: 1,             // Nivel 1: Comportamiento dentro del baseline
  ELEVATED_WATCH: 2,     // Nivel 2: Desviación menor, incrementar telemetría
  SUSPICIOUS: 3,         // Nivel 3: Alerta y restricción parcial
  CONFIRMED_VIOLATION: 4,// Nivel 4: Bloqueo activo del proceso / syscall
  CRITICAL_BREACH: 5     // Nivel 5: Contención total de workload + revocación
});

/**
 * Acciones de Enforcement ejecutables
 */
const EnforcementAction = Object.freeze({
  RECORD_ONLY: 'RECORD_ONLY',
  INCREASE_LOGGING: 'INCREASE_LOGGING',
  BLOCK_SYSCALL: 'BLOCK_SYSCALL',
  SUSPEND_PROCESS: 'SUSPEND_PROCESS',      // Reversible: SIGSTOP
  TERMINATE_PROCESS: 'TERMINATE_PROCESS',  // No reversible: SIGKILL
  ISOLATE_NETWORK: 'ISOLATE_NETWORK',      // Reversible: regla temporal de firewall
  REVOKE_CREDENTIAL: 'REVOKE_CREDENTIAL'   // Solicitud a Sentinel Identity / Cloud
});

module.exports = {
  EventType,
  ThreatLevel,
  EnforcementAction
};
