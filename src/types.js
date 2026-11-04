'use strict';

/**
 * Event Types emitidos por los sensores (Tetragon, Linux Audit, Proc, eBPF)
 */
const EventType = Object.freeze({
  PROCESS_EXEC: 'PROCESS_EXEC',
  PROCESS_EXIT: 'PROCESS_EXIT',
  FILE_OPEN_ATTEMPT: 'FILE_OPEN_ATTEMPT',
  FILE_OPEN_RESULT: 'FILE_OPEN_RESULT',
  FILE_READ: 'FILE_READ',
  FILE_WRITE: 'FILE_WRITE',
  NETWORK_CONNECT: 'NETWORK_CONNECT',
  NETWORK_CONNECT_ATTEMPT: 'NETWORK_CONNECT_ATTEMPT',
  NETWORK_CONNECT_RESULT: 'NETWORK_CONNECT_RESULT',
  NETWORK_SEND: 'NETWORK_SEND',
  NETWORK_SEND_ATTEMPT: 'NETWORK_SEND_ATTEMPT',
  NETWORK_SEND_RESULT: 'NETWORK_SEND_RESULT',
  CAPABILITY_CHECK: 'CAPABILITY_CHECK',
  // Deprecated in-process compatibility alias. V2 uses CAPABILITY_CHECK.
  CAPABILITY_CHANGE: 'CAPABILITY_CHECK',
  IDENTITY_ACCESS: 'IDENTITY_ACCESS',
  IDENTITY_CHANGE: 'IDENTITY_CHANGE',
  EVENT_LOSS: 'EVENT_LOSS',
  SENSOR_HEALTH: 'SENSOR_HEALTH'
});

/**
 * Severity labels only. The runtime currently operates observe-only.
 */
const ThreatLevel = Object.freeze({
  UNASSESSED: 0,         // Telemetry exists, but no policy/evidence supports a baseline verdict
  NORMAL: 1,             // Nivel 1: Comportamiento dentro del baseline
  ELEVATED_WATCH: 2,      // Señal que requiere más observación
  SUSPICIOUS: 3,          // Evidencia sospechosa correlacionada; observe-only
  CONFIRMED_VIOLATION: 4, // Severidad reservada; no ejecuta contención
  CRITICAL_BREACH: 5      // Severidad reservada; no ejecuta revocación
});

/**
 * Recommendations emitted by the observe-only runtime. These do not invoke OS enforcement.
 */
const RecommendationAction = Object.freeze({
  RECORD_ONLY: 'RECORD_ONLY',
  REQUEST_MORE_TELEMETRY: 'REQUEST_MORE_TELEMETRY'
});

// Deprecated API name retained for callers that imported the early 0.1.0 type.
const EnforcementAction = Object.freeze({
  RECORD_ONLY: RecommendationAction.RECORD_ONLY,
  REQUEST_MORE_TELEMETRY: RecommendationAction.REQUEST_MORE_TELEMETRY,
  INCREASE_LOGGING: RecommendationAction.REQUEST_MORE_TELEMETRY
});

module.exports = {
  EventType,
  ThreatLevel,
  RecommendationAction,
  EnforcementAction
};
