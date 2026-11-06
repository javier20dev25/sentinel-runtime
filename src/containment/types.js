'use strict';

/**
 * Containment levels according to Sentinel Runtime Engine v1 Spec (R1-R4)
 */
const ContainmentLevel = Object.freeze({
  R1_OBSERVE_ONLY: 'OBSERVE_ONLY',
  R2_PROCESS_SUSPEND: 'PROCESS_SUSPEND',
  R3_PROCESS_TERMINATE: 'PROCESS_TERMINATE',
  R4_NETWORK_ISOLATE: 'NETWORK_ISOLATE'
});

/**
 * Status outcomes for containment dispatch lifecycle
 */
const ContainmentStatus = Object.freeze({
  PLANNED: 'PLANNED',
  EXECUTED: 'EXECUTED',
  FAILED: 'FAILED',
  BLOCKED_UNSAFE: 'BLOCKED_UNSAFE',
  SKIPPED_DRY_RUN: 'SKIPPED_DRY_RUN'
});

module.exports = {
  ContainmentLevel,
  ContainmentStatus
};