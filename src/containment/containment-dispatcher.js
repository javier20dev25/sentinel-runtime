'use strict';

const { performance } = require('node:perf_hooks');
const { ContainmentLevel, ContainmentStatus } = require('./types');

function normalizeAdapterOutcome(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { success: false, code: 'INVALID_ADAPTER_RESULT' };
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return { success: false, code: 'INVALID_ADAPTER_RESULT' };
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some(descriptor => !Object.hasOwn(descriptor, 'value'))) {
    return { success: false, code: 'INVALID_ADAPTER_RESULT' };
  }
  const read = key => descriptors[key]?.value;
  const success = read('success') === true;
  const result = { success };
  const actionTaken = read('actionTaken');
  const code = read('code');
  const targetPid = read('targetPid');
  const timestamp = read('timestamp');
  if (typeof actionTaken === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/.test(actionTaken)) {
    result.actionTaken = actionTaken;
  } else if (success) {
    result.actionTaken = 'ACTION_REPORTED';
  }
  if (typeof code === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/.test(code)) result.code = code;
  if (Number.isSafeInteger(targetPid) && targetPid > 1) result.targetPid = targetPid;
  if (typeof timestamp === 'string' && timestamp.length <= 48 && Number.isFinite(Date.parse(timestamp))) result.timestamp = timestamp;
  if (!success && !result.code) result.code = 'ADAPTER_REPORTED_FAILURE';
  return result;
}

/**
 * ContainmentDispatcher coordinates runtime remediation decisions.
 *
 * Core Guarantees:
 * 1. Transaction Order: ACTION_PLANNED is committed to the immutable ledger
 *    BEFORE any system call or signal is dispatched.
 * 2. Attribution Safety: Destructive actions (R3/R4) are strictly blocked if
 *    the target process lacks a strong, verified exec_id (Profile D / Partial).
 * 3. Tamper-Evident Linking: The post-action record cryptographically references
 *    the planned record hash in the ledger chain.
 */
class ContainmentDispatcher {
  constructor(options = {}) {
    if (!options.ledger || typeof options.ledger.append !== 'function') {
      throw new TypeError('ContainmentDispatcher requires an EvidenceLedger instance');
    }
    this.ledger = options.ledger;
    this.adapter = options.adapter || null;
    this.dryRun = options.dryRun !== false; // default true for safety
  }

  async dispatch(request) {
    if (!request || typeof request !== 'object') {
      throw new TypeError('Containment request must be an object');
    }

    const {
      incidentId,
      ruleId,
      requestedLevel = ContainmentLevel.R1_OBSERVE_ONLY,
      targetIdentity = {},
      reason = 'Rule violation detected'
    } = request;

    if (!incidentId || typeof incidentId !== 'string') {
      throw new TypeError('request.incidentId string is required');
    }
    if (!ruleId || typeof ruleId !== 'string') {
      throw new TypeError('request.ruleId string is required');
    }

    // --- Invariant 1: Safety Attribution Check ---
    const isDestructive = (
      requestedLevel === ContainmentLevel.R3_PROCESS_TERMINATE ||
      requestedLevel === ContainmentLevel.R4_NETWORK_ISOLATE
    );

    const hasStrongExecId = (
      typeof targetIdentity.exec_id === 'string' &&
      targetIdentity.exec_id.length > 0 &&
      targetIdentity.profile !== 'D' &&
      targetIdentity.attribution !== 'UNKNOWN' &&
      targetIdentity.attribution !== 'PARTIAL'
    );

    if (isDestructive && !hasStrongExecId) {
      const blockedRecord = this.ledger.append('containment_blocked', {
        timestamp: new Date().toISOString(),
        incident_id: incidentId,
        rule_id: ruleId,
        requested_level: requestedLevel,
        target_identity: targetIdentity,
        block_reason: 'UNSAFE_TARGET_ATTRIBUTION: Destructive containment refused without verified exec_id lineage'
      });

      return {
        status: ContainmentStatus.BLOCKED_UNSAFE,
        incidentId,
        requestedLevel,
        reason: 'Destructive containment refused: target lacks strong exec_id lineage',
        evidenceRecordHash: blockedRecord.record_hash
      };
    }

    // --- Invariant 2: Pre-Action Commitment to SQLite Ledger ---
    const plannedTimestamp = new Date().toISOString();
    const plannedRecord = this.ledger.append('containment_planned', {
      timestamp: plannedTimestamp,
      incident_id: incidentId,
      rule_id: ruleId,
      requested_level: requestedLevel,
      target_identity: targetIdentity,
      reason,
      dry_run: this.dryRun
    });

    const plannedRecordHash = plannedRecord.record_hash;

    // --- Invariant 3: Remediation Dispatch ---
    const startTime = performance.now();
    let outcome = null;
    let finalStatus = ContainmentStatus.EXECUTED;

    try {
      if (requestedLevel === ContainmentLevel.R1_OBSERVE_ONLY) {
        outcome = {
          success: true,
          actionTaken: 'OBSERVE_ONLY_LOGGED',
          details: 'Event committed to ledger without process interruption'
        };
      } else if (this.dryRun) {
        outcome = {
          success: true,
          actionTaken: `${requestedLevel}_DRY_RUN`,
          details: 'Dry-run enabled: no signal or network rule emitted'
        };
        finalStatus = ContainmentStatus.SKIPPED_DRY_RUN;
      } else {
        if (!this.adapter) {
          throw new Error(`No containment adapter configured for level: ${requestedLevel}`);
        }
        const adapterResult = await this.adapter.execute({
          level: requestedLevel,
          targetIdentity,
          plannedRecordHash
        });
        outcome = normalizeAdapterOutcome(adapterResult);
        if (!outcome.success) finalStatus = ContainmentStatus.FAILED;
      }
    } catch (err) {
      finalStatus = ContainmentStatus.FAILED;
      outcome = {
        success: false,
        code: err && typeof err.code === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/.test(err.code) ? err.code : 'ADAPTER_ERROR'
      };
    }

    const durationMs = Number((performance.now() - startTime).toFixed(3));

    // --- Invariant 4: Post-Action Commitment to SQLite Ledger ---
    const resultRecord = this.ledger.append('containment_result', {
      timestamp: new Date().toISOString(),
      incident_id: incidentId,
      planned_record_hash: plannedRecordHash,
      status: finalStatus,
      duration_ms: durationMs,
      outcome
    });

    return {
      status: finalStatus,
      incidentId,
      requestedLevel,
      durationMs,
      plannedRecordHash,
      resultRecordHash: resultRecord.record_hash,
      outcome
    };
  }
}

module.exports = {
  ContainmentDispatcher
};
