'use strict';

const { ContainmentLevel } = require('../containment/types');

/**
 * Authoritative security decision engine.
 * Fuses deterministic, sequence (CEP), and statistical anomaly signals
 * under strict safety gates, zero-trust identity verification, and observation loss blocks.
 */
class DecisionEngine {
  constructor(options = {}) {
    this.dispatcher = options.dispatcher || null;
    // Strict safety defaults: auto-containment is disabled by default
    this.autoContain = options.autoContain === true;
    this.allowAutomatedSuspension = options.allowAutomatedSuspension === true;
    this.allowAutomatedTermination = options.allowAutomatedTermination === true;
    this.requireHumanApprovalForR2 = options.requireHumanApprovalForR2 !== false;
  }

  /**
   * Evaluates fused signals and determines the authoritative security decision.
   * Enforces safety invariants:
   * 1. Statistical anomaly alone NEVER requests process suspension (R2).
   * 2. Missing/partial process identity strictly blocks R2, R3, and R4.
   * 3. Observability degradation strictly blocks destructive actions.
   * 4. R2 requires human approval unless explicit automated suspension is granted.
   * 5. Hardcoded confidence constants never independently authorize kills.
   */
  async decide(analysis, event = null) {
    if (!analysis || typeof analysis !== 'object') return null;

    const {
      workloadId,
      identity,
      deterministicDeviation,
      sequenceDetections,
      anomalyDetections,
      observabilityStatus,
      telemetryLoss
    } = analysis;

    let threatLevel = 'NORMAL';
    let confidence = 0.0;
    let reason = 'Behavior within expected operating parameters';
    let requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
    const triggeredRules = [];
    const evidenceReferences = [];
    const safetyGatingReasons = [];

    // Check strong process identity: host_id + boot_id + exec_id
    const hasStrongIdentity = Boolean(
      identity &&
      (identity.host_id || identity.hostId) &&
      (identity.boot_id || identity.bootId) &&
      (identity.exec_id || identity.execId)
    );

    const isObservabilityDegraded = observabilityStatus === 'DEGRADED' || Boolean(telemetryLoss);

    // 1. Evaluate Deterministic Signal
    if (deterministicDeviation) {
      threatLevel = deterministicDeviation.severity === 'SUSPICIOUS' ? 'HIGH' : 'ELEVATED_WATCH';
      confidence = 0.75;
      reason = `Deterministic policy violation: ${deterministicDeviation.rule} (${deterministicDeviation.target})`;
      triggeredRules.push(deterministicDeviation.rule);
      // Deterministic policy deviation defaults to observation
      requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
    }

    // 2. Evaluate Statistical Anomaly Signal
    if (anomalyDetections && anomalyDetections.length > 0) {
      const topAnomaly = anomalyDetections[0];
      threatLevel = threatLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
      confidence = Math.max(confidence, 0.65);
      reason = `Statistical drift: ${topAnomaly.reason}`;
      triggeredRules.push(topAnomaly.type);
      // Invariant: Statistical anomaly alone MUST NEVER request R2 or higher
      requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
      safetyGatingReasons.push('Statistical anomaly alone does not authorize automated process containment');
    }

    // 3. Evaluate Causal Sequence / CEP Kill Chain Signal (Highest Precedence)
    if (sequenceDetections && sequenceDetections.length > 0) {
      const topSeq = sequenceDetections[0];
      threatLevel = topSeq.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH';
      confidence = topSeq.confidence;
      reason = topSeq.title;
      triggeredRules.push(topSeq.chainType);

      if (Array.isArray(topSeq.sourceEventKeys)) {
        evidenceReferences.push(...topSeq.sourceEventKeys);
      }

      // Safety Gate A: Strong Identity Check
      if (!hasStrongIdentity) {
        requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
        safetyGatingReasons.push('Target lacks verified host_id + boot_id + exec_id lineage');
      }
      // Safety Gate B: Observability Loss Check
      else if (isObservabilityDegraded) {
        requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
        safetyGatingReasons.push('Observability degraded / telemetry loss active; destructive containment blocked');
      }
      // Safety Gate C: Authorization Policy
      else {
        // Evaluate if R2 is authorized
        if (this.allowAutomatedSuspension && !this.requireHumanApprovalForR2) {
          requestedAction = ContainmentLevel.R2_PROCESS_SUSPEND;
        } else {
          requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
          safetyGatingReasons.push('Process suspension (R2) requires explicit human operator authorization');
        }

        // Evaluate if R3 is explicitly authorized
        if (this.allowAutomatedTermination && this.autoContain) {
          requestedAction = ContainmentLevel.R3_PROCESS_TERMINATE;
        }
      }
    }

    const decisionResult = {
      workloadId: workloadId || 'default',
      identity: identity || null,
      threatLevel,
      confidence: Number(confidence.toFixed(2)),
      reason,
      requestedAction,
      triggeredRules,
      evidenceReferences: [...new Set(evidenceReferences)],
      safetyGatingReasons,
      observabilityStatus: isObservabilityDegraded ? 'DEGRADED' : 'NORMAL',
      timestamp: new Date().toISOString()
    };

    // If auto-containment is configured and authorized, dispatch to ContainmentDispatcher
    if (this.autoContain && this.dispatcher && requestedAction !== ContainmentLevel.R1_OBSERVE_ONLY) {
      const containmentOutcome = await this.dispatcher.dispatch({
        incidentId: `inc-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        ruleId: triggeredRules[0] || 'COMPOSITE_INTELLIGENCE_VIOLATION',
        requestedLevel: requestedAction,
        targetIdentity: identity,
        reason
      });
      decisionResult.containmentOutcome = containmentOutcome;
    }

    return decisionResult;
  }
}

module.exports = {
  DecisionEngine
};
