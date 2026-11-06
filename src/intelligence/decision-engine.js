'use strict';

const { ContainmentLevel } = require('../containment/types');

class DecisionEngine {
  constructor(options = {}) {
    this.dispatcher = options.dispatcher || null;
    this.autoContain = options.autoContain === true;
    this.minConfidenceForKill = options.minConfidenceForKill || 0.85;
  }

  /**
   * Evaluates fused signals and determines the authoritative security decision.
   */
  async decide(analysis, event = null) {
    if (!analysis) return null;

    const {
      workloadId,
      identity,
      deterministicDeviation,
      sequenceDetections,
      anomalyDetections
    } = analysis;

    let threatLevel = 'NORMAL';
    let confidence = 0.0;
    let reason = 'Behavior within expected operating parameters';
    let requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
    const triggeredRules = [];

    // Evaluate Deterministic Signal
    if (deterministicDeviation) {
      threatLevel = deterministicDeviation.severity === 'SUSPICIOUS' ? 'HIGH' : 'ELEVATED_WATCH';
      confidence = 0.80;
      reason = `Deterministic policy violation: ${deterministicDeviation.rule} (${deterministicDeviation.target})`;
      triggeredRules.push(deterministicDeviation.rule);
      requestedAction = ContainmentLevel.R1_OBSERVE_ONLY;
    }

    // Evaluate Statistical Anomaly Signal
    if (anomalyDetections && anomalyDetections.length > 0) {
      const topAnomaly = anomalyDetections[0];
      threatLevel = 'HIGH';
      confidence = Math.max(confidence, 0.75);
      reason = `Statistical drift detected: ${topAnomaly.reason}`;
      triggeredRules.push(topAnomaly.type);
      requestedAction = ContainmentLevel.R2_PROCESS_SUSPEND;
    }

    // Evaluate Causal / Sequence Kill Chain Signal (Highest Precedence)
    if (sequenceDetections && sequenceDetections.length > 0) {
      const topSeq = sequenceDetections[0];
      threatLevel = 'CRITICAL';
      confidence = topSeq.confidence;
      reason = topSeq.title;
      triggeredRules.push(topSeq.chainType);

      if (confidence >= this.minConfidenceForKill) {
        requestedAction = ContainmentLevel.R3_PROCESS_TERMINATE;
      } else {
        requestedAction = ContainmentLevel.R2_PROCESS_SUSPEND;
      }
    }

    const decisionResult = {
      workloadId,
      identity,
      threatLevel,
      confidence: Number(confidence.toFixed(2)),
      reason,
      requestedAction,
      triggeredRules,
      timestamp: new Date().toISOString()
    };

    // If auto-containment is configured with a ContainmentDispatcher, execute the action
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