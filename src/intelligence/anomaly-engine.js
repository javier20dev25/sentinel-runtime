'use strict';

/**
 * Streaming statistical anomaly detector using Exponentially Weighted Moving Average (EWMA)
 * and Cumulative Sum Control Chart (CUSUM) algorithms.
 *
 * Runs incrementally in O(1) time per event with zero external dependencies.
 */
class StreamingStatTracker {
  constructor(options = {}) {
    this.alpha = options.alpha || 0.1; // Smoothing factor
    this.thresholdZ = options.thresholdZ || 3.0; // 3 sigma for outlier
    this.cusumK = options.cusumK || 0.5; // Allowance parameter
    this.cusumH = options.cusumH || 5.0; // Decision threshold

    this.mean = null;
    this.variance = null;
    this.cusumPos = 0;
    this.count = 0;
  }

  update(value) {
    this.count++;
    if (this.mean === null) {
      this.mean = value;
      this.variance = 0;
      return { isAnomaly: false, zScore: 0, cusumAlert: false };
    }

    const prevMean = this.mean;
    const prevVar = this.variance;
    const prevStdDev = Math.sqrt(Math.max(prevVar, 1e-6));
    const diff = value - prevMean;

    // Z-Score test against prior established baseline
    const zScore = Math.abs(diff) / prevStdDev;
    const isOutlier = this.count > 5 && zScore >= this.thresholdZ;

    // CUSUM Drift detection
    this.cusumPos = Math.max(0, this.cusumPos + (diff / prevStdDev) - this.cusumK);
    const cusumAlert = this.count > 10 && this.cusumPos > this.cusumH;
    if (cusumAlert) {
      // Reset CUSUM state after alert
      this.cusumPos = 0;
    }

    // Update EWMA Mean & Variance for next observation
    this.mean = this.alpha * value + (1 - this.alpha) * prevMean;
    this.variance = (1 - this.alpha) * (prevVar + this.alpha * diff * diff);

    return {
      isAnomaly: isOutlier || cusumAlert,
      zScore: Number(zScore.toFixed(2)),
      cusumAlert,
      mean: Number(this.mean.toFixed(2))
    };
  }
}

class AnomalyEngine {
  constructor(options = {}) {
    this.workloadTrackers = new Map(); // workloadId -> { processRateTracker, networkRateTracker, lastTick }
  }

  getTracker(workloadId) {
    if (!this.workloadTrackers.has(workloadId)) {
      this.workloadTrackers.set(workloadId, {
        processExecRate: new StreamingStatTracker({ alpha: 0.15, thresholdZ: 3.5, cusumH: 6.0 }),
        networkBurstRate: new StreamingStatTracker({ alpha: 0.15, thresholdZ: 3.5, cusumH: 6.0 }),
        lastEventTime: Date.now(),
        recentExecs: 0,
        recentConns: 0
      });
    }
    return this.workloadTrackers.get(workloadId);
  }

  evaluate(event, workloadId = 'default', now = Date.now()) {
    const tracker = this.getTracker(workloadId);
    const eventType = event.eventType || event.event_type;
    const anomalies = [];

    if (eventType === 'PROCESS_EXEC') {
      tracker.recentExecs++;
      const res = tracker.processExecRate.update(tracker.recentExecs);
      if (res.isAnomaly) {
        anomalies.push({
          type: 'ANOMALOUS_PROCESS_BURST',
          severity: 'HIGH',
          zScore: res.zScore,
          reason: `Sudden burst in process creation rate (Z-score: ${res.zScore}, mean: ${res.mean})`
        });
      }
    } else if (
      eventType === 'NETWORK_CONNECT' ||
      eventType === 'NETWORK_CONNECT_ATTEMPT' ||
      eventType === 'NETWORK_SEND_RESULT'
    ) {
      tracker.recentConns++;
      const res = tracker.networkBurstRate.update(tracker.recentConns);
      if (res.isAnomaly) {
        anomalies.push({
          type: 'ANOMALOUS_NETWORK_BURST',
          severity: 'HIGH',
          zScore: res.zScore,
          reason: `Sudden spike in outbound network events (Z-score: ${res.zScore}, mean: ${res.mean})`
        });
      }
    }

    return anomalies.length > 0 ? anomalies : null;
  }
}

module.exports = {
  StreamingStatTracker,
  AnomalyEngine
};