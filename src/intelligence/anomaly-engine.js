'use strict';

const DEFAULT_ALPHA = 0.15;
const DEFAULT_THRESHOLD_Z = 3.5;
const DEFAULT_CUSUM_K = 0.5;
const DEFAULT_CUSUM_H = 6.0;
const DEFAULT_WARMUP_OBSERVATIONS = 15;
const DEFAULT_WINDOW_MS = 1000; // 1-second rate observation window
const DEFAULT_MAX_TRACKERS = 1000;
const DEFAULT_TRACKER_TTL_MS = 5 * 60 * 1000; // 5-minute idle TTL

/**
 * Streaming statistical anomaly detector using Exponentially Weighted Moving Average (EWMA)
 * and Cumulative Sum Control Chart (CUSUM).
 *
 * Evaluates streaming time-normalized rate metrics in O(1) time per observation.
 * Uses standard IEEE 754 floating point arithmetic with epsilon-bounded variance.
 */
class StreamingStatTracker {
  constructor(options = {}) {
    this.alpha = options.alpha || DEFAULT_ALPHA;
    this.thresholdZ = options.thresholdZ || DEFAULT_THRESHOLD_Z;
    this.cusumK = options.cusumK || DEFAULT_CUSUM_K;
    this.cusumH = options.cusumH || DEFAULT_CUSUM_H;
    this.warmupObservations = options.warmupObservations || DEFAULT_WARMUP_OBSERVATIONS;

    this.mean = null;
    this.variance = null;
    this.cusumPos = 0;
    this.count = 0;
  }

  /**
   * Updates baseline and checks for anomalies against time-normalized rate.
   * Requires warmup period before issuing alerts to prevent false positives during baseline initialization.
   */
  update(rate) {
    if (typeof rate !== 'number' || !Number.isFinite(rate) || rate < 0) {
      throw new TypeError('rate must be a non-negative finite number');
    }

    this.count++;

    // Initial observation
    if (this.mean === null) {
      this.mean = rate;
      this.variance = 0;
      return { isAnomaly: false, zScore: 0, cusumAlert: false, mean: this.mean, warmedUp: false };
    }

    const prevMean = this.mean;
    const prevVar = this.variance;
    const prevStdDev = Math.sqrt(Math.max(prevVar, 1e-6));
    const diff = rate - prevMean;
    const zScore = Math.abs(diff) / prevStdDev;

    // CUSUM drift detection (accumulate only after warmup establishes baseline)
    const warmedUp = this.count >= this.warmupObservations;
    const isOutlier = warmedUp && (zScore >= this.thresholdZ);

    let cusumAlert = false;
    if (warmedUp) {
      this.cusumPos = Math.max(0, this.cusumPos + (diff / prevStdDev) - this.cusumK);
      cusumAlert = this.cusumPos > this.cusumH;
      if (cusumAlert) {
        // Reset CUSUM accumulator after alert
        this.cusumPos = 0;
      }
    } else {
      this.cusumPos = 0;
    }

    // Incremental EWMA update for mean and variance
    this.mean = this.alpha * rate + (1 - this.alpha) * prevMean;
    this.variance = (1 - this.alpha) * (prevVar + this.alpha * diff * diff);

    return {
      isAnomaly: isOutlier || cusumAlert,
      zScore: Number(zScore.toFixed(2)),
      cusumAlert,
      mean: Number(this.mean.toFixed(2)),
      observedRate: Number(rate.toFixed(2)),
      warmedUp
    };
  }
}

/**
 * Windowed rate accumulator for a single metric channel.
 * Converts discrete timestamped events into time-normalized event rates (events / second).
 */
class ChannelRateWindow {
  constructor(options = {}) {
    this.windowMs = options.windowMs || DEFAULT_WINDOW_MS;
    this.tracker = new StreamingStatTracker(options);
    this.windowStartMs = null;
    this.eventCountInWindow = 0;
    this.lastEventTime = null;
  }

  recordEvent(timestamp) {
    if (typeof timestamp !== 'number' || !Number.isFinite(timestamp) || timestamp <= 0) {
      return null;
    }

    // Handle initial event
    if (this.windowStartMs === null) {
      this.windowStartMs = timestamp;
      this.eventCountInWindow = 1;
      this.lastEventTime = timestamp;
      return null;
    }

    // Handle timestamp regression safely: do not rewind time or corrupt active window
    if (timestamp < this.lastEventTime) {
      return null;
    }
    this.lastEventTime = timestamp;

    const elapsed = timestamp - this.windowStartMs;

    if (elapsed >= this.windowMs) {
      // Compute time-normalized rate (events per second)
      const rate = (this.eventCountInWindow * 1000) / Math.max(elapsed, 1);
      const updateResult = this.tracker.update(rate);

      // Start new observation window
      this.windowStartMs = timestamp;
      this.eventCountInWindow = 1;

      return updateResult;
    }

    this.eventCountInWindow++;
    return null;
  }

  forceFlush(now) {
    if (this.windowStartMs === null || this.eventCountInWindow === 0) return null;
    const elapsed = Math.max(now - this.windowStartMs, this.windowMs);
    const rate = (this.eventCountInWindow * 1000) / elapsed;
    const updateResult = this.tracker.update(rate);
    this.windowStartMs = now;
    this.eventCountInWindow = 0;
    return updateResult;
  }
}

/**
 * Real-time streaming anomaly engine for workloads.
 * Measures event rates over sliding intervals, maintains bounded tracker memory,
 * and detects statistical execution or network bursts.
 */
class AnomalyEngine {
  constructor(options = {}) {
    this.maxTrackers = options.maxTrackers || DEFAULT_MAX_TRACKERS;
    this.trackerTtlMs = options.trackerTtlMs || DEFAULT_TRACKER_TTL_MS;
    this.windowMs = options.windowMs || DEFAULT_WINDOW_MS;
    this.lastPruneTime = 0;
    this.workloadTrackers = new Map(); // workloadId -> { processExecWindow, networkWindow, lastAccessTime }
  }

  pruneTrackers(now) {
    this.lastPruneTime = now;
    for (const [id, entry] of this.workloadTrackers.entries()) {
      if (now - entry.lastAccessTime > this.trackerTtlMs) {
        this.workloadTrackers.delete(id);
      }
    }
  }

  getTracker(workloadId, now) {
    if (now - this.lastPruneTime >= 10000) {
      this.pruneTrackers(now);
    }

    let entry = this.workloadTrackers.get(workloadId);
    if (!entry) {
      // Ensure bounded capacity under high workload churn
      if (this.workloadTrackers.size >= this.maxTrackers) {
        const oldestId = this.workloadTrackers.keys().next().value;
        if (oldestId) this.workloadTrackers.delete(oldestId);
      }

      entry = {
        processExecWindow: new ChannelRateWindow({ windowMs: this.windowMs }),
        networkWindow: new ChannelRateWindow({ windowMs: this.windowMs }),
        lastAccessTime: now
      };
      this.workloadTrackers.set(workloadId, entry);
    }

    entry.lastAccessTime = now;
    return entry;
  }

  /**
   * Evaluates an observed event for statistical rate anomalies.
   * Returns an array of anomaly descriptors if a rate boundary is crossed.
   */
  evaluate(event, workloadId = 'default', now = Date.now()) {
    if (!event || typeof event !== 'object') return null;

    const eventType = event.eventType || event.event_type;
    const tracker = this.getTracker(workloadId, now);
    const anomalies = [];

    // Derive event timestamp safely
    const eventTime = typeof event.timestamp === 'number' && Number.isFinite(event.timestamp)
      ? event.timestamp
      : (typeof event.timestamps?.source_timestamp === 'string' && /^\d+$/.test(event.timestamps.source_timestamp)
          ? Math.floor(Number(event.timestamps.source_timestamp) / 1000000) // Convert ns to ms
          : now);

    if (eventType === 'PROCESS_EXEC') {
      const rateResult = tracker.processExecWindow.recordEvent(eventTime);
      if (rateResult && rateResult.isAnomaly) {
        anomalies.push({
          type: 'ANOMALOUS_PROCESS_BURST',
          severity: 'HIGH',
          zScore: rateResult.zScore,
          rate: rateResult.observedRate,
          mean: rateResult.mean,
          cusumAlert: rateResult.cusumAlert,
          reason: `Statistical anomaly in process creation rate (${rateResult.observedRate} events/s vs baseline ${rateResult.mean} events/s, Z=${rateResult.zScore})`
        });
      }
    } else if (
      eventType === 'NETWORK_CONNECT' ||
      eventType === 'NETWORK_CONNECT_ATTEMPT' ||
      eventType === 'NETWORK_SEND_RESULT' ||
      eventType === 'NETWORK_SEND_ATTEMPT'
    ) {
      const rateResult = tracker.networkWindow.recordEvent(eventTime);
      if (rateResult && rateResult.isAnomaly) {
        anomalies.push({
          type: 'ANOMALOUS_NETWORK_BURST',
          severity: 'HIGH',
          zScore: rateResult.zScore,
          rate: rateResult.observedRate,
          mean: rateResult.mean,
          cusumAlert: rateResult.cusumAlert,
          reason: `Statistical anomaly in network egress rate (${rateResult.observedRate} events/s vs baseline ${rateResult.mean} events/s, Z=${rateResult.zScore})`
        });
      }
    }

    return anomalies.length > 0 ? anomalies : null;
  }

  getBaselineStatus(workloadId, now = Date.now()) {
    const tracker = this.workloadTrackers.get(workloadId);
    if (!tracker) return 'NOT_INITIALIZED';
    const execWarmed = tracker.processExecWindow.tracker.count >= tracker.processExecWindow.tracker.warmupObservations;
    const netWarmed = tracker.networkWindow.tracker.count >= tracker.networkWindow.tracker.warmupObservations;
    return (execWarmed && netWarmed) ? 'WARMED_UP' : 'CALIBRATING';
  }
}

module.exports = {
  StreamingStatTracker,
  ChannelRateWindow,
  AnomalyEngine
};
