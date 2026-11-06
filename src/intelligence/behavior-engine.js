'use strict';

const { SequenceDetector } = require('./sequence-detector');
const { AnomalyEngine } = require('./anomaly-engine');

class BehaviorEngine {
  constructor(options = {}) {
    this.profiles = new Map(); // workloadId -> WorkloadProfile
    this.sequenceDetector = new SequenceDetector(options);
    this.anomalyEngine = new AnomalyEngine(options);
  }

  registerProfile(workloadId, profile) {
    if (!workloadId || typeof workloadId !== 'string') throw new TypeError('workloadId is required');
    this.profiles.set(workloadId, profile);
  }

  /**
   * Processes a normalized runtime event across all real-time intelligence components.
   * Returns a consolidated signal set.
   */
  analyzeEvent(event) {
    if (!event || typeof event !== 'object') return null;

    const workloadId = event.workloadId || event.workload_id || event.workload_context?.container_id || 'default';

    // Extract process identity with host/boot correlation
    let identity = event.processIdentity || event.process_identity || null;
    if (identity && (!identity.host_id || !identity.boot_id)) {
      const hostId = identity.host_id || identity.hostId || event.host_identity?.host_id || event.hostId;
      const bootId = identity.boot_id || identity.bootId || event.host_identity?.boot_id || event.bootId;
      identity = { ...identity, host_id: hostId, boot_id: bootId };
    }

    // Extract timestamp
    const now = typeof event.timestamp === 'number' && Number.isFinite(event.timestamp)
      ? event.timestamp
      : (typeof event.timestamps?.source_timestamp === 'string' && /^\d+$/.test(event.timestamps.source_timestamp)
          ? Math.floor(Number(event.timestamps.source_timestamp) / 1000000)
          : Date.now());

    // Extract observability status & telemetry loss state
    let observabilityStatus = 'NORMAL';
    let telemetryLoss = null;
    const eventType = event.eventType || event.event_type;

    if (eventType === 'EVENT_LOSS') {
      observabilityStatus = 'DEGRADED';
      telemetryLoss = event.payload || true;
    } else if (event.loss_metrics) {
      for (const [domain, metric] of Object.entries(event.loss_metrics)) {
        if (metric && metric.state === 'MEASURED' && typeof metric.count === 'string' && BigInt(metric.count) > 0n) {
          observabilityStatus = 'DEGRADED';
          telemetryLoss = { domain, count: metric.count };
          break;
        }
      }
    }

    // 1. Deterministic baseline check against WorkloadProfile (if registered)
    const profile = this.profiles.get(workloadId);
    let deterministicDeviation = null;

    if (profile) {
      const data = event.data || event.payload || {};

      if (eventType === 'PROCESS_EXEC') {
        const bin = data.binary || data.executable_path || identity?.executablePath || '';
        const digest = data.executable_digest?.value || null;
        if (!profile.isBinaryAllowed(bin, digest)) {
          deterministicDeviation = {
            rule: 'DISALLOWED_EXECUTABLE',
            severity: 'ELEVATED_WATCH',
            target: bin
          };
        }
      } else if (eventType === 'FILE_READ' || eventType === 'FILE_OPEN_ATTEMPT') {
        const p = data.path || data.file_path || data.filename || '';
        if (profile.isPathRestricted(p)) {
          deterministicDeviation = {
            rule: 'RESTRICTED_PATH_ACCESS',
            severity: 'SUSPICIOUS',
            target: p
          };
        }
      } else if (
        eventType === 'NETWORK_CONNECT' ||
        eventType === 'NETWORK_CONNECT_ATTEMPT' ||
        eventType === 'NETWORK_SEND_RESULT' ||
        eventType === 'NETWORK_SEND_ATTEMPT'
      ) {
        const host = data.host || data.destination_ip || data.destination_host || '';
        const port = data.port ?? data.destination_port;
        if (!profile.isNetworkDestinationAllowed(host, port)) {
          deterministicDeviation = {
            rule: 'DISALLOWED_NETWORK_DESTINATION',
            severity: 'SUSPICIOUS',
            target: `${host}:${port || '?'}`
          };
        }
      }
    }

    // 2. Real-Time Complex Event Processing (FSM Sequence Detector)
    const sequenceDetections = this.sequenceDetector.evaluate(event, identity, now);

    // 3. Online Statistical Anomaly Detection (EWMA / CUSUM)
    const anomalyDetections = this.anomalyEngine.evaluate(event, workloadId, now);

    return {
      workloadId,
      identity,
      timestamp: now,
      observabilityStatus,
      telemetryLoss,
      baselineStatus: this.anomalyEngine.getBaselineStatus(workloadId, now),
      deterministicDeviation,
      sequenceDetections,
      anomalyDetections
    };
  }
}

module.exports = {
  BehaviorEngine
};
