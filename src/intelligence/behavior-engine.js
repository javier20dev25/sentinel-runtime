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

    const workloadId = event.workloadId || event.workload_id || 'default';
    const identity = event.processIdentity || event.process_identity || { pid: event.pid };
    const now = Date.now();

    // 1. Deterministic baseline check against WorkloadProfile (if registered)
    const profile = this.profiles.get(workloadId);
    let deterministicDeviation = null;

    if (profile) {
      const eventType = event.eventType || event.event_type;
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
        eventType === 'NETWORK_SEND_RESULT'
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
      deterministicDeviation,
      sequenceDetections,
      anomalyDetections
    };
  }
}

module.exports = {
  BehaviorEngine
};