'use strict';

const DEFAULT_CORRELATION_WINDOW_MS = 60 * 1000; // 60s sliding window
const DEFAULT_MAX_PROCESSES = 5000;
const DEFAULT_PRUNE_INTERVAL_MS = 5000;
const MAX_STAGES_PER_PROCESS = 32;
const MAX_TRIGGERED_INCIDENTS_PER_PROCESS = 128;

const ChainType = Object.freeze({
  SUSPICIOUS_EXFILTRATION: 'SUSPICIOUS_EXFILTRATION_SEQUENCE',
  SUSPICIOUS_NETWORK_AND_SHELL: 'SUSPICIOUS_NETWORK_AND_SHELL_SEQUENCE',
  SUSPICIOUS_REVERSE_SHELL: 'SUSPICIOUS_NETWORK_AND_SHELL_SEQUENCE', // backwards-compatible alias
  CAPABILITY_CHECK_OBSERVED: 'CAPABILITY_CHECK_OBSERVED'
});

/**
 * Real-time Finite State Machine (FSM) & Complex Event Processing (CEP) engine.
 * Correlates multi-step attack sequences with strict timestamp ordering,
 * strong process attribution, incident deduplication, and bounded memory.
 */
class SequenceDetector {
  constructor(options = {}) {
    this.windowMs = options.windowMs || DEFAULT_CORRELATION_WINDOW_MS;
    this.maxProcesses = options.maxProcesses || DEFAULT_MAX_PROCESSES;
    this.pruneIntervalMs = options.pruneIntervalMs || DEFAULT_PRUNE_INTERVAL_MS;
    this.lastPruneTime = 0;
    // Map: processKey -> { identity, stages: Map(stageName -> stageData), triggeredIncidents: Set, firstSeen, lastSeen }
    this.processFsm = new Map();
  }

  /**
   * Derives a strong, collision-free key for process attribution.
   * Strict invariant: Causal correlation across events requires host_id + boot_id + exec_id.
   * Partial identities (e.g. PID-only or missing exec_id) return null to prevent
   * false causal attribution or cross-process state contamination.
   */
  processKey(identity) {
    if (!identity || typeof identity !== 'object') return null;
    const host = identity.host_id || identity.hostId;
    const boot = identity.boot_id || identity.bootId;
    const exec = identity.exec_id || identity.execId;

    if (!host || typeof host !== 'string' || host.trim() === '') return null;
    if (!boot || typeof boot !== 'string' || boot.trim() === '') return null;
    if (!exec || typeof exec !== 'string' || exec.trim() === '') return null;

    return `${host}:${boot}:${exec}`;
  }

  /**
   * Bounded pruning of expired process states and individual stages.
   * Runs conditionally based on time interval or capacity threshold to maintain O(1) event ingestion.
   */
  prune(now) {
    this.lastPruneTime = now;
    for (const [key, state] of this.processFsm.entries()) {
      if (now - state.lastSeen > this.windowMs) {
        this.processFsm.delete(key);
      } else {
        // Prune stale stages within surviving processes
        for (const [stage, data] of state.stages.entries()) {
          if (now - data.timestamp > this.windowMs) {
            state.stages.delete(stage);
          }
        }
      }
    }

    // Capacity bound safeguard: evict oldest if still over limit
    if (this.processFsm.size > this.maxProcesses) {
      const excess = this.processFsm.size - this.maxProcesses;
      const iterator = this.processFsm.keys();
      for (let i = 0; i < excess; i++) {
        const oldestKey = iterator.next().value;
        if (oldestKey) this.processFsm.delete(oldestKey);
      }
    }
  }

  setStage(state, stageName, stageData) {
    if (state.stages.size >= MAX_STAGES_PER_PROCESS) {
      const oldestStage = state.stages.keys().next().value;
      if (oldestStage) state.stages.delete(oldestStage);
    }
    state.stages.set(stageName, stageData);
  }

  recordIncident(state, incidentKey) {
    if (state.triggeredIncidents.size >= MAX_TRIGGERED_INCIDENTS_PER_PROCESS) {
      const oldest = state.triggeredIncidents.keys().next().value;
      if (oldest) state.triggeredIncidents.delete(oldest);
    }
    state.triggeredIncidents.add(incidentKey);
  }

  /**
   * Evaluates an observed event and updates the process FSM state.
   * Returns detected kill-chain transitions if triggered.
   */
  evaluate(event, identity, now = Date.now()) {
    if (!event || typeof event !== 'object') return null;

    const key = this.processKey(identity);
    // Strict safety invariant: No strong causal attribution without complete identity
    if (!key) return null;

    const eventType = event.eventType || event.event_type;

    // Process Exit lifecycle: close and purge process FSM state immediately
    if (eventType === 'PROCESS_EXIT') {
      this.processFsm.delete(key);
      return null;
    }

    // Rate-limited or capacity-triggered pruning
    if (now - this.lastPruneTime >= this.pruneIntervalMs || this.processFsm.size >= this.maxProcesses) {
      this.prune(now);
    }

    let state = this.processFsm.get(key);
    if (!state) {
      state = {
        identity,
        stages: new Map(),
        triggeredIncidents: new Set(),
        firstSeen: now,
        lastSeen: now
      };
      this.processFsm.set(key, state);
    }

    // Handle potential timestamp regressions safely
    if (now >= state.lastSeen) {
      state.lastSeen = now;
    }

    const data = event.data || event.payload || {};
    const sourceEventKey = event.sourceEventKey || event.source_event_key || event.eventId || event.event_id || null;
    const detections = [];

    // Stage 1: Process Exec
    if (eventType === 'PROCESS_EXEC') {
      const binary = data.binary || data.executable_path || '';
      this.setStage(state, 'EXEC_INITIALIZED', { timestamp: now, binary, sourceEventKey });
      if (isShellOrInterpreter(binary)) {
        this.setStage(state, 'INTERPRETER_SPAWNED', { timestamp: now, binary, sourceEventKey });
      }
    }

    // Stage 2: Sensitive File Access
    if (eventType === 'FILE_READ' || eventType === 'FILE_OPEN_ATTEMPT') {
      const targetPath = data.path || data.file_path || data.filename || '';
      if (isSensitivePath(targetPath)) {
        this.setStage(state, 'SENSITIVE_FILE_ACCESSED', { timestamp: now, path: targetPath, sourceEventKey });
      }
    }

    // Stage 3: Network Outbound Attempt / Result
    if (
      eventType === 'NETWORK_CONNECT' ||
      eventType === 'NETWORK_CONNECT_ATTEMPT' ||
      eventType === 'NETWORK_SEND_RESULT' ||
      eventType === 'NETWORK_SEND_ATTEMPT'
    ) {
      const host = data.host || data.destination_ip || data.destination_host || '';
      const port = data.port ?? data.destination_port;
      this.setStage(state, 'NETWORK_OUTBOUND_ATTEMPT', { timestamp: now, host, port, sourceEventKey });
    }

    // Stage 4: Capability Check (cap_capable)
    if (eventType === 'CAPABILITY_CHECK' || event.process_kprobe?.function_name === 'cap_capable') {
      const capName = data.capability_name || data.capability || '';
      if (capName === 'CAP_SETUID' || capName === 'CAP_SYS_ADMIN' || capName === 'CAP_NET_RAW') {
        this.setStage(state, 'PRIVILEGED_CAPABILITY_REQUESTED', { timestamp: now, capability: capName, sourceEventKey });
      }
    }

    // --- Strict FSM Chain Evaluations with Chronological Ordering ---

    // A. Suspicious Exfiltration Sequence:
    // Requires: SENSITIVE_FILE_ACCESSED strictly happened BEFORE NETWORK_OUTBOUND_ATTEMPT
    if (state.stages.has('SENSITIVE_FILE_ACCESSED') && state.stages.has('NETWORK_OUTBOUND_ATTEMPT')) {
      const fileStage = state.stages.get('SENSITIVE_FILE_ACCESSED');
      const netStage = state.stages.get('NETWORK_OUTBOUND_ATTEMPT');

      // Strict chronological validation: file access must precede network egress
      if (fileStage.timestamp < netStage.timestamp) {
        const incidentKey = `${ChainType.SUSPICIOUS_EXFILTRATION}:${fileStage.sourceEventKey || fileStage.timestamp}:${netStage.sourceEventKey || netStage.timestamp}`;
        if (!state.triggeredIncidents.has(incidentKey)) {
          this.recordIncident(state, incidentKey);
          detections.push({
            chainType: ChainType.SUSPICIOUS_EXFILTRATION,
            severity: 'HIGH',
            confidence: 0.70, // Conservative: transfer of bytes not verified
            title: 'Suspicious Sequence: Sensitive file read followed by network outbound attempt (transfer unconfirmed)',
            details: {
              fileAccessed: fileStage.path,
              networkTarget: `${netStage.host}:${netStage.port || '?'}`
            },
            sourceEventKeys: [fileStage.sourceEventKey, netStage.sourceEventKey].filter(Boolean),
            stageTimestamps: {
              fileAccess: fileStage.timestamp,
              networkAttempt: netStage.timestamp
            },
            incidentKey
          });
        }
      }
    }

    // B. Suspicious Network and Shell Sequence:
    // Requires: NETWORK_OUTBOUND_ATTEMPT strictly happened BEFORE or CONCURRENTLY with INTERPRETER_SPAWNED
    if (state.stages.has('NETWORK_OUTBOUND_ATTEMPT') && state.stages.has('INTERPRETER_SPAWNED')) {
      const netStage = state.stages.get('NETWORK_OUTBOUND_ATTEMPT');
      const interpStage = state.stages.get('INTERPRETER_SPAWNED');

      // Strict chronological validation: network connection precedes or coincides with interpreter spawn
      if (netStage.timestamp <= interpStage.timestamp) {
        const incidentKey = `${ChainType.SUSPICIOUS_NETWORK_AND_SHELL}:${netStage.sourceEventKey || netStage.timestamp}:${interpStage.sourceEventKey || interpStage.timestamp}`;
        if (!state.triggeredIncidents.has(incidentKey)) {
          this.recordIncident(state, incidentKey);
          detections.push({
            chainType: ChainType.SUSPICIOUS_NETWORK_AND_SHELL,
            severity: 'HIGH',
            confidence: 0.65, // Conservative: socket inheritance unproven without fd/parent-child inspection
            title: 'Suspicious Sequence: Outbound network connection followed by interpreter execution (socket inheritance unconfirmed)',
            details: {
              interpreter: interpStage.binary,
              networkPeer: `${netStage.host}:${netStage.port || '?'}`
            },
            sourceEventKeys: [netStage.sourceEventKey, interpStage.sourceEventKey].filter(Boolean),
            stageTimestamps: {
              networkAttempt: netStage.timestamp,
              interpreterSpawn: interpStage.timestamp
            },
            incidentKey
          });
        }
      }
    }

    // C. Capability Check Observed:
    // Requires: PRIVILEGED_CAPABILITY_REQUESTED followed by EXEC_INITIALIZED or INTERPRETER_SPAWNED
    if (state.stages.has('PRIVILEGED_CAPABILITY_REQUESTED') && state.stages.has('INTERPRETER_SPAWNED')) {
      const capStage = state.stages.get('PRIVILEGED_CAPABILITY_REQUESTED');
      const interpStage = state.stages.get('INTERPRETER_SPAWNED');

      if (capStage.timestamp <= interpStage.timestamp) {
        const incidentKey = `${ChainType.CAPABILITY_CHECK_OBSERVED}:${capStage.sourceEventKey || capStage.timestamp}:${interpStage.sourceEventKey || interpStage.timestamp}`;
        if (!state.triggeredIncidents.has(incidentKey)) {
          this.recordIncident(state, incidentKey);
          detections.push({
            chainType: ChainType.CAPABILITY_CHECK_OBSERVED,
            severity: 'MEDIUM',
            confidence: 0.60, // Conservative: cap_capable check is not proof of privilege acquisition
            title: 'Capability Check Observed: Privileged capability requested before interpreter launch',
            details: {
              capability: capStage.capability
            },
            sourceEventKeys: [capStage.sourceEventKey, interpStage.sourceEventKey].filter(Boolean),
            stageTimestamps: {
              capabilityRequested: capStage.timestamp,
              interpreterSpawn: interpStage.timestamp
            },
            incidentKey
          });
        }
      }
    }

    return detections.length > 0 ? detections : null;
  }
}

function isShellOrInterpreter(p) {
  if (!p) return false;
  const lower = p.toLowerCase();
  return (
    lower.endsWith('/sh') ||
    lower.endsWith('/bash') ||
    lower.endsWith('/dash') ||
    lower.endsWith('/zsh') ||
    lower.endsWith('/python') ||
    lower.endsWith('/python3') ||
    lower.endsWith('/perl') ||
    lower.endsWith('/nc') ||
    lower.endsWith('/ncat')
  );
}

function isSensitivePath(p) {
  if (!p) return false;
  return (
    p.startsWith('/etc/shadow') ||
    p.startsWith('/etc/sudoers') ||
    p.includes('/.ssh/') ||
    p.includes('/.aws/') ||
    p.endsWith('/.env') ||
    p.includes('credentials') ||
    p.startsWith('/proc/kcore')
  );
}

module.exports = {
  SequenceDetector,
  ChainType
};
