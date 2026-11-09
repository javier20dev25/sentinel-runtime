'use strict';

const DEFAULT_CORRELATION_WINDOW_MS = 60 * 1000; // 60s sliding window
const DEFAULT_MAX_PROCESSES = 5000;
const DEFAULT_PRUNE_INTERVAL_MS = 5000;
const MAX_STAGES_PER_PROCESS = 32;
const MAX_TRIGGERED_INCIDENTS_PER_PROCESS = 128;
const MAX_EXEC_IDS_PER_PROCESS = 16;

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
    // Map: processKey -> { identity, execIds, parentExecId, stages, triggeredIncidents, firstSeen, lastSeen, exitedAt }
    this.processFsm = new Map();
    // These bounded indices allow exact direct-parent attribution without joining on PID alone.
    this.processesByExec = new Map();
    this.childrenByParentExec = new Map();
  }

  /**
   * Derives a process-instance key that survives execve transitions without
   * allowing PID reuse to merge unrelated processes. Every event still needs
   * host_id + boot_id + exec_id; PID + process_start_time keeps one process
   * together when its exec_id changes after execve.
   */
  processKey(identity) {
    if (!identity || typeof identity !== 'object') return null;
    const host = identity.host_id || identity.hostId;
    const boot = identity.boot_id || identity.bootId;
    const exec = identity.exec_id || identity.execId;

    if (!host || typeof host !== 'string' || host.trim() === '') return null;
    if (!boot || typeof boot !== 'string' || boot.trim() === '') return null;
    if (!exec || typeof exec !== 'string' || exec.trim() === '') return null;

    const pid = identity.pid;
    const start = identity.process_start_time ?? identity.processStartTime ?? identity.start_time ?? identity.startTime;
    const startText = typeof start === 'string' && /^\d{1,20}$/.test(start)
      ? start
      : Number.isSafeInteger(start) && start >= 0 ? String(start) : null;
    if (Number.isSafeInteger(pid) && pid >= 0 && pid <= 0xffffffff && startText !== null) {
      return `${host}:${boot}:pid:${pid}:${startText}`;
    }
    return `${host}:${boot}:exec:${exec}`;
  }

  lineageKey(host, boot, exec) {
    if (![host, boot, exec].every(value => typeof value === 'string' && value.trim() !== '')) return null;
    return `${host}:${boot}:exec:${exec}`;
  }

  addIndex(index, lineage, processKey) {
    if (!lineage) return;
    let keys = index.get(lineage);
    if (!keys) {
      keys = new Set();
      index.set(lineage, keys);
    }
    keys.add(processKey);
  }

  indexIdentity(state, key, identity) {
    const host = identity.host_id || identity.hostId;
    const boot = identity.boot_id || identity.bootId;
    const exec = identity.exec_id || identity.execId;
    const parentExec = identity.parent_exec_id || identity.parentExecId;
    if (typeof exec === 'string' && exec) {
      if (!state.execIds.includes(exec)) {
        state.execIds.push(exec);
        if (state.execIds.length > MAX_EXEC_IDS_PER_PROCESS) state.execIds.shift();
      }
      this.addIndex(this.processesByExec, this.lineageKey(host, boot, exec), key);
    }
    if (!state.parentExecId && typeof parentExec === 'string' && parentExec) {
      state.parentExecId = parentExec;
      state.parentLineageKey = this.lineageKey(host, boot, parentExec);
    }
    if (state.parentLineageKey) this.addIndex(this.childrenByParentExec, state.parentLineageKey, key);
  }

  rebuildIndexes() {
    this.processesByExec.clear();
    this.childrenByParentExec.clear();
    for (const [key, state] of this.processFsm) {
      const host = state.identity.host_id || state.identity.hostId;
      const boot = state.identity.boot_id || state.identity.bootId;
      for (const exec of state.execIds) {
        this.addIndex(this.processesByExec, this.lineageKey(host, boot, exec), key);
      }
      if (state.parentLineageKey) this.addIndex(this.childrenByParentExec, state.parentLineageKey, key);
    }
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
    this.rebuildIndexes();
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

    // Rate-limited or capacity-triggered pruning
    if (now - this.lastPruneTime >= this.pruneIntervalMs || this.processFsm.size >= this.maxProcesses) {
      this.prune(now);
    }

    let state = this.processFsm.get(key);
    if (!state) {
      state = {
        identity,
        execIds: [],
        parentExecId: null,
        parentLineageKey: null,
        stages: new Map(),
        triggeredIncidents: new Set(),
        firstSeen: now,
        lastSeen: now,
        exitedAt: null
      };
      this.processFsm.set(key, state);
    }

    this.indexIdentity(state, key, identity);

    // Exit closes the process but retains only sensitive-file evidence briefly so a
    // directly related parent can be correlated with its later network attempt.
    if (eventType === 'PROCESS_EXIT') {
      state.lastSeen = Math.max(state.lastSeen, now);
      state.exitedAt = now;
      if (!state.stages.has('SENSITIVE_FILE_ACCESSED')) this.processFsm.delete(key);
      this.rebuildIndexes();
      return null;
    }
    if (state.exitedAt !== null) return null;

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
        this.setStage(state, 'SENSITIVE_FILE_ACCESSED', { timestamp: now, path: targetPath, eventType, sourceEventKey });
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
      this.setStage(state, 'NETWORK_OUTBOUND_ATTEMPT', { timestamp: now, host, port, eventType, sourceEventKey });
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
            title: `Suspicious Sequence: ${fileStage.eventType === 'FILE_READ' ? 'sensitive file read activity' : 'sensitive file-open attempt'} followed by network outbound attempt (transfer unconfirmed)`,
            details: {
              fileAccessed: fileStage.path,
              fileAccessType: fileStage.eventType,
              networkTarget: `${netStage.host}:${netStage.port || '?'}`,
              networkEventType: netStage.eventType || null
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
    // Requires: NETWORK_OUTBOUND_ATTEMPT before a later interpreter exec.
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

    const crossProcessDetection = this.detectDirectParentSequence(key, identity, now);
    if (crossProcessDetection) detections.push(crossProcessDetection);

    return detections.length > 0 ? detections : null;
  }

  detectDirectParentSequence(currentKey, identity, now) {
    const host = identity.host_id || identity.hostId;
    const boot = identity.boot_id || identity.bootId;
    const currentExec = identity.exec_id || identity.execId;
    const parentExec = identity.parent_exec_id || identity.parentExecId;
    const relatedKeys = new Set();
    const parentLineage = this.lineageKey(host, boot, parentExec);
    const currentLineage = this.lineageKey(host, boot, currentExec);

    // If this is the parent process, inspect only children whose sensor supplied
    // this exact parent_exec_id on the same host boot.
    for (const childKey of this.childrenByParentExec.get(currentLineage) || []) relatedKeys.add(childKey);
    // If this is a child, inspect only its exact parent_exec_id on the same host boot.
    for (const parentKey of this.processesByExec.get(parentLineage) || []) relatedKeys.add(parentKey);
    relatedKeys.delete(currentKey);

    const current = this.processFsm.get(currentKey);
    if (!current) return null;
    const currentFile = current.stages.get('SENSITIVE_FILE_ACCESSED');
    const currentNetwork = current.stages.get('NETWORK_OUTBOUND_ATTEMPT');

    for (const relatedKey of relatedKeys) {
      const related = this.processFsm.get(relatedKey);
      if (!related) continue;
      const relatedFile = related.stages.get('SENSITIVE_FILE_ACCESSED');
      const relatedNetwork = related.stages.get('NETWORK_OUTBOUND_ATTEMPT');
      const pairs = [
        { fileStage: currentFile, fileState: current, netStage: relatedNetwork, netState: related },
        { fileStage: relatedFile, fileState: related, netStage: currentNetwork, netState: current }
      ];
      const pair = pairs.find(candidate => candidate.fileStage && candidate.netStage &&
        candidate.fileState !== candidate.netState && candidate.fileStage.timestamp < candidate.netStage.timestamp &&
        candidate.netStage.timestamp - candidate.fileStage.timestamp <= this.windowMs &&
        now - Math.max(candidate.fileStage.timestamp, candidate.netStage.timestamp) <= this.windowMs);
      if (!pair) continue;
      const { fileStage, fileState, netStage, netState } = pair;
      const fileIdentity = fileState.identity;
      const netIdentity = netState.identity;
      const incidentKey = `${ChainType.SUSPICIOUS_EXFILTRATION}:DIRECT_PARENT:${fileStage.sourceEventKey || fileStage.timestamp}:${netStage.sourceEventKey || netStage.timestamp}`;
      if (fileState.triggeredIncidents.has(incidentKey) || netState.triggeredIncidents.has(incidentKey)) continue;
      this.recordIncident(fileState, incidentKey);
      this.recordIncident(netState, incidentKey);

      return {
        chainType: ChainType.SUSPICIOUS_EXFILTRATION,
        severity: 'HIGH',
        confidence: 0.55,
        title: 'Suspicious direct parent-child sequence: child sensitive file-open attempt followed by parent network attempt (content read and transfer unconfirmed)',
        details: {
          fileAccessed: fileStage.path,
          fileAccessType: fileStage.eventType,
          fileProcess: { pid: fileIdentity.pid ?? null, execId: fileIdentity.exec_id || fileIdentity.execId || null },
          networkTarget: `${netStage.host}:${netStage.port || '?'}`,
          networkEventType: netStage.eventType || null,
          networkProcess: { pid: netIdentity.pid ?? null, execId: netIdentity.exec_id || netIdentity.execId || null },
          attribution: 'DIRECT_PARENT_EXEC_ID_AND_HOST_BOOT'
        },
        sourceEventKeys: [fileStage.sourceEventKey, netStage.sourceEventKey].filter(Boolean),
        stageTimestamps: { fileAccess: fileStage.timestamp, networkAttempt: netStage.timestamp },
        attribution: {
          relationship: 'DIRECT_PARENT_CHILD',
          fileProcessParentExecId: fileState.parentExecId || null,
          networkProcessExecId: netIdentity.exec_id || netIdentity.execId || null
        },
        incidentKey
      };
    }
    return null;
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
  if (typeof p !== 'string' || p === '') return false;
  const normalized = p.replace(/^\/proc\/(?:self|thread-self|\d+)\/root(?=\/|$)/, '');
  return (
    normalized.startsWith('/etc/shadow') ||
    normalized.startsWith('/etc/sudoers') ||
    normalized.includes('/.ssh/') ||
    normalized.includes('/.aws/') ||
    normalized.endsWith('/.env') ||
    normalized.includes('credentials') ||
    normalized.startsWith('/proc/kcore')
  );
}

module.exports = {
  SequenceDetector,
  ChainType
};
