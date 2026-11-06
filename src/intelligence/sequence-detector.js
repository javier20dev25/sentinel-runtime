'use strict';

const DEFAULT_CORRELATION_WINDOW_MS = 60 * 1000; // 60s sliding window

const ChainType = Object.freeze({
  EXFILTRATION: 'EXFILTRATION_KILL_CHAIN',
  REVERSE_SHELL: 'REVERSE_SHELL_CHAIN',
  PRIVILEGE_ESCALATION: 'PRIVILEGE_ESCALATION_CHAIN'
});

/**
 * Real-time Finite State Machine (FSM) & Complex Event Processing (CEP) engine.
 * Correlates multi-step attack sequences within sliding temporal windows.
 */
class SequenceDetector {
  constructor(options = {}) {
    this.windowMs = options.windowMs || DEFAULT_CORRELATION_WINDOW_MS;
    // Map: processKey -> { stages: Map(stageName -> { timestamp, metadata }), firstSeen, lastSeen }
    this.processFsm = new Map();
  }

  processKey(identity) {
    if (!identity) return null;
    const host = identity.host_id || identity.hostId || 'local';
    const boot = identity.boot_id || identity.bootId || 'default';
    const exec = identity.exec_id || identity.execId || `pid:${identity.pid || 0}`;
    return `${host}:${boot}:${exec}`;
  }

  prune(now) {
    for (const [key, state] of this.processFsm.entries()) {
      if (now - state.lastSeen > this.windowMs) {
        this.processFsm.delete(key);
      } else {
        // Prune stale individual stages
        for (const [stage, data] of state.stages.entries()) {
          if (now - data.timestamp > this.windowMs) {
            state.stages.delete(stage);
          }
        }
      }
    }
  }

  /**
   * Evaluates an observed event and updates the process FSM state.
   * Returns detected kill-chain transitions if triggered.
   */
  evaluate(event, identity, now = Date.now()) {
    const key = this.processKey(identity);
    if (!key) return null;

    this.prune(now);

    let state = this.processFsm.get(key);
    if (!state) {
      state = {
        identity,
        stages: new Map(),
        firstSeen: now,
        lastSeen: now
      };
      this.processFsm.set(key, state);
    }
    state.lastSeen = now;

    const eventType = event.eventType || event.event_type;
    const data = event.data || event.payload || {};
    const detections = [];

    // 1. Process Exec Stage
    if (eventType === 'PROCESS_EXEC') {
      const binary = data.binary || data.executable_path || '';
      state.stages.set('EXEC_INITIALIZED', { timestamp: now, binary });
      if (isShellOrInterpreter(binary)) {
        state.stages.set('INTERPRETER_SPAWNED', { timestamp: now, binary });
      }
    }

    // 2. Sensitive File Access Stage
    if (eventType === 'FILE_READ' || eventType === 'FILE_OPEN_ATTEMPT') {
      const targetPath = data.path || data.file_path || data.filename || '';
      if (isSensitivePath(targetPath)) {
        state.stages.set('SENSITIVE_FILE_ACCESSED', { timestamp: now, path: targetPath });
      }
    }

    // 3. Network Outbound Stage
    if (
      eventType === 'NETWORK_CONNECT' ||
      eventType === 'NETWORK_CONNECT_ATTEMPT' ||
      eventType === 'NETWORK_SEND_RESULT' ||
      eventType === 'NETWORK_SEND_ATTEMPT'
    ) {
      const host = data.host || data.destination_ip || data.destination_host || '';
      const port = data.port ?? data.destination_port;
      state.stages.set('NETWORK_OUTBOUND_ATTEMPT', { timestamp: now, host, port });
    }

    // 4. Capability Check Stage (Privilege Escalation)
    if (eventType === 'CAPABILITY_CHECK' || event.process_kprobe?.function_name === 'cap_capable') {
      const capName = data.capability_name || data.capability || '';
      if (capName === 'CAP_SETUID' || capName === 'CAP_SYS_ADMIN' || capName === 'CAP_NET_RAW') {
        state.stages.set('PRIVILEGED_CAPABILITY_REQUESTED', { timestamp: now, capability: capName });
      }
    }

    // --- FSM Chain Evaluations ---

    // A. Exfiltration Kill Chain:
    // SENSITIVE_FILE_ACCESSED -> NETWORK_OUTBOUND_ATTEMPT within window
    if (state.stages.has('SENSITIVE_FILE_ACCESSED') && state.stages.has('NETWORK_OUTBOUND_ATTEMPT')) {
      const fileStage = state.stages.get('SENSITIVE_FILE_ACCESSED');
      const netStage = state.stages.get('NETWORK_OUTBOUND_ATTEMPT');
      detections.push({
        chainType: ChainType.EXFILTRATION,
        severity: 'CRITICAL',
        confidence: 0.95,
        title: 'Exfiltration Sequence Detected: Sensitive file read followed by network dispatch',
        details: {
          fileAccessed: fileStage.path,
          networkTarget: `${netStage.host}:${netStage.port || '?'}`
        }
      });
    }

    // B. Reverse Shell Chain:
    // NETWORK_OUTBOUND_ATTEMPT -> INTERPRETER_SPAWNED
    if (state.stages.has('NETWORK_OUTBOUND_ATTEMPT') && state.stages.has('INTERPRETER_SPAWNED')) {
      const interpStage = state.stages.get('INTERPRETER_SPAWNED');
      const netStage = state.stages.get('NETWORK_OUTBOUND_ATTEMPT');
      detections.push({
        chainType: ChainType.REVERSE_SHELL,
        severity: 'CRITICAL',
        confidence: 0.90,
        title: 'Reverse Shell Sequence: Interactive interpreter attached to network socket',
        details: {
          interpreter: interpStage.binary,
          networkPeer: `${netStage.host}:${netStage.port || '?'}`
        }
      });
    }

    // C. Privilege Escalation Chain:
    // PRIVILEGED_CAPABILITY_REQUESTED -> SENSITIVE_FILE_ACCESSED or INTERPRETER_SPAWNED
    if (state.stages.has('PRIVILEGED_CAPABILITY_REQUESTED') && state.stages.has('INTERPRETER_SPAWNED')) {
      const capStage = state.stages.get('PRIVILEGED_CAPABILITY_REQUESTED');
      detections.push({
        chainType: ChainType.PRIVILEGE_ESCALATION,
        severity: 'CRITICAL',
        confidence: 0.88,
        title: 'Privilege Escalation Sequence: Root capability checked before shell spawn',
        details: {
          capability: capStage.capability
        }
      });
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