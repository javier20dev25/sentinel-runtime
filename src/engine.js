'use strict';

const { performance } = require('node:perf_hooks');
const { EventType, ThreatLevel, RecommendationAction } = require('./types');

const DEFAULT_WINDOW_MS = 5 * 60 * 1000;
const DEFAULT_MAX_CHAINS = 10000;
const DEFAULT_MAX_EVENT_IDS = 50000;
const ANALYZED_EVENT_TYPES = new Set([
  EventType.PROCESS_EXEC,
  EventType.PROCESS_EXIT,
  EventType.FILE_READ,
  EventType.FILE_OPEN_ATTEMPT,
  EventType.NETWORK_CONNECT,
  EventType.NETWORK_CONNECT_ATTEMPT,
  EventType.NETWORK_SEND_ATTEMPT,
  EventType.NETWORK_SEND_RESULT
]);

/**
 * Deterministic, observe-only correlation engine. It recommends telemetry
 * responses but never sends process signals or changes host policy.
 */
class BehavioralSequenceEngine {
  constructor(options = {}) {
    this.profiles = new Map();
    this.processChains = new Map();
    this.eventIds = new Map();
    this.windowMs = positiveInt(options.windowMs, DEFAULT_WINDOW_MS);
    this.maxChains = positiveInt(options.maxChains, DEFAULT_MAX_CHAINS);
    this.maxEventIds = positiveInt(options.maxEventIds, DEFAULT_MAX_EVENT_IDS);
    this.onDecision = options.onDecision || (() => {});
    this.clock = options.clock || (() => performance.now());
    this.lastIngestTime = -Infinity;
  }

  registerProfile(workloadId, profile) {
    if (typeof workloadId !== 'string' || workloadId.length === 0) throw new TypeError('workloadId is required');
    if (!profile || typeof profile.isBinaryAllowed !== 'function') throw new TypeError('profile must be a WorkloadProfile');
    this.profiles.set(workloadId, profile);
  }

  processEvent(event) {
    if (!event || typeof event !== 'object') throw new TypeError('event must be an object');
    const clockValue = this.clock();
    if (!Number.isFinite(clockValue)) throw new TypeError('Engine clock must return a finite monotonic number');
    const ingestTime = Math.max(this.lastIngestTime, clockValue);
    this.lastIngestTime = ingestTime;
    const identity = readIdentity(event);
    const workloadId = event.workloadId || event.workload_id || event.workloadContext?.container_id || 'unassigned';
    const eventType = event.eventType || event.event_type;
    const timestamp = normalizeTimestamp(event.timestamp ?? event.timestamps?.source_timestamp, this.clock());
    const data = event.data || event.payload || {};
    const eventId = event.sourceEventKey || event.source_event_key || event.eventId || event.event_id || null;

    this.prune(ingestTime);
    if (eventId && this.eventIds.has(eventId)) {
      return this.decision(event, identity, workloadId, ThreatLevel.UNASSESSED, RecommendationAction.RECORD_ONLY,
        'Duplicate source event ignored', { eventClass: 'DUPLICATE_EVENT', enforcementMode: 'OBSERVE_ONLY' });
    }
    if (eventId) this.rememberEvent(eventId, ingestTime);

    if (!ANALYZED_EVENT_TYPES.has(eventType)) {
      return this.decision(event, identity, workloadId, ThreatLevel.UNASSESSED,
        RecommendationAction.RECORD_ONLY, `Event family is not analyzed by this engine: ${String(eventType)}`,
        { eventClass: 'UNASSESSED', enforcementMode: 'OBSERVE_ONLY' });
    }

    if (!identity) {
      return this.decision(event, null, workloadId, ThreatLevel.ELEVATED_WATCH,
        RecommendationAction.REQUEST_MORE_TELEMETRY, 'Stable process identity unavailable; event not correlated');
    }

    const key = processKey(identity);
    if (eventType === EventType.PROCESS_EXIT) {
      this.processChains.delete(key);
      return this.decision(event, identity, workloadId, ThreatLevel.UNASSESSED,
        RecommendationAction.RECORD_ONLY, 'Process exit observed; causal state closed, exit behavior is not assessed');
    }

    const profile = this.profiles.get(workloadId);
    if (!profile) {
      return this.decision(event, identity, workloadId, ThreatLevel.UNASSESSED,
        RecommendationAction.RECORD_ONLY, 'No workload profile; baseline assessment is unavailable',
        { eventClass: 'UNASSESSED', enforcementMode: 'OBSERVE_ONLY' });
    }

    let chain = this.processChains.get(key);
    if (!chain) {
      chain = { identity, workloadId, stages: new Map(), lastSeen: timestamp, lastSeenIngest: ingestTime, firstSeen: timestamp, eventCount: 0 };
      this.processChains.set(key, chain);
    }
    chain.lastSeen = Math.max(chain.lastSeen, timestamp);
    chain.lastSeenIngest = ingestTime;
    chain.eventCount++;
    this.processChains.delete(key);
    this.processChains.set(key, chain);
    for (const [name, seenAt] of chain.stages) {
      if (ingestTime - seenAt > this.windowMs) chain.stages.delete(name);
    }

    let level = ThreatLevel.NORMAL;
    let reason = 'Behavior matches configured profile';
    let stage = null;
    let eventClass = eventType;

    if (eventType === EventType.PROCESS_EXEC) {
      const binary = data.binary || data.executable_path || event.processIdentity?.executablePath || event.process_identity?.executable_path || '';
      const digest = data.executable_digest?.value || data.executableDigest || null;
      if (!profile.isBinaryAllowed(binary, digest)) {
        stage = 'UNEXPECTED_EXECUTABLE';
        level = ThreatLevel.ELEVATED_WATCH;
        reason = `Executable is not in the exact-path or digest allowlist: ${binary || '(missing path)'}`;
      }
    } else if (eventType === EventType.FILE_READ || eventType === EventType.FILE_OPEN_ATTEMPT) {
      const targetPath = data.path || data.file_path || data.filename || '';
      if (profile.isPathRestricted(targetPath)) {
        stage = 'RESTRICTED_FILE_ACCESS';
        level = ThreatLevel.SUSPICIOUS;
        reason = `Restricted or untrusted file path observed: ${targetPath || '(missing path)'}`;
      }
    } else if (eventType === EventType.NETWORK_CONNECT || eventType === EventType.NETWORK_CONNECT_ATTEMPT) {
      const host = data.host || data.destination_ip || data.destination_host || '';
      const port = data.port ?? data.destination_port;
      if (!profile.isNetworkDestinationAllowed(host, port)) {
        stage = 'NETWORK_CONNECT_ATTEMPT';
        level = ThreatLevel.SUSPICIOUS;
        reason = `Connection attempt is outside the configured destination allowlist: ${host || '(missing host)'}:${port ?? '?'}`;
      } else {
        eventClass = 'NETWORK_DESTINATION_ALLOWED';
      }
    } else if (eventType === EventType.NETWORK_SEND_ATTEMPT) {
      const host = data.host || data.destination_ip || data.destination_host || '';
      const port = data.port ?? data.destination_port;
      if (!profile.isNetworkDestinationAllowed(host, port)) {
        stage = 'UNAUTHORIZED_NETWORK_SEND_ATTEMPT';
        level = ThreatLevel.SUSPICIOUS;
        reason = `Send attempt is outside the configured destination allowlist: ${host || '(missing host)'}:${port ?? '?'}`;
      } else {
        eventClass = 'OUTBOUND_ATTEMPT';
        reason = 'Outbound send was attempted; kernel acceptance and peer receipt are not established';
      }
    } else if (eventType === EventType.NETWORK_SEND_RESULT) {
      const bytes = toNonNegativeBigInt(data.return_code ?? data.bytes_accepted_by_kernel ?? 0);
      if (bytes > 0n) {
        const host = data.host || data.destination_ip || data.destination_host || '';
        const port = data.port ?? data.destination_port;
        if (!profile.isNetworkDestinationAllowed(host, port)) {
          stage = 'UNAUTHORIZED_NETWORK_SEND';
          level = ThreatLevel.SUSPICIOUS;
          reason = `Kernel accepted bytes for a destination outside the configured allowlist: ${host || '(missing host)'}:${port ?? '?'}`;
          eventClass = 'OUTBOUND_ACTIVITY_OBSERVED';
        } else {
          stage = 'LOCAL_STACK_ACCEPTED_BYTES';
          reason = 'Bytes were accepted by the local kernel networking stack; peer receipt is not established';
          eventClass = 'OUTBOUND_ACTIVITY_OBSERVED';
        }
      }
    }

    if (stage) chain.stages.set(stage, ingestTime);
    const stages = new Set(chain.stages.keys());
    if (stages.has('UNEXPECTED_EXECUTABLE') && stages.has('RESTRICTED_FILE_ACCESS') && stages.has('LOCAL_STACK_ACCEPTED_BYTES')) {
      level = Math.max(level, ThreatLevel.SUSPICIOUS);
      reason = 'Correlated suspicious process, restricted file access, and local network-stack activity; exfiltration is not proven';
      eventClass = 'SUSPICIOUS_SEQUENCE';
    }

    return this.decision(event, identity, workloadId, level,
      level === ThreatLevel.NORMAL ? RecommendationAction.RECORD_ONLY : RecommendationAction.REQUEST_MORE_TELEMETRY,
      reason, { eventClass, stages: [...stages], correlationWindowMs: this.windowMs, enforcementMode: 'OBSERVE_ONLY' });
  }

  prune(now) {
    while (this.processChains.size) {
      const [key, chain] = this.processChains.entries().next().value;
      if (now - chain.lastSeenIngest <= this.windowMs) break;
      this.processChains.delete(key);
    }
    while (this.eventIds.size) {
      const [key, seenAt] = this.eventIds.entries().next().value;
      if (now - seenAt <= this.windowMs) break;
      this.eventIds.delete(key);
    }
    while (this.processChains.size > this.maxChains) this.processChains.delete(this.processChains.keys().next().value);
    while (this.eventIds.size > this.maxEventIds) this.eventIds.delete(this.eventIds.keys().next().value);
  }

  rememberEvent(eventId, timestamp) {
    this.eventIds.set(String(eventId), timestamp);
    while (this.eventIds.size > this.maxEventIds) this.eventIds.delete(this.eventIds.keys().next().value);
  }

  decision(event, identity, workloadId, threatLevel, action, reason, extra = {}) {
    const result = {
      workloadId,
      pid: identity?.pid ?? readPid(event),
      processIdentity: identity,
      threatLevel,
      action,
      reason,
      enforcementMode: 'OBSERVE_ONLY',
      ...extra
    };
    if (action !== RecommendationAction.RECORD_ONLY) this.onDecision(result);
    return result;
  }
}

function readIdentity(event) {
  const process = event.processIdentity || event.process_identity || {};
  const host = event.hostIdentity || event.host_identity || {};
  const hostId = event.hostId || host.hostId || host.host_id;
  const bootId = event.bootId || host.bootId || host.boot_id;
  const execId = event.execId || process.execId || process.exec_id;
  if (![hostId, bootId, execId].every(value => typeof value === 'string' && value.length > 0)) return null;
  const rawPid = event.pid ?? process.pid;
  const pid = Number.isInteger(rawPid) && rawPid >= 0 ? rawPid : null;
  return { hostId, bootId, execId, pid };
}

function readPid(event) {
  const value = event.pid ?? event.processIdentity?.pid ?? event.process_identity?.pid;
  return Number.isInteger(value) && value >= 0 ? value : null;
}

function processKey(identity) {
  return JSON.stringify([identity.hostId, identity.bootId, identity.execId]);
}

function normalizeTimestamp(value, fallback) {
  if (typeof value === 'bigint') return Number(value / 1000000n);
  if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) {
    const parsed = BigInt(value);
    return Number(parsed > 100000000000000n ? parsed / 1000000n : parsed);
  }
  if (Number.isFinite(value)) return value;
  return fallback;
}

function toNonNegativeBigInt(value) {
  try {
    if (typeof value === 'bigint') return value >= 0n ? value : 0n;
    if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0 ? BigInt(value) : 0n;
    if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  } catch { /* Invalid byte counts are treated as unobserved. */ }
  return 0n;
}

function positiveInt(value, fallback) {
  return Number.isSafeInteger(value) && value > 0 ? value : fallback;
}

module.exports = { BehavioralSequenceEngine, processKey, readIdentity };
