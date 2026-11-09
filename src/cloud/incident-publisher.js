'use strict';

const crypto = require('node:crypto');
const { canonicalJson } = require('../contracts/canonical-json');

const MAX_CORRELATED_EVENTS = 32;
const MAX_ENVELOPE_BYTES = 28 * 1024;
const MAX_COMMAND_DISPLAY_CHARS = 2048;
const SENSITIVE_KEY = /(^|[_-])(authorization|token|password|passwd|secret|api[_-]?key|private[_-]?key|command[_-]?line|argv|arguments?|process[_-]?args|environment|env|stdin|stdout|stderr|output|payload[_-]?bytes)([_-]|$)/i;

function severityFor(value) {
  if (typeof value === 'number') {
    if (value >= 5) return 'CRITICAL';
    if (value >= 3) return 'HIGH';
    if (value >= 2) return 'MEDIUM';
    return null;
  }
  const normalized = String(value || '').toUpperCase();
  if (['CRITICAL', 'CRITICAL_BREACH'].includes(normalized)) return 'CRITICAL';
  if (['HIGH', 'SUSPICIOUS', 'CONFIRMED_VIOLATION'].includes(normalized)) return 'HIGH';
  if (['MEDIUM', 'ELEVATED_WATCH'].includes(normalized)) return 'MEDIUM';
  return null;
}

function isIncidentDecision(decision) {
  if (!decision || typeof decision !== 'object') return false;
  if (severityFor(decision.threatLevel ?? decision.threat_level)) return true;
  return Boolean(decision.deterministicDeviation || decision.deterministic_deviation ||
    decision.sequenceDetections?.length || decision.sequence_detections?.length);
}

function redact(value, depth = 0) {
  if (depth > 8) return '[DEPTH_LIMIT]';
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'string') return value.slice(0, 2048);
  if (Array.isArray(value)) return value.slice(0, 64).map(item => redact(item, depth + 1));
  if (!value || typeof value !== 'object') return null;
  const output = Object.create(null);
  for (const [key, item] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) continue;
    output[key] = redact(item, depth + 1);
  }
  return output;
}

function commandDisplay(event) {
  const eventType = String(event?.event_type || event?.eventType || '').toUpperCase();
  if (eventType !== 'PROCESS_EXEC') return null;
  const identity = event.process_identity || event.processIdentity || {};
  const payload = event.payload || event.data || {};
  const binary = typeof identity.executable_path === 'string' ? identity.executable_path
    : typeof identity.binary_path === 'string' ? identity.binary_path
      : typeof payload.binary === 'string' ? payload.binary : '';
  const argumentValue = typeof payload.arguments_raw === 'string' ? payload.arguments_raw
    : Array.isArray(payload.argv) ? payload.argv.filter(value => typeof value === 'string').slice(0, 64).join(' ')
      : typeof identity.arguments_raw === 'string' ? identity.arguments_raw : '';
  const raw = [binary, argumentValue].filter(Boolean).join(' ').slice(0, MAX_COMMAND_DISPLAY_CHARS * 4);
  const result = redactCommandText(raw);
  const executable = binary ? redactCommandText(binary).text.slice(0, 512) : null;
  return {
    executable_path: executable || null,
    command_display: result.text || null,
    arguments_capture_status: typeof payload.arguments_capture_status === 'string'
      ? payload.arguments_capture_status.slice(0, 48) : 'NOT_SUPPLIED',
    redacted_item_count: result.redactedItemCount,
    truncated: result.truncated
  };
}

function redactCommandText(value) {
  let text = String(value || '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  let redactedItemCount = 0;
  const patterns = [
    { regex: /((?:^|\s)--?(?:token|access[-_]?token|api[-_]?key|password|passwd|secret|client[-_]?secret|access[-_]?key|private[-_]?key|authorization|credential|user|username)(?:=|\s+))(?:(?:"[^"]*")|(?:'[^']*')|[^\s]+)/gi, replace: '$1[REDACTED]' },
    { regex: /((?:^|\s)(?:-u|--user)(?:=|\s+))(?:(?:"[^"]*")|(?:'[^']*')|[^\s]+)/gi, replace: '$1[REDACTED]' },
    { regex: /((?:^|\s)[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CLIENT_SECRET)[A-Z0-9_]*=)(?:(?:"[^"]*")|(?:'[^']*')|[^\s]+)/gi, replace: '$1[REDACTED]' },
    { regex: /((?:authorization\s*[:=]\s*)?bearer\s+)[A-Za-z0-9._~+/-]{8,}/gi, replace: '$1[REDACTED]' },
    { regex: /(https?:\/\/)[^/\s:@]+:[^@\s/]+(@)/gi, replace: '$1[REDACTED]$2' },
    { regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, replace: '[REDACTED_JWT]' },
    { regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replace: '[REDACTED_AWS_KEY]' },
    { regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,})\b/g, replace: '[REDACTED_TOKEN]' },
    { regex: /((?:["']?(?:token|password|passwd|secret|api[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']?))([^"'&,\s}]+)/gi, replace: '$1[REDACTED]' }
  ];
  for (const pattern of patterns) {
    text = text.replace(pattern.regex, (...args) => {
      redactedItemCount++;
      return args[0].replace(pattern.regex, pattern.replace);
    });
  }
  text = text.replace(/(\/home\/)[^/\s]+/g, '$1<user>').replace(/(\/mnt\/c\/Users\/)[^/\s]+/gi, '$1<user>');
  const truncated = text.length > MAX_COMMAND_DISPLAY_CHARS;
  if (truncated) text = `${text.slice(0, MAX_COMMAND_DISPLAY_CHARS - 1)}…`;
  return { text, redactedItemCount, truncated };
}

function readRule(decision, event) {
  const sequence = decision.sequenceDetections?.[0] || decision.sequence_detections?.[0];
  const deviation = decision.deterministicDeviation || decision.deterministic_deviation;
  const candidate = sequence?.chainType || sequence?.chain_type || sequence?.rule || deviation?.rule || decision.eventClass;
  return typeof candidate === 'string' && candidate.length <= 128 ? candidate :
    (typeof event?.event_type === 'string' ? `RUNTIME_${event.event_type}` : 'RUNTIME_BEHAVIORAL_SIGNAL');
}

function eventKeysFor(decision, primaryKey) {
  const candidateRefs = decision.evidenceReferences || decision.evidence_references;
  const refs = Array.isArray(candidateRefs) ? candidateRefs : [];
  const candidateDetections = decision.sequenceDetections || decision.sequence_detections;
  const detections = Array.isArray(candidateDetections) ? candidateDetections : [];
  const detectedRefs = detections.flatMap(item => item?.sourceEventKeys || item?.source_event_keys || []);
  return [...new Set([primaryKey, ...refs, ...detectedRefs].filter(key => typeof key === 'string' && /^[a-f0-9]{64}$/i.test(key)))].slice(0, MAX_CORRELATED_EVENTS);
}

function containmentStatus(decision) {
  const outcome = decision.containmentOutcome || decision.containment_outcome;
  if (!outcome) return { level: 'R0', status: 'OBSERVED', outcome: null };
  const requested = String(outcome.requestedLevel || outcome.requested_level || 'OBSERVE_ONLY');
  const level = /NETWORK_ISOLATE/.test(requested) ? 'R4' : /PROCESS_TERMINATE/.test(requested) ? 'R3' : /PROCESS_SUSPEND/.test(requested) ? 'R2' : 'R1';
  const status = ({ PLANNED: 'ACTION_PLANNED', SKIPPED_DRY_RUN: 'ACTION_PLANNED', EXECUTED: 'ACTION_DISPATCHED', FAILED: 'ACTION_FAILED', BLOCKED_UNSAFE: 'ACTION_FAILED' })[outcome.status] || 'ACTION_OUTCOME_UNKNOWN';
  return { level, status, outcome: redact(outcome) };
}

function buildRuntimeIncidentEnvelope({ entry, records, hostId, bootId, observabilityState = 'UNKNOWN' }) {
  const decision = entry.decision || {};
  const primaryEvent = entry.event || {};
  const primaryKey = primaryEvent.source_event_key || primaryEvent.sourceEventKey;
  const trigger = records.find(record => record.event?.source_event_key === primaryKey) || records[records.length - 1];
  if (!trigger || !isIncidentDecision(decision)) return null;

  const eventKeys = eventKeysFor(decision, primaryKey);
  const evidenceRecords = records.filter(record => eventKeys.includes(record.event?.source_event_key));
  const evidenceKey = evidenceRecords[evidenceRecords.length - 1]?.record_hash || trigger.record_hash;
  const ruleId = readRule(decision, trigger.event);
  const sourceIdentity = trigger.event?.process_identity || trigger.event?.processIdentity || {};
  const actorId = typeof sourceIdentity.exec_id === 'string' ? `exec:${sourceIdentity.exec_id}` :
    (Number.isInteger(sourceIdentity.pid) ? `pid:${sourceIdentity.pid}` : 'unknown');
  const idempotencyKey = crypto.createHash('sha256')
    .update('SENTINEL-RUNTIME-INCIDENT-V1\0', 'utf8')
    .update(hostId, 'utf8').update('\0').update(bootId, 'utf8').update('\0')
    .update(ruleId, 'utf8').update('\0').update([...eventKeys].sort().join('\0'), 'utf8')
    .digest('hex');
  const containment = containmentStatus(decision);
  const confidence = Number(decision.confidence);
  const envelope = {
    contract_version: 'sentinel-runtime-incident-v1',
    analysis_status: 'NOT_REQUESTED',
    source: {
      product: 'sentinel-runtime',
      provider: trigger.event?.sensor_metadata?.provider || trigger.event?.provider || 'tetragon',
      event_keys: eventKeys,
      observed_at: trigger.event?.timestamps?.source_timestamp || trigger.event?.timestamp || null
    },
    observations: evidenceRecords.map(record => {
      const executionContext = commandDisplay(record.event || {});
      return {
        sequence: record.sequence,
        event: redact(record.event),
        ...(executionContext ? { execution_context: executionContext } : {}),
        ledger_proof: {
          algorithm: 'SENTINEL-EVIDENCE-LEDGER-V1/SHA-256',
          previous_hash: record.previous_hash,
          record_hash: record.record_hash,
          verification_status: 'AGENT_REPORTED_NOT_CLOUD_VERIFIED',
          external_anchor: false
        }
      };
    }),
    decision: {
      producer: 'sentinel-runtime',
      severity: severityFor(decision.threatLevel ?? decision.threat_level),
      confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : null,
      rationale: String(decision.reason || decision.title || 'Runtime behavioral signal').slice(0, 1024),
      matched_rules: [...new Set([ruleId, ...(Array.isArray(decision.triggeredRules || decision.triggered_rules) ? (decision.triggeredRules || decision.triggered_rules) : [])])].slice(0, 32),
      requested_action: decision.requestedAction || decision.action || 'RECORD_ONLY',
      safety_gates: (Array.isArray(decision.safetyGatingReasons || decision.safety_gating_reasons) ? (decision.safetyGatingReasons || decision.safety_gating_reasons) : []).slice(0, 32),
      observability_state: observabilityState
    },
    containment: {
      level: containment.level,
      status: containment.status,
      requested_action: containment.outcome?.requestedLevel || containment.outcome?.requested_level || null,
      actual_action: containment.outcome?.outcome?.actionTaken || containment.outcome?.outcome?.action_taken || null,
      result_record_hash: containment.outcome?.resultRecordHash || containment.outcome?.result_record_hash || null,
      details: containment.outcome
    },
    evidence: {
      record_hash: evidenceKey,
      records: evidenceRecords.map(record => ({ sequence: record.sequence, previous_hash: record.previous_hash, record_hash: record.record_hash })),
      verification_status: 'AGENT_REPORTED_NOT_CLOUD_VERIFIED',
      external_anchor: false
    }
  };

  while (Buffer.byteLength(canonicalJson(envelope), 'utf8') > MAX_ENVELOPE_BYTES && envelope.observations.length > 1) {
    envelope.observations.shift();
    envelope.source.event_keys.shift();
    envelope.evidence.records.shift();
    envelope.evidence.truncated = true;
  }
  if (Buffer.byteLength(canonicalJson(envelope), 'utf8') > MAX_ENVELOPE_BYTES) {
    const only = envelope.observations[0];
    const event = only?.event || {};
    only.event = {
      event_type: event.event_type || null,
      source_event_key: event.source_event_key || null,
      timestamps: event.timestamps || null,
      process_identity: event.process_identity || null
    };
    envelope.evidence.truncated = true;
  }

  return {
    incident_id: `inc_${idempotencyKey}`,
    idempotency_key: idempotencyKey,
    actor_type: 'WORKLOAD',
    actor_id: actorId,
    rule_id: ruleId,
    severity: severityFor(decision.threatLevel ?? decision.threat_level) || 'MEDIUM',
    containment_level: containment.level,
    containment_status: containment.status,
    evidence_record_hash: evidenceKey,
    sanitized_envelope: envelope
  };
}

class RuntimeIncidentPublisher {
  constructor({ ledger, client, hostId, bootId, onStatus = () => {}, retryBaseMs = 1000, retryMaxMs = 300000 }) {
    if (!ledger || typeof ledger.append !== 'function' || typeof ledger.getCloudDeliveryRecords !== 'function') throw new TypeError('Evidence ledger is required for durable Cloud delivery');
    if (!client || typeof client.sendIncidentEnvelope !== 'function') throw new TypeError('Cloud client is required');
    if (typeof hostId !== 'string' || !hostId || typeof bootId !== 'string' || !bootId) throw new TypeError('Trusted hostId and bootId are required');
    this.ledger = ledger;
    this.client = client;
    this.hostId = hostId;
    this.bootId = bootId;
    this.onStatus = onStatus;
    this.retryBaseMs = Number.isSafeInteger(retryBaseMs) && retryBaseMs > 0 ? Math.min(retryBaseMs, 60000) : 1000;
    this.retryMaxMs = Number.isSafeInteger(retryMaxMs) && retryMaxMs >= this.retryBaseMs ? Math.min(retryMaxMs, 1800000) : 300000;
    this.states = new Map();
    this.busy = false;
    this.retryTimer = null;
    this.restoreState();
  }

  restoreState() {
    for (const row of this.ledger.getCloudDeliveryRecords({ limit: 20000 })) {
      let payload;
      try { payload = JSON.parse(row.payload_json); } catch { continue; }
      if (!payload?.incident_id) continue;
      const current = this.states.get(payload.incident_id) || {};
      if (row.record_type === 'cloud_delivery_ack') {
        this.states.set(payload.incident_id, { ...current, status: 'ACKNOWLEDGED' });
      } else if (row.record_type === 'cloud_delivery_pending') {
        this.states.set(payload.incident_id, { status: 'PENDING', envelope: payload.envelope, retryCount: 0, nextAttemptAt: 0 });
      } else if (row.record_type === 'cloud_delivery_retry' && current.status === 'PENDING') {
        this.states.set(payload.incident_id, {
          ...current,
          retryCount: Number.isSafeInteger(payload.retry_count) ? payload.retry_count : current.retryCount,
          nextAttemptAt: Number.isFinite(Date.parse(payload.next_attempt_at)) ? Date.parse(payload.next_attempt_at) : 0
        });
      }
    }
  }

  consider(entry, observabilityState) {
    if (!isIncidentDecision(entry?.decision)) return false;
    const primaryKey = entry?.event?.source_event_key || entry?.event?.sourceEventKey;
    if (typeof primaryKey !== 'string' || !/^[a-f0-9]{64}$/i.test(primaryKey)) return false;
    const keys = eventKeysFor(entry.decision, primaryKey);
    const records = this.ledger.getEventRecordsBySourceEventKeys(keys);
    const envelope = buildRuntimeIncidentEnvelope({ entry, records, hostId: this.hostId, bootId: this.bootId, observabilityState });
    if (!envelope || this.states.has(envelope.incident_id)) return false;
    this.ledger.append('cloud_delivery_pending', {
      timestamp: new Date().toISOString(),
      incident_id: envelope.incident_id,
      envelope
    });
    this.states.set(envelope.incident_id, { status: 'PENDING', envelope, retryCount: 0, nextAttemptAt: 0 });
    return true;
  }

  async sendHeartbeat(data) {
    if (typeof this.client.sendHeartbeat !== 'function') return { ok: false, error: 'HEARTBEAT_NOT_SUPPORTED' };
    return this.client.sendHeartbeat(data);
  }

  async flushPending() {
    if (this.busy) return { sent: 0, failed: 0, queued: this.pendingCount() };
    this.busy = true;
    let sent = 0;
    let failed = 0;
    try {
      for (const [incidentId, state] of this.states) {
        if (state.status !== 'PENDING') continue;
        if (state.nextAttemptAt > Date.now()) continue;
        let result;
        try { result = await this.client.sendIncidentEnvelope(state.envelope); }
        catch { result = { ok: false, error: 'CLOUD_CLIENT_EXCEPTION' }; }
        if (!result?.ok) {
          failed++;
          const retryCount = (state.retryCount || 0) + 1;
          const delayMs = Math.min(this.retryBaseMs * (2 ** Math.min(retryCount - 1, 20)), this.retryMaxMs);
          const nextAttemptAt = Date.now() + delayMs;
          this.ledger.append('cloud_delivery_retry', {
            timestamp: new Date().toISOString(),
            incident_id: incidentId,
            retry_count: retryCount,
            next_attempt_at: new Date(nextAttemptAt).toISOString(),
            error_code: /^[A-Z0-9_:-]{1,64}$/.test(result?.error || '') ? result.error : 'CLOUD_DELIVERY_FAILED'
          });
          this.states.set(incidentId, { ...state, retryCount, nextAttemptAt });
          continue;
        }
        this.ledger.append('cloud_delivery_ack', {
          timestamp: new Date().toISOString(),
          incident_id: incidentId,
          cloud_incident_id: result.data?.incident_id || null,
          duplicate: result.data?.duplicate === true,
          recorded_at: result.data?.recorded_at || null
        });
        this.states.set(incidentId, { status: 'ACKNOWLEDGED' });
        sent++;
      }
    } finally {
      this.busy = false;
    }
    this.scheduleRetry();
    const status = { sent, failed, queued: this.pendingCount() };
    if (sent || failed) this.onStatus({ type: 'cloud_delivery', ...status });
    return status;
  }

  pendingCount() {
    let count = 0;
    for (const state of this.states.values()) if (state.status === 'PENDING') count++;
    return count;
  }

  scheduleRetry() {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
    let nextAttemptAt = Infinity;
    for (const state of this.states.values()) {
      if (state.status === 'PENDING') nextAttemptAt = Math.min(nextAttemptAt, state.nextAttemptAt || Date.now());
    }
    if (!Number.isFinite(nextAttemptAt)) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void this.flushPending().catch(() => {});
    }, Math.max(0, nextAttemptAt - Date.now()));
    this.retryTimer.unref?.();
  }

  close() {
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }
}

module.exports = {
  RuntimeIncidentPublisher,
  buildRuntimeIncidentEnvelope,
  isIncidentDecision,
  severityFor
};
