'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { BehavioralSequenceEngine } = require('../engine');
const { normalizeTetragonJson } = require('../adapters/tetragon-json');
const { materializeTetragonEventV2, EventMaterializationError } = require('../contracts/materialize-tetragon-v2');
const { syntheticObservabilityEventKey, canonicalPayloadSha256 } = require('../contracts/event-keys');
const { validateEventV2 } = require('../contracts/validate-event-v2');
const { WorkloadProfile } = require('../profiler');
const { ThreatLevel } = require('../types');
const { BehaviorEngine, DecisionEngine } = require('../intelligence');
const { getRawResponseBytes, getRawResponseByteLength, loadTetragonApi } = require('./tetragon-proto');
const { timestampNs } = require('../adapters/tetragon-json');

const SUPPORTED_TETRAGON_VERSION = /^v?1\.8\.0$/;
const MAX_PEM_BYTES = 4 * 1024 * 1024;
const MAX_GRPC_MESSAGE_BYTES = 16 * 1024 * 1024;
const DEFAULT_QUEUE_CAPACITY = 512;
const DEFAULT_QUEUE_BYTE_CAPACITY = 64 * 1024 * 1024;
const MAX_QUEUE_BYTE_CAPACITY = 256 * 1024 * 1024;
const DEFAULT_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 30000;
const CORE_EVENT_TYPES = Object.freeze([
  'PROCESS_EXEC', 'PROCESS_EXIT', 'PROCESS_LOADER', 'PROCESS_THROTTLE', 'RATE_LIMIT_INFO'
]);
const POLICY_EVENT_TYPES = Object.freeze([
  'PROCESS_KPROBE', 'PROCESS_TRACEPOINT', 'PROCESS_UPROBE', 'PROCESS_LSM', 'PROCESS_USDT'
]);
const MAX_TRACING_POLICY_NAMES = 32;
const MAX_TRACING_POLICY_NAME_LENGTH = 253;
const TRACING_POLICY_NAME_RE = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$/;
const FATAL_GRPC_CODES = new Set([3, 5, 7, 9, 12, 16]); // INVALID_ARGUMENT, NOT_FOUND, PERMISSION_DENIED, FAILED_PRECONDITION, UNIMPLEMENTED, UNAUTHENTICATED
const OBSERVABILITY_STATES = Object.freeze({
  HEALTHY: 'HEALTHY',
  GAP_DETECTED: 'GAP_DETECTED',
  DEGRADED: 'DEGRADED',
  GAP_ACKNOWLEDGED: 'GAP_ACKNOWLEDGED',
  RECOVERY_PENDING: 'RECOVERY_PENDING',
  RECOVERED: 'RECOVERED'
});
const OBSERVABILITY_RECOVERY_EVIDENCE_KINDS = new Set(['OPERATOR_ACK', 'SENSOR_REPLAY_VERIFIED']);

function parseTetragonAddress(address, platform = process.platform) {
  if (typeof address !== 'string' || address.length === 0 || address.length > 2048) throw new TypeError('Tetragon address is required');
  if (address.startsWith('unix://')) {
    const socketPath = address.slice('unix://'.length);
    if (platform !== 'linux') throw new Error('Tetragon Unix-socket collection requires Linux');
    if (!path.posix.isAbsolute(socketPath) || socketPath.includes('\0')) throw new TypeError('Unix socket address must contain an absolute path');
    return { target: address, transportProtocol: 'GRPC_UNIX_SOCKET' };
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(address)) throw new TypeError('TCP Tetragon address must be host:port without a URI scheme');
  const match = address.match(/^(?:\[([0-9a-fA-F:.]+)\]|([a-zA-Z0-9._-]+)):([0-9]{1,5})$/);
  if (!match) throw new TypeError('TCP Tetragon address must be host:port or [IPv6]:port');
  const port = Number(match[3]);
  if (port < 1 || port > 65535) throw new RangeError('Tetragon TCP port must be between 1 and 65535');
  return { target: address, transportProtocol: 'GRPC_TCP' };
}

function readPem(filePath, expectedPattern, label) {
  if (typeof filePath !== 'string' || filePath.length === 0) throw new TypeError(`${label} path is required`);
  const resolved = path.resolve(filePath);
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size < 1 || stat.size > MAX_PEM_BYTES) throw new RangeError(`${label} must be a regular PEM file no larger than ${MAX_PEM_BYTES} bytes`);
  if (label === 'TLS client key' && process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
    throw new Error('TLS client key must not be accessible by group or other users (use mode 0600 or stricter)');
  }
  const contents = fs.readFileSync(resolved);
  if (!expectedPattern.test(contents.toString('ascii'))) throw new TypeError(`${label} does not contain an expected PEM block`);
  return contents;
}

function createTetragonConnection(options = {}) {
  const address = options.address || 'unix:///var/run/tetragon/tetragon.sock';
  const endpoint = parseTetragonAddress(address, options.platform || process.platform);
  const api = loadTetragonApi();
  let credentials;
  if (endpoint.transportProtocol === 'GRPC_UNIX_SOCKET') {
    if (options.tlsCa || options.tlsClientCert || options.tlsClientKey) throw new Error('TLS files are valid only for a Tetragon TCP endpoint');
    credentials = api.grpc.credentials.createInsecure();
  } else {
    if (!options.tlsCa) throw new Error('Tetragon TCP requires --tls-ca; plaintext gRPC is disabled');
    const rootCert = readPem(options.tlsCa, /-----BEGIN CERTIFICATE-----/, 'TLS CA');
    const hasClientCert = Boolean(options.tlsClientCert);
    const hasClientKey = Boolean(options.tlsClientKey);
    if (hasClientCert !== hasClientKey) throw new Error('mTLS requires both --tls-client-cert and --tls-client-key');
    const certChain = hasClientCert
      ? readPem(options.tlsClientCert, /-----BEGIN CERTIFICATE-----/, 'TLS client certificate') : null;
    const privateKey = hasClientKey
      ? readPem(options.tlsClientKey, /-----BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----/, 'TLS client key') : null;
    credentials = api.grpc.credentials.createSsl(rootCert, privateKey, certChain);
  }
  const client = new api.service(endpoint.target, credentials, {
    'grpc.max_receive_message_length': MAX_GRPC_MESSAGE_BYTES,
    'grpc.keepalive_time_ms': 30000,
    'grpc.keepalive_timeout_ms': 10000,
    'grpc.keepalive_permit_without_calls': 0
  });
  return {
    client,
    close: () => client.close(),
    target: endpoint.target,
    transportProtocol: endpoint.transportProtocol,
    transportAuthentication: endpoint.transportProtocol === 'GRPC_UNIX_SOCKET'
      ? 'NONE_UNAUTHENTICATED'
      : (options.tlsClientCert ? 'MUTUAL_TLS' : 'TLS_SERVER_AUTH')
  };
}

function getAgentVersion(client, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    client.getVersion({}, { deadline }, (error, response) => {
      if (error) reject(error);
      else if (typeof response?.version !== 'string' || response.version.length === 0) reject(new Error('Tetragon GetVersion returned no version'));
      else resolve(response.version);
    });
  });
}

function sourceIdForHost(hostId, bootId) {
  const hash = crypto.createHash('sha256').update(hostId, 'utf8').update('\0').update(bootId, 'utf8').digest('hex');
  return `tetragon:${hash}`;
}

function normalizeTracingPolicyNames(value = []) {
  if (!Array.isArray(value) || value.length > MAX_TRACING_POLICY_NAMES) {
    throw new TypeError(`tetragonPolicyNames must be an array of at most ${MAX_TRACING_POLICY_NAMES} policy names`);
  }
  const names = [];
  const seen = new Set();
  for (const name of value) {
    if (typeof name !== 'string' || name.length === 0 || name.length > MAX_TRACING_POLICY_NAME_LENGTH ||
        !TRACING_POLICY_NAME_RE.test(name) || name.split('.').some((label) => label.length > 63)) {
      throw new TypeError('Tetragon tracing policy names must be lowercase DNS subdomains no longer than 253 characters');
    }
    if (seen.has(name)) throw new TypeError(`Duplicate Tetragon tracing policy name: ${name}`);
    seen.add(name);
    names.push(name);
  }
  return names;
}

function buildGetEventsRequest(policyNames = []) {
  const names = normalizeTracingPolicyNames(policyNames);
  const allowList = [{ event_set: [...CORE_EVENT_TYPES] }];
  if (names.length > 0) {
    // Tetragon ORs allow_list filters, while predicates within each Filter
    // are ANDed. Keep noisy policy events scoped to explicitly selected
    // policies so they cannot crowd native process lifecycle events out.
    allowList.push({ event_set: [...POLICY_EVENT_TYPES], policy_names: names });
  }
  return { allow_list: allowList };
}

class TetragonGrpcCollector {
  constructor(options = {}) {
    if (!options.ledger || typeof options.ledger.recordEventsWithCheckpoint !== 'function') throw new TypeError('Evidence ledger with transactional checkpoints is required');
    if (typeof options.hostId !== 'string' || !options.hostId) throw new TypeError('hostId must be provided by trusted target configuration');
    if (typeof options.bootId !== 'string' || !options.bootId) throw new TypeError('bootId must be provided by trusted target configuration');
    if (typeof options.connectionFactory !== 'function') throw new TypeError('connectionFactory is required');
    const batchSize = options.batchSize === undefined ? 128 : options.batchSize;
    const queueCapacity = options.queueCapacity === undefined ? DEFAULT_QUEUE_CAPACITY : options.queueCapacity;
    const queueByteCapacity = options.queueByteCapacity === undefined ? DEFAULT_QUEUE_BYTE_CAPACITY : options.queueByteCapacity;
    const flushIntervalMs = options.flushIntervalMs === undefined ? 1000 : options.flushIntervalMs;
    const maxEvents = options.maxEvents === undefined ? null : options.maxEvents;
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 4096) throw new RangeError('batchSize must be between 1 and 4096');
    if (!Number.isSafeInteger(queueCapacity) || queueCapacity < 16 || queueCapacity > 16384) throw new RangeError('queueCapacity must be between 16 and 16384');
    if (!Number.isSafeInteger(queueByteCapacity) || queueByteCapacity < 16 * 1024 * 1024 || queueByteCapacity > MAX_QUEUE_BYTE_CAPACITY) throw new RangeError('queueByteCapacity must be between 16 and 256 MiB');
    if (!Number.isSafeInteger(flushIntervalMs) || flushIntervalMs < 10 || flushIntervalMs > 60000) throw new RangeError('flushIntervalMs must be between 10 and 60000');
    if (maxEvents !== null && (!Number.isSafeInteger(maxEvents) || maxEvents < 1)) throw new RangeError('maxEvents must be a positive safe integer');

    this.ledger = options.ledger;
    this.hostId = options.hostId;
    this.bootId = options.bootId;
    this.workloadId = options.workloadId || 'unassigned';
    this.batchSize = batchSize;
    this.queueCapacity = queueCapacity;
    this.queueByteCapacity = queueByteCapacity;
    this.flushIntervalMs = flushIntervalMs;
    this.maxEvents = maxEvents;
    this.expectedNodeName = options.expectedNodeName || null;
    this.captureProcessArguments = options.captureProcessArguments === true;
    this.tetragonPolicyNames = normalizeTracingPolicyNames(options.tetragonPolicyNames);
    this.connectionFactory = options.connectionFactory;
    this.onStatus = typeof options.onStatus === 'function' ? options.onStatus : () => {};
    this.engine = options.engine || new BehavioralSequenceEngine();
    this.behaviorEngine = options.behaviorEngine || null;
    this.decisionEngine = options.decisionEngine || null;
    this.incidentPublisher = options.incidentPublisher || null;
    if (options.intelligence && !this.behaviorEngine) {
      this.behaviorEngine = new BehaviorEngine(options);
      this.decisionEngine = options.decisionEngine || new DecisionEngine(options);
    }
    if (options.profiles) {
      for (const [workloadId, config] of Object.entries(options.profiles)) {
        const wp = new WorkloadProfile(config);
        this.engine.registerProfile(workloadId, wp);
        if (this.behaviorEngine) {
          this.behaviorEngine.registerProfile(workloadId, wp);
        }
      }
    }
    this.sourceId = sourceIdForHost(this.hostId, this.bootId);
    this.collectorSessionId = crypto.randomUUID();
    this.observabilityState = OBSERVABILITY_STATES.HEALTHY;
    this.observabilityDegraded = false;
    this.observabilityReason = null;
    this.observabilitySince = null;
    this.observabilityRecovery = null;
    this.lastCommittedCheckpoint = null;
    this.metrics = {
      connections: 0,
      received: 0,
      persisted: 0,
      duplicate_events_suppressed: 0,
      supported: 0,
      unsupported: 0,
      rejected: 0,
      rate_limit_reports: 0,
      queue_drops_lower_bound: '0',
      queue_dropped_bytes_lower_bound: '0',
      shutdown_queue_discarded_lower_bound: '0',
      shutdown_queue_discarded_bytes_lower_bound: '0',
      unprocessed_at_limit_lower_bound: '0',
      cloud_incidents_queued: 0,
      cloud_incidents_sent: 0,
      cloud_delivery_failures: 0
    };
  }

  observabilityDetails() {
    return {
      observability_state: this.observabilityState,
      observability_degraded: this.observabilityDegraded,
      observability_reason: this.observabilityReason,
      observability_since: this.observabilitySince
    };
  }

  applyObservabilityState(state, reason = null, { evidence = null, persist = true } = {}) {
    if (!Object.values(OBSERVABILITY_STATES).includes(state)) {
      throw new TypeError(`Unsupported observability state: ${state}`);
    }
    const degraded = state !== OBSERVABILITY_STATES.HEALTHY && state !== OBSERVABILITY_STATES.RECOVERED;
    const changed = this.observabilityState !== state || this.observabilityDegraded !== degraded;
    this.observabilityState = state;
    this.observabilityDegraded = degraded;
    if (state === OBSERVABILITY_STATES.HEALTHY || state === OBSERVABILITY_STATES.RECOVERED) {
      this.observabilityReason = null;
    } else if (reason) {
      this.observabilityReason = reason;
    }
    if (changed) this.observabilitySince = new Date().toISOString();
    this.observabilityRecovery = evidence;
    const engineReason = degraded ? (this.observabilityReason || 'Observability degraded') : null;
    if (typeof this.decisionEngine?.setObservabilityState === 'function') {
      this.decisionEngine.setObservabilityState(state, degraded, engineReason);
    } else {
      this.decisionEngine?.setObservabilityDegraded?.(degraded, engineReason);
    }
    if (persist) this.persistObservabilityState();
  }

  markObservabilityDegraded(reason, state = OBSERVABILITY_STATES.DEGRADED) {
    const nextState = state === OBSERVABILITY_STATES.GAP_DETECTED
      ? OBSERVABILITY_STATES.GAP_DETECTED
      : OBSERVABILITY_STATES.DEGRADED;
    if (this.observabilityState === nextState) {
      if (!this.observabilityReason && reason) this.observabilityReason = reason;
      return;
    }
    if (this.observabilityState === OBSERVABILITY_STATES.DEGRADED && nextState === OBSERVABILITY_STATES.GAP_DETECTED) {
      return;
    }
    this.applyObservabilityState(nextState, reason || 'Observability degraded');
  }

  markObservabilityGapAcknowledged(evidence) {
    if (!this.observabilityDegraded) throw new Error('Observability is not degraded');
    if (this.observabilityState === OBSERVABILITY_STATES.RECOVERY_PENDING) {
      throw new Error('Observability recovery is already pending');
    }
    const acknowledgement = normalizeObservabilityRecoveryEvidence(evidence, 'OPERATOR_ACK');
    this.applyObservabilityState(OBSERVABILITY_STATES.GAP_ACKNOWLEDGED, 'GAP_ACKNOWLEDGED', { evidence: acknowledgement });
    this.recordHealth('OBSERVABILITY_GAP_ACKNOWLEDGED', { ...this.observabilityDetails(), acknowledgement });
  }

  markObservabilityRecoveryPending(evidence) {
    if (!this.observabilityDegraded) throw new Error('Observability is not degraded');
    if (this.observabilityState === OBSERVABILITY_STATES.RECOVERY_PENDING) {
      throw new Error('Observability recovery is already pending');
    }
    const recovery = normalizeObservabilityRecoveryEvidence(evidence, 'SENSOR_REPLAY_VERIFIED');
    this.applyObservabilityState(OBSERVABILITY_STATES.RECOVERY_PENDING, 'RECOVERY_PENDING', { evidence: recovery });
    this.recordHealth('OBSERVABILITY_RECOVERY_PENDING', { ...this.observabilityDetails(), recovery });
  }

  markObservabilityRecovered(evidence) {
    if (this.observabilityState !== OBSERVABILITY_STATES.RECOVERY_PENDING) {
      throw new Error('Observability recovery requires an explicit RECOVERY_PENDING state');
    }
    const recovery = normalizeObservabilityRecoveryEvidence(evidence, 'SENSOR_REPLAY_VERIFIED');
    if (!sameObservabilityReplayEvidence(this.observabilityRecovery, recovery)) {
      throw new Error('Observability recovery evidence does not match the pending replay verification');
    }
    this.applyObservabilityState(OBSERVABILITY_STATES.RECOVERED, null, { evidence: recovery });
    this.recordHealth('OBSERVABILITY_RECOVERED', { ...this.observabilityDetails(), recovery });
  }

  persistObservabilityState() {
    if (!this.lastCommittedCheckpoint) return;
    const checkpoint = {
      ...this.lastCommittedCheckpoint,
      observability_state: this.observabilityState,
      observability_reason: this.observabilityReason,
      observability_since: this.observabilitySince,
      observability_recovery: this.observabilityRecovery
    };
    this.ledger.recordEventsWithCheckpoint([], checkpoint);
    this.lastCommittedCheckpoint = checkpoint;
  }

  restoreObservabilityState(checkpoint) {
    if (!checkpoint) {
      this.applyObservabilityState(OBSERVABILITY_STATES.HEALTHY, null, { persist: false });
      return;
    }
    const priorState = typeof checkpoint.observability_state === 'string'
      ? checkpoint.observability_state.slice(0, 64) : 'UNKNOWN';
    if (priorState === OBSERVABILITY_STATES.GAP_ACKNOWLEDGED) {
      this.applyObservabilityState(
        OBSERVABILITY_STATES.GAP_ACKNOWLEDGED,
        checkpoint.observability_reason || 'COLLECTOR_RESTART_PRIOR_OBSERVABILITY_GAP_ACKNOWLEDGED',
        { evidence: checkpoint.observability_recovery || null, persist: false }
      );
      return;
    }
    this.applyObservabilityState(
      OBSERVABILITY_STATES.DEGRADED,
      `COLLECTOR_RESTART_PRIOR_OBSERVABILITY_${priorState}`,
      { persist: false }
    );
  }

  baselineCheckpoint() {
    return {
      source_id: this.sourceId,
      provider: 'tetragon',
      cursor_kind: 'GRPC_SEQUENCE',
      stream_epoch: null,
      sequence_number: '0',
      last_source_event_key: null,
      tetragon_version: null,
      transport_protocol: null,
      replay_supported: false,
      upstream_acknowledgement: false,
      stream_gap_state: 'UNKNOWN_UNTIL_SENSOR_REPLAY_EXISTS'
    };
  }

  async run(signal) {
    let previousCheckpoint = this.ledger.getLatestSourceCheckpoint(this.sourceId);
    this.lastCommittedCheckpoint = checkpointWithoutLedgerSequence(previousCheckpoint) || this.baselineCheckpoint();
    this.restoreObservabilityState(previousCheckpoint);
    this.persistObservabilityState();
    let retryDelay = DEFAULT_BACKOFF_MS;
    let hadDisconnect = false;
    let intentionalStop = false;
    let stopReason = null;
    this.recordHealth('COLLECTOR_STARTED', {
      source_id: this.sourceId,
      replay_supported: false,
      upstream_acknowledgement: false,
      previous_checkpoint: previousCheckpoint,
      prior_observability_state: previousCheckpoint?.observability_state || null,
      coverage: 'LIVE_EVENTS_AFTER_CONNECTION_ONLY',
      ...this.observabilityDetails()
    });
    if (this.incidentPublisher) void this.flushCloudPending();

    while (!signal?.aborted && !intentionalStop) {
      let connection;
      let streamEpoch = crypto.randomUUID();
      try {
        connection = await this.connectionFactory();
        const agentVersion = await getAgentVersion(connection.client);
        if (!SUPPORTED_TETRAGON_VERSION.test(agentVersion)) {
          const error = new Error(`Unsupported Tetragon version ${agentVersion}; this collector is pinned to v1.8.0`);
          error.permanent = true;
          throw error;
        }
        this.onStatus({ type: 'connected', tetragon_version: agentVersion, transport_protocol: connection.transportProtocol });
        this.metrics.connections++;
        if (this.observabilityState === OBSERVABILITY_STATES.GAP_DETECTED) {
          this.markObservabilityDegraded(this.observabilityReason || 'STREAM_GAP_UNKNOWN_NO_SENSOR_REPLAY');
        }
        const streamGapState = previousCheckpoint || hadDisconnect ? 'UNKNOWN' : 'NO_PRIOR_LOCAL_CHECKPOINT';
        this.recordHealth('STREAM_CONNECTED', {
          source_id: this.sourceId,
          stream_epoch: streamEpoch,
          tetragon_version: agentVersion,
          transport_protocol: connection.transportProtocol,
          replay_supported: false,
          upstream_acknowledgement: false,
          prior_checkpoint: previousCheckpoint,
          prior_observability_state: previousCheckpoint?.observability_state || null,
          stream_gap_state: streamGapState,
          ...this.observabilityDetails()
        });
        const result = await this.consumeConnection(connection, {
          agentVersion,
          streamEpoch,
          transportProtocol: connection.transportProtocol,
          transportAuthentication: connection.transportAuthentication || 'NONE_UNAUTHENTICATED',
          collectorSessionId: this.collectorSessionId,
          signal
        });
        if (result.intentionalStop) {
          intentionalStop = true;
          stopReason = result.stopReason || 'REQUESTED';
          if (result.shutdownDiscardedEvents > 0) {
            this.metrics.shutdown_queue_discarded_lower_bound = (BigInt(this.metrics.shutdown_queue_discarded_lower_bound) + BigInt(result.shutdownDiscardedEvents)).toString();
            this.metrics.shutdown_queue_discarded_bytes_lower_bound = (BigInt(this.metrics.shutdown_queue_discarded_bytes_lower_bound) + BigInt(result.shutdownDiscardedBytes)).toString();
            this.markObservabilityDegraded('COLLECTOR_SHUTDOWN_QUEUE_DISCARD');
            this.recordHealth('COLLECTOR_SHUTDOWN_QUEUE_DISCARD', {
              stream_epoch: streamEpoch,
              shutdown_discarded_events_lower_bound: String(result.shutdownDiscardedEvents),
              shutdown_discarded_bytes_lower_bound: String(result.shutdownDiscardedBytes),
              stream_gap_state: 'UNKNOWN',
              source_replay_available: false,
              ...this.observabilityDetails()
            });
          }
          if (result.queueDrops > 0) {
            this.metrics.queue_drops_lower_bound = (BigInt(this.metrics.queue_drops_lower_bound) + BigInt(result.queueDrops)).toString();
            this.metrics.queue_dropped_bytes_lower_bound = (BigInt(this.metrics.queue_dropped_bytes_lower_bound) + BigInt(result.queueDroppedBytes)).toString();
            this.markObservabilityDegraded('COLLECTOR_QUEUE_OVERFLOW');
            this.recordHealth('COLLECTOR_QUEUE_OVERFLOW', {
              stream_epoch: streamEpoch,
              queue_drops_lower_bound: String(result.queueDrops),
              queue_dropped_bytes_lower_bound: String(result.queueDroppedBytes),
              stream_gap_state: 'UNKNOWN',
              ...this.observabilityDetails()
            });
          }
          if (result.unprocessedAtLimit > 0) {
            this.metrics.unprocessed_at_limit_lower_bound = (BigInt(this.metrics.unprocessed_at_limit_lower_bound) + BigInt(result.unprocessedAtLimit)).toString();
            this.recordHealth('COLLECTOR_LIMIT_REACHED', {
              stream_epoch: streamEpoch,
              configured_max_events: this.maxEvents,
              unprocessed_events_at_limit_lower_bound: String(result.unprocessedAtLimit),
              unprocessed_bytes_at_limit_lower_bound: String(result.unprocessedBytesAtLimit),
              stream_gap_state: 'UNKNOWN',
              source_replay_available: false,
              ...this.observabilityDetails()
            });
          }
          break;
        }
        const error = new Error('Tetragon GetEvents stream ended without a requested stop');
        error.code = 14;
        throw error;
      } catch (error) {
        if (signal?.aborted) break;
        if (error.queueDrops > 0) {
          this.metrics.queue_drops_lower_bound = (BigInt(this.metrics.queue_drops_lower_bound) + BigInt(error.queueDrops)).toString();
          this.metrics.queue_dropped_bytes_lower_bound = (BigInt(this.metrics.queue_dropped_bytes_lower_bound) + BigInt(error.queueDroppedBytes || 0)).toString();
          this.markObservabilityDegraded('COLLECTOR_QUEUE_OVERFLOW');
          this.recordHealth('COLLECTOR_QUEUE_OVERFLOW', {
            stream_epoch: streamEpoch,
            queue_drops_lower_bound: String(error.queueDrops),
            queue_dropped_bytes_lower_bound: String(error.queueDroppedBytes || 0),
            stream_gap_state: 'UNKNOWN',
            source_replay_available: false,
            ...this.observabilityDetails()
          });
        }
        if (error.permanent || error.code === undefined || FATAL_GRPC_CODES.has(error.code)) {
          this.recordHealth('COLLECTOR_FATAL_ERROR', { message: safeErrorMessage(error), grpc_code: error.code ?? null });
          throw error;
        }
        hadDisconnect = true;
        previousCheckpoint = this.ledger.getLatestSourceCheckpoint(this.sourceId);
        this.markObservabilityDegraded('STREAM_GAP_UNKNOWN_NO_SENSOR_REPLAY', OBSERVABILITY_STATES.GAP_DETECTED);
        this.recordHealth('STREAM_DISCONNECTED', {
          stream_epoch: streamEpoch,
          message: safeErrorMessage(error),
          grpc_code: error.code ?? null,
          persistence_stage: error.persistenceStage || null,
          database_error_code: error.code || null,
          database_error_number: Number.isInteger(error.errcode) ? error.errcode : null,
          transaction_rollback_error: error.rollbackError || null,
          stream_gap_state: 'UNKNOWN',
          source_replay_available: false,
          last_committed_checkpoint: previousCheckpoint,
          ...this.observabilityDetails()
        });
        this.onStatus({ type: 'reconnecting', delay_ms: retryDelay, grpc_code: error.code ?? null });
        await delayWithSignal(jitter(retryDelay), signal);
        retryDelay = Math.min(MAX_BACKOFF_MS, retryDelay * 2);
      } finally {
        try { connection?.close(); } catch { /* connection teardown is best-effort */ }
      }
    }

    if (signal?.aborted && !intentionalStop) {
      this.recordHealth('COLLECTOR_STOPPED', { reason: 'SIGNAL', source_id: this.sourceId, ...this.observabilityDetails() });
    } else if (intentionalStop) {
      this.recordHealth('COLLECTOR_STOPPED', {
        reason: stopReason || 'REQUESTED',
        source_id: this.sourceId,
        ...this.observabilityDetails()
      });
    }
    if (this.incidentPublisher) await this.flushCloudPending();
    return { ...this.metrics, mode: 'observe-only', source_id: this.sourceId };
  }

  async consumeConnection(connection, session) {
    const stream = connection.client.getEvents(buildGetEventsRequest(this.tetragonPolicyNames));
    const queue = [];
    const capacity = this.queueCapacity;
    const byteCapacity = this.queueByteCapacity;
    let queuedBytes = 0;
    let terminal = false;
    let terminalError = null;
    let wake = null;
    let intentionalStop = false;
    let queueDrops = 0;
    let queueDroppedBytes = 0;
    let shutdownDiscardedEvents = 0;
    let shutdownDiscardedBytes = 0;
    let unprocessedAtLimit = 0;
    let unprocessedBytesAtLimit = 0;
    let stopReason = null;
    let receivedThisSession = 0;
    const pending = [];
    let streamSequence = 0n;
    let lastSequence = '0';
    let lastEventKey = null;
    let flushTimer = null;
    let failed = false;
    let nextCooperativeYieldAt = 32;

    const notify = () => {
      if (wake) { const resolve = wake; wake = null; resolve(); }
    };
    const cancel = () => { try { stream.cancel(); } catch { /* already closed */ } };
    const onData = response => {
      if (terminal || intentionalStop) return;
      const byteLength = getRawResponseByteLength(response);
      if (!Number.isSafeInteger(byteLength)) {
        terminalError = Object.assign(new Error('Tetragon response decoder did not preserve the original protobuf bytes'), { code: 13 });
        terminal = true;
        cancel();
        notify();
        return;
      }
      if (queue.length >= capacity || queuedBytes + byteLength > byteCapacity) {
        queueDrops++;
        queueDroppedBytes += byteLength;
        terminalError = Object.assign(new Error('Tetragon collector queue capacity exceeded'), { code: 8 });
        terminal = true;
        cancel();
        notify();
        return;
      }
      queue.push({ response, byteLength });
      queuedBytes += byteLength;
      if (queue.length >= capacity) stream.pause?.();
      notify();
    };
    const onError = error => { if (!terminal) { terminalError = error; terminal = true; notify(); } };
    const ignorePostCancelError = () => {};
    const onEnd = () => { terminal = true; notify(); };
    const onAbort = () => { terminal = true; cancel(); notify(); };
    stream.on('data', onData);
    stream.on('error', onError);
    stream.on('end', onEnd);
    session.signal?.addEventListener('abort', onAbort, { once: true });

    const flush = () => {
      if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; }
      if (!pending.length && lastSequence === '0') return;
      const checkpoint = {
        source_id: this.sourceId,
        provider: 'tetragon',
        cursor_kind: 'GRPC_SEQUENCE',
        stream_epoch: session.streamEpoch,
        sequence_number: lastSequence,
        last_source_event_key: lastEventKey,
        tetragon_version: session.agentVersion,
        transport_protocol: session.transportProtocol,
        replay_supported: false,
        upstream_acknowledgement: false,
        stream_gap_state: 'UNKNOWN_UNTIL_SENSOR_REPLAY_EXISTS',
        observability_state: this.observabilityState,
        observability_reason: this.observabilityReason,
        observability_since: this.observabilitySince,
        observability_recovery: this.observabilityRecovery
      };
      const written = this.ledger.recordEventsWithCheckpoint(pending, checkpoint);
      const committedEntries = pending.slice();
      this.metrics.persisted += written.events.length;
      this.metrics.duplicate_events_suppressed += written.duplicates;
      this.lastCommittedCheckpoint = checkpoint;
      pending.length = 0;
      if (this.incidentPublisher) {
        for (const entry of committedEntries) {
          try {
            if (this.incidentPublisher.consider(entry, this.observabilityState)) this.metrics.cloud_incidents_queued++;
          } catch (error) {
            this.metrics.cloud_delivery_failures++;
            this.onStatus({ type: 'cloud_delivery_queue_failed', code: error.code || 'LOCAL_OUTBOX_ERROR' });
          }
        }
        if (this.incidentPublisher.pendingCount() > 0) void this.flushCloudPending();
      }
    };
    const scheduleFlush = () => {
      if (!flushTimer) {
        flushTimer = setTimeout(() => {
          flushTimer = null;
          try { flush(); } catch (error) { failed = true; terminalError = error; terminal = true; cancel(); notify(); }
        }, this.flushIntervalMs);
        flushTimer.unref?.();
      }
    };
    const pushEntry = (entry, eventKey) => {
      pending.push(entry);
      lastSequence = String(streamSequence);
      lastEventKey = eventKey || null;
      if (pending.length >= this.batchSize) flush();
      else scheduleFlush();
    };

    try {
      while (true) {
        if (receivedThisSession >= nextCooperativeYieldAt) {
          nextCooperativeYieldAt += 32;
          await yieldToEventLoop();
        }
        if (session.signal?.aborted) {
          shutdownDiscardedEvents = queue.length;
          shutdownDiscardedBytes = queuedBytes;
          queue.length = 0;
          queuedBytes = 0;
          if (pending.length) flush();
          intentionalStop = true;
          stopReason = 'SIGNAL';
          break;
        }
        if (queue.length === 0) {
          if (terminal) break;
          await new Promise(resolve => { wake = resolve; });
          continue;
        }
        const queued = queue.shift();
        const response = queued.response;
        queuedBytes -= queued.byteLength;
        if (queue.length <= Math.floor(capacity / 2)) stream.resume?.();
        if (this.expectedNodeName && response.node_name !== this.expectedNodeName) {
          const actual = typeof response.node_name === 'string' && response.node_name.length > 0 ? response.node_name : '<missing>';
          const error = new Error(`Tetragon node_name mismatch: expected ${this.expectedNodeName}, received ${actual}`);
          error.permanent = true;
          throw error;
        }
        streamSequence++;
        receivedThisSession++;
        this.metrics.received++;
        const raw = getRawResponseBytes(response);
        if (!raw) throw new Error('Tetragon response decoder did not preserve the original protobuf bytes');
        const rawHash = sha256(raw);
        const field = typeof response.event === 'string'
          ? response.event
          : ['process_exec', 'process_exit', 'process_kprobe', 'process_tracepoint', 'process_loader', 'process_uprobe', 'process_throttle', 'process_lsm', 'process_usdt', 'test', 'rate_limit_info'].find(key => Object.hasOwn(response, key));
        const cursor = {
          cursor_kind: 'GRPC_SEQUENCE', stream_epoch: session.streamEpoch,
          sequence_number: String(streamSequence), raw_payload_sha256: rawHash
        };
        const evidence = {
          source_cursor: cursor,
          sensor_metadata: {
            provider: 'tetragon', tetragon_version: session.agentVersion,
            transport_protocol: session.transportProtocol,
            node_name: response.node_name || null,
            cluster_name: response.cluster_name || null
          },
          raw_payload_sha256: rawHash
        };

        if (field === 'rate_limit_info') {
          const rawCount = response.rate_limit_info?.number_of_dropped_process_events;
          if (typeof rawCount !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(rawCount) || BigInt(rawCount) > 18446744073709551615n) {
            this.metrics.rejected++;
            pushEntry({
              event: { provider: 'tetragon', eventType: 'RATE_LIMIT_INFO_REJECTED', sourceEventKey: null, eventId: rawHash },
              decision: null,
              evidence: { ...evidence, reason: 'INVALID_DROPPED_PROCESS_EVENT_COUNT' }
            }, null);
          } else {
            this.metrics.rate_limit_reports++;
            const sourceEventKey = syntheticObservabilityEventKey({
              hostId: this.hostId, bootId: this.bootId, producerId: 'sentinel-runtime-tetragon-collector-v1',
              producerEpoch: session.streamEpoch, sequenceNumber: String(streamSequence), payloadSha256: rawHash
            });
            const dropped = BigInt(rawCount);
            const observedAt = nowNanoseconds();
            const providerTimestamp = timestampNs(response.time);
            const eventPayload = dropped > 0n
              ? { loss_source: 'sensor_throttle', dropped_count: rawCount, window_seconds: null, window_status: 'UNKNOWN', scope: 'GLOBAL', cgroup_path: null }
              : {
                  sensor_status: 'DEGRADED', uptime_seconds: null, uptime_status: 'UNKNOWN', coverage_status: 'PARTIAL',
                  counter_reset_domains: [], counter_unverifiable_domains: [],
                  unavailable_counters: ['ebpf_kernel', 'grpc_transport', 'log_rotation', 'parser_reject', 'runtime_queue', 'storage_drop', 'tetragon_bpf_missed_events', 'tetragon_listener_overflow', 'tetragon_field_filter_drops', 'tetragon_observer_queue_drops', 'tetragon_aggregation_buffer_drops'],
                  heartbeat_timestamp: observedAt
                };
            const lossMetrics = createUnknownLossMetrics(observedAt);
            lossMetrics.sensor_throttle = {
              state: dropped === 0n ? 'ZERO_OBSERVED' : 'MEASURED', count: rawCount,
              source: 'GetEventsResponse.rate_limit_info.number_of_dropped_process_events',
              observed_at: observedAt, scope: 'GLOBAL', window_seconds: null
            };
            const eventType = dropped > 0n ? 'EVENT_LOSS' : 'SENSOR_HEALTH';
            const normalizedV2 = {
              schema_version: '2.0.0', event_id: crypto.randomUUID(), source_event_key: null,
              event_type: eventType, source_provider: 'tetragon', source_event_type: 'RATE_LIMIT_INFO', source_event_id: rawHash,
              host_identity: {
                host_id: this.hostId, boot_id: this.bootId, node_name: response.node_name || null,
                node_name_status: response.node_name ? 'OBSERVED_IN_SENSOR' : 'ABSENT_IN_SENSOR'
              },
              timestamps: {
                source_timestamp: providerTimestamp || observedAt, provider_observation_timestamp: observedAt,
                provider_event_timestamp: providerTimestamp, ingest_timestamp: nowNanoseconds()
              },
              sensor_metadata: {
                collector_id: 'sentinel-runtime-tetragon-grpc-v1', collector_session_id: session.collectorSessionId,
                sensor_version: session.agentVersion, transport_protocol: session.transportProtocol,
                transport_authentication: session.transportAuthentication, debug_process_flags: null, debug_refcnt: null,
                producer_id: 'sentinel-runtime-tetragon-grpc-v1', producer_epoch: session.streamEpoch,
                producer_sequence_number: String(streamSequence)
              },
              process_identity: null,
              workload_context: { context_type: 'UNKNOWN', container_id: null, pod_name: null, namespace_name: null, cgroup_path: null, namespaces_capture_status: 'UNAVAILABLE' },
              source_cursor: cursor,
              loss_metrics: lossMetrics,
              payload: eventPayload
            };
            normalizedV2.source_event_key = syntheticObservabilityEventKey({
              hostId: this.hostId, bootId: this.bootId, producerId: normalizedV2.sensor_metadata.producer_id,
              producerEpoch: normalizedV2.sensor_metadata.producer_epoch, sequenceNumber: normalizedV2.sensor_metadata.producer_sequence_number,
              eventType: normalizedV2.event_type,
              payloadSha256: canonicalPayloadSha256(eventPayload)
            });
            const validation = validateEventV2(normalizedV2);
            if (!validation.valid) throw new Error(`RATE_LIMIT_INFO normalization violates Event Contract v2: ${validation.errors.map(error => `${error.path}: ${error.message}`).join('; ')}`);
            pushEntry({
              event: { provider: 'tetragon', eventType: 'RATE_LIMIT_INFO', sourceEventKey, eventId: rawHash, reportedDroppedProcessEvents: rawCount },
              decision: null,
              evidence: { ...evidence, loss_domain: 'sensor_throttle', reported_dropped_process_events: rawCount, count_semantics: 'Raw value from this RATE_LIMIT_INFO frame only; the pinned v1.8.0 proto does not specify a reporting interval or cumulative/reset semantics' }
            }, sourceEventKey);
            pushEntry({
              event: normalizedV2, decision: null,
              evidence: { ...evidence, normalized_from: 'GetEventsResponse.rate_limit_info', window_status: 'UNKNOWN', provider_timestamp_ns: providerTimestamp }
            }, normalizedV2.source_event_key);
          }
        } else if (typeof field === 'string' && field.startsWith('process_') && response[field]) {
          const record = { time: response.time, [field]: response[field] };
          let normalized;
          try {
            normalized = normalizeTetragonJson(record, raw, {
              hostId: this.hostId, bootId: this.bootId, workloadId: this.workloadId
            });
          } catch (error) {
            this.metrics.rejected++;
            pushEntry({ event: { provider: 'tetragon', sourceType: field, outcome: 'NORMALIZATION_REJECT', eventId: rawHash }, decision: null,
              evidence: { ...evidence, reason: safeErrorMessage(error) } }, null);
            continue;
          }
          if (!normalized.supported) {
            this.metrics.unsupported++;
            pushEntry({ event: { provider: 'tetragon', sourceType: field, outcome: normalized.reason, eventId: rawHash }, decision: null,
              evidence: { ...evidence, source_type: field } }, null);
          } else {
            let event;
            try {
              event = materializeTetragonEventV2(normalized, {
                hostId: this.hostId,
                bootId: this.bootId,
                collectorSessionId: session.collectorSessionId,
                sensorVersion: session.agentVersion,
                transportProtocol: session.transportProtocol,
                transportAuthentication: session.transportAuthentication,
                nodeName: response.node_name || null,
                nodeNameStatus: 'OBSERVED_IN_SENSOR',
                sourceCursor: cursor,
                aggregationDisabled: true,
                captureProcessArguments: this.captureProcessArguments
              });
            } catch (error) {
              if (!(error instanceof EventMaterializationError)) throw error;
              this.metrics.rejected++;
              pushEntry({
                event: { provider: 'tetragon', event_type: 'EVENT_CONTRACT_V2_REJECT', source_type: field, reason_code: error.code },
                decision: null,
                evidence: { ...evidence, reason: safeErrorMessage(error), source_type: field }
              }, null);
              continue;
            }
            this.metrics.supported++;
            let decision;
            if (this.behaviorEngine) {
              const analysis = this.behaviorEngine.analyzeEvent(event);
              if (this.decisionEngine) {
                decision = await this.decisionEngine.decide(analysis, event);
              } else {
                decision = analysis;
              }
            } else {
              decision = this.engine.processEvent(normalized);
            }
            pushEntry({
              event,
              decision,
              evidence: {
                ...evidence,
                normalized_from: field,
                source_function: normalized.sourceFunction || null,
                tracing_policy_name: normalized.policyName || null,
                raw_arguments_preserved: false
              }
            }, normalized.sourceEventKey);
          }
        } else {
          this.metrics.unsupported++;
          const sourceType = typeof field === 'string' ? field : 'no_event';
          const syntheticKey = syntheticObservabilityEventKey({
            hostId: this.hostId, bootId: this.bootId, producerId: 'sentinel-runtime-tetragon-collector-v1',
            producerEpoch: session.streamEpoch, sequenceNumber: String(streamSequence), payloadSha256: rawHash
          });
          pushEntry({
            event: { provider: 'tetragon', eventType: 'UNSUPPORTED_NATIVE_EVENT', sourceType, sourceEventKey: syntheticKey, eventId: rawHash },
            decision: null,
            evidence: { ...evidence, source_type: sourceType }
          }, syntheticKey);
        }

        if (this.maxEvents !== null && this.metrics.received >= this.maxEvents) {
          intentionalStop = true;
          stopReason = 'MAX_EVENTS';
          terminal = true;
          if (queue.length > 0) unprocessedAtLimit = queue.length;
          if (queue.length > 0) unprocessedBytesAtLimit = queue.reduce((total, item) => total + item.byteLength, 0);
          queue.length = 0;
          queuedBytes = 0;
          cancel();
          break;
        }
      }
      if (pending.length) flush();
      if (terminalError && !intentionalStop) {
        terminalError.queueDrops = queueDrops;
        terminalError.queueDroppedBytes = queueDroppedBytes;
        throw terminalError;
      }
      return { intentionalStop, stopReason, queueDrops, queueDroppedBytes, shutdownDiscardedEvents, shutdownDiscardedBytes, unprocessedAtLimit, unprocessedBytesAtLimit, received: receivedThisSession };
    } catch (error) {
      failed = true;
      if (queueDrops > 0) error.queueDrops = queueDrops;
      if (queueDroppedBytes > 0) error.queueDroppedBytes = queueDroppedBytes;
      if (pending.length) {
        try { flush(); } catch (persistError) { error.persistError = safeErrorMessage(persistError); }
      }
      throw error;
    } finally {
      if (flushTimer) clearTimeout(flushTimer);
      stream.removeListener('data', onData);
      stream.removeListener('end', onEnd);
      session.signal?.removeEventListener('abort', onAbort);
      // Install a terminal listener before cancellation. grpc-js can emit its
      // CANCELLED error asynchronously after a processing/persistence failure;
      // removing the only error listener first would crash the Runtime process.
      stream.on('error', ignorePostCancelError);
      stream.removeListener('error', onError);
      if (!terminal) {
        terminal = true;
        cancel();
      }
      if (failed) this.onStatus({ type: 'stream_failed', stream_epoch: session.streamEpoch });
    }
  }

  async flushCloudPending() {
    if (!this.incidentPublisher) return { sent: 0, failed: 0, queued: 0 };
    try {
      const result = await this.incidentPublisher.flushPending();
      this.metrics.cloud_incidents_sent += result.sent;
      this.metrics.cloud_delivery_failures += result.failed;
      return result;
    } catch {
      this.metrics.cloud_delivery_failures++;
      return { sent: 0, failed: 1, queued: this.incidentPublisher.pendingCount() };
    }
  }

  recordHealth(eventType, details) {
    this.ledger.append('sensor_health', {
      timestamp: new Date().toISOString(),
      event: { provider: 'tetragon', event_type: eventType, host_id: this.hostId, boot_id: this.bootId },
      details
    });
    this.onStatus({ type: 'sensor_health', event_type: eventType, ...details });
  }
}

function normalizeObservabilityRecoveryEvidence(evidence, expectedKind = null) {
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    throw new TypeError('Observability recovery evidence must be an object');
  }
  const kind = typeof evidence.kind === 'string' ? evidence.kind.trim() : '';
  const reference = typeof evidence.reference === 'string' ? evidence.reference.trim() : '';
  if (!OBSERVABILITY_RECOVERY_EVIDENCE_KINDS.has(kind)) {
    throw new TypeError('Observability recovery evidence kind must be OPERATOR_ACK or SENSOR_REPLAY_VERIFIED');
  }
  if (expectedKind && kind !== expectedKind) {
    throw new TypeError(`Observability recovery evidence kind must be ${expectedKind}`);
  }
  if (!reference || reference.length > 512) {
    throw new TypeError('Observability recovery evidence reference must be a bounded non-empty string');
  }
  const normalized = {
    kind,
    reference,
    observed_at: typeof evidence.observed_at === 'string' && evidence.observed_at
      ? evidence.observed_at.slice(0, 64) : new Date().toISOString(),
    notes: typeof evidence.notes === 'string' ? evidence.notes.slice(0, 1024) : null
  };
  if (kind === 'SENSOR_REPLAY_VERIFIED') {
    const replayId = boundedObservabilityString(evidence.replay_id, 'replay_id', 256);
    const windowStart = observabilityTimestamp(evidence.window_start, 'window_start');
    const windowEnd = observabilityTimestamp(evidence.window_end, 'window_end');
    if (Date.parse(windowStart) > Date.parse(windowEnd)) {
      throw new TypeError('window_start must not be after window_end');
    }
    const sourceSequenceStart = observabilitySequence(evidence.source_sequence_start, 'source_sequence_start');
    const sourceSequenceEnd = observabilitySequence(evidence.source_sequence_end, 'source_sequence_end');
    if (BigInt(sourceSequenceStart) > BigInt(sourceSequenceEnd)) {
      throw new TypeError('source_sequence_start must not be after source_sequence_end');
    }
    if (!Number.isSafeInteger(evidence.event_count) || evidence.event_count < 0) {
      throw new TypeError('event_count must be a non-negative safe integer');
    }
    if (evidence.verified !== true) {
      throw new TypeError('SENSOR_REPLAY_VERIFIED evidence requires verified=true');
    }
    const verificationMethod = boundedObservabilityString(evidence.verification_method, 'verification_method', 128);
    const replayHash = evidence.replay_hash === undefined || evidence.replay_hash === null
      ? null : boundedObservabilityString(evidence.replay_hash, 'replay_hash', 64).toLowerCase();
    if (replayHash && !/^[a-f0-9]{64}$/.test(replayHash)) {
      throw new TypeError('replay_hash must be a SHA-256 hex digest');
    }
    Object.assign(normalized, {
      replay_id: replayId,
      window_start: windowStart,
      window_end: windowEnd,
      source_sequence_start: sourceSequenceStart,
      source_sequence_end: sourceSequenceEnd,
      event_count: evidence.event_count,
      verified: true,
      verification_method: verificationMethod,
      replay_hash: replayHash
    });
  }
  return normalized;
}

function sameObservabilityReplayEvidence(pending, recovery) {
  if (!pending || !recovery) return false;
  const fields = [
    'kind', 'reference', 'replay_id', 'window_start', 'window_end',
    'source_sequence_start', 'source_sequence_end', 'event_count'
  ];
  if (fields.some(field => pending[field] !== recovery[field])) return false;
  if (pending.replay_hash && recovery.replay_hash && pending.replay_hash !== recovery.replay_hash) return false;
  return true;
}

function boundedObservabilityString(value, label, maxLength) {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > maxLength) {
    throw new TypeError(`${label} must be a bounded non-empty string`);
  }
  return trimmed;
}

function observabilityTimestamp(value, label) {
  const text = boundedObservabilityString(value, label, 64);
  const parsed = Date.parse(text);
  if (!Number.isFinite(parsed)) throw new TypeError(`${label} must be an ISO-8601 timestamp`);
  return new Date(parsed).toISOString();
}

function observabilitySequence(value, label) {
  if (typeof value === 'number' && !Number.isSafeInteger(value)) {
    throw new TypeError(`${label} must be a safe integer or integer string`);
  }
  const text = typeof value === 'bigint' ? value.toString() : String(value ?? '').trim();
  if (!/^\d+$/.test(text) || text.length > 64) {
    throw new TypeError(`${label} must be a non-negative integer string`);
  }
  return BigInt(text).toString();
}

function checkpointWithoutLedgerSequence(checkpoint) {
  if (!checkpoint) return null;
  const { sequence, ...rest } = checkpoint;
  return rest;
}

function safeErrorMessage(error) {
  return typeof error?.details === 'string' && error.details.length <= 1024
    ? error.details
    : String(error?.message || error || 'unknown error').slice(0, 1024);
}

function jitter(delayMs) { return Math.max(100, Math.floor(delayMs * (0.8 + Math.random() * 0.4))); }

function yieldToEventLoop() { return new Promise(resolve => setImmediate(resolve)); }

function delayWithSignal(ms, signal) {
  if (signal?.aborted) return Promise.resolve();
  return new Promise(resolve => {
    const timer = setTimeout(done, ms);
    function done() { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve(); }
    signal?.addEventListener('abort', done, { once: true });
  });
}

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function nowNanoseconds() { return (BigInt(Date.now()) * 1000000n).toString(); }
function createUnknownLossMetrics(observedAt) {
  const domains = [
    'ebpf_kernel', 'sensor_throttle', 'grpc_transport', 'log_rotation', 'parser_reject', 'runtime_queue', 'storage_drop',
    'tetragon_bpf_missed_events', 'tetragon_listener_overflow', 'tetragon_field_filter_drops',
    'tetragon_observer_queue_drops', 'tetragon_aggregation_buffer_drops'
  ];
  return Object.fromEntries(domains.map(domain => [domain, domain === 'tetragon_aggregation_buffer_drops'
    ? { state: 'NOT_APPLICABLE', count: null, source: 'GETEVENTS_AGGREGATION_OPTIONS_NOT_REQUESTED', observed_at: observedAt, scope: null, window_seconds: null }
    : { state: 'UNKNOWN', count: null, source: null, observed_at: observedAt, scope: null, window_seconds: null }]));
}

module.exports = {
  TetragonGrpcCollector,
  buildGetEventsRequest,
  createTetragonConnection,
  getAgentVersion,
  parseTetragonAddress,
  sourceIdForHost,
  SUPPORTED_TETRAGON_VERSION,
  DEFAULT_QUEUE_CAPACITY,
  CORE_EVENT_TYPES,
  POLICY_EVENT_TYPES,
  OBSERVABILITY_STATES
};
