#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { BehavioralSequenceEngine } = require('../src/engine');
const { EvidenceLedger } = require('../src/evidence');
const { JsonlFramer, parseJsonRejectDuplicateKeys } = require('../src/ingest/jsonl');
const { normalizeTetragonJson } = require('../src/adapters/tetragon-json');
const { materializeTetragonEventV2 } = require('../src/contracts/materialize-tetragon-v2');
const { validateEventV2 } = require('../src/contracts/validate-event-v2');
const { canonicalJson } = require('../src/contracts/canonical-json');
const { TetragonGrpcCollector, createTetragonConnection } = require('../src/collectors/tetragon-grpc');
const { TetragonMetricsCollector, validateMetricsPeer } = require('../src/collectors/tetragon-metrics');
const { startTetragonReadOnlyProxy } = require('../src/collectors/tetragon-readonly-proxy');
const { WorkloadProfile } = require('../src/profiler');
const { ThreatLevel } = require('../src/types');
const { ForensicExporter } = require('../src/custody');
const { ProfileLearner } = require('../src/profiling');
const { BehaviorEngine, DecisionEngine } = require('../src/intelligence');

const DEFAULT_COLLECTOR_ADDRESS = 'unix:///run/sentinel-runtime/tetragon-readonly.sock';

async function main(argv = process.argv.slice(2)) {
  const command = argv[0] || 'help';
  const options = parseOptions(argv.slice(1));
  switch (command) {
    case 'help': case '--help': case '-h': showHelp(); return 0;
    case 'status': printStatus(); return 0;
    case 'validate-v2': return validateV2Command(options);
    case 'verify-ledger': return verifyLedgerCommand(options);
    case 'audit-log': return auditLogCommand(options);
    case 'ingest-tetragon': return ingestTetragonCommand(options);
    case 'collect-tetragon': return collectTetragonCommand(options);
    case 'tetragon-readonly-proxy': return tetragonReadOnlyProxyCommand(options);
        case 'export-custody': return exportCustodyCommand(options);
    case 'verify-custody': return verifyCustodyCommand(options);
    case 'learn-profile': return learnProfileCommand(options);
    case 'demo': return runSafeDemo();
    default:
      console.error(`Unknown command: ${command}`);
      showHelp();
      return 2;
  }
}

function parseOptions(args) {
  const options = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith('--')) throw new Error(`Unexpected argument: ${arg}`);
    const key = arg.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const value = args[i + 1];
    if (value === undefined || value.startsWith('--')) options[key] = true;
    else { options[key] = value; i++; }
  }
  return options;
}

function defaultDbPath() {
  const home = process.env.USERPROFILE || process.env.HOME || process.cwd();
  return path.join(home, '.sentinel', 'runtime.sqlite');
}

function requireOption(options, key) {
  if (typeof options[key] !== 'string' || options[key].length === 0) throw new Error(`--${key.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)} is required`);
  return options[key];
}

function resolveBootId(options) {
  const hasInlineValue = Object.hasOwn(options, 'bootId');
  const hasFileValue = Object.hasOwn(options, 'bootIdFile');
  if (hasInlineValue && hasFileValue) throw new Error('Use either --boot-id or --boot-id-file, not both');
  if (!hasFileValue) return requireOption(options, 'bootId');

  const file = options.bootIdFile;
  if (typeof file !== 'string' || file.length === 0 || !path.isAbsolute(file)) throw new TypeError('--boot-id-file must be an absolute path');
  let fd;
  try {
    const noFollow = process.platform === 'win32' ? 0 : (fs.constants.O_NOFOLLOW || 0);
    fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new TypeError('--boot-id-file must refer to a regular file');
    if (stat.size > 4096) throw new RangeError('--boot-id-file exceeds 4096 bytes');
    const bytes = fs.readFileSync(fd);
    if (bytes.length > 4096) throw new RangeError('--boot-id-file exceeds 4096 bytes');
    const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value)) throw new TypeError('--boot-id-file must contain one canonical UUID');
    return value.toLowerCase();
  } catch (error) {
    if (error instanceof TypeError || error instanceof RangeError) throw error;
    throw new Error(`Cannot read --boot-id-file: ${error.message}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function showHelp() {
  console.log(`
Sentinel Runtime â€” local behavioral event processor (observe-only)

Commands:
  status                                      Show implemented capabilities and limits
  validate-v2 --input <event.json>            Validate one Event Contract v2 event
  ingest-tetragon --input <file.jsonl>         Ingest supported Tetragon JSONL events
    --host-id <stable-id> (--boot-id <trusted-id> | --boot-id-file <path>) [--profiles <json> --workload-id <id>] [--db <path>]
    [--batch-size <1..4096>] [--checkpoint-id <id> --resume] [--node-name <name>]
    [--sensor-version <version>] [--capture-process-arguments]
                                               Atomic file checkpoint/replay for an immutable input
  collect-tetragon [--address unix:///run/sentinel-runtime/tetragon-readonly.sock]
    --host-id <stable-id> (--boot-id <trusted-id> | --boot-id-file <path>) [--tls-ca <pem>]
    [--tls-client-cert <pem> --tls-client-key <pem>] [--expected-node-name <name>]
    [--max-events <n>] [--batch-size <n> --queue-capacity <n> --queue-mib <16..256>]
    [--profiles <json> --workload-id <id>] [--db <path>] [--capture-process-arguments]
    [--metrics-url http://127.0.0.1:2112/metrics --metrics-interval-ms <1000..300000>]
    [--metrics-tls-ca <pem> --metrics-tls-client-cert <pem> --metrics-tls-client-key <pem>]
                                               Stream pinned Tetragon gRPC v1.8.0 in observe-only mode
  tetragon-readonly-proxy [--upstream-address unix:///var/run/tetragon/tetragon.sock]
    [--listen-address unix:///run/sentinel-runtime/tetragon-readonly.sock] [--socket-mode 0600]
    [--tls-ca <pem> --tls-client-cert <pem> --tls-client-key <pem>]
                                               Expose only GetVersion and GetEvents through a protected Unix socket
  verify-ledger [--db <path>]                 Verify the local evidence hash chain
  audit-log [--db <path>] [--limit <n>]         Show recent records after integrity check
  export-custody --out-dir <dir> [--db <path>] [--host-id <id>] [--boot-id <id>]
                                               Export immutable, certified evidence bundle with SHA-256 manifest
  verify-custody --manifest <custody-manifest.json> [--db <evidence.sqlite>]
                                               Independently verify forensic integrity of an exported evidence bundle
  learn-profile --input <file.jsonl> [--name <workload_id>] [--out <profile.json>]
                                               Synthesize hardened WorkloadProfile from observed JSONL event baseline
  demo                                        Run an in-memory, non-destructive example

Tetragon ingestion writes validated Event Contract v2 objects for PROCESS_EXEC, PROCESS_EXIT,
and supported kprobe hooks. Process arguments are redacted by default; opt in with
--capture-process-arguments. The gRPC collector also records observed RateLimitInfo and unsupported event families. gRPC has no server replay cursor;
disconnections are recorded with an UNKNOWN gap state. TCP requires TLS; plaintext is
accepted only for a local Unix socket. No host enforcement or fleet manager is implemented.
`);
}

function printStatus() {
  console.log(JSON.stringify({
    product: 'sentinel-runtime',
    mode: 'observe-only',
    event_engine: 'deterministic correlation with bounded state',
    tetragon_jsonl: 'PROCESS_EXEC and PROCESS_EXIT materialized as validated Event Contract v2; optional atomic file checkpoints',
    tetragon_grpc: `Tetragon v1.8.0 stream collector; defaults to read-only proxy ${DEFAULT_COLLECTOR_ADDRESS}; bounded byte-counted queue; upstream replay unavailable`,
    tetragon_readonly_proxy: `Linux Unix-socket gateway exposes only GetVersion/GetEvents; default collector route is ${DEFAULT_COLLECTOR_ADDRESS}; its upstream socket authorization remains privileged`,
    tetragon_metrics: 'opt-in Prometheus v1.8.0 health/loss polling; strict loopback HTTP or verified HTTPS; aggregation-buffer drops are not applicable while aggregation is disabled',
    event_contract_v1: 'validator available',
    event_contract_v2: 'validator and native Tetragon materializer available; draft schema only',
    evidence_ledger: 'SQLite SHA-256 hash chain with atomic event/checkpoint commits and local verification',
    external_anchor: false,
    gRPC_sensor: 'v1.8.0 WSL2 live smoke passed; production distribution/kernel matrix pending',
    active_enforcement: 'not implemented',
    service_deployment: 'separate hardened systemd proxy and collector units available; installation and fleet management are operator-managed'
  }, null, 2));
}

async function tetragonReadOnlyProxyCommand(options) {
  if (options.tlsClientCert && !options.tlsClientKey || options.tlsClientKey && !options.tlsClientCert) {
    throw new Error('Proxy mTLS requires both --tls-client-cert and --tls-client-key');
  }
  const proxy = await startTetragonReadOnlyProxy({
    upstreamAddress: options.upstreamAddress || 'unix:///var/run/tetragon/tetragon.sock',
    listenAddress: options.listenAddress,
    socketMode: options.socketMode || '0600',
    tlsCa: options.tlsCa,
    tlsClientCert: options.tlsClientCert,
    tlsClientKey: options.tlsClientKey
  });
  const controller = new AbortController();
  const onSignal = signal => controller.abort(new Error(signal));
  const onSigint = () => onSignal('SIGINT');
  const onSigterm = () => onSignal('SIGTERM');
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);
  process.stdout.write(`${JSON.stringify({ component: 'tetragon-readonly-proxy', status: 'ready',
    upstream_address: proxy.upstreamAddress, listen_address: proxy.listenAddress,
    socket_mode: proxy.socketMode.toString(8).padStart(4, '0'), tetragon_version: proxy.tetragonVersion,
    allowed_methods: proxy.allowedMethods })}\n`);
  try {
    await new Promise(resolve => controller.signal.addEventListener('abort', resolve, { once: true }));
  } finally {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    await proxy.close(10000);
  }
  process.stdout.write(`${JSON.stringify({ component: 'tetragon-readonly-proxy', status: 'stopped' })}\n`);
  return 0;
}

function validateV2Command(options) {
  const input = requireOption(options, 'input');
  const event = readJsonFile(input);
  const result = validateEventV2(event);
  console.log(JSON.stringify(result, null, 2));
  return result.valid ? 0 : 1;
}

function openLedger(options) { return new EvidenceLedger(options.db || defaultDbPath()); }

function verifyLedgerCommand(options) {
  const dbPath = options.db || defaultDbPath();
  if (!fs.existsSync(dbPath)) {
    console.log(JSON.stringify({ valid: true, checked: 0, head_hash: '0'.repeat(64), empty: true }, null, 2));
    return 0;
  }
  const ledger = new EvidenceLedger(dbPath);
  const result = ledger.verifyIntegrity();
  ledger.close();
  console.log(JSON.stringify(result, null, 2));
  return result.valid ? 0 : 1;
}

function auditLogCommand(options) {
  const dbPath = options.db || defaultDbPath();
  if (!fs.existsSync(dbPath)) {
    console.log(`No hay registros todavÃ­a en ${dbPath}`);
    return 0;
  }
  const ledger = new EvidenceLedger(dbPath);
  let integrity;
  let records;
  let incidents;
  try {
    integrity = ledger.verifyIntegrity();
    const requestedLimit = options.limit === undefined ? 1000 :
      (typeof options.limit === 'string' && /^[1-9][0-9]*$/.test(options.limit) ? Number(options.limit) : NaN);
    if (!Number.isSafeInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 100000) {
      throw new RangeError('--limit must be an integer between 1 and 100000');
    }
    records = ledger.getRecords({ limit: requestedLimit }).map(row => {
      let payload;
      try { payload = JSON.parse(row.payload_json); } catch { payload = { invalid_payload_json: row.payload_json }; }
      return { ...row, payload };
    });
    incidents = ledger.getIncidents({ limit: requestedLimit });
  } finally {
    ledger.close();
  }
  console.log(JSON.stringify({ integrity, records, incidents }, null, 2));
  return integrity.valid ? 0 : 1;
}

async function ingestTetragonCommand(options) {
  const inputPath = requireOption(options, 'input');
  const hostId = requireOption(options, 'hostId');
  const bootId = resolveBootId(options);
  const checkpointId = options.checkpointId || null;
  if (checkpointId !== null && (typeof checkpointId !== 'string' || !/^[A-Za-z0-9._:-]{1,200}$/.test(checkpointId))) {
    throw new TypeError('--checkpoint-id must contain 1-200 letters, numbers, dot, underscore, colon, or hyphen');
  }
  if (options.resume && !checkpointId) throw new Error('--resume requires --checkpoint-id');
  const engine = new BehavioralSequenceEngine();
  const useIntelligence = options.intelligence === true;
  const behaviorEngine = useIntelligence ? new BehaviorEngine(options) : null;
  const decisionEngine = useIntelligence ? new DecisionEngine(options) : null;
  if (options.profiles) {
    const profiles = readJsonFile(options.profiles);
    const profileMap = profiles.profiles || profiles;
    if (!profileMap || typeof profileMap !== 'object' || Array.isArray(profileMap)) throw new Error('Profiles file must contain an object keyed by workload ID');
    for (const [workloadId, config] of Object.entries(profileMap)) {
      const wp = new WorkloadProfile(config);
      engine.registerProfile(workloadId, wp);
      if (behaviorEngine) behaviorEngine.registerProfile(workloadId, wp);
    }
    if (typeof options.workloadId !== 'string' || !Object.hasOwn(profileMap, options.workloadId)) {
      throw new Error('--profiles requires --workload-id matching an entry in the profiles file');
    }
  }
  const batchSize = options.batchSize === undefined ? 128 :
    (typeof options.batchSize === 'string' && /^[1-9][0-9]*$/.test(options.batchSize) ? Number(options.batchSize) : NaN);
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 4096) {
    throw new RangeError('--batch-size must be an integer between 1 and 4096');
  }
  const source = checkpointId ? await fingerprintImmutableJsonl(inputPath) : inspectJsonlInput(inputPath);
  const collectorSessionId = crypto.randomUUID();
  const sourceId = checkpointId ? `file:${checkpointId}` : null;
  const ledger = openLedger(options);
  const existingIntegrity = ledger.verifyIntegrity();
  if (!existingIntegrity.valid) {
    ledger.close();
    throw new Error(`Evidence ledger integrity failure at sequence ${existingIntegrity.sequence}: ${existingIntegrity.reason}`);
  }
  let previousCheckpoint = null;
  let startOffset = 0;
  if (sourceId) {
    previousCheckpoint = ledger.getLatestSourceCheckpoint(sourceId);
    if (previousCheckpoint && !options.resume) {
      ledger.close();
      throw new Error(`Checkpoint ${checkpointId} already exists; pass --resume to continue or choose a new --checkpoint-id`);
    }
    if (options.resume && !previousCheckpoint) {
      ledger.close();
      throw new Error(`No checkpoint exists for ${checkpointId}; remove --resume to start a new ingest`);
    }
    if (previousCheckpoint) {
      if (canonicalJson(previousCheckpoint.source_fingerprint) !== canonicalJson(source.fingerprint)) {
        ledger.close();
        throw new Error('Input fingerprint does not match the checkpoint; refusing unsafe resume');
      }
      if (previousCheckpoint.complete === true) {
        ledger.close();
        console.log(JSON.stringify({ input: source.path, host_id: hostId, boot_id: bootId, batch_size: batchSize,
          checkpoint_id: checkpointId, resumed_from_offset: previousCheckpoint.byte_offset,
          counts: { frames: 0, processed: 0, unsupported: 0, rejected: 0, unassessed: 0, decisions: 0, persisted_records: 0, duplicates_suppressed: 0 },
          already_complete: true, mode: 'observe-only' }, null, 2));
        return 0;
      }
      try { startOffset = parseCheckpointOffset(previousCheckpoint.byte_offset, source.size); }
      catch (error) { ledger.close(); throw error; }
    }
  }
  const framer = new JsonlFramer({ maxFrameBytes: 16 * 1024 * 1024, initialOffset: startOffset });
  const counts = { frames: 0, processed: 0, unsupported: 0, rejected: 0, unassessed: 0, decisions: 0, persisted_records: 0, duplicates_suppressed: 0 };
  const stream = fs.createReadStream(source.path, { start: startOffset });
  const pendingRecords = [];
  let checkpointOffset = startOffset;
  const makeCheckpoint = (offset, complete) => ({
    source_id: sourceId,
    source_fingerprint: source.fingerprint,
    cursor_kind: 'FILE_BYTES',
    byte_offset: String(offset),
    complete,
    input_path: source.path
  });
  const flushRecords = () => {
    if (pendingRecords.length === 0) return;
    if (sourceId) {
      const committed = ledger.recordEventsWithCheckpoint(pendingRecords, makeCheckpoint(checkpointOffset, false));
      counts.persisted_records += committed.events.length;
      counts.duplicates_suppressed += committed.duplicates;
    } else {
      const committed = ledger.recordEvents(pendingRecords);
      counts.persisted_records += committed.length;
      counts.duplicates_suppressed += pendingRecords.length - committed.length;
    }
    pendingRecords.length = 0;
  };
  const queueRecord = (event, decision, evidence) => {
    pendingRecords.push({ event, decision, evidence });
    if (pendingRecords.length >= batchSize) flushRecords();
  };
  const processFrames = async frames => {
    for (const frame of frames) {
      counts.frames++;
      checkpointOffset = frame.byteOffset + frame.byteLength;
      if (frame.decodeError) {
        counts.rejected++;
        queueRecord({ provider: 'tetragon', outcome: 'UTF8_REJECT' }, null, {
          inputPath: source.path, byteOffset: frame.byteOffset,
          byteLength: frame.byteLength, rawPayloadSha256: sha256(frame.raw), reason: frame.decodeError
        });
        continue;
      }
      let record;
      try {
        record = parseJsonRejectDuplicateKeys(frame.text);
      } catch (error) {
        counts.rejected++;
        queueRecord({ provider: 'tetragon', outcome: 'PARSER_REJECT' }, null, {
          inputPath: source.path, byteOffset: frame.byteOffset,
          byteLength: frame.byteLength, rawPayloadSha256: sha256(frame.raw), reason: error.message
        });
        continue;
      }
      let event;
      try {
        event = normalizeTetragonJson(record, frame.raw, { hostId, bootId, workloadId: options.workloadId || 'unassigned' });
      } catch (error) {
        counts.rejected++;
        queueRecord({ provider: 'tetragon', outcome: 'NORMALIZATION_REJECT' }, null, {
          inputPath: source.path, byteOffset: frame.byteOffset,
          byteLength: frame.byteLength, rawPayloadSha256: sha256(frame.raw), reason: error.message
        });
        continue;
      }
      if (!event.supported) {
        counts.unsupported++;
        queueRecord({ provider: 'tetragon', sourceType: event.sourceType, outcome: event.reason }, null, {
          inputPath: source.path, byteOffset: frame.byteOffset,
          byteLength: frame.byteLength, rawPayloadSha256: event.rawPayloadSha256
        });
        continue;
      }
      let eventV2;
      try {
        eventV2 = materializeTetragonEventV2(event, {
          hostId, bootId,
          collectorSessionId,
          sensorVersion: options.sensorVersion || 'unknown',
          transportProtocol: 'JSON_FILE_STREAM',
          transportAuthentication: 'NOT_APPLICABLE_LOCAL_FILE',
          nodeName: options.nodeName || null,
          nodeNameStatus: 'STATIC_CONFIGURED',
          sourceCursor: {
            inode: source.inode,
            byte_offset: String(frame.byteOffset),
            byte_length: frame.byteLength,
            payload_byte_length: frame.payloadByteLength,
            delimiter_byte_length: frame.delimiterByteLength,
            file_generation_id: '1',
            raw_payload_sha256: event.rawPayloadSha256,
            cursor_kind: 'FILE_BYTES',
            device_id: source.deviceId
          },
          captureProcessArguments: options.captureProcessArguments === true
        });
      } catch (error) {
        counts.rejected++;
        queueRecord({ provider: 'tetragon', event_type: 'EVENT_CONTRACT_V2_REJECT', source_type: event.sourceType,
          reason_code: error.code || 'MATERIALIZATION_ERROR' }, null, {
          inputPath: source.path, byteOffset: frame.byteOffset, byteLength: frame.byteLength,
          rawPayloadSha256: event.rawPayloadSha256, reason: error.message
        });
        continue;
      }
      let decision;
      if (useIntelligence) {
        const analysis = behaviorEngine.analyzeEvent(eventV2);
        decision = await decisionEngine.decide(analysis, eventV2);
      } else {
        decision = engine.processEvent(event);
      }
      queueRecord(eventV2, decision, {
        inputPath: source.path, byteOffset: frame.byteOffset,
        byteLength: frame.byteLength, payloadByteLength: frame.payloadByteLength,
        delimiterByteLength: frame.delimiterByteLength, rawPayloadSha256: event.rawPayloadSha256,
        normalized_from: event.sourceType, source_function: event.sourceFunction || null,
        tracing_policy_name: event.policyName || null, raw_arguments_preserved: false
      });
      counts.processed++;
      if (decision.threatLevel === ThreatLevel.UNASSESSED || decision.threatLevel === 'NORMAL') counts.unassessed++;
      if (decision.action && decision.action !== 'RECORD_ONLY') counts.decisions++;
      else if (decision.requestedAction && decision.requestedAction !== 'R1_OBSERVE_ONLY') counts.decisions++;
    }
  };
  try {
    for await (const chunk of stream) await processFrames(framer.push(chunk));
    await processFrames(framer.finish());
    if (sourceId) checkpointOffset = source.size;
    flushRecords();
    if (sourceId) {
      let after;
      try { after = await fingerprintImmutableJsonl(inputPath); } catch (error) {
        ledger.append('sensor_health', { timestamp: new Date().toISOString(), event: { provider: 'tetragon', event_type: 'FILE_SOURCE_CHANGED' }, details: { source_id: sourceId, reason: error.message } });
        throw error;
      }
      if (canonicalJson(after.fingerprint) !== canonicalJson(source.fingerprint)) {
        ledger.append('sensor_health', { timestamp: new Date().toISOString(), event: { provider: 'tetragon', event_type: 'FILE_SOURCE_CHANGED' }, details: { source_id: sourceId, reason: 'INPUT_FINGERPRINT_CHANGED_DURING_INGEST' } });
        throw new Error('Input changed while it was being ingested; checkpoint remains incomplete and cannot be resumed against a different fingerprint');
      }
      const completed = ledger.recordEventsWithCheckpoint([], makeCheckpoint(source.size, true));
      counts.checkpoint_sequence = completed.checkpoint.sequence;
    }
  } finally {
    ledger.close();
  }
  console.log(JSON.stringify({ input: source.path, host_id: hostId, boot_id: bootId, batch_size: batchSize,
    checkpoint_id: checkpointId, resumed_from_offset: startOffset, source_fingerprint: checkpointId ? source.fingerprint : undefined,
    counts, mode: 'observe-only' }, null, 2));
  return counts.rejected > 0 ? 1 : 0;
}

async function collectTetragonCommand(options) {
  const hostId = requireOption(options, 'hostId');
  const bootId = resolveBootId(options);
  const profiles = options.profiles ? readJsonFile(options.profiles) : null;
  const profileMap = profiles ? (profiles.profiles || profiles) : null;
  if (profileMap && (typeof profileMap !== 'object' || Array.isArray(profileMap))) throw new Error('Profiles file must contain an object keyed by workload ID');
  if (profileMap && (typeof options.workloadId !== 'string' || !Object.hasOwn(profileMap, options.workloadId))) {
    throw new Error('--profiles requires --workload-id matching an entry in the profiles file');
  }
  const numberOption = (key, fallback, min, max) => {
    if (options[key] === undefined) return fallback;
    const value = typeof options[key] === 'string' && /^[1-9][0-9]*$/.test(options[key]) ? Number(options[key]) : NaN;
    if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`--${key.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)} must be between ${min} and ${max}`);
    return value;
  };
  const address = options.address || DEFAULT_COLLECTOR_ADDRESS;
  if (options.metricsUrl) validateMetricsPeer(address, options.metricsUrl);
  else if (options.metricsTlsCa || options.metricsTlsClientCert || options.metricsTlsClientKey) throw new Error('Metrics TLS options require --metrics-url');
  const maxEvents = options.maxEvents === undefined ? null : numberOption('maxEvents', null, 1, Number.MAX_SAFE_INTEGER);
  const ledger = openLedger(options);
  const integrity = ledger.verifyIntegrity();
  if (!integrity.valid) {
    ledger.close();
    throw new Error(`Evidence ledger integrity failure at sequence ${integrity.sequence}: ${integrity.reason}`);
  }
  const abortController = new AbortController();
  const onSigint = () => abortController.abort(new Error('SIGINT'));
  const onSigterm = () => abortController.abort(new Error('SIGTERM'));
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);
  let result;
  try {
    let verifiedSensorVersion = null;
    const collector = new TetragonGrpcCollector({
      ledger, hostId, bootId, workloadId: options.workloadId || 'unassigned', profiles: profileMap,
      expectedNodeName: options.expectedNodeName || null, maxEvents,
      captureProcessArguments: options.captureProcessArguments === true,
      intelligence: options.intelligence === true,
      batchSize: numberOption('batchSize', 128, 1, 4096),
      queueCapacity: numberOption('queueCapacity', 512, 16, 16384),
      queueByteCapacity: numberOption('queueMib', 64, 16, 256) * 1024 * 1024,
      flushIntervalMs: numberOption('flushIntervalMs', 1000, 10, 60000),
      connectionFactory: async () => createTetragonConnection({
        address, tlsCa: options.tlsCa, tlsClientCert: options.tlsClientCert, tlsClientKey: options.tlsClientKey
      }),
      onStatus: status => {
        if (status.type === 'connected' && /^v?1\.8\.0$/.test(status.tetragon_version || '')) verifiedSensorVersion = status.tetragon_version;
        else if (status.type === 'reconnecting') verifiedSensorVersion = null;
        process.stderr.write(`${JSON.stringify({ component: 'tetragon-collector', ...status })}\n`);
      }
    });
    let metricsTask = null;
    let metricsFailure = null;
    if (options.metricsUrl) {
      const metricsCollector = new TetragonMetricsCollector({
        ledger, hostId, bootId, nodeName: options.expectedNodeName,
        url: options.metricsUrl,
        intervalMs: numberOption('metricsIntervalMs', 5000, 1000, 300000),
        timeoutMs: numberOption('metricsTimeoutMs', 3000, 250, 30000),
        tls: {
          ca: options.metricsTlsCa,
          cert: options.metricsTlsClientCert,
          key: options.metricsTlsClientKey
        },
        getSensorVersion: () => verifiedSensorVersion,
        onStatus: status => process.stderr.write(`${JSON.stringify({ component: 'tetragon-metrics', ...status })}\n`)
      });
      metricsTask = metricsCollector.run(abortController.signal).catch(error => {
        metricsFailure = error;
        if (!abortController.signal.aborted) abortController.abort(error);
      });
    }
    try {
      result = await collector.run(abortController.signal);
    } finally {
      if (metricsTask) {
        if (!abortController.signal.aborted) abortController.abort(new Error('Tetragon gRPC collector stopped'));
        await metricsTask;
      }
    }
    if (metricsFailure) throw metricsFailure;
  } finally {
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    ledger.close();
  }
  console.log(JSON.stringify({ ...result, address, metrics_polling_enabled: Boolean(options.metricsUrl), metrics_url: options.metricsUrl || null, mode: 'observe-only' }, null, 2));
  return 0;
}

function inspectJsonlInput(inputPath) {
  const resolved = path.resolve(inputPath);
  const stat = fs.lstatSync(resolved, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink()) throw new TypeError('JSONL input must be a regular non-symlink file');
  if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('JSONL input exceeds the supported byte-offset range');
  return { path: resolved, size: Number(stat.size), deviceId: String(stat.dev), inode: String(stat.ino) };
}

async function fingerprintImmutableJsonl(inputPath) {
  const initial = inspectJsonlInput(inputPath);
  const before = fs.statSync(initial.path, { bigint: true });
  const signature = stat => [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].map(String).join(':');
  const beforeSignature = signature(before);
  const digest = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(initial.path)) digest.update(chunk);
  const after = fs.statSync(initial.path, { bigint: true });
  if (signature(after) !== beforeSignature) throw new Error('JSONL input changed while its source fingerprint was being computed');
  return {
    path: initial.path,
    size: Number(before.size),
    deviceId: String(before.dev),
    inode: String(before.ino),
    fingerprint: {
      path: initial.path,
      device_id: String(before.dev),
      inode: String(before.ino),
      size: String(before.size),
      sha256: digest.digest('hex')
    }
  };
}

function parseCheckpointOffset(value, maximum) {
  const text = typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : value;
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]*)$/.test(text)) throw new Error('Checkpoint byte offset is malformed');
  const offset = Number(text);
  if (!Number.isSafeInteger(offset) || offset > maximum) throw new Error('Checkpoint byte offset exceeds the immutable input size');
  return offset;
}

function readJsonFile(filePath) {
  const maxBytes = 16 * 1024 * 1024;
  const stats = fs.statSync(filePath);
  if (!stats.isFile() || stats.size > maxBytes) throw new RangeError(`JSON input must be a regular file no larger than ${maxBytes} bytes`);
  const bytes = fs.readFileSync(filePath);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  return parseJsonRejectDuplicateKeys(text);
}

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function exportCustodyCommand(options) {
  const dbPath = options.db || defaultDbPath();
  const outDir = options.outDir || options.outdir;
  if (!outDir) throw new Error('--out-dir is required for export-custody');

  const result = ForensicExporter.exportBundle({
    dbPath,
    outDir: path.resolve(outDir),
    hostId: options.hostId || options.host || 'unassigned-host',
    bootId: options.bootId || options.boot || 'unassigned-boot',
    signingKey: options.signKey || options.signingKey || null
  });

  console.log(JSON.stringify(result, null, 2));
  return 0;
}

function verifyCustodyCommand(options) {
  const manifestPath = options.manifest;
  if (!manifestPath) throw new Error('--manifest is required for verify-custody');

  const result = ForensicExporter.verifyBundle(path.resolve(manifestPath), options.db ? path.resolve(options.db) : null);
  console.log(JSON.stringify(result, null, 2));
  return result.certified ? 0 : 1;
}

async function learnProfileCommand(options) {
  const input = requireOption(options, 'input');
  const workloadId = options.name || options.workloadId || 'learned-workload';
  const outPath = options.out || options.output || `${workloadId}-profile.json`;

  const learner = new ProfileLearner({ workloadId });
  const profile = await learner.learnFromJsonl(path.resolve(input));

  fs.writeFileSync(path.resolve(outPath), JSON.stringify(profile, null, 2) + '\n', 'utf8');
  console.log(JSON.stringify({
    learned: true,
    workloadId: profile.workload_id,
    eventsAnalyzed: profile.events_analyzed,
    allowedBinariesCount: profile.allowed_binaries.length,
    allowedNetworkCount: profile.allowed_network_destinations.length,
    savedTo: path.resolve(outPath)
  }, null, 2));
  return 0;
}
function runSafeDemo() {
  const engine = new BehavioralSequenceEngine();
  const event = {
    eventId: 'demo-event-1', eventType: 'PROCESS_EXEC', workloadId: 'demo',
    hostIdentity: { hostId: 'demo-host', bootId: 'demo-boot' },
    processIdentity: { execId: 'demo-exec', pid: 1 },
    data: { binary: '/usr/bin/example' }
  };
  console.log(JSON.stringify({ mode: 'observe-only', decision: engine.processEvent(event) }, null, 2));
  return 0;
}

if (require.main === module) {
  main().then(code => { process.exitCode = code; }).catch(error => {
    console.error(`sentinel-runtime: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseOptions, resolveBootId };
