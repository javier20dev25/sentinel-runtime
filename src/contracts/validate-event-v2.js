'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Ajv2020 = require('ajv/dist/2020');
const {
  rawProviderEventKey,
  rawPartialProcessEventKey,
  syntheticObservabilityEventKey,
  canonicalPayloadSha256
} = require('./event-keys');

const schemaPath = path.resolve(__dirname, '../../schemas/runtime-event-v2.schema.json');
const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false, coerceTypes: false, useDefaults: false, removeAdditional: false });
const validateSchema = ajv.compile(schema);
const MAX_UINT64 = 18446744073709551615n;
const MAX_SAFE_INTEGER = BigInt(Number.MAX_SAFE_INTEGER);
const UINT64_FIELDS = new Set([
  'source_timestamp', 'provider_observation_timestamp', 'provider_event_timestamp', 'ingest_timestamp',
  'process_start_time', 'pid_ns', 'mnt_ns', 'net_ns', 'inode', 'device_id', 'byte_offset',
  'file_generation_id', 'sequence_number', 'producer_sequence_number', 'uptime_seconds', 'heartbeat_timestamp', 'offset',
  'dropped_count', 'count', 'bytes_accepted_by_kernel', 'cgroup_id', 'namespace_id'
]);

function validateEventV2(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return { valid: false, schema_version: null, event_family: null, errors: [{ path: '#', keyword: 'type', message: 'Event must be a non-null object' }], warnings: [] };
  }
  const validSchema = validateSchema(event);
  const errors = validSchema ? [] : (validateSchema.errors || []).map(error => ({
    path: error.instancePath || '#',
    keyword: error.keyword,
    message: error.message || 'Schema validation failed',
    params: error.params || {}
  }));
  const warnings = [];

  validateUint64Tree(event, '#', errors);
  validateCursor(event.source_cursor, event.sensor_metadata?.transport_protocol, errors);
  validateLossMetrics(event.loss_metrics, warnings);
  validateEventSemantics(event, errors, warnings);
  validateSourceEventKey(event, errors);

  return {
    valid: errors.length === 0,
    schema_version: event.schema_version || null,
    event_family: event.event_type || null,
    errors,
    warnings
  };
}

function validateUint64Tree(value, currentPath, errors) {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateUint64Tree(item, `${currentPath}/${index}`, errors));
    return;
  }
  if (typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (isUint64Field(key)) validateUint64(child, `${currentPath}/${escapePointer(key)}`, errors);
    else validateUint64Tree(child, `${currentPath}/${escapePointer(key)}`, errors);
  }
}

function isUint64Field(key) {
  return UINT64_FIELDS.has(key);
}

function validateUint64(value, fieldPath, errors) {
  if (value === null || value === undefined) return;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) errors.push({ path: fieldPath, keyword: 'precisionRisk', message: 'uint64 numeric values must be non-negative safe integers; use canonical decimal strings above 2^53-1' });
    return;
  }
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    errors.push({ path: fieldPath, keyword: 'uint64Format', message: 'Expected a canonical unsigned decimal integer' });
    return;
  }
  try {
    if (BigInt(value) > MAX_UINT64) errors.push({ path: fieldPath, keyword: 'maximumUint64', message: 'Value exceeds 2^64-1' });
    else if (BigInt(value) <= MAX_SAFE_INTEGER) return;
  } catch {
    errors.push({ path: fieldPath, keyword: 'uint64Format', message: 'Invalid unsigned decimal integer' });
  }
}

function validateCursor(cursor, transport, errors) {
  if (!cursor || typeof cursor !== 'object') return;
  const cursorKind = cursor.cursor_kind || 'FILE_BYTES';
  if (cursorKind === 'FILE_BYTES') {
    if (cursor.device_id !== undefined && typeof cursor.device_id !== 'string') {
      errors.push({ path: '#/source_cursor/device_id', keyword: 'type', message: 'device_id must use canonical decimal string representation' });
    }
    if (Number.isInteger(cursor.byte_length) && Number.isInteger(cursor.payload_byte_length) && Number.isInteger(cursor.delimiter_byte_length) &&
        cursor.byte_length !== cursor.payload_byte_length + cursor.delimiter_byte_length) {
      errors.push({ path: '#/source_cursor/byte_length', keyword: 'cursorInvariant', message: 'byte_length must equal payload_byte_length + delimiter_byte_length' });
    }
    if (transport && !['JSON_FILE_STREAM', 'SYNTHETIC_MEMORY'].includes(transport)) {
      errors.push({ path: '#/source_cursor/cursor_kind', keyword: 'cursorTransportMismatch', message: 'File byte cursors cannot identify gRPC stream position' });
    }
  } else if (cursorKind === 'GRPC_SEQUENCE') {
    if (transport && !['GRPC_UNIX_SOCKET', 'GRPC_TCP'].includes(transport)) errors.push({ path: '#/source_cursor/cursor_kind', keyword: 'cursorTransportMismatch', message: 'gRPC sequence cursor requires a gRPC transport' });
    if (!cursor.stream_epoch || cursor.sequence_number === undefined) errors.push({ path: '#/source_cursor', keyword: 'required', message: 'GRPC_SEQUENCE requires stream_epoch and sequence_number' });
  } else if (cursorKind === 'IN_MEMORY_SEQUENCE') {
    if (!cursor.stream_epoch || cursor.sequence_number === undefined) errors.push({ path: '#/source_cursor', keyword: 'required', message: 'IN_MEMORY_SEQUENCE requires stream_epoch and sequence_number' });
    if (transport && transport !== 'SYNTHETIC_MEMORY') errors.push({ path: '#/source_cursor/cursor_kind', keyword: 'cursorTransportMismatch', message: 'IN_MEMORY_SEQUENCE requires the in-memory transport' });
  } else if (cursorKind === 'METRICS_SCRAPE') {
    if (transport && !['PROMETHEUS_HTTP', 'PROMETHEUS_HTTPS'].includes(transport)) errors.push({ path: '#/source_cursor/cursor_kind', keyword: 'cursorTransportMismatch', message: 'METRICS_SCRAPE requires a Prometheus HTTP transport' });
    if (!cursor.scrape_epoch || cursor.sequence_number === undefined || !cursor.scrape_status) errors.push({ path: '#/source_cursor', keyword: 'required', message: 'METRICS_SCRAPE requires scrape_epoch, sequence_number, and scrape_status' });
    if (cursor.scrape_status === 'TRANSPORT_ERROR') {
      if (cursor.raw_payload_sha256 !== null || cursor.response_status !== null) errors.push({ path: '#/source_cursor', keyword: 'metricsCursorInvariant', message: 'A transport failure without an HTTP response must preserve null body hash and status' });
    } else if (cursor.scrape_status === 'RESPONSE_TOO_LARGE') {
      if (cursor.raw_payload_sha256 !== null || !Number.isInteger(cursor.response_status)) errors.push({ path: '#/source_cursor', keyword: 'metricsCursorInvariant', message: 'An oversized response preserves HTTP status and a null hash because the complete body was not captured' });
    } else if (typeof cursor.raw_payload_sha256 !== 'string' || !Number.isInteger(cursor.response_status)) {
      errors.push({ path: '#/source_cursor', keyword: 'metricsCursorInvariant', message: 'An HTTP metrics response requires a response status and hash of exact response bytes' });
    }
  } else {
    errors.push({ path: '#/source_cursor/cursor_kind', keyword: 'enum', message: 'Unknown cursor_kind' });
  }
}

function validateLossMetrics(lossMetrics, warnings) {
  if (!lossMetrics || typeof lossMetrics !== 'object') return;
  for (const [domain, metric] of Object.entries(lossMetrics)) {
    if (!metric || typeof metric !== 'object') continue;
    if (metric.state === 'UNKNOWN' || metric.state === 'UNAVAILABLE') warnings.push(`Loss metric ${domain} is ${metric.state}; observation completeness is degraded.`);
    if (metric.state === 'MEASURED_LOWER_BOUND') warnings.push(`Loss metric ${domain} is a lower bound; the true loss may be higher.`);
    if (metric.state === 'MEASURED' && metric.count !== null && metric.count !== undefined) {
      try {
        if (BigInt(String(metric.count)) > 0n) warnings.push(`Loss metric ${domain} reports dropped events; absence-based conclusions are unsafe.`);
      } catch { /* Structural validator reports malformed counts without throwing. */ }
    }
  }
}

function validateEventSemantics(event, errors, warnings) {
  if (event.source_cursor?.cursor_kind === 'METRICS_SCRAPE') {
    const protocol = event.sensor_metadata?.transport_protocol;
    const auth = event.sensor_metadata?.transport_authentication;
    if (protocol === 'PROMETHEUS_HTTP' && auth !== 'LOOPBACK_HTTP_UNAUTHENTICATED') errors.push({ path: '#/sensor_metadata/transport_authentication', keyword: 'transportAuthentication', message: 'Plain HTTP metrics are allowed only for a configured loopback endpoint' });
    if (protocol === 'PROMETHEUS_HTTPS' && !['TLS_SERVER_AUTH', 'MUTUAL_TLS'].includes(auth)) errors.push({ path: '#/sensor_metadata/transport_authentication', keyword: 'transportAuthentication', message: 'HTTPS metrics require verified TLS server authentication' });
    if (!['EVENT_LOSS', 'SENSOR_HEALTH'].includes(event.event_type)) errors.push({ path: '#/event_type', keyword: 'metricsEventType', message: 'Metrics scrapes may produce only EVENT_LOSS or SENSOR_HEALTH' });
    if (event.source_provider !== 'tetragon') errors.push({ path: '#/source_provider', keyword: 'metricsProvider', message: 'Tetragon metrics observations must identify Tetragon as their provider' });
    if (!/^v?1\.8\.0$/.test(event.sensor_metadata?.sensor_version || '')) errors.push({ path: '#/sensor_metadata/sensor_version', keyword: 'metricsVersion', message: 'The v1.8.0 metrics adapter requires a version verified by the pinned gRPC collector' });
    const producerSequence = event.sensor_metadata?.producer_sequence_number;
    if (producerSequence !== undefined && String(event.source_cursor.sequence_number) !== String(producerSequence)) errors.push({ path: '#/source_cursor/sequence_number', keyword: 'metricsCursorSequence', message: 'Metrics cursor sequence must match the synthetic producer sequence' });
    if (event.event_type === 'SENSOR_HEALTH') {
      const payload = event.payload || {};
      if (payload.uptime_status === undefined || payload.coverage_status === undefined || !Array.isArray(payload.counter_reset_domains) || !Array.isArray(payload.counter_unverifiable_domains) || !Array.isArray(payload.unavailable_counters)) errors.push({ path: '#/payload', keyword: 'metricsHealthProvenance', message: 'Metrics-backed health events must record uptime, coverage, counter reset/unverifiable, and unavailable-counter status' });
    }
  }
  const process = event.process_identity || {};
  if (process.exec_id === null) {
    if (process.exec_id_capture_status !== 'UNAVAILABLE_IN_SENSOR' || process.identity_quality !== 'PARTIAL_RECONSTRUCTED' || !Number.isInteger(process.pid)) {
      errors.push({ path: '#/process_identity', keyword: 'partialProcessIdentity', message: 'Missing exec_id requires explicit sensor absence, partial identity quality, and an observed PID' });
    }
  } else if (process.exec_id_capture_status === 'UNAVAILABLE_IN_SENSOR') {
    errors.push({ path: '#/process_identity/exec_id_capture_status', keyword: 'captureStatus', message: 'exec_id cannot be marked unavailable when a value is present' });
  }
  if (process.executable_path === null && process.executable_path_capture_status !== 'UNAVAILABLE_IN_SENSOR') {
    errors.push({ path: '#/process_identity/executable_path_capture_status', keyword: 'captureStatus', message: 'A missing executable path requires explicit sensor absence' });
  } else if (typeof process.executable_path === 'string' && process.executable_path_capture_status === 'UNAVAILABLE_IN_SENSOR') {
    errors.push({ path: '#/process_identity/executable_path_capture_status', keyword: 'captureStatus', message: 'executable_path cannot be marked unavailable when a value is present' });
  }
  if (process.credentials_capture_status === 'COLLISION_UNRESOLVED') {
    if (process.process_uid_raw === undefined || process.credentials_euid_raw === undefined) {
      errors.push({ path: '#/process_identity', keyword: 'credentialCollision', message: 'Unresolved EUID collision must preserve both raw values' });
    }
    warnings.push('Credential identity collision is unresolved and must not be used as an exclusive enforcement predicate.');
  }
  if (event.event_type === 'CAPABILITY_CHECK') warnings.push('CAPABILITY_CHECK proves an authorization check, not a capability modification.');
  if (event.event_type === 'FILE_OPEN_ATTEMPT' && event.payload?.flags_capture_status === 'UNAVAILABLE_POINTER_NOT_DEREFERENCED' &&
      (event.payload.flags !== null || event.payload.mode !== null)) {
    errors.push({ path: '#/payload', keyword: 'pointerProvenance', message: 'Flags/mode cannot be populated when open_how pointer contents were not resolved' });
  }
  if (event.event_type === 'FILE_OPEN_RESULT') {
    const code = event.payload?.return_code;
    const expectedFd = Number.isInteger(code) && code >= 0 ? code : null;
    const expectedErrno = Number.isInteger(code) && code < 0 ? -code : null;
    if (event.payload?.fd !== expectedFd || event.payload?.errno !== expectedErrno) errors.push({ path: '#/payload', keyword: 'kernelReturnInvariant', message: 'fd and errno must be derived without replacing the raw kernel return code' });
  }
  if (event.event_type === 'NETWORK_CONNECT_RESULT') {
    warnings.push('A local connect result does not establish peer handshake completion or data receipt.');
    const code = event.payload?.return_code;
    const expectedErrno = Number.isInteger(code) && code < 0 ? -code : null;
    if (event.payload?.errno !== expectedErrno) errors.push({ path: '#/payload/errno', keyword: 'kernelReturnInvariant', message: 'errno must be null for non-negative return codes or -return_code for negative codes' });
  }
  if (event.event_type === 'NETWORK_SEND_RESULT') {
    warnings.push('Local socket acceptance does not establish peer receipt; do not label it confirmed exfiltration.');
    const code = event.payload?.return_code;
    const expectedBytes = Number.isInteger(code) && code > 0 ? String(code) : 0;
    if (String(event.payload?.bytes_accepted_by_kernel) !== expectedBytes) errors.push({ path: '#/payload/bytes_accepted_by_kernel', keyword: 'kernelReturnInvariant', message: 'Locally accepted byte count must match the positive tcp_sendmsg return; failed/zero returns accept zero bytes' });
  }
  if (event.source_provider === 'synthetic_lab') warnings.push('Synthetic fixture telemetry is not evidence of a kernel event.');
}

function validateSourceEventKey(event, errors) {
  if (typeof event.source_event_key !== 'string') return;
  try {
    const hostId = event.host_identity?.host_id;
    const bootId = event.host_identity?.boot_id;
    let expected;
    if (['EVENT_LOSS', 'SENSOR_HEALTH'].includes(event.event_type)) {
      const metadata = event.sensor_metadata || {};
      expected = syntheticObservabilityEventKey({
        hostId, bootId, producerId: metadata.producer_id, producerEpoch: metadata.producer_epoch,
        sequenceNumber: metadata.producer_sequence_number, payloadSha256: canonicalPayloadSha256(event.payload)
      });
    } else {
      if (typeof event.source_cursor?.raw_payload_sha256 !== 'string') throw new TypeError('Raw provider events require raw_payload_sha256');
      const process = event.process_identity || {};
      if (typeof process.exec_id === 'string' && process.exec_id.length > 0) {
        expected = rawProviderEventKey({
          hostId, bootId, execId: process.exec_id,
          eventType: event.event_type, sourceTimestamp: event.timestamps?.source_timestamp,
          rawPayloadSha256: event.source_cursor?.raw_payload_sha256
        });
      } else if (process.exec_id === null && process.exec_id_capture_status === 'UNAVAILABLE_IN_SENSOR') {
        expected = rawPartialProcessEventKey({
          hostId, bootId, pid: process.pid, processStartTime: process.process_start_time,
          eventType: event.event_type, sourceTimestamp: event.timestamps?.source_timestamp,
          rawPayloadSha256: event.source_cursor?.raw_payload_sha256
        });
      } else {
        throw new TypeError('Raw provider process events require exec_id or an explicit PID/start-time identity fallback');
      }
    }
    if (expected !== event.source_event_key.toLowerCase()) errors.push({ path: '#/source_event_key', keyword: 'eventKeyMismatch', message: 'source_event_key does not match its domain-separated identity profile' });
  } catch (error) {
    errors.push({ path: '#/source_event_key', keyword: 'eventKeyInputs', message: `Cannot verify source event identity: ${error.message}` });
  }
}

function escapePointer(value) {
  return String(value).replace(/~/g, '~0').replace(/\//g, '~1');
}

module.exports = { validateEventV2, schema, validateSchema, validateUint64, validateCursor };
