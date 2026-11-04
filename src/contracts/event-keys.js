'use strict';

const crypto = require('node:crypto');
const { canonicalJson } = require('./canonical-json');

const DOMAIN = Object.freeze({
  RAW_PROVIDER_EVENT: 'SR1|RAW_PROVIDER_EVENT',
  RAW_PARTIAL_PROCESS_EVENT: 'SR1|RAW_PARTIAL_PROCESS_EVENT',
  DERIVED_CORRELATED_EVENT: 'SR1|DERIVED_CORRELATED_EVENT',
  SYNTHETIC_OBSERVABILITY_EVENT: 'SR1|SYNTHETIC_OBSERVABILITY_EVENT',
  // Backwards compatibility aliases
  RAW: 'SR1|RAW_PROVIDER_EVENT',
  RAW_PID_START: 'SR1|RAW_PARTIAL_PROCESS_EVENT',
  DERIVED: 'SR1|DERIVED_CORRELATED_EVENT',
  SYNTHETIC: 'SR1|SYNTHETIC_OBSERVABILITY_EVENT'
});

function lengthPrefix(value) {
  if (typeof value !== 'string') throw new TypeError('Length-prefixed event-key components must already be canonical strings');
  const bytes = Buffer.from(value, 'utf8');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([length, bytes]);
}

function hashParts(parts) {
  return crypto.createHash('sha256').update(Buffer.concat(parts.map(lengthPrefix))).digest('hex');
}

function rawProviderEventKey({ hostId, bootId, execId, eventType, sourceTimestamp, rawPayloadSha256 }) {
  requireStrings({ hostId, bootId, execId, eventType });
  const timestamp = normalizeUint64Component(sourceTimestamp, 'sourceTimestamp');
  const digest = normalizeSha256(rawPayloadSha256, 'rawPayloadSha256');
  return hashParts([DOMAIN.RAW_PROVIDER_EVENT, hostId, bootId, execId, eventType, timestamp, digest]);
}

/**
 * Computes a domain-separated cryptographic identity key for Profile D —
 * RAW_PARTIAL_PROCESS_EVENT.
 *
 * Applies to raw provider events that include Process.pid and Process.start_time
 * but omit Process.exec_id. The key uses PID and process start time as the
 * process-identity anchor in place of exec_id.
 *
 * Formula:
 *   SHA-256(LP("SR1|RAW_PARTIAL_PROCESS_EVENT") || LP(host_id) || LP(boot_id) ||
 *           LP(pid) || LP(process_start_time) || LP(event_type) ||
 *           LP(source_timestamp) || LP(raw_payload_sha256))
 *
 * Where LP(x) = 8-byte unsigned big-endian byte length of UTF-8(x) || UTF-8(x).
 *
 * --- processStartTime semantics ---
 *
 * Provider source: This value MUST come from the `start_time` field of Tetragon's
 * `Process` protobuf message (a `google.protobuf.Timestamp`), converted to
 * nanoseconds since the Unix epoch. It is NOT directly `task_struct->start_time`
 * (which is nanoseconds since boot). Do not assert direct kernel semantics without
 * a demonstrated mapping from the Tetragon proto layer.
 *
 * Exact integer conversion: `google.protobuf.Timestamp` has `seconds` (int64) and
 * `nanos` (int32) fields. The canonical uint64 value is:
 *   BigInt(seconds) * 1_000_000_000n + BigInt(nanos)
 * Values must be represented as canonical decimal strings (no leading zeros, no sign).
 *
 * Zero processStartTime semantics: A value of "0" is accepted structurally as a
 * uint64 boundary value, but does NOT constitute a valid provider-observed process
 * identity anchor. Tests using processStartTime="0" must be classified as structural
 * boundary vectors, not valid captured event vectors.
 *
 * --- pid serialization ---
 *
 * `pid` is a uint32 value in range [0, 4294967295]. When passed as a string, it
 * must be a canonical decimal string (no leading zeros, no sign prefix). When passed
 * as a number, it must be a safe integer in [0, 4294967295].
 *
 * --- rawPayloadSha256 semantics ---
 *
 * For gRPC stream events: the SHA-256 is computed over the original
 * protobuf-serialized bytes of the GetEventsResponse message as received from
 * Tetragon, preserving unknown fields, excluding the gRPC wire framing header
 * (the 5-byte length-prefixed message frame: 1 compression flag byte + 4 big-endian
 * length bytes). These are the bytes preserved by the read-only proxy before any
 * deserialization.
 *
 * For JSONL events: the SHA-256 is computed over the UTF-8 bytes of the raw JSON
 * line, excluding any line terminator (CR, LF, or CRLF).
 *
 * The hex representation must use lowercase characters only. Leading zeros must be
 * preserved to maintain exactly 64 hex characters.
 *
 * @param {object} params
 * @param {string} params.hostId       Non-empty host identity string.
 * @param {string} params.bootId       Non-empty boot identity string.
 * @param {number|string|bigint} params.pid  uint32 PID [0, 4294967295].
 * @param {number|string|bigint} params.processStartTime  uint64 nanoseconds since Unix epoch.
 * @param {string} params.eventType    Non-empty Sentinel canonical event type.
 * @param {number|string|bigint} params.sourceTimestamp   uint64 nanoseconds since Unix epoch.
 * @param {string} params.rawPayloadSha256  64-char lowercase hex SHA-256 digest.
 * @returns {string} 64-char lowercase hex SHA-256 key.
 */
function rawPartialProcessEventKey({ hostId, bootId, pid, processStartTime, eventType, sourceTimestamp, rawPayloadSha256 }) {
  requireStrings({ hostId, bootId, eventType });
  // Reject negative pid before uint64 normalization so the error identifies the uint32 domain.
  if (typeof pid === 'number' && pid < 0) throw new RangeError('pid must be a uint32 (0\u20134294967295)');
  if (typeof pid === 'bigint' && pid < 0n) throw new RangeError('pid must be a uint32 (0\u20134294967295)');
  const processId = normalizeUint64Component(pid, 'pid');
  if (BigInt(processId) > 0xffffffffn) throw new RangeError('pid must be a uint32 (0\u20134294967295)');
  const processStart = normalizeUint64Component(processStartTime, 'processStartTime');
  const timestamp = normalizeUint64Component(sourceTimestamp, 'sourceTimestamp');
  const digest = normalizeSha256(rawPayloadSha256, 'rawPayloadSha256');
  return hashParts([DOMAIN.RAW_PARTIAL_PROCESS_EVENT, hostId, bootId, processId, processStart, eventType, timestamp, digest]);
}

function derivedCorrelatedEventKey({
  hostId,
  bootId,
  correlationRuleId,
  ruleVersion,
  schemaVersion = '2.0.0',
  resultType = 'CORRELATED_EVENT',
  primaryEventKey,
  secondaryEventKey,
  constituentEventKeys
}) {
  requireStrings({ hostId, bootId, correlationRuleId, ruleVersion, schemaVersion, resultType });
  let keys = [];
  if (Array.isArray(constituentEventKeys) && constituentEventKeys.length > 0) {
    keys = constituentEventKeys.map((k, i) => normalizeSha256(k, `constituentEventKeys[${i}]`));
  } else {
    const primary = normalizeSha256(primaryEventKey, 'primaryEventKey');
    const secondary = normalizeSha256(secondaryEventKey, 'secondaryEventKey');
    keys = [primary, secondary];
  }
  return hashParts([
    DOMAIN.DERIVED_CORRELATED_EVENT,
    hostId,
    bootId,
    correlationRuleId,
    ruleVersion,
    schemaVersion,
    resultType,
    ...keys
  ]);
}

function syntheticObservabilityEventKey({
  hostId,
  bootId,
  producerId,
  producerEpoch,
  sequenceNumber,
  eventType = 'SYNTHETIC_OBSERVABILITY_EVENT',
  payloadSha256
}) {
  requireStrings({ hostId, bootId, producerId, producerEpoch, eventType });
  const sequence = normalizeUint64Component(sequenceNumber, 'sequenceNumber');
  const digest = normalizeSha256(payloadSha256, 'payloadSha256');
  return hashParts([
    DOMAIN.SYNTHETIC_OBSERVABILITY_EVENT,
    hostId,
    bootId,
    producerId,
    producerEpoch,
    sequence,
    eventType,
    digest
  ]);
}

function requireStrings(fields) {
  for (const [name, value] of Object.entries(fields)) {
    if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${name} must be a non-empty string`);
  }
}

function normalizeSha256(value, field) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) throw new TypeError(`${field} must be a 64-character SHA-256 hex digest`);
  return value.toLowerCase();
}

function normalizeUint64Component(value, field) {
  let decimal;
  if (typeof value === 'bigint') decimal = value.toString();
  else if (typeof value === 'number' && Number.isSafeInteger(value)) decimal = String(value);
  else if (typeof value === 'string' && value.length <= 20 && /^(0|[1-9][0-9]*)$/.test(value)) decimal = value;
  else throw new TypeError(`${field} must be an exact non-negative integer`);
  const integer = BigInt(decimal);
  if (integer < 0n || integer > 18446744073709551615n) throw new RangeError(`${field} exceeds uint64 range`);
  return decimal;
}

function canonicalPayloadSha256(payload) {
  return crypto.createHash('sha256').update(canonicalJson(payload), 'utf8').digest('hex');
}

module.exports = {
  DOMAIN,
  lengthPrefix,
  rawProviderEventKey,
  rawPartialProcessEventKey,
  derivedCorrelatedEventKey,
  syntheticObservabilityEventKey,
  canonicalPayloadSha256
};
