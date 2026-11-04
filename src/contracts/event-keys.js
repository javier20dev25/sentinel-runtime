'use strict';

const crypto = require('node:crypto');
const { canonicalJson } = require('./canonical-json');

const DOMAIN = Object.freeze({ RAW: 'RAW', RAW_PID_START: 'RAW_PID_START', DERIVED: 'DERIVED', SYNTHETIC: 'SYNTHETIC' });

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
  return hashParts([DOMAIN.RAW, hostId, bootId, execId, eventType, timestamp, digest]);
}

function rawPartialProcessEventKey({ hostId, bootId, pid, processStartTime, eventType, sourceTimestamp, rawPayloadSha256 }) {
  requireStrings({ hostId, bootId, eventType });
  const processId = normalizeUint64Component(pid, 'pid');
  if (BigInt(processId) > 0xffffffffn) throw new RangeError('pid exceeds uint32 range');
  const processStart = normalizeUint64Component(processStartTime, 'processStartTime');
  const timestamp = normalizeUint64Component(sourceTimestamp, 'sourceTimestamp');
  const digest = normalizeSha256(rawPayloadSha256, 'rawPayloadSha256');
  return hashParts([DOMAIN.RAW_PID_START, hostId, bootId, processId, processStart, eventType, timestamp, digest]);
}

function derivedCorrelatedEventKey({ hostId, bootId, correlationRuleId, ruleVersion, primaryEventKey, secondaryEventKey }) {
  requireStrings({ hostId, bootId, correlationRuleId, ruleVersion });
  const primary = normalizeSha256(primaryEventKey, 'primaryEventKey');
  const secondary = normalizeSha256(secondaryEventKey, 'secondaryEventKey');
  return hashParts([DOMAIN.DERIVED, hostId, bootId, correlationRuleId, ruleVersion, primary, secondary]);
}

function syntheticObservabilityEventKey({ hostId, bootId, producerId, producerEpoch, sequenceNumber, payloadSha256 }) {
  requireStrings({ hostId, bootId, producerId, producerEpoch });
  const sequence = normalizeUint64Component(sequenceNumber, 'sequenceNumber');
  const digest = normalizeSha256(payloadSha256, 'payloadSha256');
  return hashParts([DOMAIN.SYNTHETIC, hostId, bootId, producerId, producerEpoch, sequence, digest]);
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
