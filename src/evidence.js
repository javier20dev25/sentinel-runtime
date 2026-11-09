'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { DatabaseSync } = require('node:sqlite');
const { canonicalJson } = require('./contracts/canonical-json');

const GENESIS_HASH = '0'.repeat(64);
const HASH_DOMAIN = 'SENTINEL-EVIDENCE-LEDGER-V1';
const INSERT_CHUNK_ROWS = 1000;

class EvidenceLedger {
  constructor(dbPath = ':memory:', options = {}) {
    this.instrumentationEnabled = options.instrumentation === true;
    this.timings = { canonicalization_ms: 0, chain_hashing_ms: 0, sqlite_insert_ms: 0, sqlite_commit_ms: 0 };
    this.insertStatements = new Map();
    if (dbPath !== ':memory:') {
      const absolutePath = path.resolve(dbPath);
      fs.mkdirSync(path.dirname(absolutePath), { recursive: true });
      this.db = new DatabaseSync(absolutePath);
      this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;');
      this.path = absolutePath;
    } else {
      this.db = new DatabaseSync(dbPath);
      this.path = dbPath;
    }
    this.initSchema();
  }

  initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS ledger_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS evidence_records (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        record_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        record_hash TEXT NOT NULL UNIQUE
      );
      CREATE INDEX IF NOT EXISTS evidence_records_type_sequence ON evidence_records(record_type, sequence DESC);
      CREATE INDEX IF NOT EXISTS evidence_events_source_key_v2
        ON evidence_records(CASE WHEN json_valid(payload_json)
          THEN lower(json_extract(payload_json, '$.event.source_event_key')) END)
        WHERE record_type = 'event';
      CREATE INDEX IF NOT EXISTS evidence_events_source_key_legacy
        ON evidence_records(CASE WHEN json_valid(payload_json)
          THEN lower(json_extract(payload_json, '$.event.sourceEventKey')) END)
        WHERE record_type = 'event';
    `);
    this.migrateLegacyIncidents();
  }

  migrateLegacyIncidents() {
    const hasLegacyTable = this.db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = 'incidents'").get();
    const migrated = this.db.prepare("SELECT value FROM ledger_meta WHERE key = 'legacy_incidents_migrated'").get();
    if (!hasLegacyTable || migrated) return;
    const rows = this.db.prepare('SELECT * FROM incidents ORDER BY id ASC').all();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const row of rows) {
        let evidence = {};
        try { evidence = JSON.parse(row.evidence_json || '{}'); } catch { evidence = { legacy_evidence_json_invalid: true }; }
        const payload = sanitizeJsonValue({
          timestamp: row.timestamp || new Date(0).toISOString(),
          decision: {
            workloadId: row.workload_id || 'legacy-unknown', pid: row.pid ?? null,
            threatLevel: row.threat_level ?? null, action: row.action || 'RECORD_ONLY', reason: row.reason || ''
          },
          evidence: { legacy_id: row.id, ...sanitizeJsonValue(evidence) }
        });
        this.appendRecord('legacy_incident', payload);
      }
      this.db.prepare("INSERT INTO ledger_meta (key, value) VALUES ('legacy_incidents_migrated', ?)").run(new Date().toISOString());
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  recordIncident(decision, evidence = {}) {
    return this.append('incident', {
      timestamp: new Date().toISOString(),
      decision: sanitizeJsonValue(decision),
      evidence: sanitizeJsonValue(evidence)
    });
  }

  recordEvent(event, decision = null, evidence = {}) {
    return this.recordEvents([{ event, decision, evidence }])[0];
  }

  recordEvents(entries) {
    if (!Array.isArray(entries)) throw new TypeError('Event batch must be an array');
    if (entries.length > 4096) throw new RangeError('Evidence transaction cannot exceed 4096 records');
    return this.appendMany(entries.map(entry => ({
      recordType: 'event',
      payload: {
        timestamp: new Date().toISOString(),
        event: sanitizeJsonValue(entry?.event),
        decision: entry?.decision ? sanitizeJsonValue(entry.decision) : null,
        evidence: sanitizeJsonValue(entry?.evidence || {})
      }
    })));
  }

  recordEventsWithCheckpoint(entries, checkpoint) {
    if (!Array.isArray(entries)) throw new TypeError('Event batch must be an array');
    if (entries.length > 4096) throw new RangeError('Evidence transaction cannot exceed 4096 records');
    if (!checkpoint || typeof checkpoint.source_id !== 'string' || checkpoint.source_id.length === 0 || checkpoint.source_id.length > 512) {
      throw new TypeError('Checkpoint requires a bounded source_id');
    }
    const eventEntries = entries.map(entry => ({
      recordType: 'event',
      payload: {
        timestamp: new Date().toISOString(),
        event: sanitizeJsonValue(entry?.event),
        decision: entry?.decision ? sanitizeJsonValue(entry.decision) : null,
        evidence: sanitizeJsonValue(entry?.evidence || {})
      }
    }));
    const checkpointEntry = {
      recordType: 'source_checkpoint',
      payload: {
        timestamp: new Date().toISOString(),
        checkpoint: sanitizeJsonValue(checkpoint)
      }
    };
    const records = this.appendMany([...eventEntries, checkpointEntry]);
    return {
      events: records.slice(0, -1),
      checkpoint: records[records.length - 1],
      duplicates: eventEntries.length - (records.length - 1)
    };
  }

  getLatestSourceCheckpoint(sourceId) {
    if (typeof sourceId !== 'string' || sourceId.length === 0 || sourceId.length > 512) {
      throw new TypeError('sourceId must be a bounded non-empty string');
    }
    const rows = this.db.prepare(`
      SELECT sequence, payload_json FROM evidence_records
      WHERE record_type = 'source_checkpoint' ORDER BY sequence DESC
    `).all();
    for (const row of rows) {
      let payload;
      try { payload = JSON.parse(row.payload_json); } catch { continue; }
      if (payload?.checkpoint?.source_id === sourceId) {
        return { sequence: Number(row.sequence), ...payload.checkpoint };
      }
    }
    return null;
  }

  append(recordType, payload) {
    return this.appendMany([{ recordType, payload }])[0];
  }

  appendMany(entries) {
    if (!Array.isArray(entries) || entries.length === 0) return [];
    if (entries.length > 4096) throw new RangeError('Evidence transaction cannot exceed 4096 records');
    const preparationStarted = this.instrumentationEnabled ? performance.now() : 0;
    const prepared = entries.map(({ recordType, payload }) => {
      if (typeof recordType !== 'string' || recordType.length === 0) throw new TypeError('recordType is required');
      const payloadJson = canonicalJson(payload);
      if (typeof payload?.timestamp !== 'string' || payload.timestamp.length === 0) throw new TypeError('Evidence payload must contain a timestamp');
      return { recordType, payload, payloadJson, timestamp: payload.timestamp };
    });
    if (this.instrumentationEnabled) this.timings.canonicalization_ms += performance.now() - preparationStarted;
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const uniquePrepared = [];
      const stagedKeys = new Set();
      const existingKey = this.db.prepare(`
        SELECT sequence FROM evidence_records
        WHERE record_type = 'event' AND (
          CASE WHEN json_valid(payload_json)
            THEN lower(json_extract(payload_json, '$.event.source_event_key')) END = ? OR
          CASE WHEN json_valid(payload_json)
            THEN lower(json_extract(payload_json, '$.event.sourceEventKey')) END = ?
        )
        ORDER BY sequence ASC LIMIT 1
      `);
      for (const item of prepared) {
        const event = item.recordType === 'event' ? item.payload?.event : null;
        const key = typeof event?.source_event_key === 'string' ? event.source_event_key
          : typeof event?.sourceEventKey === 'string' ? event.sourceEventKey : null;
        if (!key || !/^[a-f0-9]{64}$/i.test(key)) {
          uniquePrepared.push(item);
          continue;
        }
        const canonicalKey = key.toLowerCase();
        if (stagedKeys.has(canonicalKey) || existingKey.get(canonicalKey, canonicalKey)) {
          continue;
        }
        stagedKeys.add(canonicalKey);
        uniquePrepared.push(item);
      }
      const previous = this.db.prepare('SELECT sequence, record_hash FROM evidence_records ORDER BY sequence DESC LIMIT 1').get();
      let sequence = previous ? Number(previous.sequence) : 0;
      let previousHash = previous?.record_hash || GENESIS_HASH;
      const records = [];
      const insertRows = [];
      let hashStarted = this.instrumentationEnabled ? performance.now() : 0;
      for (const item of uniquePrepared) {
        sequence++;
        const recordHash = hashRecord(sequence, item.recordType, item.payloadJson, previousHash);
        insertRows.push(sequence, item.timestamp, item.recordType, item.payloadJson, previousHash, recordHash);
        records.push({ sequence, previous_hash: previousHash, record_hash: recordHash });
        previousHash = recordHash;
        if (insertRows.length === INSERT_CHUNK_ROWS * 6) {
          if (this.instrumentationEnabled) this.timings.chain_hashing_ms += performance.now() - hashStarted;
          const insertStarted = this.instrumentationEnabled ? performance.now() : 0;
          this.flushInsertRows(insertRows);
          if (this.instrumentationEnabled) {
            this.timings.sqlite_insert_ms += performance.now() - insertStarted;
            hashStarted = performance.now();
          }
        }
      }
      if (insertRows.length) {
        if (this.instrumentationEnabled) this.timings.chain_hashing_ms += performance.now() - hashStarted;
        const insertStarted = this.instrumentationEnabled ? performance.now() : 0;
        this.flushInsertRows(insertRows);
        if (this.instrumentationEnabled) this.timings.sqlite_insert_ms += performance.now() - insertStarted;
      }
      const commitStarted = this.instrumentationEnabled ? performance.now() : 0;
      this.db.exec('COMMIT');
      if (this.instrumentationEnabled) this.timings.sqlite_commit_ms += performance.now() - commitStarted;
      return records;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  appendRecord(recordType, payload) {
    const payloadJson = canonicalJson(payload);
    const previous = this.db.prepare('SELECT sequence, record_hash FROM evidence_records ORDER BY sequence DESC LIMIT 1').get();
    const sequence = previous ? Number(previous.sequence) + 1 : 1;
    const previousHash = previous?.record_hash || GENESIS_HASH;
    const recordHash = hashRecord(sequence, recordType, payloadJson, previousHash);
    this.db.prepare(`
      INSERT INTO evidence_records (sequence, timestamp, record_type, payload_json, previous_hash, record_hash)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(sequence, payload.timestamp, recordType, payloadJson, previousHash, recordHash);
    return { sequence, previous_hash: previousHash, record_hash: recordHash };
  }

  flushInsertRows(flatValues) {
    const rowCount = flatValues.length / 6;
    let statement = this.insertStatements.get(rowCount);
    if (!statement) {
      const placeholders = Array(rowCount).fill('(?, ?, ?, ?, ?, ?)').join(',');
      statement = this.db.prepare(`
        INSERT INTO evidence_records (sequence, timestamp, record_type, payload_json, previous_hash, record_hash)
        VALUES ${placeholders}
      `);
      if (this.insertStatements.size >= 16) this.insertStatements.delete(this.insertStatements.keys().next().value);
      this.insertStatements.set(rowCount, statement);
    }
    statement.run(...flatValues);
    flatValues.length = 0;
  }

  getIncidents(options = {}) {
    const limit = Number.isSafeInteger(options.limit) && options.limit > 0 ? Math.min(options.limit, 100000) : 1000;
    const rows = this.db.prepare(`
      SELECT sequence, timestamp, record_type, payload_json, previous_hash, record_hash
      FROM evidence_records WHERE record_type IN ('incident', 'legacy_incident') ORDER BY sequence DESC LIMIT ?
    `).all(limit);
    return rows.map(row => {
      const payload = JSON.parse(row.payload_json);
      const decision = payload.decision || {};
      return {
        id: row.sequence,
        sequence: row.sequence,
        timestamp: row.timestamp,
        workload_id: decision.workloadId || decision.workload_id || 'unknown',
        pid: decision.pid ?? null,
        threat_level: decision.threatLevel ?? null,
        action: decision.action || 'RECORD_ONLY',
        reason: decision.reason || '',
        evidence_json: JSON.stringify(payload.evidence || {}),
        previous_hash: row.previous_hash,
        record_hash: row.record_hash
      };
    });
  }

  getRecords(options = {}) {
    const limit = Number.isSafeInteger(options.limit) && options.limit > 0 ? Math.min(options.limit, 100000) : 1000;
    return this.db.prepare(`
      SELECT sequence, timestamp, record_type, payload_json, previous_hash, record_hash
      FROM evidence_records ORDER BY sequence DESC LIMIT ?
    `).all(limit);
  }

  getEventRecordsBySourceEventKeys(sourceEventKeys) {
    if (!Array.isArray(sourceEventKeys) || sourceEventKeys.length === 0) return [];
    const keys = [...new Set(sourceEventKeys)];
    if (keys.length > 32 || keys.some(key => typeof key !== 'string' || !/^[a-f0-9]{64}$/i.test(key))) {
      throw new TypeError('Source event keys must be at most 32 SHA-256 hex digests');
    }
    const placeholders = keys.map(() => '?').join(', ');
    const rows = this.db.prepare(`
      SELECT sequence, timestamp, record_type, payload_json, previous_hash, record_hash
      FROM evidence_records
      WHERE record_type = 'event'
        AND lower(json_extract(payload_json, '$.event.source_event_key')) IN (${placeholders})
      ORDER BY sequence ASC
    `).all(...keys.map(key => key.toLowerCase()));
    return rows.map(row => ({
      ...row,
      sequence: Number(row.sequence),
      payload: JSON.parse(row.payload_json),
      event: JSON.parse(row.payload_json).event
    }));
  }

  getCloudDeliveryRecords(options = {}) {
    const limit = Number.isSafeInteger(options.limit) && options.limit > 0 ? Math.min(options.limit, 20000) : 20000;
    return this.db.prepare(`
      SELECT sequence, timestamp, record_type, payload_json, previous_hash, record_hash
      FROM evidence_records
        WHERE record_type IN ('cloud_delivery_pending', 'cloud_delivery_retry', 'cloud_delivery_ack')
      ORDER BY sequence ASC LIMIT ?
    `).all(limit);
  }

  verifyIntegrity() {
    const rows = this.db.prepare(`
      SELECT sequence, timestamp, record_type, payload_json, previous_hash, record_hash
      FROM evidence_records ORDER BY sequence ASC
    `).all();
    let previousHash = GENESIS_HASH;
    let expectedSequence = 1;
    for (const row of rows) {
      if (Number(row.sequence) !== expectedSequence) {
        return { valid: false, checked: expectedSequence - 1, sequence: Number(row.sequence), reason: 'SEQUENCE_GAP' };
      }
      if (row.previous_hash !== previousHash) {
        return { valid: false, checked: expectedSequence - 1, sequence: expectedSequence, reason: 'PREVIOUS_HASH_MISMATCH' };
      }
      let parsed;
      try {
        parsed = JSON.parse(row.payload_json);
      } catch {
        return { valid: false, checked: expectedSequence - 1, sequence: expectedSequence, reason: 'INVALID_PAYLOAD_JSON' };
      }
      if (parsed?.timestamp !== row.timestamp) {
        return { valid: false, checked: expectedSequence - 1, sequence: expectedSequence, reason: 'TIMESTAMP_MISMATCH' };
      }
      if (canonicalJson(parsed) !== row.payload_json) {
        return { valid: false, checked: expectedSequence - 1, sequence: expectedSequence, reason: 'NON_CANONICAL_PAYLOAD' };
      }
      const expectedHash = hashRecord(expectedSequence, row.record_type, row.payload_json, previousHash);
      if (row.record_hash !== expectedHash) {
        return { valid: false, checked: expectedSequence - 1, sequence: expectedSequence, reason: 'RECORD_HASH_MISMATCH' };
      }
      previousHash = row.record_hash;
      expectedSequence++;
    }
    return { valid: true, checked: rows.length, head_hash: previousHash, external_anchor: false };
  }

  close() {
    this.db.close();
  }
}

function sanitizeJsonValue(value, seen = new WeakSet(), depth = 0) {
  if (depth > 256) throw new RangeError('Evidence value nesting depth exceeds 256');
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('Evidence values must be finite numbers');
    return value;
  }
  if (typeof value === 'bigint') return value.toString();
  if (value === undefined) return null;
  if (typeof value !== 'object') return String(value);
  if (seen.has(value)) throw new TypeError('Evidence values cannot contain cycles');
  seen.add(value);
  let output;
  if (Array.isArray(value)) {
    output = [];
    for (let i = 0; i < value.length; i++) {
      if (!Object.hasOwn(value, i)) throw new TypeError('Evidence arrays cannot be sparse');
      output.push(sanitizeJsonValue(value[i], seen, depth + 1));
    }
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError('Evidence values must be JSON-compatible plain objects');
    if (Object.getOwnPropertySymbols(value).length) throw new TypeError('Evidence objects cannot contain symbol keys');
    output = Object.create(null);
    for (const key of Object.keys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Evidence objects cannot contain accessor properties');
      output[key] = sanitizeJsonValue(descriptor.value, seen, depth + 1);
    }
  }
  seen.delete(value);
  return output;
}

function hashRecord(sequence, recordType, payloadJson, previousHash) {
  const parts = [HASH_DOMAIN, String(sequence), recordType, previousHash, payloadJson];
  const hash = crypto.createHash('sha256');
  const length = Buffer.alloc(8);
  for (const part of parts) {
    length.writeBigUInt64BE(BigInt(Buffer.byteLength(part, 'utf8')));
    hash.update(length).update(part, 'utf8');
  }
  return hash.digest('hex');
}

module.exports = { EvidenceLedger, canonicalJson, hashRecord, GENESIS_HASH };
