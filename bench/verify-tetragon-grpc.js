#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { loadTetragonApi } = require('../src/collectors/tetragon-proto');
const { canonicalJson } = require('../src/contracts/canonical-json');
const { parseJsonRejectDuplicateKeys } = require('../src/ingest/jsonl');

const REQUIRED_SOURCE_FILES = [
  'bench/tetragon-grpc.js',
  'bin/sentinel-runtime.js', 'src/engine.js', 'src/evidence.js',
  'src/collectors/tetragon-grpc.js', 'src/collectors/tetragon-proto.js',
  'src/adapters/tetragon-json.js', 'src/contracts/event-keys.js',
  'src/contracts/canonical-json.js', 'package.json', 'package-lock.json',
  'vendor/tetragon/v1.8.0/api/v1/tetragon/bpf.proto',
  'vendor/tetragon/v1.8.0/api/v1/tetragon/capabilities.proto',
  'vendor/tetragon/v1.8.0/api/v1/tetragon/events.proto',
  'vendor/tetragon/v1.8.0/api/v1/tetragon/sensors.proto',
  'vendor/tetragon/v1.8.0/api/v1/tetragon/tetragon.proto'
];

function fail(message) { throw new Error(message); }

function makeResponse(index) {
  const stamp = 1793603696 + Math.floor(index / 1000000000);
  return {
    node_name: 'benchmark-node',
    time: { seconds: String(stamp), nanos: index % 1000000000 },
    process_exec: {
      process: {
        exec_id: `grpc-bench-${String(index).padStart(9, '0')}`,
        pid: { value: 1000 + (index % 1000000) },
        tid: { value: 1000 + (index % 1000000) },
        start_time: { seconds: String(stamp - 2), nanos: 0 },
        binary: '/usr/bin/node',
        arguments: 'node worker.js'
      }
    }
  };
}

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function verify(filePath) {
  const resolved = path.resolve(filePath);
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size > 8 * 1024 * 1024) fail('Manifest must be a regular file no larger than 8 MiB');
  const manifest = parseJsonRejectDuplicateKeys(new TextDecoder('utf-8', { fatal: true }).decode(fs.readFileSync(resolved)));
  const expectedSeal = manifest.manifest_sha256;
  delete manifest.manifest_sha256;
  const sealValid = typeof expectedSeal === 'string' && sha256(Buffer.from(canonicalJson(manifest), 'utf8')) === expectedSeal;
  if (manifest.benchmark_id !== 'SR-GRPC-002') fail('Manifest benchmark_id must be SR-GRPC-002');
  if (manifest.runtime?.tetragon_version !== 'v1.8.0') fail('Manifest runtime must be pinned to Tetragon v1.8.0');
  if (manifest.scenario?.kind !== 'SYNTHETIC_LOOPBACK_GRPC') fail('Manifest scenario kind is not the reviewed loopback gRPC case');
  if (!Number.isSafeInteger(manifest.scenario?.events) || manifest.scenario.events < 1 || manifest.scenario.events > 100000) fail('Manifest event count is outside verification bounds');
  const sourceFiles = Object.keys(manifest.source_hashes || {}).sort();
  const requiredSourceFiles = REQUIRED_SOURCE_FILES.slice().sort();
  if (sourceFiles.length !== requiredSourceFiles.length || sourceFiles.some((file, index) => file !== requiredSourceFiles[index])) {
    fail('Manifest source hash coverage does not match the reviewed SR-GRPC-002 source set');
  }

  const api = loadTetragonApi();
  const serialize = api.definition['tetragon.FineGuidanceSensors'].GetEvents.responseSerialize;
  const corpus = crypto.createHash('sha256');
  let wireBytes = 0;
  for (let index = 0; index < manifest.scenario.events; index++) {
    const bytes = serialize(makeResponse(index));
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    corpus.update(length).update(bytes);
    wireBytes += bytes.length;
  }
  const corpusHash = corpus.digest('hex');
  const corpusValid = corpusHash === manifest.scenario.wire_corpus_sha256 && wireBytes === manifest.scenario.wire_bytes;

  const root = path.resolve(__dirname, '..');
  const changedSources = Object.entries(manifest.source_hashes || {}).filter(([file, expected]) => {
    const sourcePath = path.resolve(root, file);
    if (sourcePath !== root && !sourcePath.startsWith(`${root}${path.sep}`)) return true;
    return !fs.existsSync(sourcePath) || !fs.statSync(sourcePath).isFile() || sha256(fs.readFileSync(sourcePath)) !== expected;
  }).map(([file]) => file);
  const expectedEvents = manifest.scenario.events;
  const counts = manifest.result || {};
  const resultCountsValid = counts.received === expectedEvents && counts.persisted === expectedEvents &&
    counts.supported === expectedEvents && counts.queue_drops_lower_bound === '0' &&
    counts.queue_dropped_bytes_lower_bound === '0' && counts.unprocessed_at_limit_lower_bound === '0' &&
    Number.isSafeInteger(counts.ledger_records_verified) && counts.ledger_records_verified >= expectedEvents;
  const result = {
    seal_valid: sealValid,
    deterministic_wire_corpus_valid: corpusValid,
    result_counts_valid: resultCountsValid,
    wire_bytes: wireBytes,
    wire_corpus_sha256: corpusHash,
    current_source_tree_matches: changedSources.length === 0,
    changed_sources: changedSources,
    target_revision: manifest.target_revision,
    manifest_sha256: expectedSeal
  };
  console.log(JSON.stringify(result, null, 2));
  return sealValid && corpusValid && resultCountsValid && changedSources.length === 0 ? 0 : 1;
}

try {
  if (process.argv.length !== 3) fail('Usage: node bench/verify-tetragon-grpc.js <manifest.json>');
  process.exitCode = verify(process.argv[2]);
} catch (error) {
  console.error(`verify-tetragon-grpc: ${error.message}`);
  process.exitCode = 1;
}
