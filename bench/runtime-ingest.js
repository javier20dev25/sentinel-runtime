#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { BehavioralSequenceEngine } = require('../src/engine');
const { EvidenceLedger } = require('../src/evidence');
const { WorkloadProfile } = require('../src/profiler');
const { JsonlFramer, parseJsonRejectDuplicateKeys } = require('../src/ingest/jsonl');
const { normalizeTetragonJson } = require('../src/adapters/tetragon-json');
const { canonicalJson } = require('../src/contracts/canonical-json');
const { ThreatLevel } = require('../src/types');

const DEFAULTS = Object.freeze({ events: 2000, warmup: 250, repetitions: 3, batchSize: 128 });
const SOURCE_FILES = [
  'src/engine.js', 'src/profiler.js', 'src/evidence.js', 'src/types.js',
  'src/ingest/jsonl.js', 'src/adapters/tetragon-json.js',
  'src/contracts/canonical-json.js', 'src/contracts/event-keys.js',
  'schemas/runtime-event-v2.schema.json', 'package.json', 'package-lock.json'
];

function parseArgs(argv) {
  const options = { ...DEFAULTS };
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) throw new Error(`Unexpected argument: ${argv[i]}`);
    const key = argv[i].slice(2);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) throw new Error(`--${key} requires a value`);
    if (!['events', 'warmup', 'repetitions', 'batch-size', 'revision', 'output', 'verify'].includes(key)) throw new Error(`Unknown option: --${key}`);
    const normalizedKey = key === 'batch-size' ? 'batchSize' : key;
    if (['events', 'warmup', 'repetitions', 'batchSize'].includes(normalizedKey)) {
      if (!/^[1-9][0-9]*$/.test(value)) throw new Error(`--${key} must be a positive decimal integer`);
      options[normalizedKey] = Number(value);
      if (!Number.isSafeInteger(options[normalizedKey])) throw new Error(`--${key} is too large`);
    } else options[normalizedKey] = value;
    i++;
  }
  if (options.verify) return options;
  if (typeof options.revision !== 'string' || !/^[a-f0-9]{40,64}$/i.test(options.revision)) {
    throw new Error('--revision requires the frozen git commit SHA');
  }
  if (options.events > 100000 || options.warmup > 100000 || options.repetitions > 20 || options.batchSize > 4096) {
    throw new RangeError('Benchmark bounds exceeded (events/warmup <= 100000, repetitions <= 20, batch-size <= 4096)');
  }
  return options;
}

function createCorpus(count) {
  const chunks = [];
  for (let i = 0; i < count; i++) {
    const nanos = String(i % 1000000000).padStart(9, '0');
    const record = {
      time: `2026-11-02T12:00:00.${nanos}Z`,
      process_exec: {
        process: {
          exec_id: `bench-exec-${String(i).padStart(8, '0')}`,
          parent_exec_id: '',
          pid: { value: 1000 + i },
          tid: { value: 1000 + i },
          start_time: '2026-11-02T11:59:59.000000000Z',
          binary: '/usr/bin/node',
          arguments: 'node worker.js'
        }
      }
    };
    chunks.push(Buffer.from(`${JSON.stringify(record)}\n`, 'utf8'));
  }
  return Buffer.concat(chunks);
}

function runPipeline(input, dbPath, expectedEvents, batchSize = DEFAULTS.batchSize) {
  const started = performance.now();
  const ledger = new EvidenceLedger(dbPath, { instrumentation: true });
  try {
  const engine = new BehavioralSequenceEngine({ maxChains: Math.min(expectedEvents, 10000), maxEventIds: 50000 });
  engine.registerProfile('benchmark', new WorkloadProfile({ allowedBinaries: ['/usr/bin/node'] }));
  const framer = new JsonlFramer();
  const counts = { frames: 0, normalized: 0, normal: 0, unassessed: 0, non_normal: 0, unsupported: 0, rejected: 0, ledger_records: 0 };
  const timings = { framing_ms: 0, parse_ms: 0, normalize_ms: 0, engine_ms: 0, ledger_commit_ms: 0 };
  const pending = [];
  const flush = () => {
    if (!pending.length) return;
    const commitStarted = performance.now();
    ledger.recordEvents(pending);
    timings.ledger_commit_ms += performance.now() - commitStarted;
    counts.ledger_records += pending.length;
    pending.length = 0;
  };
  const processFrames = frames => {
    for (const frame of frames) {
      counts.frames++;
      if (frame.decodeError) { counts.rejected++; continue; }
      let stageStarted = performance.now();
      const record = parseJsonRejectDuplicateKeys(frame.text);
      timings.parse_ms += performance.now() - stageStarted;
      stageStarted = performance.now();
      const event = normalizeTetragonJson(record, frame.raw, { hostId: 'bench-host', bootId: 'bench-boot', workloadId: 'benchmark' });
      timings.normalize_ms += performance.now() - stageStarted;
      if (!event.supported) { counts.unsupported++; continue; }
      stageStarted = performance.now();
      const decision = engine.processEvent(event);
      timings.engine_ms += performance.now() - stageStarted;
      if (decision.threatLevel === ThreatLevel.NORMAL) counts.normal++;
      else if (decision.threatLevel === ThreatLevel.UNASSESSED) counts.unassessed++;
      else counts.non_normal++;
      const summary = {
        provider: event.provider,
        eventType: event.eventType,
        sourceEventKey: event.sourceEventKey,
        eventId: event.eventId,
        hostIdentity: event.hostIdentity,
        processIdentity: event.processIdentity,
        data: { binary: event.data.binary || null, exitStatus: event.data.exitStatus ?? null, signal: event.data.signal || null }
      };
      pending.push({ event: summary, decision, evidence: {
        byteOffset: frame.byteOffset,
        byteLength: frame.byteLength,
        payloadByteLength: frame.payloadByteLength,
        delimiterByteLength: frame.delimiterByteLength,
        rawPayloadSha256: event.rawPayloadSha256
      } });
      counts.normalized++;
      if (pending.length >= batchSize) flush();
    }
  };
  const chunkBytes = 64 * 1024;
  for (let offset = 0; offset < input.length; offset += chunkBytes) {
    const frameStarted = performance.now();
    const frames = framer.push(input.subarray(offset, Math.min(offset + chunkBytes, input.length)));
    timings.framing_ms += performance.now() - frameStarted;
    processFrames(frames);
  }
  const frameStarted = performance.now();
  const finalFrames = framer.finish();
  timings.framing_ms += performance.now() - frameStarted;
  processFrames(finalFrames);
  flush();
  const elapsedMs = performance.now() - started;
  if (counts.normalized !== expectedEvents || counts.normal !== expectedEvents || counts.unassessed || counts.non_normal || counts.ledger_records !== expectedEvents || counts.rejected || counts.unsupported) {
    throw new Error(`Pipeline count mismatch: ${JSON.stringify(counts)}`);
  }
  const verifyStarted = performance.now();
  const integrity = ledger.verifyIntegrity();
  const verifyMs = performance.now() - verifyStarted;
  if (!integrity.valid || integrity.checked !== expectedEvents) throw new Error(`Ledger integrity failure: ${JSON.stringify(integrity)}`);
  const roundedTimings = Object.fromEntries(Object.entries(timings).map(([key, value]) => [key, round(value)]));
  const ledgerTimings = Object.fromEntries(Object.entries(ledger.timings).map(([key, value]) => [key, round(value)]));
  return { counts, elapsed_ms: round(elapsedMs), events_per_second: round(expectedEvents / (elapsedMs / 1000)), stage_timings: roundedTimings, ledger_timings: ledgerTimings, verify_ms: round(verifyMs), head_hash: integrity.head_hash };
  } finally {
    ledger.close();
  }
}

function hashFile(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function round(value) { return Math.round(value * 100) / 100; }
function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : round((sorted[middle - 1] + sorted[middle]) / 2);
}

function withTemporaryDatabase(run) {
  const tempRoot = path.resolve(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(tempRoot, 'sentinel-runtime-bench-'));
  const resolved = path.resolve(directory);
  const expectedPrefix = `${tempRoot}${path.sep}sentinel-runtime-bench-`;
  if (!resolved.startsWith(expectedPrefix)) throw new Error(`Refusing cleanup outside benchmark temp root: ${resolved}`);
  try {
    return run(path.join(resolved, 'evidence.sqlite'));
  } finally {
    const finalPath = path.resolve(resolved);
    if (path.dirname(finalPath) !== tempRoot || !path.basename(finalPath).startsWith('sentinel-runtime-bench-')) {
      throw new Error(`Refusing recursive cleanup for unexpected path: ${finalPath}`);
    }
    fs.rmSync(finalPath, { recursive: true, force: true });
  }
}

function verifyManifest(manifestPath) {
  if (typeof manifestPath !== 'string') throw new Error('--verify requires a benchmark JSON artifact');
  const resolved = path.resolve(manifestPath);
  const stats = fs.statSync(resolved);
  if (!stats.isFile() || stats.size > 8 * 1024 * 1024) throw new RangeError('Manifest must be a regular file no larger than 8 MiB');
  const manifest = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  const expectedSeal = manifest.manifest_sha256;
  delete manifest.manifest_sha256;
  const sealValid = typeof expectedSeal === 'string' && sha256(canonicalJson(manifest)) === expectedSeal;
  manifest.manifest_sha256 = expectedSeal;
  const corpusValid = sha256(createCorpus(manifest.scenario.events)) === manifest.scenario.input_sha256;
  const changedSources = Object.entries(manifest.source_hashes || {}).filter(([file, digest]) => {
    const currentPath = path.resolve(__dirname, '..', file);
    return !fs.existsSync(currentPath) || hashFile(currentPath) !== digest;
  }).map(([file]) => file);
  const result = {
    seal_valid: sealValid,
    deterministic_corpus_valid: corpusValid,
    current_source_tree_matches: changedSources.length === 0,
    changed_sources: changedSources,
    target_revision: manifest.target_revision,
    manifest_sha256: expectedSeal
  };
  console.log(JSON.stringify(result, null, 2));
  return sealValid && corpusValid ? 0 : 1;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.verify) return verifyManifest(options.verify);
  const corpus = createCorpus(options.events);
  const corpusSha256 = sha256(corpus);
  const warmupCorpus = createCorpus(Math.min(options.warmup, options.events));
  withTemporaryDatabase(dbPath => runPipeline(warmupCorpus, dbPath, Math.min(options.warmup, options.events), options.batchSize));

  const runs = [];
  for (let i = 0; i < options.repetitions; i++) {
    runs.push(withTemporaryDatabase(dbPath => runPipeline(corpus, dbPath, options.events, options.batchSize)));
  }
  const sourceHashes = Object.fromEntries(SOURCE_FILES.map(file => [file, hashFile(path.resolve(__dirname, '..', file))]));
  sourceHashes['bench/runtime-ingest.js'] = hashFile(__filename);
  const rates = runs.map(run => run.events_per_second);
  const manifest = {
    benchmark_id: 'SR-INGEST-001',
    target_revision: options.revision,
    working_tree_note: 'Commit SHA identifies HEAD; source_hashes seal the measured working-tree files, which may include uncommitted implementation changes.',
    runtime: {
      node: process.version,
      platform: process.platform,
      architecture: process.arch,
      os_release: os.release(),
      cpu_model: os.cpus()[0]?.model || 'unknown',
      logical_cpu_count: os.cpus().length
    },
    scenario: {
      name: 'Tetragon JSONL offline ingest with SQLite evidence persistence',
      events: options.events,
      warmup_events: Math.min(options.warmup, options.events),
      repetitions: options.repetitions,
      input_bytes: corpus.length,
      input_sha256: corpusSha256,
      chunk_bytes: 65536,
      sqlite: 'file-backed; journal_mode=WAL; synchronous=FULL; foreign_keys=ON',
      evidence_batch_size: options.batchSize,
      workload_profile: 'exact /usr/bin/node path; every event expected NORMAL',
      included_stages: ['JSONL framing', 'duplicate-key scan', 'JSON parse', 'Tetragon exec normalization', 'source-key hashing', 'bounded correlation', 'bounded-batch SQLite commits', 'post-run hash-chain verification'],
      excluded: ['corpus generation', 'sensor collection/eBPF', 'gRPC transport', 'kernel event production', 'cross-process taint', 'active enforcement'],
      llm_token_metrics: 'not applicable to deterministic non-LLM benchmark',
      prompt_hashes: 'not applicable'
    },
    source_hashes: sourceHashes,
    runs,
    summary: {
      median_events_per_second: median(rates),
      min_events_per_second: Math.min(...rates),
      max_events_per_second: Math.max(...rates),
      median_verify_ms: median(runs.map(run => run.verify_ms))
    }
  };
  manifest.manifest_sha256 = sha256(canonicalJson(manifest));
  const output = `${JSON.stringify(manifest, null, 2)}\n`;
  if (options.output) {
    const outputPath = path.resolve(options.output);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, output, { flag: 'wx' });
    console.log(`Wrote sealed benchmark artifact: ${outputPath}`);
  }
  console.log(output);
}

if (require.main === module) {
  try { main(); } catch (error) {
    console.error(`runtime-ingest benchmark failed: ${error.message}`);
    process.exitCode = 1;
  }
}

module.exports = { createCorpus, runPipeline, parseArgs };
