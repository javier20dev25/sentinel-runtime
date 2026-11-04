#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { TetragonGrpcCollector } = require('../src/collectors/tetragon-grpc');
const { loadTetragonApi } = require('../src/collectors/tetragon-proto');
const { EvidenceLedger } = require('../src/evidence');
const { canonicalJson } = require('../src/contracts/canonical-json');

const SOURCE_FILES = [
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

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!['--events', '--revision', '--output'].includes(key) || !value || value.startsWith('--')) throw new Error(`Invalid argument: ${key}`);
    options[key.slice(2)] = value;
    i++;
  }
  if (!/^[1-9][0-9]*$/.test(options.events || '') || !Number.isSafeInteger(Number(options.events)) || Number(options.events) > 100000) {
    throw new RangeError('--events must be between 1 and 100000');
  }
  if (!/^[a-f0-9]{40,64}$/i.test(options.revision || '')) throw new Error('--revision requires a frozen git revision SHA');
  if (typeof options.output !== 'string') throw new Error('--output is required');
  return { events: Number(options.events), revision: options.revision, output: path.resolve(options.output) };
}

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

function hashFile(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }

async function run() {
  const options = parseArgs(process.argv.slice(2));
  if (fs.existsSync(options.output)) throw new Error(`Refusing to overwrite sealed benchmark artifact: ${options.output}`);
  const api = loadTetragonApi();
  const responseMethod = api.definition['tetragon.FineGuidanceSensors'].GetEvents;
  const corpusHash = crypto.createHash('sha256');
  let totalWireBytes = 0;
  const server = new api.grpc.Server();
  server.addService(api.service.service, {
    getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents(call) {
      let index = 0;
      const send = () => {
        while (index < options.events) {
          const response = makeResponse(index++);
          const wireBytes = responseMethod.responseSerialize(response);
          const length = Buffer.alloc(8);
          length.writeBigUInt64BE(BigInt(wireBytes.length));
          corpusHash.update(length).update(wireBytes);
          totalWireBytes += wireBytes.length;
          if (!call.write(response)) { call.once('drain', send); return; }
        }
        call.end();
      };
      send();
    }
  });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', api.grpc.ServerCredentials.createInsecure(), (error, boundPort) => error ? reject(error) : resolve(boundPort));
  });

  const tempRoot = path.resolve(os.tmpdir());
  const directory = fs.mkdtempSync(path.join(tempRoot, 'sentinel-runtime-grpc-bench-'));
  const resolvedDirectory = path.resolve(directory);
  const expectedPrefix = `${tempRoot}${path.sep}sentinel-runtime-grpc-bench-`;
  if (!resolvedDirectory.startsWith(expectedPrefix)) throw new Error(`Refusing cleanup outside benchmark temp root: ${resolvedDirectory}`);
  const ledger = new EvidenceLedger(path.join(directory, 'evidence.sqlite'));
  const memorySamples = [];
  const sampleTimer = setInterval(() => memorySamples.push(process.memoryUsage().rss), 25);
  const started = performance.now();
  let result;
  try {
    const connection = new api.service(`127.0.0.1:${port}`, api.grpc.credentials.createInsecure());
    const collector = new TetragonGrpcCollector({
      ledger, hostId: 'grpc-bench-host', bootId: 'grpc-bench-boot', expectedNodeName: 'benchmark-node',
      batchSize: 128, queueCapacity: 512, queueByteCapacity: 64 * 1024 * 1024,
      maxEvents: options.events,
      connectionFactory: async () => ({ client: connection, close: () => connection.close(), transportProtocol: 'TEST_LOOPBACK_GRPC' })
    });
    result = await collector.run();
    const elapsedMs = performance.now() - started;
    const integrity = ledger.verifyIntegrity();
    if (!integrity.valid) throw new Error(`Evidence ledger integrity failed: ${JSON.stringify(integrity)}`);
    if (result.received !== options.events || result.persisted !== options.events || result.supported !== options.events ||
      result.queue_drops_lower_bound !== '0' || result.unprocessed_at_limit_lower_bound !== '0') {
      throw new Error(`Collector count mismatch: ${JSON.stringify(result)}`);
    }
    const sourceHashes = Object.fromEntries(SOURCE_FILES.map(file => [file, hashFile(path.resolve(__dirname, '..', file))]));
    const manifest = {
      benchmark_id: 'SR-GRPC-002',
      target_revision: options.revision,
      measured_worktree_dirty: true,
      runtime: { tetragon_version: 'v1.8.0', node: process.version, platform: process.platform, arch: process.arch, os_release: os.release(), cpu: os.cpus()[0]?.model || 'unknown' },
      scenario: {
        kind: 'SYNTHETIC_LOOPBACK_GRPC',
        events: options.events,
        wire_bytes: totalWireBytes,
        wire_corpus_sha256: corpusHash.digest('hex'),
        source_host: '127.0.0.1',
        event_mix: { process_exec: options.events },
        queue_capacity_events: 512,
        queue_capacity_bytes: 64 * 1024 * 1024,
        batch_size: 128
      },
      result: {
        elapsed_ms: Math.round(elapsedMs * 100) / 100,
        events_per_second: Math.round(options.events / (elapsedMs / 1000) * 100) / 100,
        received: result.received,
        persisted: result.persisted,
        supported: result.supported,
        queue_drops_lower_bound: result.queue_drops_lower_bound,
        queue_dropped_bytes_lower_bound: result.queue_dropped_bytes_lower_bound,
        unprocessed_at_limit_lower_bound: result.unprocessed_at_limit_lower_bound,
        peak_sampled_rss_bytes: memorySamples.length ? Math.max(...memorySamples) : process.memoryUsage().rss,
        ledger_records_verified: integrity.checked,
        ledger_head_hash: integrity.head_hash
      },
      methodology: 'Single end-to-end local gRPC run; server-side synthetic protobuf generation and transmission are included in elapsed time. This measures the collector, decoder, bounded queue, normalization, engine, and durable SQLite ledger together. It does not measure Tetragon, eBPF, kernel generation, or detection quality. Memory is sampled every 25 ms and may miss short peaks.',
      source_hashes: sourceHashes
    };
    manifest.manifest_sha256 = crypto.createHash('sha256').update(canonicalJson(manifest)).digest('hex');
    fs.mkdirSync(path.dirname(options.output), { recursive: true });
    fs.writeFileSync(options.output, `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
    console.log(JSON.stringify({ output: options.output, manifest_sha256: manifest.manifest_sha256, result: manifest.result, source_tree_hashes: Object.keys(sourceHashes).length }, null, 2));
  } finally {
    clearInterval(sampleTimer);
    ledger.close();
    server.forceShutdown();
    const finalPath = path.resolve(directory);
    if (path.dirname(finalPath) !== tempRoot || !path.basename(finalPath).startsWith('sentinel-runtime-grpc-bench-')) {
      throw new Error(`Refusing recursive cleanup for unexpected path: ${finalPath}`);
    }
    fs.rmSync(finalPath, { recursive: true, force: true });
  }
}

run().catch(error => {
  console.error(`sentinel-runtime-grpc-bench: ${error.message}`);
  process.exitCode = 1;
});
