'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EvidenceLedger } = require('../../src/evidence');
const { TetragonGrpcCollector, buildGetEventsRequest, createTetragonConnection, parseTetragonAddress } = require('../../src/collectors/tetragon-grpc');
const { loadTetragonApi } = require('../../src/collectors/tetragon-proto');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');
const { DecisionEngine } = require('../../src/intelligence/decision-engine');

function tempLedger() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-grpc-'));
  const ledger = new EvidenceLedger(path.join(directory, 'runtime.sqlite'));
  return { directory, ledger };
}

test('Tetragon GetEvents filters prioritize core process events and scope policy events by exact names', () => {
  assert.deepEqual(buildGetEventsRequest(), {
    allow_list: [
      { event_set: ['PROCESS_EXEC', 'PROCESS_EXIT', 'PROCESS_LOADER', 'PROCESS_THROTTLE', 'RATE_LIMIT_INFO'] }
    ]
  });
  assert.deepEqual(buildGetEventsRequest(['sentinel-runtime-observability', 'tenant-prod.runtime']), {
    allow_list: [
      { event_set: ['PROCESS_EXEC', 'PROCESS_EXIT', 'PROCESS_LOADER', 'PROCESS_THROTTLE', 'RATE_LIMIT_INFO'] },
      {
        event_set: ['PROCESS_KPROBE', 'PROCESS_TRACEPOINT', 'PROCESS_UPROBE', 'PROCESS_LSM', 'PROCESS_USDT'],
        policy_names: ['sentinel-runtime-observability', 'tenant-prod.runtime']
      }
    ]
  });
  assert.throws(() => buildGetEventsRequest(['*']), /DNS subdomains/);
  assert.throws(() => buildGetEventsRequest([`${'a'.repeat(64)}.policy`]), /DNS subdomains/);
  assert.doesNotThrow(() => buildGetEventsRequest([`${'a'.repeat(63)}.policy`]));
  assert.throws(() => buildGetEventsRequest(['sentinel-policy', 'sentinel-policy']), /Duplicate/);
  assert.throws(() => buildGetEventsRequest(Array.from({ length: 33 }, (_, index) => `policy-${index}`)), /at most 32/);
});

function processExec(execId, nodeName = 'node-a') {
  return {
    node_name: nodeName,
    time: { seconds: '1793603696', nanos: 123456000 },
    process_exec: {
      process: {
        exec_id: execId,
        pid: { value: 101 },
        tid: { value: 101 },
        start_time: { seconds: '1793603690', nanos: 100000000 },
        binary: '/usr/bin/node',
        arguments: 'node worker.js'
      }
    }
  };
}

function rawDecodedResponse(api, response) {
  const method = api.definition['tetragon.FineGuidanceSensors'].GetEvents;
  return method.responseDeserialize(method.responseSerialize(response));
}

test('Tetragon client rejects plaintext TCP and parses constrained endpoints', () => {
  assert.throws(() => createTetragonConnection({ address: '127.0.0.1:54321' }), /requires --tls-ca/);
  assert.deepEqual(parseTetragonAddress('127.0.0.1:54321'), { target: '127.0.0.1:54321', transportProtocol: 'GRPC_TCP' });
  assert.throws(() => parseTetragonAddress('http://127.0.0.1:54321'), /without a URI scheme/);
  assert.throws(() => parseTetragonAddress('127.0.0.1:65536'), /between 1 and 65535/);
  assert.throws(() => parseTetragonAddress('unix:///var/run/tetragon/tetragon.sock', 'win32'), /requires Linux/);
});

test('Tetragon TLS client keys reject group/world-readable mode on Linux', { skip: process.platform === 'win32' }, () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-tls-key-'));
  const certificate = path.join(directory, 'certificate.pem');
  const key = path.join(directory, 'client-key.pem');
  const pemCertificate = '-----BEGIN CERTIFICATE-----\nZg==\n-----END CERTIFICATE-----\n';
  fs.writeFileSync(certificate, pemCertificate);
  fs.writeFileSync(key, '-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----\n');
  fs.chmodSync(key, 0o644);
  try {
    assert.throws(() => createTetragonConnection({
      address: '127.0.0.1:54321', tlsCa: certificate, tlsClientCert: certificate, tlsClientKey: key
    }), /mode 0600 or stricter/);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('Tetragon gRPC collector ingests protobuf wire events, checkpoints commits, and reports sensor throttle loss', { timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const server = new api.grpc.Server();
  const responses = [
    processExec('exec-grpc-1'),
    { node_name: 'node-a', rate_limit_info: { number_of_dropped_process_events: '7' } },
    { node_name: 'node-a', rate_limit_info: { number_of_dropped_process_events: '2' } },
    { node_name: 'node-a', rate_limit_info: { number_of_dropped_process_events: '0' } },
    {
      node_name: 'node-a',
      time: { seconds: '1793603698', nanos: 0 },
      process_exit: { process: { exec_id: 'exec-grpc-1', pid: { value: 101 }, start_time: { seconds: '1793603690', nanos: 100000000 }, binary: '/usr/bin/node' }, status: 0, signal: '' }
    }
  ];
  let eventRequest;
  server.addService(api.service.service, {
    getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents(call) { eventRequest = call.request; for (const response of responses) call.write(response); call.end(); }
  });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', api.grpc.ServerCredentials.createInsecure(), (error, boundPort) => error ? reject(error) : resolve(boundPort));
  });
  const { directory, ledger } = tempLedger();
  let connection;
  try {
    connection = new api.service(`127.0.0.1:${port}`, api.grpc.credentials.createInsecure());
    const collector = new TetragonGrpcCollector({
      ledger, hostId: 'host-a', bootId: 'boot-a', maxEvents: 5, batchSize: 2, flushIntervalMs: 50,
      tetragonPolicyNames: ['sentinel-runtime-observability'],
      expectedNodeName: 'node-a', connectionFactory: async () => ({ client: connection, close: () => connection.close(), transportProtocol: 'GRPC_TCP', transportAuthentication: 'TLS_SERVER_AUTH' })
    });
    const result = await collector.run();
    assert.deepEqual(eventRequest.allow_list, [
      { event_set: ['PROCESS_EXEC', 'PROCESS_EXIT', 'PROCESS_LOADER', 'PROCESS_THROTTLE', 'RATE_LIMIT_INFO'] },
      { event_set: ['PROCESS_KPROBE', 'PROCESS_TRACEPOINT', 'PROCESS_UPROBE', 'PROCESS_LSM', 'PROCESS_USDT'], policy_names: ['sentinel-runtime-observability'] }
    ]);
    assert.equal(result.received, 5);
    assert.equal(result.persisted, 8);
    assert.equal(result.duplicate_events_suppressed, 0);
    assert.equal(result.supported, 2);
    assert.equal(result.rate_limit_reports, 3);
    assert.equal(Object.hasOwn(result, 'reported_dropped_process_events'), false);
    assert.equal(result.unprocessed_at_limit_lower_bound, '0');

    const records = ledger.getRecords({ limit: 100 }).map(row => ({ ...row, payload: JSON.parse(row.payload_json) }));
    const eventRecords = records.filter(row => row.record_type === 'event');
    assert.equal(eventRecords.length, 8);
    const eventType = event => event.event_type || event.eventType;
    assert.deepEqual(eventRecords.map(row => eventType(row.payload.event)).filter(Boolean).sort(), [
      'EVENT_LOSS', 'EVENT_LOSS', 'PROCESS_EXEC', 'PROCESS_EXIT', 'RATE_LIMIT_INFO', 'RATE_LIMIT_INFO', 'RATE_LIMIT_INFO', 'SENSOR_HEALTH'
    ]);
    const execRecord = eventRecords.find(row => eventType(row.payload.event) === 'PROCESS_EXEC');
    const execEvidence = execRecord.payload.evidence;
    assert.equal(validateEventV2(execRecord.payload.event).valid, true);
    assert.equal(execRecord.payload.event.payload.arguments_capture_status, 'REDACTED_BY_POLICY');
    assert.equal(execRecord.payload.event.timestamps.provider_observation_timestamp === execRecord.payload.event.timestamps.source_timestamp, false);
    const expectedRaw = api.definition['tetragon.FineGuidanceSensors'].GetEvents.responseSerialize(responses[0]);
    assert.equal(execEvidence.raw_payload_sha256, crypto.createHash('sha256').update(expectedRaw).digest('hex'));
    assert.equal(execEvidence.source_cursor.cursor_kind, 'GRPC_SEQUENCE');
    assert.equal(execEvidence.sensor_metadata.tetragon_version, 'v1.8.0');
    const throttles = eventRecords.filter(row => eventType(row.payload.event) === 'RATE_LIMIT_INFO').map(row => row.payload.evidence);
    assert.deepEqual(throttles.map(item => item.reported_dropped_process_events).sort(), ['0', '2', '7']);
    assert.ok(throttles.every(item => item.loss_domain === 'sensor_throttle'));
    assert.deepEqual(throttles.map(item => item.count_semantics), Array(3).fill('Raw value from this RATE_LIMIT_INFO frame only; the pinned v1.8.0 proto does not specify a reporting interval or cumulative/reset semantics'));
    const normalizedLossEvents = eventRecords.map(row => row.payload.event).filter(event => ['EVENT_LOSS', 'SENSOR_HEALTH'].includes(event.event_type));
    assert.deepEqual(normalizedLossEvents.map(event => event.event_type).sort(), ['EVENT_LOSS', 'EVENT_LOSS', 'SENSOR_HEALTH']);
    assert.ok(normalizedLossEvents.every(event => event.loss_metrics.sensor_throttle.state === (event.event_type === 'SENSOR_HEALTH' ? 'ZERO_OBSERVED' : 'MEASURED')));
    assert.equal(ledger.getLatestSourceCheckpoint(result.source_id).sequence_number, '5');
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    try { connection?.close(); } catch { /* best-effort teardown */ }
    server.forceShutdown();
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon gRPC collector suppresses an exact source-frame replay and reports the count', { timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const server = new api.grpc.Server();
  const replayed = processExec('exec-grpc-replayed');
  server.addService(api.service.service, {
    getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents(call) { call.write(replayed); call.write(structuredClone(replayed)); call.end(); }
  });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', api.grpc.ServerCredentials.createInsecure(), (error, boundPort) => error ? reject(error) : resolve(boundPort));
  });
  const { directory, ledger } = tempLedger();
  let connection;
  try {
    connection = new api.service(`127.0.0.1:${port}`, api.grpc.credentials.createInsecure());
    const collector = new TetragonGrpcCollector({
      ledger, hostId: 'host-replay', bootId: 'boot-replay', maxEvents: 2, batchSize: 2,
      flushIntervalMs: 50,
      connectionFactory: async () => ({ client: connection, close: () => connection.close(), transportProtocol: 'GRPC_TCP', transportAuthentication: 'TLS_SERVER_AUTH' })
    });
    const result = await collector.run();
    assert.equal(result.received, 2);
    assert.equal(result.supported, 2);
    assert.equal(result.persisted, 1);
    assert.equal(result.duplicate_events_suppressed, 1);
    const eventRows = ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'event');
    assert.equal(eventRows.length, 1);
    assert.equal(ledger.getLatestSourceCheckpoint(result.source_id).sequence_number, '2');
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    try { connection?.close(); } catch { /* best-effort teardown */ }
    server.forceShutdown();
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon gRPC collector normalizes tcp_sendmsg kretprobe as one raw provider event', { timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const server = new api.grpc.Server();
  const response = {
    node_name: 'node-a',
    time: { seconds: '1793603696', nanos: 123456000 },
    process_kprobe: {
      process: {
        exec_id: 'exec-kprobe-send', pid: { value: 101 }, tid: { value: 101 },
        start_time: { seconds: '1793603690', nanos: 100000000 }, binary: '/usr/bin/node'
      },
      function_name: 'tcp_sendmsg', policy_name: 'sentinel-observe-v1',
      args: [
        { size_arg: '4096', label: 'sentinel_size' },
        { sock_arg: { family: 'AF_INET', protocol: 'TCP', saddr: '192.0.2.10', daddr: '198.51.100.20', sport: 4567, dport: 443, state: 'ESTABLISHED' }, label: 'sentinel_socket' }
      ],
      return: { long_arg: '4096' }
    }
  };
  server.addService(api.service.service, {
    getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents(call) { call.write(response); call.end(); }
  });
  const port = await new Promise((resolve, reject) => {
    server.bindAsync('127.0.0.1:0', api.grpc.ServerCredentials.createInsecure(), (error, boundPort) => error ? reject(error) : resolve(boundPort));
  });
  const { directory, ledger } = tempLedger();
  let connection;
  try {
    connection = new api.service(`127.0.0.1:${port}`, api.grpc.credentials.createInsecure());
    const collector = new TetragonGrpcCollector({
      ledger, hostId: 'host-a', bootId: 'boot-a', maxEvents: 1, batchSize: 1,
      expectedNodeName: 'node-a',
      connectionFactory: async () => ({ client: connection, close: () => connection.close(), transportProtocol: 'GRPC_TCP', transportAuthentication: 'TLS_SERVER_AUTH' })
    });
    const result = await collector.run();
    assert.equal(result.received, 1);
    assert.equal(result.supported, 1);
    assert.equal(result.persisted, 1);
    const eventRecord = ledger.getRecords({ limit: 100 })
      .filter(row => row.record_type === 'event')
      .map(row => ({ ...row, payload: JSON.parse(row.payload_json) }))[0];
    assert.ok(eventRecord);
    const { event, evidence } = eventRecord.payload;
    assert.equal(event.event_type, 'NETWORK_SEND_RESULT');
    assert.equal(event.source_event_type, 'process_kprobe:tcp_sendmsg');
    assert.equal(event.payload.destination_ip, '198.51.100.20');
    assert.equal(event.payload.destination_port, 443);
    assert.equal(event.payload.bytes_requested, '4096');
    assert.equal(event.payload.bytes_accepted_by_kernel, '4096');
    assert.equal(event.payload.socket_fd, null);
    assert.equal(event.payload.family, 'AF_INET');
    assert.equal(eventRecord.payload.evidence.tracing_policy_name, 'sentinel-observe-v1');
    assert.equal(validateEventV2(event).valid, true);
    const rawBytes = api.definition['tetragon.FineGuidanceSensors'].GetEvents.responseSerialize(response);
    assert.equal(evidence.raw_payload_sha256, crypto.createHash('sha256').update(rawBytes).digest('hex'));
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    try { connection?.close(); } catch { /* best-effort teardown */ }
    server.forceShutdown();
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon node identity mismatch is fatal before the event reaches the ledger', async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const response = rawDecodedResponse(api, processExec('wrong-node-exec', 'node-b'));
  const stream = new EventEmitter();
  stream.pause = () => {};
  stream.resume = () => {};
  stream.cancel = () => {};
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() { process.nextTick(() => { stream.emit('data', response); stream.emit('end'); }); return stream; }
  };
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a', expectedNodeName: 'node-a',
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' })
  });
  try {
    await assert.rejects(() => collector.run(), /node_name mismatch/);
    const eventRecords = ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'event');
    assert.equal(eventRecords.length, 0);
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon persistence failure retains the cause and handles delayed cancellation errors', { timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const response = rawDecodedResponse(api, processExec('persistence-failure'));
  const stream = new EventEmitter();
  stream.pause = () => {};
  stream.resume = () => {};
  stream.cancel = () => {
    process.nextTick(() => stream.emit('error', Object.assign(new Error('1 CANCELLED: Cancelled on client'), { code: 1 })));
  };
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() {
      process.nextTick(() => stream.emit('data', response));
      return stream;
    }
  };
  const originalRecordEventsWithCheckpoint = ledger.recordEventsWithCheckpoint.bind(ledger);
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a', batchSize: 1,
    connectionFactory: async () => {
      // Fail only after startup health/checkpoint records have been persisted.
      ledger.recordEventsWithCheckpoint = () => { throw new Error('injected persistence failure'); };
      return { client, close() {}, transportProtocol: 'GRPC_TCP' };
    }
  });
  try {
    await assert.rejects(() => collector.run(), /injected persistence failure/);
    await new Promise(resolve => setTimeout(resolve, 10));
    ledger.recordEventsWithCheckpoint = originalRecordEventsWithCheckpoint;
    assert.ok(stream.listenerCount('error') >= 1, 'late grpc-js cancellation errors must remain handled');
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.recordEventsWithCheckpoint = originalRecordEventsWithCheckpoint;
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon queue overflow records a lower bound and stops retrying on abort', async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const responses = Array.from({ length: 32 }, (_, index) => rawDecodedResponse(api, processExec(`queue-exec-${index}`)));
  const controller = new AbortController();
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() {
      const stream = new EventEmitter();
      stream.pause = () => {};
      stream.resume = () => {};
      stream.cancel = () => {};
      process.nextTick(() => { for (const response of responses) stream.emit('data', response); });
      return stream;
    }
  };
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a', batchSize: 4096, queueCapacity: 16,
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' }),
    onStatus(status) { if (status.event_type === 'COLLECTOR_QUEUE_OVERFLOW') controller.abort(); }
  });
  try {
    const result = await collector.run(controller.signal);
    assert.equal(result.queue_drops_lower_bound, '1');
    assert.equal(result.received, 16);
    const health = ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'sensor_health');
    assert.ok(health.some(row => JSON.parse(row.payload_json).event.event_type === 'COLLECTOR_QUEUE_OVERFLOW'));
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon collector yields under a busy stream and accounts queued events discarded at shutdown', { timeout: 5000 }, async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const responses = Array.from({ length: 64 }, (_, index) => rawDecodedResponse(api, processExec(`shutdown-exec-${index}`)));
  const controller = new AbortController();
  let cancelled = false;
  let abortTimer = null;
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() {
      const stream = new EventEmitter();
      stream.pause = () => { if (!abortTimer) abortTimer = setTimeout(() => controller.abort(), 0); };
      stream.resume = () => {};
      stream.cancel = () => { cancelled = true; };
      setImmediate(() => {
        for (const response of responses) stream.emit('data', response);
      });
      return stream;
    }
  };
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-shutdown', bootId: 'boot-shutdown', maxEvents: 100000, batchSize: 16, queueCapacity: 64,
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' })
  });
  const started = Date.now();
  try {
    const result = await collector.run(controller.signal);
    assert.ok(Date.now() - started < 1500, 'shutdown must not wait for the entire stream backlog');
    assert.ok(BigInt(result.shutdown_queue_discarded_lower_bound) > 0n);
    const health = ledger.getRecords({ limit: 1000 }).filter(row => row.record_type === 'sensor_health');
    assert.ok(health.some(row => JSON.parse(row.payload_json).event.event_type === 'COLLECTOR_SHUTDOWN_QUEUE_DISCARD'));
    const stopped = health.map(row => JSON.parse(row.payload_json)).find(record => record.event.event_type === 'COLLECTOR_STOPPED');
    assert.equal(stopped.details.reason, 'SIGNAL', 'a signal stop must not be mislabeled as a reached event limit');
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    if (abortTimer) clearTimeout(abortTimer);
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon collector rejects the historical provider release before streaming', async () => {
  const { directory, ledger } = tempLedger();
  let streamed = false;
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.7.1' }); },
    getEvents() { streamed = true; throw new Error('must not start stream'); }
  };
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a',
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' })
  });
  try {
    await assert.rejects(() => collector.run(), /pinned to v1.8.0/);
    assert.equal(streamed, false);
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon exact-version gate also rejects an unreviewed patch release', async () => {
  const { directory, ledger } = tempLedger();
  const client = { getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.1' }); } };
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a',
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' })
  });
  try {
    await assert.rejects(() => collector.run(), /Unsupported Tetragon version v1\.8\.1/);
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon max-events cutoff reports queued events separately from overflow', async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const responses = [rawDecodedResponse(api, processExec('limit-1')), rawDecodedResponse(api, processExec('limit-2'))];
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() {
      const stream = new EventEmitter();
      stream.pause = () => {};
      stream.resume = () => {};
      stream.cancel = () => {};
      process.nextTick(() => { for (const response of responses) stream.emit('data', response); });
      return stream;
    }
  };
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a', maxEvents: 1,
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' })
  });
  try {
    const result = await collector.run();
    assert.equal(result.received, 1);
    assert.equal(result.queue_drops_lower_bound, '0');
    assert.equal(result.unprocessed_at_limit_lower_bound, '1');
    const health = ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'sensor_health');
    assert.ok(health.some(row => JSON.parse(row.payload_json).event.event_type === 'COLLECTOR_LIMIT_REACHED'));
    const stopped = health.map(row => JSON.parse(row.payload_json)).find(record => record.event.event_type === 'COLLECTOR_STOPPED');
    assert.equal(stopped.details.reason, 'MAX_EVENTS', 'a reached limit must be labeled distinctly from a signal stop');
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon stream gap keeps subsequent detections observe-only', { timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const execResponse = rawDecodedResponse(api, processExec('exec-after-gap'));
  let connections = 0;
  const client = {
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() {
      const stream = new EventEmitter();
      stream.pause = () => {};
      stream.resume = () => {};
      stream.cancel = () => {};
      connections++;
      if (connections === 1) {
        process.nextTick(() => stream.emit('error', Object.assign(new Error('sensor unavailable'), { code: 14 })));
      } else {
        process.nextTick(() => { stream.emit('data', execResponse); stream.emit('end'); });
      }
      return stream;
    }
  };
  const analysis = {
    workloadId: 'gap-worker',
    identity: { host_id: 'host-gap', boot_id: 'boot-gap', exec_id: 'exec-after-gap', pid: 202 },
    deterministicDeviation: null,
    sequenceDetections: [{
      chainType: 'SUSPICIOUS_EXFILTRATION_SEQUENCE',
      severity: 'HIGH',
      confidence: 0.7,
      title: 'Suspicious exfiltration detected',
      sourceEventKeys: ['key-before-gap', 'key-after-gap']
    }],
    anomalyDetections: null,
    observabilityStatus: 'NORMAL',
    telemetryLoss: null
  };
  const decisionEngine = new DecisionEngine({ allowAutomatedSuspension: true, requireHumanApprovalForR2: false });
  const collector = new TetragonGrpcCollector({
    ledger, hostId: 'host-gap', bootId: 'boot-gap', maxEvents: 1, batchSize: 1, flushIntervalMs: 10,
    connectionFactory: async () => ({ client, close() {}, transportProtocol: 'GRPC_TCP' }),
    behaviorEngine: { analyzeEvent: () => analysis },
    decisionEngine
  });
  try {
    const result = await collector.run();
    assert.equal(result.received, 1);
    assert.equal(connections, 2);
    const rows = ledger.getRecords({ limit: 100 }).map(row => ({ ...row, payload: JSON.parse(row.payload_json) }));
    const disconnected = rows.find(row => row.record_type === 'sensor_health' &&
      row.payload.event.event_type === 'STREAM_DISCONNECTED');
    assert.ok(disconnected);
    assert.equal(disconnected.payload.details.observability_degraded, true);
    const exec = rows.find(row => row.record_type === 'event' && row.payload.event.event_type === 'PROCESS_EXEC');
    assert.ok(exec);
    assert.equal(exec.payload.decision.requestedAction, 'OBSERVE_ONLY');
    assert.equal(exec.payload.decision.observabilityStatus, 'DEGRADED');
    assert.ok(exec.payload.decision.safetyGatingReasons.some(reason => reason.includes('Observability degraded')));
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Tetragon collector restart preserves degraded observability and requires evidence to recover', { timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const { directory, ledger } = tempLedger();
  const firstExecResponse = rawDecodedResponse(api, processExec('exec-before-restart'));
  const secondExecResponse = rawDecodedResponse(api, processExec('exec-after-restart'));
  const clientFor = response => ({
    getVersion(_request, _options, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents() {
      const stream = new EventEmitter();
      stream.pause = () => {};
      stream.resume = () => {};
      stream.cancel = () => {};
      process.nextTick(() => { stream.emit('data', response); stream.emit('end'); });
      return stream;
    }
  });
  const analysis = {
    workloadId: 'restart-worker',
    identity: { host_id: 'host-restart', boot_id: 'boot-restart', exec_id: 'exec-after-restart', pid: 303 },
    deterministicDeviation: null,
    sequenceDetections: [{
      chainType: 'SUSPICIOUS_EXFILTRATION_SEQUENCE',
      severity: 'HIGH',
      confidence: 0.7,
      title: 'Suspicious exfiltration detected',
      sourceEventKeys: ['key-before-restart', 'key-after-restart']
    }],
    anomalyDetections: null,
    observabilityStatus: 'NORMAL',
    telemetryLoss: null
  };
  const firstCollector = new TetragonGrpcCollector({
    ledger, hostId: 'host-restart', bootId: 'boot-restart', maxEvents: 1, batchSize: 1, flushIntervalMs: 10,
    connectionFactory: async () => ({ client: clientFor(firstExecResponse), close() {}, transportProtocol: 'GRPC_TCP' })
  });
  const decisionEngine = new DecisionEngine({ allowAutomatedSuspension: true, requireHumanApprovalForR2: false });
  const secondCollector = new TetragonGrpcCollector({
    ledger, hostId: 'host-restart', bootId: 'boot-restart', maxEvents: 1, batchSize: 1, flushIntervalMs: 10,
    connectionFactory: async () => ({ client: clientFor(secondExecResponse), close() {}, transportProtocol: 'GRPC_TCP' }),
    behaviorEngine: { analyzeEvent: () => analysis },
    decisionEngine
  });
  try {
    const firstResult = await firstCollector.run();
    assert.equal(firstResult.received, 1);
    assert.equal(firstCollector.observabilityState, 'HEALTHY');
    const firstCheckpoint = ledger.getLatestSourceCheckpoint(firstCollector.sourceId);
    assert.equal(firstCheckpoint.observability_state, 'HEALTHY');

    const secondResult = await secondCollector.run();
    assert.equal(secondResult.received, 1);
    assert.equal(secondCollector.observabilityState, 'DEGRADED');
    assert.equal(secondCollector.observabilityDegraded, true);
    assert.equal(decisionEngine.observabilityDegraded, true);

    const rows = ledger.getRecords({ limit: 200 }).map(row => ({ ...row, payload: JSON.parse(row.payload_json) }));
    const connected = rows.find(row => row.record_type === 'sensor_health' &&
      row.payload.event.event_type === 'STREAM_CONNECTED');
    assert.ok(connected);
    assert.equal(connected.payload.details.observability_state, 'DEGRADED');
    assert.equal(connected.payload.details.prior_checkpoint.observability_state, 'HEALTHY');
    assert.equal(connected.payload.details.observability_degraded, true);
    const exec = rows.find(row => row.record_type === 'event' &&
      row.payload.event.event_type === 'PROCESS_EXEC' &&
      row.payload.event.process_identity?.exec_id === 'exec-after-restart');
    assert.ok(exec);
    assert.equal(exec.payload.decision.requestedAction, 'OBSERVE_ONLY');
    assert.equal(exec.payload.decision.observabilityStatus, 'DEGRADED');
    assert.ok(exec.payload.decision.safetyGatingReasons.some(reason => reason.includes('Observability degraded')));
    const degradedCheckpoint = ledger.getLatestSourceCheckpoint(secondCollector.sourceId);
    assert.equal(degradedCheckpoint.observability_state, 'DEGRADED');

    // 1. Operator acknowledges gap - records human risk acceptance, but observability remains degraded (safety invariant)
    assert.throws(() => secondCollector.markObservabilityGapAcknowledged({ kind: 'INVALID' }), /OPERATOR_ACK/);
    assert.throws(() => secondCollector.markObservabilityGapAcknowledged({ kind: 'OPERATOR_ACK' }), /reference/);
    secondCollector.markObservabilityGapAcknowledged({ kind: 'OPERATOR_ACK', reference: 'incident-1' });
    assert.equal(secondCollector.observabilityState, 'GAP_ACKNOWLEDGED');
    assert.equal(secondCollector.observabilityDegraded, true);
    assert.equal(decisionEngine.observabilityDegraded, true);
    assert.equal(decisionEngine.observabilityState, 'GAP_ACKNOWLEDGED');
    const ackCheckpoint = ledger.getLatestSourceCheckpoint(secondCollector.sourceId);
    assert.equal(ackCheckpoint.observability_state, 'GAP_ACKNOWLEDGED');
    assert.equal(ackCheckpoint.observability_recovery.reference, 'incident-1');

    // 2. Scenario E: Second restart of collector with prior GAP_ACKNOWLEDGED restores GAP_ACKNOWLEDGED and preserves degraded gate
    const thirdExecResponse = rawDecodedResponse(api, processExec('exec-after-second-restart'));
    const thirdDecisionEngine = new DecisionEngine({ allowAutomatedSuspension: true, requireHumanApprovalForR2: false });
    const thirdAnalysis = {
      ...analysis,
      identity: { host_id: 'host-restart', boot_id: 'boot-restart', exec_id: 'exec-after-second-restart', pid: 404 }
    };
    const thirdCollector = new TetragonGrpcCollector({
      ledger, hostId: 'host-restart', bootId: 'boot-restart', maxEvents: 1, batchSize: 1, flushIntervalMs: 10,
      connectionFactory: async () => ({ client: clientFor(thirdExecResponse), close() {}, transportProtocol: 'GRPC_TCP' }),
      behaviorEngine: { analyzeEvent: () => thirdAnalysis },
      decisionEngine: thirdDecisionEngine
    });
    const thirdResult = await thirdCollector.run();
    assert.equal(thirdResult.received, 1);
    assert.equal(thirdCollector.observabilityState, 'GAP_ACKNOWLEDGED');
    assert.equal(thirdCollector.observabilityDegraded, true);
    assert.equal(thirdDecisionEngine.observabilityDegraded, true);
    assert.equal(thirdDecisionEngine.observabilityState, 'GAP_ACKNOWLEDGED');
    const thirdRows = ledger.getRecords({ limit: 50 }).map(row => ({ ...row, payload: JSON.parse(row.payload_json) }));
    const thirdExec = thirdRows.find(row => row.record_type === 'event' &&
      row.payload.event.event_type === 'PROCESS_EXEC' &&
      row.payload.event.process_identity?.exec_id === 'exec-after-second-restart');
    assert.ok(thirdExec);
    assert.equal(thirdExec.payload.decision.requestedAction, 'OBSERVE_ONLY');
    assert.equal(thirdExec.payload.decision.observabilityStatus, 'DEGRADED');

    // 3. Scenario F: Attempting recovery via OPERATOR_ACK is rejected
    assert.throws(() => thirdCollector.markObservabilityRecoveryPending({ kind: 'OPERATOR_ACK', reference: 'incident-2' }), /SENSOR_REPLAY_VERIFIED/);
    assert.throws(() => thirdCollector.markObservabilityRecovered({ kind: 'OPERATOR_ACK', reference: 'incident-2' }), /RECOVERY_PENDING/);

    // 4. Scenario G: Invalid, incomplete, or corrupted replay evidence is strictly rejected
    const baseReplay = {
      kind: 'SENSOR_REPLAY_VERIFIED',
      reference: 'replay-session-1',
      replay_id: 'rep-001',
      window_start: '2026-11-08T00:00:00.000Z',
      window_end: '2026-11-08T00:05:00.000Z',
      source_sequence_start: '10',
      source_sequence_end: '50',
      event_count: 40,
      verified: true,
      verification_method: 'HASH_CHAIN_COMPARE',
      replay_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    };
    // Window inverted
    assert.throws(() => thirdCollector.markObservabilityRecoveryPending({ ...baseReplay, window_start: '2026-11-08T00:10:00.000Z', window_end: '2026-11-08T00:05:00.000Z' }), /window_start/);
    // Sequences inverted
    assert.throws(() => thirdCollector.markObservabilityRecoveryPending({ ...baseReplay, source_sequence_start: '100', source_sequence_end: '50' }), /source_sequence_start/);
    // Negative event count
    assert.throws(() => thirdCollector.markObservabilityRecoveryPending({ ...baseReplay, event_count: -1 }), /event_count/);
    // verified !== true
    assert.throws(() => thirdCollector.markObservabilityRecoveryPending({ ...baseReplay, verified: false }), /verified=true/);
    // Malformed replay_hash
    assert.throws(() => thirdCollector.markObservabilityRecoveryPending({ ...baseReplay, replay_hash: 'not-a-valid-sha256' }), /replay_hash/);

    // 5. Scenario H: Valid replay transitions through RECOVERY_PENDING to RECOVERED and clears degradation
    thirdCollector.markObservabilityRecoveryPending(baseReplay);
    assert.equal(thirdCollector.observabilityState, 'RECOVERY_PENDING');
    assert.equal(thirdCollector.observabilityDegraded, true);
    assert.equal(thirdDecisionEngine.observabilityDegraded, true);
    assert.equal(thirdDecisionEngine.observabilityState, 'RECOVERY_PENDING');

    // Mismatched hash on recover throws
    assert.throws(() => thirdCollector.markObservabilityRecovered({ ...baseReplay, replay_hash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' }), /match/);

    // Matching replay recovers cleanly
    thirdCollector.markObservabilityRecovered(baseReplay);
    assert.equal(thirdCollector.observabilityState, 'RECOVERED');
    assert.equal(thirdCollector.observabilityDegraded, false);
    assert.equal(thirdDecisionEngine.observabilityDegraded, false);
    assert.equal(thirdDecisionEngine.observabilityState, 'RECOVERED');
    const recoveredCheckpoint = ledger.getLatestSourceCheckpoint(thirdCollector.sourceId);
    assert.equal(recoveredCheckpoint.observability_state, 'RECOVERED');
    assert.equal(recoveredCheckpoint.observability_recovery.reference, 'replay-session-1');
    const recoveryHealth = ledger.getRecords({ limit: 20 }).map(row => ({ ...row, payload: JSON.parse(row.payload_json) }))
      .find(row => row.record_type === 'sensor_health' && row.payload.event.event_type === 'OBSERVABILITY_RECOVERED');
    assert.ok(recoveryHealth);
    assert.equal(recoveryHealth.payload.details.observability_state, 'RECOVERED');
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
