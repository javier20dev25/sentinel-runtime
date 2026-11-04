'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EvidenceLedger } = require('../../src/evidence');
const { TetragonGrpcCollector, createTetragonConnection, parseTetragonAddress } = require('../../src/collectors/tetragon-grpc');
const { loadTetragonApi } = require('../../src/collectors/tetragon-proto');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');

function tempLedger() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-grpc-'));
  const ledger = new EvidenceLedger(path.join(directory, 'runtime.sqlite'));
  return { directory, ledger };
}

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
  server.addService(api.service.service, {
    getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents(call) { for (const response of responses) call.write(response); call.end(); }
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
      expectedNodeName: 'node-a', connectionFactory: async () => ({ client: connection, close: () => connection.close(), transportProtocol: 'GRPC_TCP', transportAuthentication: 'TLS_SERVER_AUTH' })
    });
    const result = await collector.run();
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
    assert.equal(ledger.verifyIntegrity().valid, true);
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
