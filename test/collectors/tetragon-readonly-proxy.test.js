'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { getRawResponseBytes, loadTetragonApi } = require('../../src/collectors/tetragon-proto');
const { parseSocketMode, parseUnixSocketAddress, startTetragonReadOnlyProxy } = require('../../src/collectors/tetragon-readonly-proxy');

test('read-only Tetragon proxy accepts only constrained Unix socket permissions', () => {
  assert.equal(parseUnixSocketAddress('unix:///run/sentinel-runtime/proxy.sock', 'linux'), '/run/sentinel-runtime/proxy.sock');
  assert.throws(() => parseUnixSocketAddress('127.0.0.1:5555', 'linux'), /unix/);
  assert.throws(() => parseUnixSocketAddress('unix:///run/../tmp/proxy.sock', 'linux'), /canonical/);
  assert.throws(() => parseUnixSocketAddress('unix:///run/proxy.sock', 'win32'), /requires Linux/);
  assert.equal(parseSocketMode('0600'), 0o600);
  assert.equal(parseSocketMode('0660'), 0o660);
  assert.throws(() => parseSocketMode('0666'), /other-user access/);
  assert.throws(() => parseSocketMode('0700'), /owner read\/write/);
  assert.throws(() => parseSocketMode('0888'), /octal/);
});

test('read-only Tetragon proxy passes stream/version RPCs and rejects policy administration', { skip: process.platform !== 'linux', timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-ro-proxy-'));
  const upstreamPath = path.join(directory, 'upstream.sock');
  const listenPath = path.join(directory, 'readonly.sock');
  const upstreamServer = new api.grpc.Server();
  let mutationCalls = 0;
  const implementation = {};
  for (const method of Object.values(api.service.service)) {
    if (method.responseStream) implementation[method.originalName] = call => { call.end(); };
    else implementation[method.originalName] = (_call, callback) => callback(null, {});
  }
  implementation.getVersion = (_call, callback) => callback(null, { version: 'v1.8.0' });
  implementation.getEvents = call => { call.write({ node_name: 'node-a' }); call.end(); };
  implementation.addTracingPolicy = (_call, callback) => { mutationCalls++; callback(null, {}); };
  const upstreamEventsMethod = api.service.service.GetEvents;
  const unknownWireField = Buffer.from([0xf8, 0x07, 0x01]);
  const upstreamServiceDefinition = {
    ...api.service.service,
    GetEvents: Object.assign({}, upstreamEventsMethod, {
      responseSerialize(message) {
        return Buffer.concat([upstreamEventsMethod.responseSerialize(message), unknownWireField]);
      }
    })
  };
  upstreamServer.addService(upstreamServiceDefinition, implementation);

  let proxy;
  let client;
  let proxySocketRemoved = false;
  try {
    await new Promise((resolve, reject) => {
      upstreamServer.bindAsync(`unix://${upstreamPath}`, api.grpc.ServerCredentials.createInsecure(), error => error ? reject(error) : resolve());
    });
    fs.chmodSync(upstreamPath, 0o600);
    proxy = await startTetragonReadOnlyProxy({
      upstreamAddress: `unix://${upstreamPath}`,
      listenAddress: `unix://${listenPath}`,
      socketMode: '0600'
    });
    assert.deepEqual(proxy.allowedMethods, ['GetVersion', 'GetEvents']);
    assert.equal(fs.statSync(listenPath).mode & 0o777, 0o600);

    client = new api.service(`unix://${listenPath}`, api.grpc.credentials.createInsecure());
    const version = await new Promise((resolve, reject) => client.getVersion({}, (error, response) => error ? reject(error) : resolve(response)));
    assert.equal(version.version, 'v1.8.0');
    const messages = await new Promise((resolve, reject) => {
      const result = [];
      const stream = client.getEvents({});
      stream.on('data', message => result.push(message));
      stream.once('error', reject);
      stream.once('end', () => resolve(result));
    });
    assert.deepEqual(messages.map(message => message.node_name), ['node-a']);
    const expectedRawResponse = Buffer.concat([
      upstreamEventsMethod.responseSerialize({ node_name: 'node-a' }), unknownWireField
    ]);
    assert.ok(getRawResponseBytes(messages[0]).equals(expectedRawResponse), 'proxy must preserve exact protobuf bytes, including unknown fields');

    const denied = await new Promise(resolve => client.addTracingPolicy({}, error => resolve(error)));
    assert.equal(denied.code, api.grpc.status.UNIMPLEMENTED);
    assert.equal(mutationCalls, 0);
  } finally {
    try { client?.close(); } catch { /* best-effort teardown */ }
    if (proxy) {
      await proxy.close(1000);
      proxySocketRemoved = !fs.existsSync(listenPath);
    }
    upstreamServer.forceShutdown();
    fs.rmSync(directory, { recursive: true, force: true });
  }
  assert.equal(proxySocketRemoved, true);
});

test('read-only Tetragon proxy permits one upstream event stream and releases it on cancellation', { skip: process.platform !== 'linux', timeout: 15000 }, async () => {
  const api = loadTetragonApi();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-ro-proxy-limit-'));
  const upstreamPath = path.join(directory, 'upstream.sock');
  const listenPath = path.join(directory, 'readonly.sock');
  const upstreamServer = new api.grpc.Server();
  let upstreamCalls = 0;
  upstreamServer.addService(api.service.service, {
    getVersion(_call, callback) { callback(null, { version: 'v1.8.0' }); },
    getEvents(call) {
      upstreamCalls++;
      call.write({ node_name: `node-${upstreamCalls}` });
    }
  });

  let proxy;
  let client;
  try {
    await new Promise((resolve, reject) => {
      upstreamServer.bindAsync(`unix://${upstreamPath}`, api.grpc.ServerCredentials.createInsecure(), error => error ? reject(error) : resolve());
    });
    fs.chmodSync(upstreamPath, 0o600);
    proxy = await startTetragonReadOnlyProxy({
      upstreamAddress: `unix://${upstreamPath}`,
      listenAddress: `unix://${listenPath}`,
      socketMode: '0600'
    });
    client = new api.service(`unix://${listenPath}`, api.grpc.credentials.createInsecure());

    const first = client.getEvents({});
    await new Promise((resolve, reject) => {
      first.once('data', resolve);
      first.once('error', reject);
    });

    const rejected = client.getEvents({});
    const error = await new Promise(resolve => rejected.once('error', resolve));
    assert.equal(error.code, api.grpc.status.RESOURCE_EXHAUSTED);
    assert.equal(upstreamCalls, 1, 'the rejected client must not open another Tetragon stream');

    first.cancel();
    await new Promise(resolve => setTimeout(resolve, 25));
    const replacement = client.getEvents({});
    await new Promise((resolve, reject) => {
      replacement.once('data', resolve);
      replacement.once('error', reject);
    });
    assert.equal(upstreamCalls, 2, 'a new stream is allowed after the previous client disconnects');
    replacement.cancel();
  } finally {
    try { client?.close(); } catch { /* best-effort teardown */ }
    if (proxy) await proxy.close(1000);
    upstreamServer.forceShutdown();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
