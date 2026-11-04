#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadTetragonApi, getRawResponseBytes } = require('../../src/collectors/tetragon-proto');
const { startTetragonReadOnlyProxy } = require('../../src/collectors/tetragon-readonly-proxy');

async function unary(client, method, request = {}) {
  return new Promise((resolve, reject) => client[method](request, (error, response) => error ? reject(error) : resolve(response)));
}

async function main() {
  if (process.platform !== 'linux') throw new Error('Live read-only proxy smoke requires Linux');
  const args = process.argv.slice(2);
  const upstreamAddress = args[0] || 'unix:///var/run/tetragon/tetragon.sock';
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-runtime-live-proxy-'));
  fs.chmodSync(directory, 0o700);
  const listenAddress = `unix://${path.join(directory, 'readonly.sock')}`;
  let proxy;
  let client;
  let stream;
  try {
    proxy = await startTetragonReadOnlyProxy({ upstreamAddress, listenAddress, socketMode: '0600' });
    const api = loadTetragonApi();
    client = new api.service(proxy.listenAddress, api.grpc.credentials.createInsecure());
    const version = await unary(client, 'getVersion');
    assert.match(version.version, /^v?1\.8\.0$/);

    const denied = await new Promise(resolve => client.getHealth({}, error => resolve(error)));
    assert.equal(denied.code, api.grpc.status.UNIMPLEMENTED, 'client-facing service must not expose non-allowlisted methods');

    const frames = await new Promise((resolve, reject) => {
      const seen = [];
      let settled = false;
      const timer = setTimeout(() => finish(new Error('Timed out waiting for live Tetragon events')), 15000);
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(result);
      };
      stream = client.getEvents({});
      stream.on('data', response => {
        const raw = getRawResponseBytes(response);
        if (!raw) return finish(new Error('Read-only proxy did not preserve raw protobuf response bytes'));
        seen.push({ bytes: raw.length, sha256: crypto.createHash('sha256').update(raw).digest('hex') });
        if (seen.length >= 5) { stream.cancel(); finish(null, seen); }
      });
      stream.once('error', error => { if (!settled) finish(error); });
      stream.once('end', () => finish(null, seen));
    });
    if (frames.length < 1) throw new Error('Live Tetragon stream returned no frames during the smoke window');
    console.log(JSON.stringify({ tetragon_version: version.version, client_methods: proxy.allowedMethods,
      blocked_read_method: 'GetHealth', blocked_status: 'UNIMPLEMENTED', frames_forwarded: frames.length,
      raw_frame_sha256: frames.map(frame => frame.sha256), mode: 'READ_ONLY' }, null, 2));
  } finally {
    try { stream?.cancel(); } catch { /* best-effort teardown */ }
    try { client?.close(); } catch { /* best-effort teardown */ }
    if (proxy) await proxy.close(2000);
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
