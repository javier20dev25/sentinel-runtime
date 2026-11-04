'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { SentinelRuntimeCloudClient } = require('../../src/cloud/cloud-client');

test('SentinelRuntimeCloudClient rejects CLI tokens (sntl_ prefix)', () => {
  const cliToken = 'sntl_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF';
  assert.throws(
    () => new SentinelRuntimeCloudClient({ apiKey: cliToken }),
    /Invalid token format: Sentinel Runtime requires a dedicated host token starting with 'snt_rt_'/
  );
});

test('SentinelRuntimeCloudClient rejects non-runtime tokens without snt_rt_ prefix', () => {
  assert.throws(
    () => new SentinelRuntimeCloudClient({ apiKey: 'random_raw_key_123456789012345678901234567890' }),
    /Invalid token format: Sentinel Runtime token must begin with 'snt_rt_'/
  );
});

test('SentinelRuntimeCloudClient accepts valid snt_rt_ tokens', () => {
  const validToken = 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF';
  const client = new SentinelRuntimeCloudClient({ apiKey: validToken });
  assert.equal(client.hasValidKey(), true);
  assert.equal(client.apiKey, validToken);
});

test('SentinelRuntimeCloudClient handles unconfigured key gracefully (offline mode)', async () => {
  const client = new SentinelRuntimeCloudClient({ apiKey: null });
  assert.equal(client.hasValidKey(), false);

  const heartbeat = await client.sendHeartbeat();
  assert.equal(heartbeat.ok, false);
  assert.equal(heartbeat.offline, true);
  assert.equal(heartbeat.reason, 'NO_VALID_RUNTIME_KEY');

  const incident = await client.sendIncidentEnvelope({ rule_id: 'TEST' });
  assert.equal(incident.ok, false);
  assert.equal(incident.offline, true);
});

test('SentinelRuntimeCloudClient handles unreachable endpoint gracefully without crashing', async () => {
  const validToken = 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF';
  const client = new SentinelRuntimeCloudClient({
    apiKey: validToken,
    endpoint: 'http://127.0.0.1:54321', // Unreachable local port
    timeoutMs: 300
  });

  const res = await client.sendHeartbeat({ status: 'HEALTHY' });
  assert.equal(res.ok, false);
  assert.equal(res.offline, true);
});
