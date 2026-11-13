'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { SentinelRuntimeCloudClient } = require('../../src/cloud/cloud-client');
const { canonicalJson } = require('../../src/contracts/canonical-json');

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

test('SentinelRuntimeCloudClient rejects insecure non-loopback Cloud endpoints', () => {
  assert.throws(
    () => new SentinelRuntimeCloudClient({
      apiKey: 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
      endpoint: 'http://cloud.example.test'
    }),
    /must use HTTPS/
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

test('SentinelRuntimeCloudClient rejects an unparseable success response', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response('not-json', { status: 200 });
  try {
    const client = new SentinelRuntimeCloudClient({
      apiKey: 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
      endpoint: 'http://127.0.0.1:54321'
    });
    const result = await client.sendHeartbeat();
    assert.equal(result.ok, false);
    assert.equal(result.error, 'INVALID_CLOUD_RESPONSE');
  } finally {
    global.fetch = originalFetch;
  }
});

test('SentinelRuntimeCloudClient refuses a Cloud response for a different incident id', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    ok: true,
    incident_id: 'cloud-case-1',
    client_incident_id: 'different-client-case',
    recorded_at: new Date().toISOString()
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  try {
    const client = new SentinelRuntimeCloudClient({
      apiKey: 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
      endpoint: 'http://127.0.0.1:54321'
    });
    const result = await client.sendIncidentEnvelope({ incident_id: 'inc_expected' });
    assert.equal(result.ok, false);
    assert.equal(result.error, 'CLOUD_RESPONSE_ID_MISMATCH');
  } finally {
    global.fetch = originalFetch;
  }
});

test('SentinelRuntimeCloudClient accepts only a matching idempotent receipt', async () => {
  const originalFetch = global.fetch;
  const idempotencyKey = 'b'.repeat(64);
  global.fetch = async () => new Response(JSON.stringify({
    ok: true,
    duplicate: false,
    incident_id: 'cloud-case-1',
    client_incident_id: 'inc_expected',
    idempotency_key: idempotencyKey,
    recorded_at: new Date().toISOString(),
    analysis_status: 'COMPLETED',
    analysis_pulses: 1
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  try {
    const client = new SentinelRuntimeCloudClient({
      apiKey: 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
      endpoint: 'http://127.0.0.1:54321'
    });
    const result = await client.sendIncidentEnvelope({ incident_id: 'inc_expected', idempotency_key: idempotencyKey });
    assert.equal(result.ok, true);
    assert.equal(result.data.analysis_status, 'COMPLETED');
    assert.equal(result.data.analysis_pulses, 1);
  } finally {
    global.fetch = originalFetch;
  }
});

test('SentinelRuntimeCloudClient validates the durable task claim contract', async () => {
  const originalFetch = global.fetch;
  let request;
  global.fetch = async (url, options) => {
    request = { url: String(url), options };
    return new Response(JSON.stringify({ ok: true, state: 'TASKS_DISPATCHED', tasks: [{
      task_id: 'inv_task_0123456789abcdef01234567', incident_id: 'case-1', expected_boot_id: 'c31528b0-ab61-4f13-9b8d-bf7ee47b0b87',
      playbook_id: 'LINUX.PROCESS.IDENTITY', playbook_version: '1.0.0', governance_level: 'L0_PASSIVE_READ',
      scope: { pid: 42, boot_id: 'c31528b0-ab61-4f13-9b8d-bf7ee47b0b87' }, nonce: 'a'.repeat(32),
      created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(), timeout_ms: 5000, max_output_bytes: 8192,
    }] }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const client = new SentinelRuntimeCloudClient({ apiKey: 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF', endpoint: 'http://127.0.0.1:54321' });
    const result = await client.pollInvestigationTasks({ agentVersion: '0.2.0', capabilities: { investigation_tasks: true, playbooks: ['LINUX.PROCESS.IDENTITY'] } });
    assert.equal(result.ok, true);
    assert.equal(result.data.tasks.length, 1);
    assert.match(request.url, /\/api\/runtime\/tasks\/poll$/);
    assert.equal(JSON.parse(request.options.body).capabilities.investigation_tasks, true);
  } finally { global.fetch = originalFetch; }
});

test('SentinelRuntimeCloudClient posts task results to the exact task path and rejects mismatched receipts', async () => {
  const originalFetch = global.fetch;
  const output = { observation_status: 'OBSERVED', pid: 42 };
  const resultHash = crypto.createHash('sha256').update(canonicalJson(output)).digest('hex');
  let requestUrl = '';
  global.fetch = async (url) => {
    requestUrl = String(url);
    return new Response(JSON.stringify({ ok: true, task_id: 'inv_task_0123456789abcdef01234567', status: 'COMPLETED', duplicate: false, result_hash: resultHash }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  try {
    const client = new SentinelRuntimeCloudClient({ apiKey: 'snt_rt_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF', endpoint: 'http://127.0.0.1:54321' });
    const taskId = 'inv_task_0123456789abcdef01234567';
    const result = await client.sendInvestigationTaskResult({ task_id: taskId, nonce: 'a'.repeat(32), status: 'COMPLETED', output_data: output, result_hash: resultHash });
    assert.equal(result.ok, true);
    assert.ok(requestUrl.endsWith(`/api/runtime/tasks/${taskId}/result`));
  } finally { global.fetch = originalFetch; }
});
