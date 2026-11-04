'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { EvidenceLedger } = require('../../src/evidence');
const { TetragonMetricsCollector, parsePrometheusText, validateMetricsUrl, validateMetricsPeer, requestMetrics } = require('../../src/collectors/tetragon-metrics');
const { validateEventV2 } = require('../../src/contracts/validate-event-v2');

const START = 999999900;
const NOW_MS = 1000000000000;

function exposition({ ringbuf = 0, bpf = 0, notify = 0, field = 0, queue = 0, start = START } = {}) {
  return Buffer.from([
    '# HELP tetragon_observer_ringbuf_events_lost_total Ring buffer loss',
    '# TYPE tetragon_observer_ringbuf_events_lost counter',
    `tetragon_observer_ringbuf_events_lost_total ${ringbuf}`,
    '# TYPE tetragon_bpf_missed_events counter',
    `tetragon_bpf_missed_events_total{error="EAGAIN"} ${bpf}`,
    '# TYPE tetragon_notify_overflowed_events counter',
    `tetragon_notify_overflowed_events_total ${notify}`,
    '# TYPE tetragon_field_filter_failed counter',
    `tetragon_field_filter_failed_total ${field}`,
    '# TYPE tetragon_observer_ringbuf_queue_events_lost counter',
    `tetragon_observer_ringbuf_queue_events_lost_total ${queue}`,
    '# TYPE process_start_time_seconds gauge',
    `process_start_time_seconds ${start}`,
    '# TYPE tetragon_observer_ringbuf_errors counter',
    'tetragon_observer_ringbuf_errors_total 0'
  ].join('\n'));
}

function makeCollector(ledger, request, overrides = {}) {
  return new TetragonMetricsCollector({
    ledger, hostId: 'host-a', bootId: 'boot-a', url: 'http://127.0.0.1:2112/metrics',
    getSensorVersion: () => 'v1.8.0', request, ...overrides
  });
}

function persistedEvents(ledger) {
  return ledger.getRecords({ limit: 100 }).filter(row => row.record_type === 'event')
    .map(row => JSON.parse(row.payload_json).event);
}

test('Prometheus parser aggregates counter label series and requires pinned counter types', () => {
  const parsed = parsePrometheusText(Buffer.from([
    '# TYPE tetragon_bpf_missed_events counter',
    'tetragon_bpf_missed_events_total{error="EAGAIN"} 2',
    'tetragon_bpf_missed_events_total{error="ENOSPC"} 3',
    '# TYPE process_start_time_seconds gauge',
    'process_start_time_seconds 12345.5'
  ].join('\n')));
  assert.equal(parsed.counters.tetragon_bpf_missed_events_total, '5');
  assert.equal(parsed.processStartTimeSeconds, 12345.5);
  assert.throws(() => parsePrometheusText(Buffer.from('tetragon_bpf_missed_events_total 1')), /declared as a Prometheus counter/);
  assert.throws(() => parsePrometheusText(Buffer.from([
    '# TYPE tetragon_bpf_missed_events counter',
    'tetragon_bpf_missed_events_total 9007199254740992'
  ].join('\n'))), /exactly representable/);
});

test('metrics URL policy permits loopback HTTP and requires verified TLS off-host', () => {
  assert.equal(validateMetricsUrl('http://127.0.0.1:2112/metrics').protocol, 'http:');
  assert.equal(validateMetricsUrl('http://[::1]:2112/metrics').protocol, 'http:');
  assert.throws(() => validateMetricsUrl('http://metrics.example.com:2112/metrics'), /loopback/);
  assert.throws(() => validateMetricsUrl('http://127.0.0.1:2112/metrics?token=secret'), /without credentials, query/);
  assert.equal(validateMetricsUrl('https://metrics.example.com/metrics').protocol, 'https:');
  assert.equal(validateMetricsPeer('unix:///var/run/tetragon.sock', 'http://127.0.0.1:2112/metrics'), true);
  assert.throws(() => validateMetricsPeer('unix:///var/run/tetragon.sock', 'https://metrics.example.com/metrics'), /loopback/);
  assert.equal(validateMetricsPeer('tetragon.example.com:54321', 'https://tetragon.example.com:2112/metrics'), true);
  assert.throws(() => validateMetricsPeer('tetragon.example.com:54321', 'https://other.example.com:2112/metrics'), /same host identity/);
  assert.throws(() => validateMetricsPeer('tetragon.example.com:54321', 'http://tetragon.example.com:2112/metrics'), /Plain HTTP metrics are restricted to a loopback endpoint/);
});

test('HTTP scrape reads exact loopback bytes and does not follow redirects', async t => {
  let redirectHits = 0;
  let redirect = false;
  const body = Buffer.from('# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds 1\n');
  const server = http.createServer((request, response) => {
    if (redirect) {
      response.writeHead(302, { location: '/metrics' });
      response.end();
      return;
    }
    redirectHits++;
    response.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' });
    response.end(body);
  });
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', error => error ? reject(error) : resolve()));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const address = server.address();
  const response = await requestMetrics(`http://127.0.0.1:${address.port}/metrics`);
  assert.equal(response.status, 200);
  assert.equal(response.body.toString(), body.toString());
  redirect = true;
  const redirected = await requestMetrics(`http://127.0.0.1:${address.port}/metrics`);
  assert.equal(redirected.status, 302);
  assert.equal(redirectHits, 1);
});

test('metrics collector emits validated health and loss deltas with an atomic durable cursor', async () => {
  const ledger = new EvidenceLedger(':memory:');
  const bodies = [
    exposition({ ringbuf: 0, bpf: 2, notify: 0, field: 3, queue: 0 }),
    exposition({ ringbuf: 1, bpf: 2, notify: 0, field: 4, queue: 1 })
  ];
  const collector = makeCollector(ledger, async () => ({ status: 200, contentType: 'text/plain; version=0.0.4', body: bodies.shift() }));
  const first = await collector.scrapeOnce(NOW_MS);
  assert.equal(first.status, 'SUCCESS', JSON.stringify(persistedEvents(ledger)[0]?.payload));
  assert.deepEqual(first.positive_loss_deltas.map(item => item.domain).sort(), ['tetragon_bpf_missed_events', 'tetragon_field_filter_drops']);
  assert.equal(first.status, 'SUCCESS');
  const second = await collector.scrapeOnce(NOW_MS + 10000);
  assert.deepEqual(second.positive_loss_deltas.map(item => item.domain).sort(), ['ebpf_kernel', 'tetragon_field_filter_drops', 'tetragon_observer_queue_drops']);
  const events = persistedEvents(ledger);
  assert.equal(events.filter(event => event.event_type === 'SENSOR_HEALTH').length, 2);
  assert.equal(events.filter(event => event.event_type === 'EVENT_LOSS').length, 5);
  for (const event of events) assert.equal(validateEventV2(event).valid, true);
  const latest = ledger.getLatestSourceCheckpoint(collector.sourceId);
  assert.equal(latest.counters.tetragon_bpf_missed_events_total, '2');
  assert.equal(latest.producer_sequence_number, String(events.length));
  assert.equal(ledger.verifyIntegrity().valid, true);
  ledger.close();
});

test('counter restarts and unavailable metrics stay unknown instead of generating false loss', async () => {
  const ledger = new EvidenceLedger(':memory:');
  const responses = [
    { status: 200, contentType: 'text/plain', body: exposition({ ringbuf: 20, bpf: 50, field: 8 }) },
    { status: 200, contentType: 'text/plain', body: exposition({ ringbuf: 1, bpf: 2, field: 0, start: START + 100 }) }
  ];
  const collector = makeCollector(ledger, async () => responses.shift());
  await collector.scrapeOnce(NOW_MS);
  const restarted = await collector.scrapeOnce(NOW_MS + 10000);
  assert.deepEqual(restarted.positive_loss_deltas, []);
  const latestHealth = persistedEvents(ledger).filter(event => event.event_type === 'SENSOR_HEALTH')[0];
  assert.deepEqual(latestHealth.payload.counter_reset_domains, [
    'ebpf_kernel', 'tetragon_bpf_missed_events', 'tetragon_field_filter_drops',
    'tetragon_listener_overflow', 'tetragon_observer_queue_drops'
  ]);
  assert.equal(latestHealth.loss_metrics.ebpf_kernel.state, 'UNKNOWN');
  assert.equal(latestHealth.loss_metrics.tetragon_aggregation_buffer_drops.state, 'NOT_APPLICABLE');
  ledger.close();
});

test('HTTP and transport failures are committed as degraded health without inventing raw bytes', async () => {
  const ledger = new EvidenceLedger(':memory:');
  const collector = makeCollector(ledger, async () => ({ status: 503, contentType: 'text/plain', body: Buffer.from('unavailable') }));
  const failed = await collector.scrapeOnce(NOW_MS);
  assert.equal(failed.status, 'HTTP_ERROR');
  const health = persistedEvents(ledger)[0];
  assert.equal(health.event_type, 'SENSOR_HEALTH');
  assert.equal(health.source_cursor.scrape_status, 'HTTP_ERROR');
  assert.equal(health.source_cursor.raw_payload_sha256.length, 64);
  assert.equal(health.loss_metrics.ebpf_kernel.state, 'UNAVAILABLE');
  assert.equal(validateEventV2(health).valid, true);

  const networkFailure = makeCollector(ledger, async () => { const error = new Error('connect refused'); error.kind = 'TRANSPORT_ERROR'; throw error; });
  const unavailable = await networkFailure.scrapeOnce(NOW_MS + 1000);
  assert.equal(unavailable.status, 'TRANSPORT_ERROR');
  const latest = persistedEvents(ledger)[0];
  assert.equal(latest.source_cursor.raw_payload_sha256, null);
  assert.equal(latest.source_cursor.response_status, null);
  assert.equal(validateEventV2(latest).valid, true);
  ledger.close();
});
