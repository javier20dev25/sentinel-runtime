'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { canonicalPayloadSha256, syntheticObservabilityEventKey } = require('../contracts/event-keys');
const { validateEventV2 } = require('../contracts/validate-event-v2');
const { canonicalJson } = require('../contracts/canonical-json');

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_LINE_BYTES = 64 * 1024;
const MAX_UINT64 = 18446744073709551615n;
const PRODUCER_ID = 'sentinel-runtime-tetragon-metrics-v1';
const COUNTER_DOMAINS = Object.freeze({
  ebpf_kernel: 'tetragon_observer_ringbuf_events_lost_total',
  tetragon_bpf_missed_events: 'tetragon_bpf_missed_events_total',
  tetragon_listener_overflow: 'tetragon_notify_overflowed_events_total',
  tetragon_field_filter_drops: 'tetragon_field_filter_failed_total',
  tetragon_observer_queue_drops: 'tetragon_observer_ringbuf_queue_events_lost_total'
});
const SOURCE_NAMES = Object.freeze({
  ebpf_kernel: 'tetragon_observer_ringbuf_events_lost_total',
  tetragon_bpf_missed_events: 'tetragon_bpf_missed_events_total',
  tetragon_listener_overflow: 'tetragon_notify_overflowed_events_total',
  tetragon_field_filter_drops: 'tetragon_field_filter_failed_total',
  tetragon_observer_queue_drops: 'tetragon_observer_ringbuf_queue_events_lost_total'
});
const LOSS_DOMAINS = Object.freeze([
  'ebpf_kernel', 'sensor_throttle', 'grpc_transport', 'log_rotation', 'parser_reject', 'runtime_queue', 'storage_drop',
  'tetragon_bpf_missed_events', 'tetragon_listener_overflow', 'tetragon_field_filter_drops',
  'tetragon_observer_queue_drops', 'tetragon_aggregation_buffer_drops'
]);

function validateMetricsUrl(value, tls = {}) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search) throw new TypeError('Metrics endpoint must be an HTTP(S) URL without credentials, query, or fragment');
  if (url.pathname !== '/metrics' && url.pathname !== '/') throw new TypeError('Metrics endpoint path must be /metrics or /');
  if (url.protocol === 'http:' && !isLoopback(url.hostname)) throw new Error('Plain HTTP metrics are restricted to a loopback endpoint');
  if (url.protocol === 'http:' && (tls.ca || tls.cert || tls.key)) throw new Error('Metrics TLS files cannot be used with an HTTP endpoint');
  if (Boolean(tls.cert) !== Boolean(tls.key)) throw new Error('Metrics mTLS requires both client certificate and private key');
  if (url.protocol === 'http:' && tls.cert) throw new Error('Metrics mTLS requires HTTPS');
  return url;
}

function isLoopback(hostname) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const family = net.isIP(normalized);
  if (family === 4) return Number(normalized.split('.')[0]) === 127;
  return family === 6 && normalized === '::1';
}

function validateMetricsPeer(grpcAddress, metricsAddress) {
  const metrics = validateMetricsUrl(metricsAddress);
  if (grpcAddress.startsWith('unix://')) {
    if (!isLoopback(metrics.hostname)) throw new Error('A local Tetragon Unix socket may use only a loopback metrics endpoint');
    return true;
  }
  const match = grpcAddress.match(/^(?:\[([^\]]+)\]|([^:]+)):[0-9]+$/);
  if (!match) throw new TypeError('Cannot bind a metrics endpoint to the configured Tetragon TCP host');
  const grpcHost = (match[1] || match[2]).toLowerCase().replace(/\.$/, '');
  const metricsHost = metrics.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (grpcHost !== metricsHost) throw new Error('A remote Tetragon metrics endpoint must use the same host identity as the gRPC endpoint');
  if (metrics.protocol !== 'https:') throw new Error('A remote Tetragon metrics endpoint requires HTTPS');
  return true;
}

function readTlsFile(file, label, kind) {
  const resolved = require('node:path').resolve(file);
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size < 1 || stat.size > 4 * 1024 * 1024) throw new RangeError(`${label} must be a regular PEM file no larger than 4 MiB`);
  if (kind === 'key' && process.platform !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error(`${label} must not be accessible by group or other users`);
  const bytes = fs.readFileSync(resolved);
  const pattern = kind === 'key' ? /-----BEGIN (?:PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----/ : /-----BEGIN CERTIFICATE-----/;
  if (!pattern.test(bytes.toString('ascii'))) throw new TypeError(`${label} must contain an expected PEM block`);
  return bytes;
}

function requestMetrics(url, options = {}) {
  const tls = options.tls || {};
  const parsedUrl = validateMetricsUrl(url, tls);
  const transport = parsedUrl.protocol === 'https:' ? https : http;
  const requestOptions = {
    protocol: parsedUrl.protocol,
    hostname: parsedUrl.hostname.replace(/^\[|\]$/g, ''),
    port: parsedUrl.port || undefined,
    path: `${parsedUrl.pathname === '/' ? '/metrics' : parsedUrl.pathname}`,
    method: 'GET',
    headers: { accept: 'text/plain; version=0.0.4, application/openmetrics-text; version=1.0.0' },
    timeout: options.timeoutMs || 3000,
    rejectUnauthorized: true
  };
  if (tls.ca) requestOptions.ca = readTlsFile(tls.ca, 'Metrics TLS CA', 'cert');
  if (tls.cert) requestOptions.cert = readTlsFile(tls.cert, 'Metrics TLS client certificate', 'cert');
  if (tls.key) requestOptions.key = readTlsFile(tls.key, 'Metrics TLS client key', 'key');

  return new Promise((resolve, reject) => {
    let settled = false;
    const request = transport.request(requestOptions, response => {
      const chunks = [];
      let length = 0;
      response.on('data', chunk => {
        length += chunk.length;
        if (length > MAX_RESPONSE_BYTES) {
          const error = new RangeError(`Tetragon metrics response exceeds ${MAX_RESPONSE_BYTES} bytes`);
          error.kind = 'RESPONSE_TOO_LARGE';
          error.responseStatus = response.statusCode || null;
          request.destroy(error);
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => finish(null, {
        status: response.statusCode || 0,
        contentType: String(response.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase(),
        body: Buffer.concat(chunks, length)
      }));
      response.on('error', error => finish(error));
    });
    const timer = setTimeout(() => {
      const error = new Error('Tetragon metrics request timed out');
      error.kind = 'TRANSPORT_ERROR';
      request.destroy(error);
    }, options.timeoutMs || 3000);
    timer.unref?.();
    request.on('error', error => finish(error));
    request.end();

    function finish(error, response) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(response);
    }
  });
}

function parsePrometheusText(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('Prometheus exposition must be exact response bytes');
  if (buffer.length > MAX_RESPONSE_BYTES) throw new RangeError(`Metrics response exceeds ${MAX_RESPONSE_BYTES} bytes`);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  const types = new Map();
  const samples = new Map();
  const wanted = new Set([...Object.values(COUNTER_DOMAINS), 'process_start_time_seconds', 'tetragon_observer_ringbuf_errors_total']);

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    if (Buffer.byteLength(rawLine, 'utf8') > MAX_LINE_BYTES) throw new RangeError(`Prometheus line ${index + 1} exceeds ${MAX_LINE_BYTES} bytes`);
    const line = rawLine.trim();
    if (!line || line === '# EOF') continue;
    if (line.startsWith('#')) {
      const typeMatch = line.match(/^#\s+TYPE\s+([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(counter|gauge|histogram|summary|untyped)\s*$/);
      if (typeMatch) {
        if (types.has(typeMatch[1]) && types.get(typeMatch[1]) !== typeMatch[2]) throw new TypeError(`Conflicting metric type for ${typeMatch[1]}`);
        types.set(typeMatch[1], typeMatch[2]);
      }
      continue;
    }
    const sample = parseSampleLine(line);
    if (!wanted.has(sample.name)) continue;
    const baseName = sample.name.endsWith('_total') ? sample.name.slice(0, -6) : sample.name;
    const metricType = types.get(sample.name) || types.get(baseName);
    const expectedType = sample.name === 'process_start_time_seconds' ? 'gauge' : 'counter';
    if (metricType !== expectedType) throw new TypeError(`${sample.name} must be declared as a Prometheus ${expectedType}`);

    const labelKey = canonicalJson(sample.labels);
    const identity = `${sample.name}\0${labelKey}`;
    if (samples.has(identity)) throw new TypeError(`Duplicate Prometheus series for ${sample.name}`);
    const value = Number(sample.value);
    if (!Number.isFinite(value) || value < 0) throw new TypeError(`Invalid Prometheus value for ${sample.name}`);
    if (expectedType === 'counter' && (!Number.isSafeInteger(value) || BigInt(value) > MAX_UINT64)) throw new RangeError(`${sample.name} is not an exactly representable uint64 counter`);
    samples.set(identity, { name: sample.name, labels: sample.labels, value });
  }

  const counters = {};
  for (const name of Object.values(COUNTER_DOMAINS)) {
    const series = [...samples.values()].filter(sample => sample.name === name);
    if (series.length === 0) continue;
    const total = series.reduce((sum, sample) => sum + BigInt(sample.value), 0n);
    if (total > MAX_UINT64) throw new RangeError(`${name} aggregate exceeds uint64`);
    counters[name] = total.toString();
  }
  const starts = [...samples.values()].filter(sample => sample.name === 'process_start_time_seconds');
  if (starts.length > 1) throw new TypeError('process_start_time_seconds must have exactly one unlabeled series');
  if (starts.length === 1 && Object.keys(starts[0].labels).length !== 0) throw new TypeError('process_start_time_seconds must not have labels');
  const ringbufErrors = [...samples.values()].filter(sample => sample.name === 'tetragon_observer_ringbuf_errors_total');
  const ringbufErrorTotal = ringbufErrors.reduce((sum, sample) => sum + BigInt(sample.value), 0n);
  if (ringbufErrorTotal > MAX_UINT64) throw new RangeError('tetragon_observer_ringbuf_errors_total aggregate exceeds uint64');
  return {
    counters,
    processStartTimeSeconds: starts.length ? starts[0].value : null,
    ringbufErrorCount: ringbufErrors.length ? ringbufErrorTotal.toString() : null
  };
}

function parseSampleLine(line) {
  const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+([^\s]+)(?:\s+[^\s]+)?$/);
  if (!match) throw new TypeError('Malformed Prometheus sample line');
  return { name: match[1], labels: match[2] === undefined ? {} : parseLabels(match[2]), value: match[3] };
}

function parseLabels(text) {
  const labels = {};
  let cursor = 0;
  while (cursor < text.length) {
    const keyMatch = text.slice(cursor).match(/^([a-zA-Z_][a-zA-Z0-9_]*)="/);
    if (!keyMatch) throw new TypeError('Malformed Prometheus label set');
    const key = keyMatch[1];
    if (Object.hasOwn(labels, key)) throw new TypeError(`Duplicate Prometheus label ${key}`);
    cursor += keyMatch[0].length;
    let value = '';
    let closed = false;
    while (cursor < text.length) {
      const char = text[cursor++];
      if (char === '"') { closed = true; break; }
      if (char !== '\\') { value += char; continue; }
      if (cursor >= text.length) throw new TypeError('Incomplete escape in Prometheus label');
      const escaped = text[cursor++];
      if (escaped === 'n') value += '\n';
      else if (escaped === '"' || escaped === '\\') value += escaped;
      else throw new TypeError('Invalid escape in Prometheus label');
    }
    if (!closed || Buffer.byteLength(value, 'utf8') > 4096) throw new TypeError('Invalid or oversized Prometheus label value');
    labels[key] = value;
    if (cursor === text.length) break;
    if (text[cursor++] !== ',') throw new TypeError('Malformed Prometheus label separator');
  }
  return labels;
}

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function epochSecondsToNanoseconds(seconds) { return (BigInt(Math.floor(seconds)) * 1000000000n).toString(); }
function nowNanoseconds(nowMs = Date.now()) { return (BigInt(nowMs) * 1000000n).toString(); }
function lossMetric(state, count = null, source = null, observedAt = null, windowSeconds = null) {
  return { state, count, source, observed_at: observedAt, scope: source && state !== 'NOT_APPLICABLE' ? 'GLOBAL' : null, window_seconds: windowSeconds };
}
function emptyLossMetrics(state = 'UNKNOWN', observedAt = null) {
  return Object.fromEntries(LOSS_DOMAINS.map(domain => [domain, domain === 'tetragon_aggregation_buffer_drops'
    ? lossMetric('NOT_APPLICABLE', null, 'GETEVENTS_AGGREGATION_OPTIONS_NOT_REQUESTED', observedAt, null)
    : lossMetric(state, null, null, observedAt, null)]));
}
function measuredLossMetrics(values, observedAt, windowSeconds) {
  const metrics = emptyLossMetrics('UNKNOWN', observedAt);
  for (const [domain, value] of Object.entries(values)) {
    const count = String(value.count);
    metrics[domain] = lossMetric(BigInt(count) === 0n ? 'ZERO_OBSERVED' : 'MEASURED', count, SOURCE_NAMES[domain], observedAt, windowSeconds);
  }
  metrics.tetragon_aggregation_buffer_drops = lossMetric('NOT_APPLICABLE', null, 'GETEVENTS_AGGREGATION_OPTIONS_NOT_REQUESTED', observedAt, windowSeconds);
  return metrics;
}

function eventTemplate({ eventType, payload, lossMetrics, metadata, cursor, hostId, bootId, nodeName, timestampNs }) {
  const event = {
    schema_version: '2.0.0', event_id: crypto.randomUUID(), source_event_key: null, event_type: eventType,
    source_provider: 'tetragon', source_event_type: 'PROMETHEUS_METRICS_SCRAPE', source_event_id: cursor.raw_payload_sha256,
    host_identity: { host_id: hostId, boot_id: bootId, node_name: nodeName || null, node_name_status: nodeName ? 'STATIC_CONFIGURED' : 'ABSENT_IN_SENSOR' },
    timestamps: { source_timestamp: timestampNs, provider_observation_timestamp: timestampNs, provider_event_timestamp: null, ingest_timestamp: nowNanoseconds() },
    sensor_metadata: metadata,
    process_identity: null,
    workload_context: { context_type: 'UNKNOWN', container_id: null, pod_name: null, namespace_name: null, cgroup_path: null, namespaces_capture_status: 'UNAVAILABLE' },
    source_cursor: cursor,
    loss_metrics: lossMetrics,
    payload
  };
  event.source_event_key = syntheticObservabilityEventKey({
    hostId, bootId, producerId: metadata.producer_id, producerEpoch: metadata.producer_epoch,
    sequenceNumber: metadata.producer_sequence_number, eventType: event.event_type,
    payloadSha256: canonicalPayloadSha256(payload)
  });
  const checked = validateEventV2(event);
  if (!checked.valid) throw new Error(`Generated Tetragon metrics event violates Event Contract v2: ${checked.errors.map(item => `${item.path}: ${item.message}`).join('; ')}`);
  return event;
}

class TetragonMetricsCollector {
  constructor(options = {}) {
    if (!options.ledger || typeof options.ledger.recordEventsWithCheckpoint !== 'function') throw new TypeError('Evidence ledger with transactional checkpoints is required');
    if (typeof options.hostId !== 'string' || !options.hostId) throw new TypeError('hostId must be provided by trusted target configuration');
    if (typeof options.bootId !== 'string' || !options.bootId) throw new TypeError('bootId must be provided by trusted host configuration');
    this.ledger = options.ledger;
    this.hostId = options.hostId;
    this.bootId = options.bootId;
    this.nodeName = options.nodeName || null;
    this.url = validateMetricsUrl(options.url, options.tls || {}).toString();
    this.tls = options.tls || {};
    this.intervalMs = options.intervalMs ?? 5000;
    this.timeoutMs = options.timeoutMs ?? 3000;
    if (!Number.isSafeInteger(this.intervalMs) || this.intervalMs < 1000 || this.intervalMs > 300000) throw new RangeError('metrics interval must be between 1000 and 300000 ms');
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs < 250 || this.timeoutMs > 30000) throw new RangeError('metrics timeout must be between 250 and 30000 ms');
    this.getSensorVersion = typeof options.getSensorVersion === 'function' ? options.getSensorVersion : () => null;
    this.request = options.request || requestMetrics;
    this.onStatus = typeof options.onStatus === 'function' ? options.onStatus : () => {};
    this.sessionId = crypto.randomUUID();
    this.epoch = crypto.randomUUID();
    this.sourceId = `tetragon-metrics:${crypto.createHash('sha256').update(`${this.hostId}\0${this.bootId}\0${this.url}`).digest('hex')}`;
    this.previous = this.ledger.getLatestSourceCheckpoint(this.sourceId);
    this.sequence = 0n;
  }

  async run(signal) {
    while (!signal?.aborted) {
      if (!this.getSensorVersion()) {
        await delay(this.intervalMs, signal);
        continue;
      }
      await this.scrapeOnce();
      await delay(this.intervalMs, signal);
    }
    return { source_id: this.sourceId, stopped: true, scrapes: this.sequence.toString() };
  }

  async scrapeOnce(nowMs = Date.now()) {
    const verifiedVersion = this.getSensorVersion();
    if (!/^v?1\.8\.0$/.test(verifiedVersion || '')) throw new Error('Tetragon metrics scraping is blocked until the gRPC collector verifies sensor version v1.8.0');
    const timestamp = nowNanoseconds(nowMs);
    let response = null;
    let parsed = null;
    let scrapeStatus = 'SUCCESS';
    let errorMessage = null;
    try {
      response = await this.request(this.url, { tls: this.tls, timeoutMs: this.timeoutMs });
      if (response.status < 200 || response.status >= 300) scrapeStatus = 'HTTP_ERROR';
      else if (!['text/plain', 'application/openmetrics-text', 'application/octet-stream'].includes(String(response.contentType || '').split(';', 1)[0].trim().toLowerCase())) {
        scrapeStatus = 'PARSE_ERROR';
        errorMessage = `Unexpected metrics content type: ${response.contentType || '<missing>'}`;
      } else {
        try { parsed = parsePrometheusText(response.body); }
        catch (error) { scrapeStatus = error instanceof RangeError && /exceeds 4194304 bytes/.test(error.message) ? 'RESPONSE_TOO_LARGE' : 'PARSE_ERROR'; errorMessage = safeError(error); }
      }
    } catch (error) {
      scrapeStatus = error.kind || 'TRANSPORT_ERROR';
      errorMessage = safeError(error);
      response = error.responseStatus ? { status: error.responseStatus, contentType: '', body: null } : null;
    }

    const rawHash = response?.body ? sha256(response.body) : response?.body?.length === 0 ? sha256(response.body) : null;
    const previous = this.previous;
    const candidateProcessStart = parsed?.processStartTimeSeconds;
    const currentProcessStart = Number.isFinite(candidateProcessStart) && candidateProcessStart > 0 && candidateProcessStart <= nowMs / 1000
      ? candidateProcessStart : null;
    const previousProcessStart = previous?.process_start_time_seconds ?? null;
    const processContinuous = currentProcessStart !== null && currentProcessStart !== undefined &&
      previousProcessStart !== null && String(currentProcessStart) === String(previousProcessStart) &&
      typeof previous?.last_successful_scrape_timestamp_ns === 'string';
    const processRestarted = previousProcessStart !== null && currentProcessStart !== null && currentProcessStart !== undefined && String(currentProcessStart) !== String(previousProcessStart);
    const intervalStart = previous?.last_successful_scrape_timestamp_ns;
    const windowSeconds = processContinuous && intervalStart
      ? Math.max(0, Number(BigInt(timestamp) - BigInt(intervalStart)) / 1e9)
      : currentProcessStart !== null && currentProcessStart !== undefined ? Math.max(0, nowMs / 1000 - currentProcessStart) : null;
    const resetDomains = [];
    const unverifiableDomains = [];
    const observed = {};
    const nextCounters = { ...(previous?.counters || {}) };
    if (scrapeStatus === 'SUCCESS' && parsed) {
      for (const [domain, metricName] of Object.entries(COUNTER_DOMAINS)) {
        const total = parsed.counters[metricName];
        if (total === undefined) continue;
        const priorTotal = previous?.counters?.[metricName];
        if (processRestarted) {
          resetDomains.push(domain);
          nextCounters[metricName] = total;
          continue;
        }
        if (currentProcessStart === null || currentProcessStart === undefined) continue;
        if (processContinuous && priorTotal !== undefined) {
          if (BigInt(total) < BigInt(priorTotal)) resetDomains.push(domain);
          else observed[domain] = { count: BigInt(total) - BigInt(priorTotal) };
        } else if (!previous?.last_successful_scrape_timestamp_ns) {
          observed[domain] = { count: BigInt(total) };
        } else if (priorTotal !== undefined) {
          unverifiableDomains.push(domain);
        }
        nextCounters[metricName] = total;
      }
    }

    let lossMetrics;
    if (scrapeStatus !== 'SUCCESS') lossMetrics = emptyLossMetrics(scrapeStatus === 'TRANSPORT_ERROR' ? 'UNKNOWN' : 'UNAVAILABLE', timestamp);
    else {
      lossMetrics = measuredLossMetrics(observed, timestamp, windowSeconds);
      for (const domain of resetDomains) lossMetrics[domain] = lossMetric('UNKNOWN', null, SOURCE_NAMES[domain], timestamp, null);
      for (const domain of unverifiableDomains) lossMetrics[domain] = lossMetric('UNKNOWN', null, SOURCE_NAMES[domain], timestamp, null);
      for (const [domain, metricName] of Object.entries(COUNTER_DOMAINS)) {
        if (parsed.counters[metricName] === undefined) lossMetrics[domain] = lossMetric('UNAVAILABLE', null, metricName, timestamp, windowSeconds);
      }
    }

    const unavailableCounters = [];
    if (scrapeStatus !== 'SUCCESS') unavailableCounters.push(...Object.values(COUNTER_DOMAINS), 'process_start_time_seconds');
    else {
      for (const metricName of Object.values(COUNTER_DOMAINS)) if (parsed.counters[metricName] === undefined) unavailableCounters.push(metricName);
      if (currentProcessStart === null || currentProcessStart === undefined) unavailableCounters.push('process_start_time_seconds');
    }
    const cursorStatus = scrapeStatus;
    const cursor = {
      cursor_kind: 'METRICS_SCRAPE', scrape_epoch: this.epoch, sequence_number: null,
      scrape_status: cursorStatus, response_status: response?.status ?? null, raw_payload_sha256: rawHash
    };
    const transportProtocol = this.url.startsWith('https:') ? 'PROMETHEUS_HTTPS' : 'PROMETHEUS_HTTP';
    const transportAuthentication = this.url.startsWith('https:') ? (this.tls.cert ? 'MUTUAL_TLS' : 'TLS_SERVER_AUTH') : 'LOOPBACK_HTTP_UNAUTHENTICATED';
    const metadataBase = {
      collector_id: 'sentinel-runtime-tetragon-metrics-v1', collector_session_id: this.sessionId,
      sensor_version: verifiedVersion, transport_protocol: transportProtocol,
      transport_authentication: transportAuthentication, debug_process_flags: null, debug_refcnt: null,
      producer_id: PRODUCER_ID, producer_epoch: this.epoch
    };
    const uptime = currentProcessStart !== null && currentProcessStart !== undefined && currentProcessStart <= nowMs / 1000
      ? Math.floor(nowMs / 1000 - currentProcessStart) : null;
    const sensorStatus = scrapeStatus !== 'SUCCESS' ? (scrapeStatus === 'TRANSPORT_ERROR' ? 'UNAVAILABLE' : 'DEGRADED') : 'DEGRADED';
    const healthPayload = {
      sensor_status: sensorStatus, uptime_seconds: uptime,
      uptime_status: uptime === null ? 'UNAVAILABLE' : 'OBSERVED', heartbeat_timestamp: timestamp,
      coverage_status: 'PARTIAL', counter_reset_domains: [...new Set(resetDomains)].sort(),
      counter_unverifiable_domains: [...new Set(unverifiableDomains)].sort(),
      unavailable_counters: [...new Set(unavailableCounters)].sort(),
      active_tracing_policies: []
    };
    if (parsed?.ringbufErrorCount !== null && parsed?.ringbufErrorCount !== undefined) healthPayload.observer_error_count = parsed.ringbufErrorCount;
    if (errorMessage) healthPayload.health_detail = errorMessage.slice(0, 512);

    const events = [];
    const positiveDeltas = Object.entries(observed).filter(([, value]) => value.count > 0n);
    for (const [domain, value] of positiveDeltas) {
      const seq = ++this.sequence;
      const eventCursor = { ...cursor, sequence_number: seq.toString() };
      const eventMetrics = { ...lossMetrics };
      for (const [measuredDomain, measuredValue] of Object.entries(observed)) {
        eventMetrics[measuredDomain] = lossMetric(measuredValue.count === 0n ? 'ZERO_OBSERVED' : 'MEASURED', measuredValue.count.toString(), SOURCE_NAMES[measuredDomain], timestamp, windowSeconds);
      }
      const payload = {
        loss_source: domain, dropped_count: value.count.toString(), window_seconds: windowSeconds,
        window_status: windowSeconds === null ? 'UNKNOWN' : (processContinuous ? 'MEASURED' : 'APPROXIMATED'),
        scope: 'GLOBAL', cgroup_path: null
      };
      const metadata = { ...metadataBase, producer_sequence_number: seq.toString() };
      events.push({ event: eventTemplate({ eventType: 'EVENT_LOSS', payload, lossMetrics: eventMetrics, metadata, cursor: eventCursor, hostId: this.hostId, bootId: this.bootId, nodeName: this.nodeName, timestampNs: timestamp }), evidence: { metrics_endpoint: sanitizeEndpoint(this.url), metric_name: COUNTER_DOMAINS[domain], counter_semantics: processContinuous ? 'DELTA_SINCE_LAST_SUCCESSFUL_SCRAPE' : 'CUMULATIVE_SINCE_TETRAGON_PROCESS_START', process_start_time_seconds: currentProcessStart ?? null } });
    }

    const healthSeq = ++this.sequence;
    const healthCursor = { ...cursor, sequence_number: healthSeq.toString() };
    const healthMetadata = { ...metadataBase, producer_sequence_number: healthSeq.toString() };
    events.push({ event: eventTemplate({ eventType: 'SENSOR_HEALTH', payload: healthPayload, lossMetrics, metadata: healthMetadata, cursor: healthCursor, hostId: this.hostId, bootId: this.bootId, nodeName: this.nodeName, timestampNs: timestamp }), evidence: { metrics_endpoint: sanitizeEndpoint(this.url), scrape_status: scrapeStatus, response_sha256: rawHash, error: errorMessage, process_start_time_seconds: currentProcessStart ?? null, counter_totals: parsed?.counters || null } });

    const checkpoint = {
      source_id: this.sourceId, scrape_epoch: this.epoch, producer_sequence_number: this.sequence.toString(),
      last_attempt_timestamp_ns: timestamp,
      last_successful_scrape_timestamp_ns: scrapeStatus === 'SUCCESS' ? timestamp : (previous?.last_successful_scrape_timestamp_ns || null),
      process_start_time_seconds: scrapeStatus === 'SUCCESS' ? (currentProcessStart ?? null) : previousProcessStart,
      counters: scrapeStatus === 'SUCCESS' ? nextCounters : (previous?.counters || {}),
      scrape_status: scrapeStatus
    };
    const persisted = this.ledger.recordEventsWithCheckpoint(events, checkpoint);
    this.previous = this.ledger.getLatestSourceCheckpoint(this.sourceId);
    this.onStatus({ type: 'metrics_scrape', status: scrapeStatus, events: events.length, reset_domains: resetDomains, unverifiable_domains: unverifiableDomains, unavailable_counters: unavailableCounters, sequence_number: this.sequence.toString() });
    return { status: scrapeStatus, persisted_events: persisted.events.length, reset_domains: resetDomains, unverifiable_domains: unverifiableDomains, unavailable_counters: unavailableCounters, positive_loss_deltas: positiveDeltas.map(([domain, value]) => ({ domain, count: value.count.toString() })) };
  }
}

function sanitizeEndpoint(value) { const url = new URL(value); return `${url.protocol}//${url.host}${url.pathname}`; }
function safeError(error) { return String(error?.message || error).replace(/[\r\n\t]/g, ' ').slice(0, 512); }
function delay(ms, signal) {
  if (signal?.aborted) return Promise.resolve();
  return new Promise(resolve => {
    const timer = setTimeout(done, ms);
    function done() { clearTimeout(timer); signal?.removeEventListener('abort', done); resolve(); }
    signal?.addEventListener('abort', done, { once: true });
  });
}

module.exports = {
  TetragonMetricsCollector,
  COUNTER_DOMAINS,
  LOSS_DOMAINS,
  validateMetricsUrl,
  validateMetricsPeer,
  parsePrometheusText,
  parseSampleLine,
  parseLabels,
  requestMetrics,
  isLoopback
};
