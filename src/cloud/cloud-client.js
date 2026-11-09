'use strict';

const fs = require('node:fs');
const path = require('node:path');

const RUNTIME_TOKEN_PREFIX = 'snt_rt_';
const CLI_TOKEN_PREFIX = 'sntl_';
const DEFAULT_CLOUD_ENDPOINT = 'https://sentinel-psi-nine.vercel.app';
const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const RUNTIME_ANALYSIS_STATUSES = new Set([
  'NOT_REQUESTED', 'PENDING', 'COMPLETED', 'QUOTA_REQUIRED', 'NOT_INCLUDED',
  'ANALYSIS_UNAVAILABLE', 'ANALYSIS_FAILED'
]);

class SentinelRuntimeCloudClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.apiKey] - Dedicated Sentinel Runtime token (snt_rt_...)
   * @param {string} [options.endpoint] - Sentinel Cloud base URL
   * @param {string} [options.configPath] - Path to optional runtime.conf
   * @param {number} [options.timeoutMs] - HTTP timeout in milliseconds
   */
  constructor(options = {}) {
    this.endpoint = normalizeEndpoint(options.endpoint || process.env.SENTINEL_RUNTIME_API_URL || process.env.SENTINEL_CLOUD_ENDPOINT || DEFAULT_CLOUD_ENDPOINT);
    this.timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    this.apiKey = options.apiKey || process.env.SENTINEL_RUNTIME_API_KEY;
    if (typeof this.apiKey === 'string') this.apiKey = this.apiKey.trim();

    if (!this.apiKey && options.configPath) {
      this.apiKey = this._loadApiKeyFromConfig(options.configPath);
    } else if (!this.apiKey && fs.existsSync('/etc/sentinel/runtime.conf')) {
      this.apiKey = this._loadApiKeyFromConfig('/etc/sentinel/runtime.conf');
    }

    if (this.apiKey) {
      this._validateTokenFormat(this.apiKey);
    }
  }

  _loadApiKeyFromConfig(configPath) {
    try {
      const content = fs.readFileSync(configPath, 'utf8');
      for (const line of content.split(/\r?\n/)) {
        const match = line.match(/^\s*(?:SENTINEL_RUNTIME_API_KEY|api_key)\s*=\s*["']?([^"'\s]+)["']?/i);
        if (match) return match[1];
      }
    } catch {
      // Configuration file is optional
    }
    return null;
  }

  _validateTokenFormat(token) {
    if (typeof token !== 'string') {
      throw new Error('Runtime API key must be a string.');
    }
    const trimmed = token.trim();
    if (trimmed.startsWith(CLI_TOKEN_PREFIX)) {
      throw new Error(
        "Invalid token format: Sentinel Runtime requires a dedicated host token starting with 'snt_rt_'. " +
        "Standard Sentinel CLI tokens ('sntl_') are not permitted for runtime host communication."
      );
    }
    if (!trimmed.startsWith(RUNTIME_TOKEN_PREFIX)) {
      throw new Error(
        "Invalid token format: Sentinel Runtime token must begin with 'snt_rt_'. " +
        "Generate a host credential from the Sentinel Cloud Enterprise admin console."
      );
    }
    if (trimmed.length < 40) {
      throw new Error("Invalid token format: Sentinel Runtime token has insufficient entropy or is truncated.");
    }
  }

  hasValidKey() {
    return Boolean(this.apiKey && this.apiKey.startsWith(RUNTIME_TOKEN_PREFIX));
  }

  /**
   * Dispatch lightweight host heartbeat.
   * Fail-safe: returns status object; never throws on transport or server failure.
   */
  async sendHeartbeat(data = {}) {
    if (!this.hasValidKey()) {
      return { ok: false, offline: true, reason: 'NO_VALID_RUNTIME_KEY' };
    }

    const payload = {
      status: data.status || 'HEALTHY',
      kernel_version: data.kernelVersion || null,
      tetragon_version: data.tetragonVersion || 'v1.8.0',
      runtime_version: data.runtimeVersion || '0.1.0',
      loss_events_count: data.lossEventsCount || 0,
    };

    return this._post('/api/runtime/heartbeat', payload, { expectedHeartbeat: true });
  }

  /**
   * Transmit a sanitized Incident Intelligence Envelope.
   * Fail-safe: returns status object; never disrupts local engine operations.
   */
  async sendIncidentEnvelope(envelope) {
    if (!this.hasValidKey()) {
      return { ok: false, offline: true, reason: 'NO_VALID_RUNTIME_KEY' };
    }

    if (!envelope || typeof envelope !== 'object') {
      return { ok: false, error: 'INVALID_ENVELOPE_OBJECT' };
    }

    return this._post('/api/runtime/incidents', envelope, {
      expectedClientIncidentId: envelope.incident_id,
      expectedIdempotencyKey: envelope.idempotency_key
    });
  }

  async _post(urlPath, payload, expectations = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.endpoint}${urlPath}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'User-Agent': 'sentinel-runtime/0.2.0'
        },
        redirect: 'error',
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      const responseText = await readBoundedResponse(response, MAX_RESPONSE_BYTES);
      let parsed;
      try { parsed = JSON.parse(responseText); }
      catch { return { ok: false, offline: false, error: 'INVALID_CLOUD_RESPONSE', status: response.status }; }

      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          error: typeof parsed?.error === 'string' ? parsed.error.slice(0, 256) : `HTTP ${response.status}`,
          offline: false
        };
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.ok !== true) {
        return { ok: false, offline: false, error: 'INVALID_CLOUD_RESPONSE', status: response.status };
      }
      if (expectations.expectedClientIncidentId &&
          parsed.client_incident_id !== expectations.expectedClientIncidentId) {
        return { ok: false, offline: false, error: 'CLOUD_RESPONSE_ID_MISMATCH', status: response.status };
      }
      if (expectations.expectedClientIncidentId &&
          (typeof parsed.incident_id !== 'string' || !Number.isFinite(Date.parse(parsed.recorded_at)))) {
        return { ok: false, offline: false, error: 'INVALID_CLOUD_RESPONSE', status: response.status };
      }
      if (expectations.expectedClientIncidentId &&
          (!RUNTIME_ANALYSIS_STATUSES.has(parsed.analysis_status) || typeof parsed.duplicate !== 'boolean' ||
            parsed.idempotency_key !== expectations.expectedIdempotencyKey ||
            (parsed.analysis_pulses !== undefined && (!Number.isSafeInteger(parsed.analysis_pulses) || parsed.analysis_pulses < 0 || parsed.analysis_pulses > 1)))) {
        return { ok: false, offline: false, error: 'INVALID_CLOUD_RESPONSE', status: response.status };
      }
      if (expectations.expectedHeartbeat &&
          (typeof parsed.host_id !== 'string' || typeof parsed.device_name !== 'string' || typeof parsed.environment !== 'string' ||
            !['HEALTHY', 'DEGRADED', 'DISCONNECTED', 'CONTAINED'].includes(parsed.status))) {
        return { ok: false, offline: false, error: 'INVALID_CLOUD_RESPONSE', status: response.status };
      }
      return { ok: true, data: parsed };
    } catch (err) {
      return {
        ok: false,
        offline: true,
        error: err.name === 'AbortError' ? 'TIMEOUT' : err.message
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

function normalizeEndpoint(value) {
  let parsed;
  try { parsed = new URL(value); }
  catch { throw new TypeError('Sentinel Cloud endpoint must be a valid HTTPS URL'); }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const localHttp = parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(hostname);
  if ((parsed.protocol !== 'https:' && !localHttp) || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError('Sentinel Cloud endpoint must use HTTPS and cannot contain credentials, query strings, or fragments');
  }
  return parsed.toString().replace(/\/+$/, '');
}

async function readBoundedResponse(response, maxBytes) {
  const declaredLength = Number(response.headers?.get?.('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    await response.body?.cancel?.();
    throw new Error('CLOUD_RESPONSE_TOO_LARGE');
  }
  if (!response.body?.getReader) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) throw new Error('CLOUD_RESPONSE_TOO_LARGE');
    return text;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error('CLOUD_RESPONSE_TOO_LARGE');
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

module.exports = {
  SentinelRuntimeCloudClient,
  RUNTIME_TOKEN_PREFIX,
  CLI_TOKEN_PREFIX
};
