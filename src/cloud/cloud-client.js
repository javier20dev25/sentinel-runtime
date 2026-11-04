'use strict';

const fs = require('node:fs');
const path = require('node:path');

const RUNTIME_TOKEN_PREFIX = 'snt_rt_';
const CLI_TOKEN_PREFIX = 'sntl_';
const DEFAULT_CLOUD_ENDPOINT = 'https://sentinel-cloud.onrender.com';
const DEFAULT_TIMEOUT_MS = 5000;

class SentinelRuntimeCloudClient {
  /**
   * @param {Object} [options]
   * @param {string} [options.apiKey] - Dedicated Sentinel Runtime token (snt_rt_...)
   * @param {string} [options.endpoint] - Sentinel Cloud base URL
   * @param {string} [options.configPath] - Path to optional runtime.conf
   * @param {number} [options.timeoutMs] - HTTP timeout in milliseconds
   */
  constructor(options = {}) {
    this.endpoint = (options.endpoint || process.env.SENTINEL_CLOUD_ENDPOINT || DEFAULT_CLOUD_ENDPOINT).replace(/\/+$/, '');
    this.timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    this.apiKey = options.apiKey || process.env.SENTINEL_RUNTIME_API_KEY;

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

    return this._post('/api/runtime/heartbeat', payload);
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

    return this._post('/api/runtime/incidents', envelope);
  }

  async _post(urlPath, payload) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.endpoint}${urlPath}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'User-Agent': 'sentinel-runtime/0.1.0'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      const responseText = await response.text();
      let parsed = null;
      try {
        parsed = JSON.parse(responseText);
      } catch {
        parsed = { raw: responseText };
      }

      if (!response.ok) {
        return {
          ok: false,
          status: response.status,
          error: parsed?.error || `HTTP ${response.status}`,
          offline: false
        };
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

module.exports = {
  SentinelRuntimeCloudClient,
  RUNTIME_TOKEN_PREFIX,
  CLI_TOKEN_PREFIX
};
