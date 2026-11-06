'use strict';

const fs = require('node:fs');
const readline = require('node:readline');
const { parseJsonRejectDuplicateKeys } = require('../ingest/jsonl');

const DEFAULT_RESTRICTED_PATHS = [
  '/etc/shadow',
  '/etc/gshadow',
  '/etc/sudoers',
  '/etc/sudoers.d',
  '/root/.ssh',
  '/home/*/.ssh',
  '/proc/kcore',
  '/dev/mem',
  '/dev/kmem'
];

class ProfileLearner {
  constructor(options = {}) {
    this.workloadId = options.workloadId || 'learned-workload';
    this.strict = options.strict === true;
    this.binaries = new Map(); // path -> Set of digests
    this.accessedPaths = new Set();
    this.networkDestinations = new Set();
    this.eventCount = 0;
  }

  observeEvent(rawEvent) {
    if (!rawEvent || typeof rawEvent !== 'object') return;
    this.eventCount++;

    const eventType = rawEvent.eventType || rawEvent.event_type;
    const data = rawEvent.data || rawEvent.payload || {};

    if (eventType === 'PROCESS_EXEC' || rawEvent.process_kprobe?.function_name === '__x64_sys_execve') {
      const binPath = data.binary || data.executable_path || rawEvent.processIdentity?.executablePath || rawEvent.process_kprobe?.process?.binary;
      if (binPath && typeof binPath === 'string') {
        const normalized = binPath.trim();
        const digest = data.executable_digest?.value || data.executableDigest || null;
        if (!this.binaries.has(normalized)) {
          this.binaries.set(normalized, new Set());
        }
        if (digest) {
          this.binaries.get(normalized).add(digest);
        }
      }
    } else if (eventType === 'FILE_READ' || eventType === 'FILE_OPEN_ATTEMPT') {
      const p = data.path || data.file_path || data.filename;
      if (p && typeof p === 'string') {
        this.accessedPaths.add(p.trim());
      }
    } else if (
      eventType === 'NETWORK_CONNECT' ||
      eventType === 'NETWORK_CONNECT_ATTEMPT' ||
      eventType === 'NETWORK_SEND_RESULT' ||
      eventType === 'NETWORK_SEND_ATTEMPT'
    ) {
      const host = data.host || data.destination_ip || data.destination_host;
      const port = data.port ?? data.destination_port;
      if (host && typeof host === 'string') {
        const dest = port ? `${host.trim()}:${port}` : host.trim();
        this.networkDestinations.add(dest);
      }
    }
  }

  async learnFromJsonl(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error(`Input JSONL file not found: ${filePath}`);
    }

    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({
      input: fileStream,
      crlfDelay: Infinity
    });

    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = parseJsonRejectDuplicateKeys(trimmed);
        this.observeEvent(parsed);
      } catch {
        // Skip malformed lines in learning pass
      }
    }

    return this.generateProfile();
  }

  generateProfile() {
    const allowedBinaries = [];
    for (const [binPath, digests] of this.binaries.entries()) {
      if (digests.size > 0) {
        for (const d of digests) {
          allowedBinaries.push({ path: binPath, digest: d });
        }
      } else {
        allowedBinaries.push({ path: binPath });
      }
    }

    // Sort deterministically for reproducible profiling
    allowedBinaries.sort((a, b) => a.path.localeCompare(b.path));
    const sortedNetwork = [...this.networkDestinations].sort();

    return {
      workload_id: this.workloadId,
      profile_version: '1.0.0',
      learned_at: new Date().toISOString(),
      events_analyzed: this.eventCount,
      allowed_binaries: allowedBinaries,
      restricted_paths: DEFAULT_RESTRICTED_PATHS,
      allowed_network_destinations: sortedNetwork
    };
  }
}

module.exports = {
  ProfileLearner,
  DEFAULT_RESTRICTED_PATHS
};