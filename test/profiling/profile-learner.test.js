'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ProfileLearner, DEFAULT_RESTRICTED_PATHS } = require('../../src/profiling');

describe('ProfileLearner - Automated Baseline Discovery', () => {
  it('learns allowed binaries, network destinations and paths from observed events', () => {
    const learner = new ProfileLearner({ workloadId: 'payment-gateway' });

    learner.observeEvent({
      eventType: 'PROCESS_EXEC',
      data: {
        binary: '/usr/bin/node',
        executable_digest: { value: 'sha256:abcd1234ef567890' }
      }
    });

    learner.observeEvent({
      eventType: 'PROCESS_EXEC',
      data: {
        binary: '/usr/bin/node' // duplicate path without digest
      }
    });

    learner.observeEvent({
      eventType: 'NETWORK_CONNECT',
      data: {
        destination_host: 'api.stripe.com',
        destination_port: 443
      }
    });

    learner.observeEvent({
      eventType: 'FILE_READ',
      data: {
        path: '/var/www/app/config.json'
      }
    });

    const profile = learner.generateProfile();

    assert.equal(profile.workload_id, 'payment-gateway');
    assert.equal(profile.events_analyzed, 4);

    // Verify allowed binaries
    assert.equal(profile.allowed_binaries.length, 1);
    assert.equal(profile.allowed_binaries[0].path, '/usr/bin/node');
    assert.equal(profile.allowed_binaries[0].digest, 'sha256:abcd1234ef567890');

    // Verify network destinations
    assert.deepEqual(profile.allowed_network_destinations, ['api.stripe.com:443']);

    // Verify default restricted paths
    assert.deepEqual(profile.restricted_paths, DEFAULT_RESTRICTED_PATHS);
  });

  it('learns baseline profiles directly from a JSONL export file', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-learner-test-'));
    const jsonlPath = path.join(tmpDir, 'events.jsonl');

    try {
      const sampleEvents = [
        JSON.stringify({ eventType: 'PROCESS_EXEC', data: { binary: '/usr/bin/python3' } }),
        JSON.stringify({ eventType: 'NETWORK_CONNECT', data: { destination_host: '10.0.0.5', destination_port: 8080 } }),
        JSON.stringify({ eventType: 'FILE_READ', data: { path: '/etc/hosts' } })
      ].join('\n');

      fs.writeFileSync(jsonlPath, sampleEvents, 'utf8');

      const learner = new ProfileLearner({ workloadId: 'backend-worker' });
      const profile = await learner.learnFromJsonl(jsonlPath);

      assert.equal(profile.workload_id, 'backend-worker');
      assert.equal(profile.events_analyzed, 3);
      assert.equal(profile.allowed_binaries[0].path, '/usr/bin/python3');
      assert.deepEqual(profile.allowed_network_destinations, ['10.0.0.5:8080']);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});