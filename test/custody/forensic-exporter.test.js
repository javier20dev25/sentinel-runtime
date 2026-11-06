'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { EvidenceLedger } = require('../../src/evidence');
const { ForensicExporter } = require('../../src/custody');

describe('ForensicExporter - Immutable Chain Custody Verification', () => {
  it('exports and independently verifies an authentic evidence bundle', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-custody-test-'));
    const dbPath = path.join(tmpDir, 'source.sqlite');
    const outDir = path.join(tmpDir, 'bundle');

    try {
      const ledger = new EvidenceLedger(dbPath);
      ledger.recordIncident(
        { workloadId: 'api-service', threatLevel: 'HIGH', action: 'ALERT', reason: 'Unusual network port' },
        { remoteIp: '198.51.100.1' }
      );
      ledger.append('containment_planned', { timestamp: new Date().toISOString(), action: 'PROCESS_SUSPEND', pid: 1234 });
      ledger.append('containment_result', { timestamp: new Date().toISOString(), status: 'EXECUTED', duration_ms: 1.2 });
      ledger.close();

      const exportResult = ForensicExporter.exportBundle({
        dbPath,
        outDir,
        hostId: 'prod-worker-01',
        bootId: 'boot-uuid-1234'
      });

      assert.equal(exportResult.certified, true);
      assert.ok(fs.existsSync(exportResult.manifestPath));
      assert.ok(fs.existsSync(exportResult.targetDbPath));

      // Independently verify authentic package
      const verifyResult = ForensicExporter.verifyBundle(exportResult.manifestPath);
      assert.equal(verifyResult.certified, true);
      assert.equal(verifyResult.host_id, 'prod-worker-01');
      assert.equal(verifyResult.records_checked, 3);
      assert.equal(verifyResult.database_sha256, exportResult.databaseSha256);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
    }
  });

  it('fails verification if the exported database file is altered after manifest generation', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-custody-tamper-'));
    const dbPath = path.join(tmpDir, 'source.sqlite');
    const outDir = path.join(tmpDir, 'bundle');

    try {
      const ledger = new EvidenceLedger(dbPath);
      ledger.recordIncident({ threatLevel: 'CRITICAL', reason: 'Reverse shell detected' });
      ledger.close();

      const exportResult = ForensicExporter.exportBundle({ dbPath, outDir });
      assert.equal(exportResult.certified, true);

      // Tamper: append garbage bytes to exported SQLite file
      fs.appendFileSync(exportResult.targetDbPath, 'TAMPERED_DATA_BYTES');

      // Verify should detect hash discrepancy
      const verifyResult = ForensicExporter.verifyBundle(exportResult.manifestPath);
      assert.equal(verifyResult.certified, false);
      assert.match(verifyResult.reason, /Database hash mismatch/);
    } finally {
      try { fs.rmSync(tmpDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch {}
    }
  });
});