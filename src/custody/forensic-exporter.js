'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { EvidenceLedger } = require('../evidence');
const { canonicalJson } = require('../contracts/canonical-json');

class ForensicExporter {
  /**
   * Generates an immutable, verified custody export bundle.
   * Fails closed if the ledger fails hash-chain integrity verification.
   */
  static exportBundle(options = {}) {
    const {
      dbPath,
      outDir,
      hostId = 'unknown-host',
      bootId = 'unknown-boot',
      signingKey = null
    } = options;

    if (!dbPath || !fs.existsSync(dbPath)) {
      throw new Error(`Database file not found at: ${dbPath}`);
    }
    if (!outDir) {
      throw new TypeError('outDir is required for custody export');
    }

    fs.mkdirSync(outDir, { recursive: true });

    // 1. Verify ledger integrity before export
    const ledger = new EvidenceLedger(dbPath);
    let integrity = null;
    let records = [];
    try {
      integrity = ledger.verifyIntegrity();
      records = ledger.getRecords({ limit: 100000 });
    } finally {
      ledger.close();
    }

    if (!integrity || !integrity.valid) {
      throw new Error(`Ledger integrity check failed. Cannot export corrupted chain: ${JSON.stringify(integrity)}`);
    }

    // 2. Safely copy the SQLite database
    const targetDbName = 'evidence.sqlite';
    const targetDbPath = path.join(outDir, targetDbName);
    fs.copyFileSync(dbPath, targetDbPath);

    // 3. Compute exact SHA-256 of the exported database file
    const dbBytes = fs.readFileSync(targetDbPath);
    const databaseSha256 = crypto.createHash('sha256').update(dbBytes).digest('hex');

    // 4. Extract incident & containment summaries
    let incidentCount = 0;
    let containmentPlannedCount = 0;
    let containmentResultCount = 0;
    const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };

    for (const r of records) {
      if (r.record_type === 'incident') {
        incidentCount++;
        try {
          const payload = JSON.parse(r.payload_json);
          const sev = payload.decision?.threatLevel || 'UNKNOWN';
          severityCounts[sev] = (severityCounts[sev] || 0) + 1;
        } catch {}
      } else if (r.record_type === 'containment_planned') {
        containmentPlannedCount++;
      } else if (r.record_type === 'containment_result') {
        containmentResultCount++;
      }
    }

    const chronological = [...records].reverse();
    const genesisHash = chronological.length > 0 ? chronological[0].previous_hash : '0'.repeat(64);
    const headHash = integrity.head_hash;

    const manifestBody = {
      spec_version: '1.0.0',
      generator: 'sentinel-runtime-forensics',
      generated_at: new Date().toISOString(),
      host_identity: {
        host_id: hostId,
        boot_id: bootId
      },
      chain_custody: {
        genesis_hash: genesisHash,
        head_hash: headHash,
        total_records_checked: integrity.checked,
        empty: integrity.empty === true
      },
      database_artifact: {
        file_name: targetDbName,
        sha256: databaseSha256,
        size_bytes: dbBytes.length
      },
      evidence_summary: {
        incidents: incidentCount,
        containment_planned: containmentPlannedCount,
        containment_results: containmentResultCount,
        severity_breakdown: severityCounts
      }
    };

    // 5. Canonicalize & sign or digest manifest
    const canonicalManifest = canonicalJson(manifestBody);
    let sealType = 'SHA-256';
    let sealValue = crypto.createHash('sha256').update(canonicalManifest).digest('hex');

    if (signingKey) {
      sealType = 'HMAC-SHA256';
      sealValue = crypto.createHmac('sha256', signingKey).update(canonicalManifest).digest('hex');
    }

    const completeManifest = {
      ...manifestBody,
      cryptographic_seal: {
        algorithm: sealType,
        digest: sealValue
      }
    };

    const manifestPath = path.join(outDir, 'custody-manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(completeManifest, null, 2) + '\n', 'utf8');

    return {
      certified: true,
      manifestPath,
      targetDbPath,
      databaseSha256,
      headHash,
      totalRecords: integrity.checked
    };
  }

  /**
   * Independently verifies an exported custody package.
   */
  static verifyBundle(manifestPath, explicitDbPath = null) {
    if (!manifestPath || !fs.existsSync(manifestPath)) {
      throw new Error(`Manifest file not found at: ${manifestPath}`);
    }

    const rawManifest = fs.readFileSync(manifestPath, 'utf8');
    const manifest = JSON.parse(rawManifest);

    const dbPath = explicitDbPath || path.join(path.dirname(manifestPath), manifest.database_artifact.file_name);
    if (!fs.existsSync(dbPath)) {
      return {
        certified: false,
        reason: `Artifact database missing: ${dbPath}`
      };
    }

    // Check DB SHA-256
    const dbBytes = fs.readFileSync(dbPath);
    const computedDbHash = crypto.createHash('sha256').update(dbBytes).digest('hex');
    if (computedDbHash !== manifest.database_artifact.sha256) {
      return {
        certified: false,
        reason: `Database hash mismatch! Expected: ${manifest.database_artifact.sha256}, Got: ${computedDbHash}`
      };
    }

    // Verify chain integrity in SQLite
    const ledger = new EvidenceLedger(dbPath);
    let integrity = null;
    try {
      integrity = ledger.verifyIntegrity();
    } finally {
      ledger.close();
    }

    if (!integrity.valid) {
      return {
        certified: false,
        reason: 'Database ledger hash chain is broken or tampered',
        details: integrity
      };
    }

    if (integrity.head_hash !== manifest.chain_custody.head_hash) {
      return {
        certified: false,
        reason: `Chain head mismatch! Expected: ${manifest.chain_custody.head_hash}, Got: ${integrity.head_hash}`
      };
    }

    return {
      certified: true,
      verified_at: new Date().toISOString(),
      host_id: manifest.host_identity?.host_id,
      records_checked: integrity.checked,
      head_hash: integrity.head_hash,
      database_sha256: computedDbHash
    };
  }
}

module.exports = {
  ForensicExporter
};