'use strict';

const { parentPort, workerData } = require('node:worker_threads');
const { EvidenceLedger } = require('../evidence');

let ledger;
try {
  ledger = new EvidenceLedger(workerData.dbPath);
  const verification = ledger.verifyIntegrity();
  const latest = ledger.getRecords({ limit: 1 })[0] || null;
  parentPort.postMessage({
    verification: {
      ...verification,
      latest_sequence: latest ? Number(latest.sequence) : 0,
      latest_record_hash: latest?.record_hash || null,
      checked_at: new Date().toISOString(),
    },
    evidence_status: 'AGENT_REPORTED_NOT_CLOUD_VERIFIED',
    canonicalization: 'SENTINEL_EVIDENCE_LEDGER_V1',
  });
} catch (error) {
  parentPort.postMessage({
    verification: { valid: false, checked: 0, reason: 'LEDGER_OPEN_OR_VERIFY_FAILED', detail: String(error?.message || 'unknown').slice(0, 256) },
    evidence_status: 'AGENT_REPORTED_NOT_CLOUD_VERIFIED',
  });
} finally {
  ledger?.close();
}
