'use strict';

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

class EvidenceLedger {
  constructor(dbPath = ':memory:') {
    if (dbPath !== ':memory:') {
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    }
    this.db = new DatabaseSync(dbPath);
    this.initSchema();
  }

  initSchema() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        workload_id TEXT NOT NULL,
        pid INTEGER NOT NULL,
        threat_level INTEGER NOT NULL,
        action TEXT NOT NULL,
        reason TEXT NOT NULL,
        evidence_json TEXT NOT NULL
      );
    `);
  }

  recordIncident(decision, evidence = {}) {
    const stmt = this.db.prepare(`
      INSERT INTO incidents (timestamp, workload_id, pid, threat_level, action, reason, evidence_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      new Date().toISOString(),
      decision.workloadId,
      decision.pid,
      decision.threatLevel,
      decision.action,
      decision.reason,
      JSON.stringify(evidence)
    );
  }

  getIncidents() {
    const stmt = this.db.prepare('SELECT * FROM incidents ORDER BY id DESC');
    return stmt.all();
  }
}

module.exports = { EvidenceLedger };
