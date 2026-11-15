'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { auditInstallation } = require('../../src/security/install-audit');

const linuxOnly = process.platform === 'linux' ? {} : { skip: 'POSIX ownership and mode checks require Linux' };

test('auditInstallation rejects a relative installation root', () => {
  assert.throws(() => auditInstallation('opt/sentinel-runtime'), /absolute path/);
});

test('auditInstallation reports a missing installation root without throwing', () => {
  const root = path.join(os.tmpdir(), `sentinel-missing-${process.pid}-${Date.now()}`);
  const report = auditInstallation(root);
  assert.equal(report.ok, false);
  assert.equal(report.violations[0].code, 'ROOT_MISSING');
});

test('auditInstallation detects writable files and ownership mismatches', linuxOnly, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-'));
  try {
    const child = path.join(root, 'child');
    const file = path.join(child, 'sentinel-runtime.js');
    fs.mkdirSync(child);
    fs.writeFileSync(file, '#!/usr/bin/env node\n', 'utf8');
    fs.chmodSync(root, 0o755);
    fs.chmodSync(child, 0o755);
    fs.chmodSync(file, 0o644);

    const baseline = auditInstallation(root, {
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    });
    assert.equal(baseline.ok, true, JSON.stringify(baseline.violations));
    assert.equal(baseline.entries, 3);

    fs.chmodSync(file, 0o666);
    const writable = auditInstallation(root, {
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    });
    assert.equal(writable.ok, false);
    assert.deepEqual(writable.violations.map(violation => violation.code), ['GROUP_OR_OTHER_WRITABLE']);

    const wrongOwner = auditInstallation(root, {
      expectedUid: process.getuid() + 1,
      expectedGid: process.getgid()
    });
    assert.equal(wrongOwner.ok, false);
    assert.ok(wrongOwner.violations.some(violation => violation.code === 'OWNERSHIP_MISMATCH'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('auditInstallation does not treat a symlink mode as writable', linuxOnly, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-audit-link-'));
  try {
    const target = path.join(root, 'target');
    fs.mkdirSync(target);
    fs.symlinkSync(target, path.join(root, 'link'));
    const report = auditInstallation(root, {
      expectedUid: process.getuid(),
      expectedGid: process.getgid()
    });
    assert.equal(report.ok, true, JSON.stringify(report.violations));
    assert.equal(report.symlinks, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
