'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_MAX_ENTRIES = 100000;

function auditInstallation(root, options = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root)) {
    throw new TypeError('Installation root must be an absolute path');
  }
  const expectedUid = options.expectedUid === undefined ? 0 : options.expectedUid;
  const expectedGid = options.expectedGid === undefined ? 0 : options.expectedGid;
  if (!Number.isSafeInteger(expectedUid) || expectedUid < 0 || !Number.isSafeInteger(expectedGid) || expectedGid < 0) {
    throw new TypeError('Expected UID and GID must be non-negative safe integers');
  }
  const maxEntries = options.maxEntries === undefined ? DEFAULT_MAX_ENTRIES : options.maxEntries;
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw new TypeError('maxEntries must be a positive safe integer');
  }

  const rootStat = fs.lstatSync(root, { throwIfNoEntry: false });
  if (!rootStat) {
    return result(root, 0, 0, [{ path: root, code: 'ROOT_MISSING', message: 'Installation root does not exist' }]);
  }
  if (!rootStat.isDirectory()) {
    return result(root, 1, 0, [{ path: root, code: 'ROOT_NOT_DIRECTORY', message: 'Installation root is not a directory' }]);
  }

  const violations = [];
  let entries = 0;
  let symlinks = 0;
  const visit = (absolutePath, relativePath) => {
    entries++;
    if (entries > maxEntries) throw new RangeError(`Installation tree exceeds ${maxEntries} entries`);

    let stat;
    try {
      stat = fs.lstatSync(absolutePath);
    } catch (error) {
      violations.push({ path: relativePath, code: 'UNREADABLE', message: error.message });
      return;
    }

    if (!Number.isInteger(stat.uid) || !Number.isInteger(stat.gid)) {
      violations.push({ path: relativePath, code: 'OWNERSHIP_UNAVAILABLE', message: 'Ownership metadata is unavailable for this entry' });
    } else if (stat.uid !== expectedUid || stat.gid !== expectedGid) {
      violations.push({
        path: relativePath,
        code: 'OWNERSHIP_MISMATCH',
        message: `Expected uid ${expectedUid} and gid ${expectedGid}, observed uid ${stat.uid} and gid ${stat.gid}`
      });
    }

    if (stat.isSymbolicLink()) {
      symlinks++;
      return;
    }
    if (!stat.isDirectory() && !stat.isFile()) {
      violations.push({ path: relativePath, code: 'UNEXPECTED_FILE_TYPE', message: 'Only directories, regular files, and symbolic links are allowed' });
      return;
    }

    const writableBy = [];
    if ((stat.mode & 0o020) !== 0) writableBy.push('group');
    if ((stat.mode & 0o002) !== 0) writableBy.push('other');
    if (writableBy.length > 0) {
      violations.push({
        path: relativePath,
        code: 'GROUP_OR_OTHER_WRITABLE',
        message: `Entry is writable by ${writableBy.join(' and ')}`
      });
    }

    if (!stat.isDirectory()) return;
    let children;
    try {
      children = fs.readdirSync(absolutePath, { withFileTypes: true });
    } catch (error) {
      violations.push({ path: relativePath, code: 'UNREADABLE', message: error.message });
      return;
    }
    children.sort((left, right) => left.name.localeCompare(right.name));
    for (const child of children) {
      visit(path.join(absolutePath, child.name), relativePath === '.' ? child.name : path.join(relativePath, child.name));
    }
  };

  visit(root, '.');
  return result(root, entries, symlinks, violations);
}

function result(root, entries, symlinks, violations) {
  return { ok: violations.length === 0, root, entries, symlinks, violations };
}

module.exports = { auditInstallation };
