'use strict';

/** RFC 8785-compatible serialization for JSON data model values used by Sentinel. */
function canonicalJson(value, ancestors = new Set(), depth = 0) {
  if (depth > 256) throw new RangeError('Canonical JSON nesting depth exceeds 256');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    assertUnicodeScalarString(value);
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Canonical JSON cannot contain non-finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new TypeError('Canonical JSON cannot serialize cyclic values');
    ancestors.add(value);
    const items = [];
    try {
      for (let i = 0; i < value.length; i++) {
        if (!Object.hasOwn(value, i)) throw new TypeError('Canonical JSON cannot serialize sparse arrays');
        items.push(canonicalJson(value[i], ancestors, depth + 1));
      }
      return `[${items.join(',')}]`;
    } finally {
      ancestors.delete(value);
    }
  }
  if (typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new TypeError(`Canonical JSON cannot serialize ${typeof value} or non-plain objects`);
  }
  if (ancestors.has(value)) throw new TypeError('Canonical JSON cannot serialize cyclic values');
  const symbols = Object.getOwnPropertySymbols(value);
  if (symbols.length) throw new TypeError('Canonical JSON cannot serialize symbol keys');
  const keys = Object.keys(value).sort();
  for (const key of keys) assertUnicodeScalarString(key);
  ancestors.add(value);
  try {
    return `{${keys.map(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) throw new TypeError('Canonical JSON cannot serialize accessor properties');
      return `${JSON.stringify(key)}:${canonicalJson(descriptor.value, ancestors, depth + 1)}`;
    }).join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

function assertUnicodeScalarString(value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new TypeError('Canonical JSON rejects unpaired high surrogates');
      i++;
    } else if (code >= 0xdc00 && code <= 0xdfff) throw new TypeError('Canonical JSON rejects unpaired low surrogates');
  }
}

module.exports = { canonicalJson };
