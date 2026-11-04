'use strict';

/**
 * SENTINEL RUNTIME — EVENT CONTRACT & VALIDATOR TEST SUITE (HARDENED - PHASE 001A-R2)
 *
 * Suites Obligatorias de Validación y Seguridad:
 * 1. Suite uint64 completa (0 <= n <= 2^64 - 1, decimal canónico, rechazo de ceros iniciales y desbordamiento).
 * 2. Suite de caracteres NUL (U+0000) en rutas vs. caracteres válidos en Linux (newlines, tabs).
 * 3. Suite de límites de longitud (maxLength en rutas, strings y argumentos).
 * 4. Suite de arrays (maxItems en arguments y tracing policies).
 * 5. Suite de workload consistency (HOST_PROCESS con container_id: null).
 * 6. Suite de provenance warnings (unknown_source, other_provider, unauthenticated, synthetic transport).
 * 7. Tests originales de las 14 familias documentadas (valid, incomplete, invalid).
 * 8. Tests de no-mutación estricta con Object.freeze.
 * 9. Tests de determinismo (1,000 iteraciones y 500 llamadas concurrentes).
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const { validateEvent } = require('../../src/contracts/validate-event');
const {
  EventFamily,
  SourceProvider,
  TransportProtocol,
  toSafeUint64String,
  MAX_SAFE_INTEGER,
  MAX_UINT64
} = require('../../src/contracts/event-types');

const fixturesBaseDir = path.resolve(__dirname, '../fixtures/events/v1');
const baseValid = JSON.parse(
  fs.readFileSync(path.join(fixturesBaseDir, 'process_exec/valid.json'), 'utf8')
);

// -----------------------------------------------------------------------------
// SUITE 1: SUITE UINT64 COMPLETA (P-01 & P-02)
// -----------------------------------------------------------------------------
test('Suite 1: uint64 Complete Boundary Enforcement', async (t) => {
  await t.test('1.1 Acepta valores límite válidos: 0, 1, 2^53 - 1, 2^64 - 2, 2^64 - 1', () => {
    const validUint64s = [
      0,
      1,
      MAX_SAFE_INTEGER, // 9007199254740991
      '0',
      '1',
      '9007199254740991',
      '18446744073709551614', // 2^64 - 2
      '18446744073709551615'  // 2^64 - 1
    ];

    for (const val of validUint64s) {
      const clone = structuredClone(baseValid);
      clone.source_timestamp = val;
      const res = validateEvent(clone);
      assert.strictEqual(res.valid, true, `Expected valid for uint64: ${val}, got errors: ${JSON.stringify(res.errors)}`);
      assert.strictEqual(typeof toSafeUint64String(val), 'string');
    }
  });

  await t.test('1.2 Rechaza desbordamiento absoluto 2^64 (18446744073709551616)', () => {
    const clone = structuredClone(baseValid);
    clone.source_timestamp = '18446744073709551616'; // 2^64
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false, 'Expected 2^64 to be rejected');
    assert.ok(res.errors.some(e => e.keyword === 'maximumUint64'));
    assert.throws(() => toSafeUint64String('18446744073709551616'), RangeError);
  });

  await t.test('1.3 Rechaza strings con ceros iniciales no canónicos ("007", "0123")', () => {
    const nonCanonical = ['007', '0123', '00', '00000000000000000001'];
    for (const val of nonCanonical) {
      const clone = structuredClone(baseValid);
      clone.source_timestamp = val;
      const res = validateEvent(clone);
      assert.strictEqual(res.valid, false, `Expected ${val} with leading zeros to be rejected`);
      assert.throws(() => toSafeUint64String(val), TypeError);
    }
  });

  await t.test('1.4 Rechaza Number superior a MAX_SAFE_INTEGER (riesgo de precisión IEEE 754)', () => {
    const clone = structuredClone(baseValid);
    clone.source_timestamp = 9007199254740992; // 2^53
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false);
    assert.ok(res.errors.some(e => e.keyword === 'precisionRisk'));
    assert.throws(() => toSafeUint64String(9007199254740992), RangeError);
  });

  await t.test('1.5 Rechaza negativos, decimales, vacíos y notación exponencial en string', () => {
    const invalidInputs = [-1, '-1', '', 1.5, '1.5', '1e10', '1e25', null, 'not_digits'];
    for (const val of invalidInputs) {
      if (val === null) continue;
      const clone = structuredClone(baseValid);
      clone.source_timestamp = val;
      const res = validateEvent(clone);
      assert.strictEqual(res.valid, false, `Expected invalid for ${val}`);
      assert.throws(() => toSafeUint64String(val), Error);
    }
  });

  await t.test('1.6 Soporte estricto de BigInt en toSafeUint64String', () => {
    assert.strictEqual(toSafeUint64String(0n), '0');
    assert.strictEqual(toSafeUint64String(18446744073709551615n), '18446744073709551615');
    assert.throws(() => toSafeUint64String(-1n), TypeError);
    assert.throws(() => toSafeUint64String(18446744073709551616n), RangeError);
  });
});

// -----------------------------------------------------------------------------
// SUITE 2: SUITE DE CARACTERES NUL (U+0000) VS CARACTERES LINUX VÁLIDOS (P-02)
// -----------------------------------------------------------------------------
test('Suite 2: NUL Byte (U+0000) Rejection & Linux Path Character Fidelity', async (t) => {
  await t.test('2.1 Rechaza NUL byte (U+0000) en executable_path', () => {
    const clone = structuredClone(baseValid);
    clone.process_identity.executable_path = '/bin/bash\u0000/injected';
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false, 'Expected NUL byte in executable_path to be rejected');
    assert.ok(res.errors.some(e => e.keyword === 'pattern'));
  });

  await t.test('2.2 Rechaza NUL byte (U+0000) en working_dir', () => {
    const clone = structuredClone(baseValid);
    clone.payload.working_dir = '/app\u0000/cfg';
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false, 'Expected NUL byte in working_dir to be rejected');
  });

  await t.test('2.3 Rechaza NUL byte en payload.path de FILE_OPEN_ATTEMPT', () => {
    const openValid = JSON.parse(
      fs.readFileSync(path.join(fixturesBaseDir, 'file_open_attempt/valid.json'), 'utf8')
    );
    const clone = structuredClone(openValid);
    clone.payload.path = '/etc/shadow\u0000.bak';
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false, 'Expected NUL byte in payload.path to be rejected');
  });

  await t.test('2.4 Acepta caracteres válidos de Linux en rutas (newlines, tabs, espacios)', () => {
    const clone = structuredClone(baseValid);
    clone.process_identity.executable_path = '/app/bin/special\nname\twith spaces';
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, true, `Expected valid for Linux path with newline/tab, got errors: ${JSON.stringify(res.errors)}`);
  });
});

// -----------------------------------------------------------------------------
// SUITE 3: SUITE DE LÍMITES DE LONGITUD (P-03 BOUNDARY LIMITS)
// -----------------------------------------------------------------------------
test('Suite 3: Field-Level Boundary Limits & DoS Constraints', async (t) => {
  await t.test('3.1 executable_path: acepta 4096 caracteres, rechaza 4097', () => {
    const clone = structuredClone(baseValid);
    clone.process_identity.executable_path = '/a/' + 'b'.repeat(4093); // exact 4096
    assert.strictEqual(validateEvent(clone).valid, true);

    clone.process_identity.executable_path = '/a/' + 'b'.repeat(4094); // 4097
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false);
    assert.ok(res.errors.some(e => e.keyword === 'maxLength'));
  });

  await t.test('3.2 arguments individuales: acepta 131072 chars, rechaza 131073', () => {
    const clone = structuredClone(baseValid);
    clone.payload.arguments = ['node', 'a'.repeat(131072)]; // exact 128 KB
    assert.strictEqual(validateEvent(clone).valid, true);

    clone.payload.arguments = ['node', 'a'.repeat(131073)]; // 128 KB + 1
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false);
    assert.ok(res.errors.some(e => e.keyword === 'maxLength'));
  });

  await t.test('3.3 host_id: acepta 255 chars, rechaza 256', () => {
    const clone = structuredClone(baseValid);
    clone.host_id = 'h'.repeat(255);
    assert.strictEqual(validateEvent(clone).valid, true);

    clone.host_id = 'h'.repeat(256);
    assert.strictEqual(validateEvent(clone).valid, false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 4: SUITE DE ARRAYS (P-03 ARRAY CONSTRAINTS)
// -----------------------------------------------------------------------------
test('Suite 4: Array Constraints (maxItems)', async (t) => {
  await t.test('4.1 arguments array: acepta 1024 items, rechaza 1025', () => {
    const clone = structuredClone(baseValid);
    clone.payload.arguments = new Array(1024).fill('arg');
    assert.strictEqual(validateEvent(clone).valid, true);

    clone.payload.arguments = new Array(1025).fill('arg');
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false);
    assert.ok(res.errors.some(e => e.keyword === 'maxItems'));
  });

  await t.test('4.2 k8s_metadata: maxProperties 20 y labels maxProperties 64', () => {
    const clone = structuredClone(baseValid);
    const bigLabels = {};
    for (let i = 0; i < 64; i++) bigLabels[`label_${i}`] = 'val';
    clone.workload_context.k8s_metadata.labels = bigLabels;
    assert.strictEqual(validateEvent(clone).valid, true);

    bigLabels['label_overflow'] = 'overflow';
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false);
    assert.ok(res.errors.some(e => e.keyword === 'maxProperties'));
  });
});

// -----------------------------------------------------------------------------
// SUITE 5: SUITE DE WORKLOAD CONSISTENCY (P-05 HOST_PROCESS)
// -----------------------------------------------------------------------------
test('Suite 5: Workload Context Semantic Consistency (P-05)', async (t) => {
  await t.test('5.1 HOST_PROCESS con container_id: null es VÁLIDO', () => {
    const clone = structuredClone(baseValid);
    clone.workload_context.workload_type = 'HOST_PROCESS';
    clone.workload_context.container_id = null;
    assert.strictEqual(validateEvent(clone).valid, true);
  });

  await t.test('5.2 HOST_PROCESS con container_id NO NULO es RECHAZADO', () => {
    const clone = structuredClone(baseValid);
    clone.workload_context.workload_type = 'HOST_PROCESS';
    clone.workload_context.container_id = 'container_12345';
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, false, 'Expected HOST_PROCESS with container_id to be rejected');
  });

  await t.test('5.3 CONTAINER con container_id es VÁLIDO', () => {
    const clone = structuredClone(baseValid);
    clone.workload_context.workload_type = 'CONTAINER';
    clone.workload_context.container_id = 'c1234567890';
    assert.strictEqual(validateEvent(clone).valid, true);
  });
});

// -----------------------------------------------------------------------------
// SUITE 6: SUITE DE PROVENANCE WARNINGS (P-04)
// -----------------------------------------------------------------------------
test('Suite 6: Structured Provenance Warnings (P-04)', async (t) => {
  await t.test('6.1 Emite warning estructurado para UNKNOWN_SOURCE', () => {
    const clone = structuredClone(baseValid);
    clone.source_provider = SourceProvider.UNKNOWN_SOURCE;
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, true);
    assert.ok(res.warnings.some(w => w.includes('UNKNOWN_SOURCE')));
  });

  await t.test('6.2 Emite warning estructurado para OTHER_PROVIDER', () => {
    const clone = structuredClone(baseValid);
    clone.source_provider = SourceProvider.OTHER_PROVIDER;
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, true);
    assert.ok(res.warnings.some(w => w.includes('OTHER_PROVIDER')));
  });

  await t.test('6.3 Emite warning para transport_authenticated: false', () => {
    const clone = structuredClone(baseValid);
    clone.provenance.transport_authenticated = false;
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, true);
    assert.ok(res.warnings.some(w => w.includes('transport_authenticated: false')));
  });

  await t.test('6.4 Emite warning para Tetragon con transporte SYNTHETIC_MEMORY', () => {
    const clone = structuredClone(baseValid);
    clone.source_provider = SourceProvider.TETRAGON;
    clone.provenance.transport_protocol = TransportProtocol.SYNTHETIC_MEMORY;
    const res = validateEvent(clone);
    assert.strictEqual(res.valid, true);
    assert.ok(res.warnings.some(w => w.includes('Tetragon telemetry claimed over SYNTHETIC_MEMORY')));
  });
});

// -----------------------------------------------------------------------------
// SUITE 7: CONFORMIDAD DE FIXTURES DE LAS 14 FAMILIAS
// -----------------------------------------------------------------------------
test('Suite 7: 14 Documented Event Families Fixture Conformance', async (t) => {
  const families = Object.values(EventFamily);

  for (const family of families) {
    const dirName = family.toLowerCase();
    const familyDir = path.join(fixturesBaseDir, dirName);

    await t.test(`Familia: ${family}`, () => {
      // 1. Valid fixture debe pasar
      const validPath = path.join(familyDir, 'valid.json');
      const validEvent = JSON.parse(fs.readFileSync(validPath, 'utf8'));
      const validRes = validateEvent(validEvent);
      assert.strictEqual(validRes.valid, true, `Valid failed for ${family}: ${JSON.stringify(validRes.errors)}`);
      assert.strictEqual(validRes.event_family, family);

      // 2. Incomplete fixture debe ser válido pero con advertencias
      const incPath = path.join(familyDir, 'incomplete.json');
      const incompleteEvent = JSON.parse(fs.readFileSync(incPath, 'utf8'));
      const incRes = validateEvent(incompleteEvent);
      assert.strictEqual(incRes.valid, true, `Incomplete failed for ${family}: ${JSON.stringify(incRes.errors)}`);
      assert.ok(incRes.warnings.length > 0);

      // 3. Invalid fixture debe fallar
      const invPath = path.join(familyDir, 'invalid.json');
      const invalidEvent = JSON.parse(fs.readFileSync(invPath, 'utf8'));
      const invRes = validateEvent(invalidEvent);
      assert.strictEqual(invRes.valid, false, `Invalid passed for ${family}`);
    });
  }
});

// -----------------------------------------------------------------------------
// SUITE 8: INVARIANTE DE NO-MUTACIÓN ESTRICTA
// -----------------------------------------------------------------------------
test('Suite 8: Strict Non-Mutation Invariant with Deep Object.freeze', () => {
  const clone = structuredClone(baseValid);

  // Serializar antes
  const beforeStr = JSON.stringify(clone);

  // Congelar en profundidad
  Object.freeze(clone);
  Object.freeze(clone.process_identity);
  Object.freeze(clone.process_identity.process_namespace);
  Object.freeze(clone.workload_context);
  Object.freeze(clone.payload);
  Object.freeze(clone.provenance);
  Object.freeze(clone.loss_metrics);

  const res = validateEvent(clone);
  assert.strictEqual(res.valid, true);

  // Serializar después
  const afterStr = JSON.stringify(clone);
  assert.strictEqual(beforeStr, afterStr, 'validateEvent violated non-mutation invariant');
});

// -----------------------------------------------------------------------------
// SUITE 9: DETERMINISMO EN VALIDACIONES REPETIDAS Y CONCURRENTES
// -----------------------------------------------------------------------------
test('Suite 9: Determinism in Repeated and Concurrent Validations', async () => {
  const firstRes = validateEvent(baseValid);
  const firstJson = JSON.stringify(firstRes);

  // 1,000 llamadas secuenciales
  for (let i = 0; i < 1000; i++) {
    const curRes = validateEvent(baseValid);
    assert.strictEqual(JSON.stringify(curRes), firstJson, `Determinism failure at ${i}`);
  }

  // 500 llamadas concurrentes
  const promises = [];
  for (let i = 0; i < 500; i++) {
    promises.push(Promise.resolve().then(() => validateEvent(baseValid)));
  }
  const results = await Promise.all(promises);
  assert.ok(results.every(r => JSON.stringify(r) === firstJson), 'Concurrent validations were not deterministic');
});
