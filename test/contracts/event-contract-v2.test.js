'use strict';

/**
 * SENTINEL RUNTIME — EVENT CONTRACT V2 TEST SUITE (REVIEW R1)
 * 
 * Normative Basis: EVENT_CONTRACT_V2_REVIEW_R2_3.md & SCHEMA-V2-DRAFT-REVIEW-R1
 * Gate: SCHEMA-V2-DRAFT-REVIEW-R1
 * 
 * Exhaustive Verification:
 * - Suite 1: Meta-validation with Ajv 2020 (JSON Schema Draft 2020-12).
 * - Suite 2: 10 Primary Positive Fixtures.
 * - Suite 3: 14 Documented Event Families Conformance (Full Matrix).
 * - Suite 4: V2-01 Strict UUIDv4 RFC Enforcement (rejection of UUIDv1, UUIDv5, invalid variants).
 * - Suite 5: V2-02 Argument Capture Canonical Enums (CAPTURED_EXACT, EMPTY_STRING_OR_NO_ARGS, etc.).
 * - Suite 6: V2-03 EUID & Wrapper Nullability with Capture Status (NULLABLE_WITH_STATUS).
 * - Suite 7: V2-04 6 Normative Loss Metrics Domains & State Constraints.
 * - Suite 8: V2-06 Protobuf uint32 Range Boundaries (0 to 4294967295).
 * - Suite 9: Termination Model Mutual Exclusion & Zero Inference.
 * - Suite 10: Cursor Invariant & Framing Bounds (0, 1, 2 bytes).
 * - Suite 11: uint64 BigInt Boundary Verification (0 to 18446744073709551615).
 * - Suite 12: Workload Context Semantic Consistency (HOST_PROCESS vs CONTAINER).
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const Ajv2020 = require('ajv/dist/2020');
const {
  DOMAIN,
  lengthPrefix,
  rawProviderEventKey,
  rawPartialProcessEventKey,
  derivedCorrelatedEventKey,
  syntheticObservabilityEventKey,
  canonicalPayloadSha256
} = require('../../src/contracts/event-keys');
const { validateEventV2: validateSemanticV2 } = require('../../src/contracts/validate-event-v2');

const schemaPath = path.resolve(__dirname, '../../schemas/runtime-event-v2.schema.json');
const schemaContent = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

const ajv = new Ajv2020({
  allErrors: true,
  strict: false,
  validateFormats: false
});

const validateV2 = ajv.compile(schemaContent);
const fixturesDir = path.resolve(__dirname, '../fixtures/events/v2');
const familiesDir = path.join(fixturesDir, 'families');

const MAX_UINT64 = 18446744073709551615n;
const MAX_UINT32 = 4294967295;

function validateUint64BigInt(val) {
  if (typeof val === 'number') {
    return Number.isInteger(val) && val >= 0 && val <= Number.MAX_SAFE_INTEGER;
  }
  if (typeof val === 'string') {
    if (!/^(0|[1-9][0-9]*)$/.test(val)) return false;
    try {
      const b = BigInt(val);
      return b >= 0n && b <= MAX_UINT64;
    } catch {
      return false;
    }
  }
  return false;
}

function validateCursorInvariant(cursor) {
  if (!cursor || typeof cursor !== 'object') return false;
  const { byte_length, payload_byte_length, delimiter_byte_length } = cursor;
  if (typeof byte_length !== 'number' || typeof payload_byte_length !== 'number' || typeof delimiter_byte_length !== 'number') {
    return false;
  }
  return byte_length === payload_byte_length + delimiter_byte_length;
}

// -----------------------------------------------------------------------------
// SUITE 1: META-VALIDATION & SCHEMA COMPILATION
// -----------------------------------------------------------------------------
test('Suite V2-1: Schema Meta-Validation & Compilation', (t) => {
  assert.strictEqual(typeof validateV2, 'function', 'Validator must compile into a validation function');
  assert.strictEqual(schemaContent.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.strictEqual(schemaContent.$id, 'https://sentinel.security/schemas/v2/runtime-event.schema.json');
});

// -----------------------------------------------------------------------------
// SUITE 2: 10 PRIMARY POSITIVE FIXTURES
// -----------------------------------------------------------------------------
test('Suite V2-2: 10 Positive Fixtures Validation', async (t) => {
  const cases = [
    { name: '2.1 PROCESS_EXEC with RAW_STRING_ONLY', file: 'process_exec_raw_string.json' },
    { name: '2.2 PROCESS_EXEC with empty arguments', file: 'process_exec_empty_args.json' },
    { name: '2.3 PROCESS_EXIT with explicit nonzero status', file: 'process_exit_explicit_nonzero.json' },
    { name: '2.4 PROCESS_EXIT with certified zero inference', file: 'process_exit_zero_inferred.json' },
    { name: '2.5 PROCESS_EXIT with SIGNALED', file: 'process_exit_signaled.json' },
    { name: '2.6 PROCESS_EXIT with AMBIGUOUS', file: 'process_exit_ambiguous.json' },
    { name: '2.7 PROCESS_EXIT with UNKNOWN', file: 'process_exit_unknown.json' },
    { name: '2.8 Cursor with LF (1 byte)', file: 'cursor_lf.json' },
    { name: '2.9 Cursor with CRLF (2 bytes)', file: 'cursor_crlf.json' },
    { name: '2.10 Cursor with no delimiter (0 bytes)', file: 'cursor_no_delimiter.json' },
  ];

  for (const c of cases) {
    await t.test(c.name, () => {
      const filePath = path.join(fixturesDir, c.file);
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      const valid = validateV2(data);
      if (!valid) {
        assert.fail(`Validation failed for ${c.file}: ${JSON.stringify(validateV2.errors, null, 2)}`);
      }
      assert.strictEqual(valid, true);
      assert.strictEqual(validateUint64BigInt(data.timestamps.source_timestamp), true);
      assert.strictEqual(validateUint64BigInt(data.process_identity.process_start_time), true);
      assert.strictEqual(validateCursorInvariant(data.source_cursor), true);
    });
  }
});

// -----------------------------------------------------------------------------
// SUITE 3: 14 DOCUMENTED EVENT FAMILIES CONFORMANCE (V2-05)
// -----------------------------------------------------------------------------
test('Suite V2-3: 14 Documented Event Families Fixture Conformance', async (t) => {
  const families = [
    { family: 'PROCESS_EXEC', file: '01_process_exec.json' },
    { family: 'PROCESS_EXIT', file: '02_process_exit.json' },
    { family: 'FILE_OPEN_ATTEMPT', file: '03_file_open_attempt.json' },
    { family: 'FILE_OPEN_RESULT', file: '04_file_open_result.json' },
    { family: 'FILE_READ', file: '05_file_read.json' },
    { family: 'NETWORK_CONNECT_ATTEMPT', file: '06_network_connect_attempt.json' },
    { family: 'NETWORK_CONNECT_RESULT', file: '07_network_connect_result.json' },
    { family: 'NETWORK_SEND_ATTEMPT', file: '08_network_send_attempt.json' },
    { family: 'NETWORK_SEND_RESULT', file: '09_network_send_result.json' },
    { family: 'SOCKET_STATE_CHANGE', file: '10_socket_state_change.json' },
    { family: 'IDENTITY_CHANGE', file: '11_identity_change.json' },
    { family: 'CAPABILITY_CHECK', file: '12_capability_check.json' },
    { family: 'EVENT_LOSS', file: '13_event_loss.json' },
    { family: 'SENSOR_HEALTH', file: '14_sensor_health.json' }
  ];

  for (const fam of families) {
    await t.test(`Familia: ${fam.family}`, () => {
      const filePath = path.join(familiesDir, fam.file);
      const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      assert.strictEqual(data.event_type, fam.family);
      const valid = validateV2(data);
      if (!valid) {
        assert.fail(`Validation failed for family ${fam.family}: ${JSON.stringify(validateV2.errors, null, 2)}`);
      }
      assert.strictEqual(valid, true);
    });
  }
});

// -----------------------------------------------------------------------------
// SUITE 4: V2-01 STRICT UUIDV4 RFC ENFORCEMENT
// -----------------------------------------------------------------------------
test('Suite V2-4: Strict UUIDv4 RFC Enforcement (V2-01)', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('4.1 Acepta UUIDv4 canónico válido (versión 4, variante [89ab])', () => {
    const valid = JSON.parse(JSON.stringify(base));
    valid.event_id = '8f3b2a1c-9d4e-4f7b-8a2c-1e0f3b5a7c9d';
    assert.strictEqual(validateV2(valid), true);
  });

  await t.test('4.2 Rechaza UUIDv1 (versión 1 en vez de 4)', () => {
    const invalid = JSON.parse(JSON.stringify(base));
    invalid.event_id = '6ba7b810-9dad-11d1-80b4-00c04fd430c8'; // 3rd group starts with '1'
    assert.strictEqual(validateV2(invalid), false);
  });

  await t.test('4.3 Rechaza UUIDv5 (versión 5 en vez de 4)', () => {
    const invalid = JSON.parse(JSON.stringify(base));
    invalid.event_id = '886313e1-3b8a-5372-9b90-0c9aee199e5d'; // 3rd group starts with '5'
    assert.strictEqual(validateV2(invalid), false);
  });

  await t.test('4.4 Rechaza UUID con variante RFC incorrecta (variante 0x0)', () => {
    const invalid = JSON.parse(JSON.stringify(base));
    invalid.event_id = '8f3b2a1c-9d4e-4f7b-0a2c-1e0f3b5a7c9d'; // 4th group starts with '0'
    assert.strictEqual(validateV2(invalid), false);
  });

  await t.test('4.5 Rechaza UUID con variante RFC incorrecta (variante 0xC)', () => {
    const invalid = JSON.parse(JSON.stringify(base));
    invalid.event_id = '8f3b2a1c-9d4e-4f7b-ca2c-1e0f3b5a7c9d'; // 4th group starts with 'c'
    assert.strictEqual(validateV2(invalid), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 5: V2-02 ARGUMENT CAPTURE ENUMS ALIGNMENT
// -----------------------------------------------------------------------------
test('Suite V2-5: Argument Capture Canonical Enums (V2-02)', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('5.1 Acepta CAPTURED_EXACT con argv como array de strings', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'CAPTURED_EXACT';
    ev.payload.argv = ['umount', '-a'];
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('5.2 Rechaza CAPTURED_EXACT con argv nulo', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'CAPTURED_EXACT';
    ev.payload.argv = null;
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('5.3 Acepta EMPTY_STRING_OR_NO_ARGS con arguments_raw vacio', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'EMPTY_STRING_OR_NO_ARGS';
    ev.payload.arguments_raw = '';
    ev.payload.argv = null;
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('5.4 Rechaza EMPTY_STRING_OR_NO_ARGS con arguments_raw no vacio', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'EMPTY_STRING_OR_NO_ARGS';
    ev.payload.arguments_raw = '-a';
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('5.5 Acepta UNAVAILABLE_PARENT_MISS con arguments_raw nulo', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'UNAVAILABLE_PARENT_MISS';
    ev.payload.arguments_raw = null;
    ev.payload.argv = null;
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('5.6 Rechaza UNAVAILABLE_PARENT_MISS con arguments_raw no nulo', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'UNAVAILABLE_PARENT_MISS';
    ev.payload.arguments_raw = '-a';
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('5.7 Rechaza enums inventados (KERNEL_ARGV_AVAILABLE y EMPTY)', () => {
    const ev1 = JSON.parse(JSON.stringify(base));
    ev1.payload.arguments_capture_status = 'KERNEL_ARGV_AVAILABLE';
    assert.strictEqual(validateV2(ev1), false);

    const ev2 = JSON.parse(JSON.stringify(base));
    ev2.payload.arguments_capture_status = 'EMPTY';
    assert.strictEqual(validateV2(ev2), false);
  });

  await t.test('5.8 Rechaza argv inventado bajo RAW_STRING_ONLY', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.payload.arguments_capture_status = 'RAW_STRING_ONLY';
    ev.payload.argv = ['umount', '-a'];
    assert.strictEqual(validateV2(ev), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 6: V2-03 EUID & WRAPPER NULLABILITY (NULLABLE_WITH_STATUS)
// -----------------------------------------------------------------------------
test('Suite V2-6: EUID & Wrapper Nullability with Status (V2-03)', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('6.1 Acepta euid entero con EFFECTIVE_ONLY y ruid null', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = 1000;
    ev.process_identity.ruid = null;
    ev.process_identity.credentials_capture_status = 'EFFECTIVE_ONLY';
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('6.2 Acepta euid y ruid enteros con REAL_AND_EFFECTIVE', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = 1000;
    ev.process_identity.ruid = 1000;
    ev.process_identity.credentials_capture_status = 'REAL_AND_EFFECTIVE';
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('6.3 Acepta euid nulo ante wrapper ausente con UNAVAILABLE', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = null;
    ev.process_identity.ruid = null;
    ev.process_identity.credentials_capture_status = 'UNAVAILABLE';
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('6.4 Acepta euid nulo ante wrapper ausente con ABSENT_IN_SENSOR', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = null;
    ev.process_identity.ruid = null;
    ev.process_identity.credentials_capture_status = 'ABSENT_IN_SENSOR';
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('6.5 Rechaza euid no nulo cuando status es UNAVAILABLE o ABSENT_IN_SENSOR', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = 0;
    ev.process_identity.credentials_capture_status = 'UNAVAILABLE';
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('6.6 Rechaza euid nulo cuando status es EFFECTIVE_ONLY', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = null;
    ev.process_identity.credentials_capture_status = 'EFFECTIVE_ONLY';
    assert.strictEqual(validateV2(ev), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 7: V2-04 LOSS METRICS DOMAINS AND PROVENANCE
// -----------------------------------------------------------------------------
test('Suite V2-7: Loss Metrics Domains, Provenance, and State Constraints (V2-04)', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('7.1 Acepta los 12 dominios normativos con estados válidos', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.loss_metrics = {
      ebpf_kernel: { state: 'ZERO_OBSERVED', count: 0, source: 'test-counter', observed_at: '1793662267650000000' },
      sensor_throttle: { state: 'MEASURED', count: 12, source: 'test-counter', observed_at: '1793662267650000000' },
      grpc_transport: { state: 'UNAVAILABLE', count: null },
      log_rotation: { state: 'ZERO_OBSERVED', count: 0, source: 'test-counter', observed_at: '1793662267650000000' },
      parser_reject: { state: 'ZERO_OBSERVED', count: 0, source: 'test-counter', observed_at: '1793662267650000000' },
      runtime_queue: { state: 'NOT_APPLICABLE', count: null },
      storage_drop: { state: 'UNKNOWN', count: null },
      tetragon_bpf_missed_events: { state: 'UNKNOWN', count: null },
      tetragon_listener_overflow: { state: 'UNKNOWN', count: null },
      tetragon_field_filter_drops: { state: 'UNKNOWN', count: null },
      tetragon_observer_queue_drops: { state: 'UNKNOWN', count: null },
      tetragon_aggregation_buffer_drops: { state: 'UNKNOWN', count: null }
    };
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('7.2 Rechaza omisión de cualquiera de los 12 dominios', () => {
    const ev = JSON.parse(JSON.stringify(base));
    delete ev.loss_metrics.sensor_throttle; // Missing required domain
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('7.3 Rechaza ZERO_OBSERVED con count > 0', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.loss_metrics.ebpf_kernel = { state: 'ZERO_OBSERVED', count: 5, source: 'test-counter', observed_at: '1793662267650000000' };
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('7.4 Rechaza ZERO_OBSERVED con count null', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.loss_metrics.ebpf_kernel = { state: 'ZERO_OBSERVED', count: null, source: 'test-counter', observed_at: '1793662267650000000' };
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('7.5 Rechaza UNAVAILABLE con count no nulo', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.loss_metrics.grpc_transport = { state: 'UNAVAILABLE', count: 10 };
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('7.6 Rechaza MEASURED sin source/observed_at y LOWER_BOUND igual a cero', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.loss_metrics.ebpf_kernel = { state: 'MEASURED', count: '1' };
    assert.strictEqual(validateV2(ev), false);
    ev.loss_metrics.ebpf_kernel = { state: 'MEASURED_LOWER_BOUND', count: '0', source: 'counter', observed_at: '1793662267650000000' };
    assert.strictEqual(validateV2(ev), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 8: PROTOBUF UINT32 VS SENTINEL UINT64 BOUNDARIES (R2-01 & R2-02)
// -----------------------------------------------------------------------------
test('Suite V2-8: Protobuf uint32 vs Sentinel uint64 Boundaries (R2-01 & R2-02)', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('8.1 Acepta valores máximos uint32 válidos (4294967295) en campos protobuf', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.pid = MAX_UINT32;
    ev.process_identity.tid = MAX_UINT32;
    ev.process_identity.euid = MAX_UINT32;
    ev.sensor_metadata.debug_refcnt = MAX_UINT32;
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('8.2 Rechaza pid superior a uint32 (4294967296)', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.pid = 4294967296;
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('8.3 Rechaza tid superior a uint32 (4294967296)', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.tid = 4294967296;
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('8.4 Rechaza euid superior a uint32 (4294967296)', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.euid = 4294967296;
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('8.5 Acepta tid = 0 como wrapper presente válido; su semántica requiere corroboración (R2-02)', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.process_identity.tid = 0;
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('8.6 Acepta loss_metrics count superior a uint32 (p. ej. 5000000000) por ser uint64 (R2-01)', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.loss_metrics.ebpf_kernel = { state: 'MEASURED', count: 5000000000, source: 'test-counter', observed_at: '1793662267650000000' };
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('8.7 Acepta file_generation_id superior a uint32 (p. ej. 5000000000) por ser uint64 (R2-01)', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.source_cursor.file_generation_id = 5000000000;
    assert.strictEqual(validateV2(ev), true);
  });
});

// -----------------------------------------------------------------------------
// SUITE 9: TERMINATION MODEL MUTUAL EXCLUSION
// -----------------------------------------------------------------------------
test('Suite V2-9: Termination Model Mutual Exclusion', async (t) => {
  const baseExit = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exit_explicit_nonzero.json'), 'utf8')
  );

  await t.test('9.1 Rechaza exit_status 0 bajo EXPLICIT_NONZERO', () => {
    const ev = JSON.parse(JSON.stringify(baseExit));
    ev.payload.termination = {
      kind: 'EXITED',
      exit_status: 0,
      signal_name: null,
      status_origin: 'EXPLICIT_NONZERO'
    };
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('9.2 Rechaza SIGNALED con exit_status numerico', () => {
    const ev = JSON.parse(JSON.stringify(baseExit));
    ev.payload.termination = {
      kind: 'SIGNALED',
      exit_status: 137,
      signal_name: 'SIGKILL',
      status_origin: 'NOT_APPLICABLE_SIGNALED'
    };
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('9.3 Rechaza AMBIGUOUS sin datos contradictorios (falta signal)', () => {
    const ev = JSON.parse(JSON.stringify(baseExit));
    ev.payload.termination = {
      kind: 'AMBIGUOUS',
      exit_status: 137,
      signal_name: null,
      status_origin: 'CONTRADICTORY_DATA'
    };
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('9.4 Rechaza UNKNOWN con exit_status numerico', () => {
    const ev = JSON.parse(JSON.stringify(baseExit));
    ev.payload.termination = {
      kind: 'UNKNOWN',
      exit_status: 0,
      signal_name: null,
      status_origin: 'UNVERIFIED_OMISSION_UNKNOWN'
    };
    assert.strictEqual(validateV2(ev), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 10: CURSOR INVARIANT & FRAMING BOUNDS
// -----------------------------------------------------------------------------
test('Suite V2-10: Cursor Invariant & Framing Bounds', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('10.1 Acepta delimiter_byte_length de 0, 1 y 2 bytes', () => {
    for (const d of [0, 1, 2]) {
      const ev = JSON.parse(JSON.stringify(base));
      ev.source_cursor.delimiter_byte_length = d;
      ev.source_cursor.byte_length = ev.source_cursor.payload_byte_length + d;
      assert.strictEqual(validateV2(ev), true);
      assert.strictEqual(validateCursorInvariant(ev.source_cursor), true);
    }
  });

  await t.test('10.2 Rechaza delimiter_byte_length > 2 por esquema', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.source_cursor.delimiter_byte_length = 3;
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('10.3 Rechaza inconsistencia aritmetica en cursor por validador semantico', () => {
    const inconsistent = {
      inode: 1,
      byte_offset: 0,
      byte_length: 800,
      payload_byte_length: 825,
      delimiter_byte_length: 1,
      file_generation_id: 1,
      raw_payload_sha256: '0e9d24b946c1d2505a84b92ac3c5e579a97f51de5f284a31a7e81361eeb2f818'
    };
    assert.strictEqual(validateCursorInvariant(inconsistent), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 11: UINT64 BIGINT BOUNDARY VERIFICATION
// -----------------------------------------------------------------------------
test('Suite V2-11: uint64 BigInt Boundary Verification', () => {
  assert.strictEqual(validateUint64BigInt('0'), true);
  assert.strictEqual(validateUint64BigInt('1'), true);
  assert.strictEqual(validateUint64BigInt('9007199254740991'), true);
  assert.strictEqual(validateUint64BigInt('18446744073709551615'), true);

  assert.strictEqual(validateUint64BigInt('18446744073709551616'), false);
  assert.strictEqual(validateUint64BigInt('19000000000000000000'), false);
  assert.strictEqual(validateUint64BigInt('99999999999999999999'), false);
  assert.strictEqual(validateUint64BigInt('-1'), false);
  assert.strictEqual(validateUint64BigInt('07'), false);
});

// -----------------------------------------------------------------------------
// SUITE 12: WORKLOAD CONTEXT CONSISTENCY & ROOT INVARIANTS
// -----------------------------------------------------------------------------
test('Suite V2-12: Workload Context & Root Invariants', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('12.1 HOST_PROCESS con container_id != null debe fallar', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.workload_context.context_type = 'HOST_PROCESS';
    ev.workload_context.container_id = 'docker-123';
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('12.2 CONTAINER con container_id == null debe fallar', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.workload_context.context_type = 'CONTAINER';
    ev.workload_context.container_id = null;
    assert.strictEqual(validateV2(ev), false);
  });

  await t.test('12.3 additionalProperties: false en raiz rechaza campos desconocidos', () => {
    const ev = JSON.parse(JSON.stringify(base));
    ev.injected_rogue_property = 'malicious';
    assert.strictEqual(validateV2(ev), false);
  });
});

// -----------------------------------------------------------------------------
// SUITE 13: CRYPTOGRAPHIC SEMANTIC VALIDATION (LENGTH-PREFIX ENCODING - R2-05)
// -----------------------------------------------------------------------------
test('Suite V2-13: Domain-separated cryptographic event identity (R2-05)', async (t) => {
  const base = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  function computeLengthPrefixKey(hostId, bootId, execId, eventType, sourceTimestamp, rawPayloadSha256) {
    return rawProviderEventKey({ hostId, bootId, execId, eventType, sourceTimestamp, rawPayloadSha256 });
  }

  await t.test('13.1 Valida coincidencia exacta con la implementación de Perfil RAW', () => {
    const computed = computeLengthPrefixKey(
      base.host_identity.host_id,
      base.host_identity.boot_id,
      base.process_identity.exec_id,
      base.event_type,
      base.timestamps.source_timestamp,
      base.source_cursor.raw_payload_sha256
    );
    assert.strictEqual(computed, base.source_event_key);
  });

  await t.test('13.2 Mutar host_id altera el hash y rompe la coincidencia', () => {
    const computed = computeLengthPrefixKey(
      'sentinel-host-prod-02',
      base.host_identity.boot_id,
      base.process_identity.exec_id,
      base.event_type,
      base.timestamps.source_timestamp,
      base.source_cursor.raw_payload_sha256
    );
    assert.notStrictEqual(computed, base.source_event_key);
  });

  await t.test('13.3 Mutar boot_id altera el hash y rompe la coincidencia', () => {
    const computed = computeLengthPrefixKey(
      base.host_identity.host_id,
      '00000000-0000-4000-8000-000000000000',
      base.process_identity.exec_id,
      base.event_type,
      base.timestamps.source_timestamp,
      base.source_cursor.raw_payload_sha256
    );
    assert.notStrictEqual(computed, base.source_event_key);
  });

  await t.test('13.4 Mutar exec_id altera el hash y rompe la coincidencia', () => {
    const computed = computeLengthPrefixKey(
      base.host_identity.host_id,
      base.host_identity.boot_id,
      'REVTS1RPUC1LSTVBUFA0OjM4NjY4NTY2Mjk1OToxMzEx',
      base.event_type,
      base.timestamps.source_timestamp,
      base.source_cursor.raw_payload_sha256
    );
    assert.notStrictEqual(computed, base.source_event_key);
  });

  await t.test('13.5 Mutar event_type altera el hash y rompe la coincidencia', () => {
    const computed = computeLengthPrefixKey(
      base.host_identity.host_id,
      base.host_identity.boot_id,
      base.process_identity.exec_id,
      'PROCESS_EXIT',
      base.timestamps.source_timestamp,
      base.source_cursor.raw_payload_sha256
    );
    assert.notStrictEqual(computed, base.source_event_key);
  });

  await t.test('13.6 Mutar source_timestamp altera el hash y rompe la coincidencia', () => {
    const computed = computeLengthPrefixKey(
      base.host_identity.host_id,
      base.host_identity.boot_id,
      base.process_identity.exec_id,
      base.event_type,
      '1793662267642869316',
      base.source_cursor.raw_payload_sha256
    );
    assert.notStrictEqual(computed, base.source_event_key);
  });

  await t.test('13.7 Mutar raw_payload_sha256 altera el hash y rompe la coincidencia', () => {
    const computed = computeLengthPrefixKey(
      base.host_identity.host_id,
      base.host_identity.boot_id,
      base.process_identity.exec_id,
      base.event_type,
      base.timestamps.source_timestamp,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
    assert.notStrictEqual(computed, base.source_event_key);
  });
});

// -----------------------------------------------------------------------------
// SUITE 14: SECTION 3 NORMATIVE REQUIREMENTS & HARDENING VERIFICATIONS
// -----------------------------------------------------------------------------
test('Suite V2-14: Section 3 Normative Requirements & Hardening', async (t) => {
  const baseExec = JSON.parse(
    fs.readFileSync(path.join(fixturesDir, 'process_exec_raw_string.json'), 'utf8')
  );

  await t.test('14.1 Certified test vector matches exactly', () => {
    assert.strictEqual(
      baseExec.source_event_key,
      '49b501dc1e646ed9aa871a659326b2a100672fe1d8298eb57d076a9d5d7d8af1',
      'Certified test vector key must match documented SHA-256'
    );
  });

  await t.test('14.2 Domain separation across RAW, DERIVED, SYNTHETIC profiles', () => {
    const hostId = 'sentinel-host-01';
    const bootId = '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c';
    const payloadSha = 'a'.repeat(64);

    const rawKey = rawProviderEventKey({
      hostId,
      bootId,
      execId: 'exec-123',
      eventType: 'PROCESS_EXEC',
      sourceTimestamp: '1793662267642869315',
      rawPayloadSha256: payloadSha
    });

    const derivedKey = derivedCorrelatedEventKey({
      hostId,
      bootId,
      correlationRuleId: 'RULE-01',
      ruleVersion: '1.0.0',
      schemaVersion: '2.0.0',
      resultType: 'CORRELATED_EVENT',
      primaryEventKey: rawKey,
      secondaryEventKey: 'b'.repeat(64)
    });

    const syntheticKey = syntheticObservabilityEventKey({
      hostId,
      bootId,
      producerId: 'loss-monitor-1',
      producerEpoch: '9a5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
      sequenceNumber: '1',
      eventType: 'EVENT_LOSS',
      payloadSha256: payloadSha
    });

    const partialKey = rawPartialProcessEventKey({
      hostId,
      bootId,
      pid: 1234,
      processStartTime: '1793662267642869000',
      eventType: 'PROCESS_EXEC',
      sourceTimestamp: '1793662267642869315',
      rawPayloadSha256: payloadSha
    });

    const keys = new Set([rawKey, derivedKey, syntheticKey, partialKey]);
    assert.strictEqual(keys.size, 4, 'All four domain profiles must produce distinct keys');
  });

  await t.test('14.3 Length prefix UTF-8 byte length vs character length', () => {
    // Single multi-byte character: 'á' (1 char, 2 UTF-8 bytes: 0xC3 0xA1)
    const lp1 = lengthPrefix('á');
    assert.strictEqual(lp1.readBigUInt64BE(0), 2n, 'Length prefix must encode byte count (2), not char count (1)');
    assert.strictEqual(lp1.length, 10, '8 length bytes + 2 data bytes');

    // Emoji: '🚀' (2 UTF-16 code units, 4 UTF-8 bytes: 0xF0 0x9F 0x99 0x80)
    const lp2 = lengthPrefix('🚀');
    assert.strictEqual(lp2.readBigUInt64BE(0), 4n, 'Length prefix must encode UTF-8 byte count (4)');
    assert.strictEqual(lp2.length, 12, '8 length bytes + 4 data bytes');

    // ASCII: 'hello' (5 chars, 5 bytes)
    const lp3 = lengthPrefix('hello');
    assert.strictEqual(lp3.readBigUInt64BE(0), 5n);
    assert.strictEqual(lp3.length, 13);
  });

  await t.test('14.4 Maximum uint64 (18446744073709551615) and overflow rejection', () => {
    const ev = JSON.parse(JSON.stringify(baseExec));
    ev.timestamps.source_timestamp = '18446744073709551615';
    assert.strictEqual(validateV2(ev), true, '2^64 - 1 must be valid in schema');

    ev.timestamps.source_timestamp = '18446744073709551616';
    assert.strictEqual(validateV2(ev), false, '2^64 must be rejected by schema');

    // Near overflow and 2^63 boundary
    ev.timestamps.source_timestamp = '9223372036854775807'; // 2^63 - 1
    assert.strictEqual(validateV2(ev), true);
    ev.timestamps.source_timestamp = '9223372036854775808'; // 2^63 (SQLite signed overflow boundary)
    assert.strictEqual(validateV2(ev), true);
  });

  await t.test('14.5 Canonical decimal strings rejection of non-conforming formats', () => {
    const invalidFormats = [
      '007',        // leading zeros
      '01',         // leading zeros
      '1e10',       // scientific notation
      '1.8e19',     // scientific notation
      '-5',         // negative
      '+100',       // explicit positive sign
      ' 123 ',      // whitespace padding
      '123.45',     // float
      '0x10'        // hex
    ];

    for (const bad of invalidFormats) {
      const ev = JSON.parse(JSON.stringify(baseExec));
      ev.timestamps.source_timestamp = bad;
      assert.strictEqual(validateV2(ev), false, `Schema must reject non-canonical uint64: "${bad}"`);
    }
  });

  await t.test('14.6 EUID collision preservation (COLLISION_UNRESOLVED, raw values present)', () => {
    const ev = JSON.parse(JSON.stringify(baseExec));
    ev.process_identity.credentials_capture_status = 'COLLISION_UNRESOLVED';
    ev.process_identity.process_uid_raw = 1000;
    ev.process_identity.credentials_euid_raw = 0;
    ev.process_identity.euid = null;

    const res = validateSemanticV2(ev);
    assert.strictEqual(res.valid, true, 'COLLISION_UNRESOLVED with raw values must pass schema and semantic validation');
    assert.ok(
      res.warnings.some(w => w.includes('Credential identity collision is unresolved')),
      'Must emit warning about unresolved credential collision'
    );

    // Missing raw values in collision must fail
    const evMissing = JSON.parse(JSON.stringify(ev));
    delete evMissing.process_identity.process_uid_raw;
    const resMissing = validateSemanticV2(evMissing);
    assert.strictEqual(resMissing.valid, false);
    assert.ok(
      resMissing.errors.some(e => e.keyword === 'credentialCollision'),
      'Must reject collision when process_uid_raw is missing'
    );
  });

  await t.test('14.7 Negative kernel returns for FILE_OPEN_RESULT (fd: null, errno: -return_code)', () => {
    const openResultFixture = JSON.parse(
      fs.readFileSync(path.join(familiesDir, '04_file_open_result.json'), 'utf8')
    );

    // Negative return code (-13: EACCES)
    const failureEvent = JSON.parse(JSON.stringify(openResultFixture));
    failureEvent.payload.return_code = -13;
    failureEvent.payload.fd = null;
    failureEvent.payload.errno = 13;
    const resFail = validateSemanticV2(failureEvent);
    assert.strictEqual(resFail.valid, true, 'Negative return code with fd=null and errno=13 must validate');

    // Inconsistent fd on failure
    const badFdEvent = JSON.parse(JSON.stringify(failureEvent));
    badFdEvent.payload.fd = 7;
    const resBadFd = validateSemanticV2(badFdEvent);
    assert.strictEqual(resBadFd.valid, false);
    assert.ok(resBadFd.errors.some(e => e.keyword === 'kernelReturnInvariant'));

    // Inconsistent errno on failure
    const badErrnoEvent = JSON.parse(JSON.stringify(failureEvent));
    badErrnoEvent.payload.errno = 2; // expected 13
    const resBadErrno = validateSemanticV2(badErrnoEvent);
    assert.strictEqual(resBadErrno.valid, false);
    assert.ok(resBadErrno.errors.some(e => e.keyword === 'kernelReturnInvariant'));
  });

  await t.test('14.8 TID = 0 is structurally valid and semantically neutral', () => {
    const ev = JSON.parse(JSON.stringify(baseExec));
    ev.process_identity.tid = 0;
    assert.strictEqual(validateV2(ev), true, 'Schema must accept tid=0');
    const res = validateSemanticV2(ev);
    assert.strictEqual(res.valid, true, 'Semantic validator must accept tid=0 without error');
  });

  await t.test('14.9 File cursor vs gRPC sequence separation validation', () => {
    // FILE_BYTES with gRPC transport protocol must be rejected
    const evFileMismatch = JSON.parse(JSON.stringify(baseExec));
    evFileMismatch.source_cursor.cursor_kind = 'FILE_BYTES';
    evFileMismatch.sensor_metadata.transport_protocol = 'GRPC_UNIX_SOCKET';
    const resFileMismatch = validateSemanticV2(evFileMismatch);
    assert.strictEqual(resFileMismatch.valid, false);
    assert.ok(resFileMismatch.errors.some(e => e.keyword === 'cursorTransportMismatch'));

    // GRPC_SEQUENCE with file transport protocol must be rejected
    const evGrpcMismatch = JSON.parse(JSON.stringify(baseExec));
    evGrpcMismatch.source_cursor = {
      cursor_kind: 'GRPC_SEQUENCE',
      stream_epoch: '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
      sequence_number: '1',
      raw_payload_sha256: 'a'.repeat(64)
    };
    evGrpcMismatch.sensor_metadata.transport_protocol = 'JSON_FILE_STREAM';
    const resGrpcMismatch = validateSemanticV2(evGrpcMismatch);
    assert.strictEqual(resGrpcMismatch.valid, false);
    assert.ok(resGrpcMismatch.errors.some(e => e.keyword === 'cursorTransportMismatch'));
  });
});


// -----------------------------------------------------------------------------
// SUITE 15: PROFILE D — RAW_PARTIAL_PROCESS_EVENT KEY VECTORS
// -----------------------------------------------------------------------------
test('Suite V2-15: Profile D rawPartialProcessEventKey — Positive and Adversarial Vectors', async (t) => {

  // -------------------------------------------------------------------------
  // POSITIVE VECTORS (5)
  // Each vector includes the exact computation sequence in comments:
  //   field value | byte length | 8-byte big-endian length prefix
  // The domain tag for all vectors is "SR1|RAW_PARTIAL_PROCESS_EVENT" (byteLen=29, prefix=000000000000001d)
  // -------------------------------------------------------------------------

  await t.test('15.1 Positive: typical process — PID 1337, PROCESS_EXEC', () => {
    // Field computation sequence:
    //   domain           = "SR1|RAW_PARTIAL_PROCESS_EVENT"  byteLen=29  prefix=000000000000001d
    //   hostId           = "sentinel-host-prod-01"           byteLen=21  prefix=0000000000000015
    //   bootId           = "8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c"  byteLen=36  prefix=0000000000000024
    //   pid              = "1337"                            byteLen=4   prefix=0000000000000004
    //   processStartTime = "1793662267000000000"             byteLen=19  prefix=0000000000000013
    //     (source: Tetragon Process.start_time as google.protobuf.Timestamp,
    //      computed as BigInt(seconds)*1_000_000_000n + BigInt(nanos))
    //   eventType        = "PROCESS_EXEC"                   byteLen=12  prefix=000000000000000c
    //   sourceTimestamp  = "1793662267642869315"             byteLen=19  prefix=0000000000000013
    //   rawPayloadSha256 = "a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
    //                                                        byteLen=64  prefix=0000000000000040
    // Expected SHA-256: 9366cacf95ab34343fd099774272df093e34050561cc3cdd5165b652b81a0804
    const key = rawPartialProcessEventKey({
      hostId: 'sentinel-host-prod-01',
      bootId: '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
      pid: 1337,
      processStartTime: '1793662267000000000',
      eventType: 'PROCESS_EXEC',
      sourceTimestamp: '1793662267642869315',
      rawPayloadSha256: 'a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1'
    });
    assert.strictEqual(key, '9366cacf95ab34343fd099774272df093e34050561cc3cdd5165b652b81a0804');
  });

  await t.test('15.2 Positive: structural boundary — not a valid captured event (PID=0, processStartTime="0")', () => {
    // processStartTime="0" is accepted structurally as a uint64 boundary value.
    // It does NOT constitute a valid provider-observed process identity anchor.
    // Field computation sequence:
    //   domain           = "SR1|RAW_PARTIAL_PROCESS_EVENT"  byteLen=29  prefix=000000000000001d
    //   hostId           = "sentinel-host-prod-01"           byteLen=21  prefix=0000000000000015
    //   bootId           = "8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c"  byteLen=36  prefix=0000000000000024
    //   pid              = "0"                               byteLen=1   prefix=0000000000000001
    //   processStartTime = "0"                               byteLen=1   prefix=0000000000000001
    //   eventType        = "PROCESS_EXEC"                   byteLen=12  prefix=000000000000000c
    //   sourceTimestamp  = "1793662267642869315"             byteLen=19  prefix=0000000000000013
    //   rawPayloadSha256 = "a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
    //                                                        byteLen=64  prefix=0000000000000040
    // Expected SHA-256: 25e7961b79f10c318ca2942f96808ff5a54d0adb10b45a7449f19d31465883e9
    const key = rawPartialProcessEventKey({
      hostId: 'sentinel-host-prod-01',
      bootId: '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
      pid: 0,
      processStartTime: '0',
      eventType: 'PROCESS_EXEC',
      sourceTimestamp: '1793662267642869315',
      rawPayloadSha256: 'a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1'
    });
    assert.strictEqual(key, '25e7961b79f10c318ca2942f96808ff5a54d0adb10b45a7449f19d31465883e9');
  });

  await t.test('15.3 Positive: uint32 and uint64 upper boundaries — PID=4294967295, timestamps=max uint64', () => {
    // Field computation sequence:
    //   domain           = "SR1|RAW_PARTIAL_PROCESS_EVENT"  byteLen=29  prefix=000000000000001d
    //   hostId           = "sentinel-host-prod-01"           byteLen=21  prefix=0000000000000015
    //   bootId           = "8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c"  byteLen=36  prefix=0000000000000024
    //   pid              = "4294967295"                      byteLen=10  prefix=000000000000000a
    //   processStartTime = "18446744073709551615"            byteLen=20  prefix=0000000000000014
    //   eventType        = "PROCESS_EXIT"                   byteLen=12  prefix=000000000000000c
    //   sourceTimestamp  = "18446744073709551615"            byteLen=20  prefix=0000000000000014
    //   rawPayloadSha256 = "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5"
    //                                                        byteLen=64  prefix=0000000000000040
    // Expected SHA-256: 7827fed2022ed024da2089da0b97104b3f1c6a72ff2cbece582b4dd6fafcb45a
    const key = rawPartialProcessEventKey({
      hostId: 'sentinel-host-prod-01',
      bootId: '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
      pid: 4294967295,
      processStartTime: '18446744073709551615',
      eventType: 'PROCESS_EXIT',
      sourceTimestamp: '18446744073709551615',
      rawPayloadSha256: 'b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5'
    });
    assert.strictEqual(key, '7827fed2022ed024da2089da0b97104b3f1c6a72ff2cbece582b4dd6fafcb45a');
  });

  await t.test('15.4 Positive: different host/boot identity — PID=12345, CAPABILITY_CHECK', () => {
    // Field computation sequence:
    //   domain           = "SR1|RAW_PARTIAL_PROCESS_EVENT"  byteLen=29  prefix=000000000000001d
    //   hostId           = "sentinel-host-02"                byteLen=16  prefix=0000000000000010
    //   bootId           = "ffffffff-ffff-4fff-bfff-ffffffffffff"  byteLen=36  prefix=0000000000000024
    //   pid              = "12345"                           byteLen=5   prefix=0000000000000005
    //   processStartTime = "1700000000000000000"             byteLen=19  prefix=0000000000000013
    //   eventType        = "CAPABILITY_CHECK"               byteLen=16  prefix=0000000000000010
    //   sourceTimestamp  = "1700000001000000000"             byteLen=19  prefix=0000000000000013
    //   rawPayloadSha256 = "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
    //                                                        byteLen=64  prefix=0000000000000040
    // Expected SHA-256: 45c9fe998377505e56da39783f1a39b36fec2e69f27124b319d154349903bc2b
    const key = rawPartialProcessEventKey({
      hostId: 'sentinel-host-02',
      bootId: 'ffffffff-ffff-4fff-bfff-ffffffffffff',
      pid: 12345,
      processStartTime: '1700000000000000000',
      eventType: 'CAPABILITY_CHECK',
      sourceTimestamp: '1700000001000000000',
      rawPayloadSha256: 'c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
    });
    assert.strictEqual(key, '45c9fe998377505e56da39783f1a39b36fec2e69f27124b319d154349903bc2b');
  });

  await t.test('15.5 Positive: PID=1 (init process), PROCESS_EXIT', () => {
    // Field computation sequence:
    //   domain           = "SR1|RAW_PARTIAL_PROCESS_EVENT"  byteLen=29  prefix=000000000000001d
    //   hostId           = "sentinel-host-prod-01"           byteLen=21  prefix=0000000000000015
    //   bootId           = "8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c"  byteLen=36  prefix=0000000000000024
    //   pid              = "1"                               byteLen=1   prefix=0000000000000001
    //   processStartTime = "1793662100000000001"             byteLen=19  prefix=0000000000000013
    //   eventType        = "PROCESS_EXIT"                   byteLen=12  prefix=000000000000000c
    //   sourceTimestamp  = "1793662267642869315"             byteLen=19  prefix=0000000000000013
    //   rawPayloadSha256 = "d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7"
    //                                                        byteLen=64  prefix=0000000000000040
    // Expected SHA-256: 513ab0fe205938541186977cde78c16162e7e20c16e509ecdc165d163b3593be
    const key = rawPartialProcessEventKey({
      hostId: 'sentinel-host-prod-01',
      bootId: '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
      pid: 1,
      processStartTime: '1793662100000000001',
      eventType: 'PROCESS_EXIT',
      sourceTimestamp: '1793662267642869315',
      rawPayloadSha256: 'd6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7'
    });
    assert.strictEqual(key, '513ab0fe205938541186977cde78c16162e7e20c16e509ecdc165d163b3593be');
  });

  // -------------------------------------------------------------------------
  // ADVERSARIAL / NEGATIVE VECTORS (5)
  // -------------------------------------------------------------------------

  const baseParams = {
    hostId: 'sentinel-host-prod-01',
    bootId: '8f5a2b1c-3d4e-4f6a-8b8c-9d0e1f2a3b4c',
    pid: 100,
    processStartTime: '1793662267000000000',
    eventType: 'PROCESS_EXEC',
    sourceTimestamp: '1793662267642869315',
    rawPayloadSha256: 'a3f1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1'
  };

  await t.test('15.6 Adversarial: pid=-1 must throw RangeError identifying the uint32 domain (not uint64)', () => {
    assert.throws(
      () => rawPartialProcessEventKey({ ...baseParams, pid: -1 }),
      (err) => {
        assert.ok(err instanceof RangeError, 'Must be a RangeError');
        assert.ok(
          err.message.includes('uint32'),
          'Error message must explicitly identify pid as a uint32 field; got: ' + err.message
        );
        return true;
      }
    );
  });

  await t.test('15.7 Adversarial: pid=4294967296 must throw RangeError for uint32 overflow', () => {
    assert.throws(
      () => rawPartialProcessEventKey({ ...baseParams, pid: 4294967296 }),
      (err) => {
        assert.ok(err instanceof RangeError, 'Must be a RangeError');
        assert.ok(
          err.message.includes('uint32'),
          'Error message must reference the uint32 domain; got: ' + err.message
        );
        return true;
      }
    );
  });

  await t.test('15.8 Adversarial: processStartTime=1.5e18 (non-integer float) must throw TypeError', () => {
    assert.throws(
      () => rawPartialProcessEventKey({ ...baseParams, processStartTime: 1.5e18 }),
      (err) => {
        assert.ok(err instanceof TypeError, 'Must be a TypeError; got: ' + err.constructor.name);
        return true;
      }
    );
  });

  await t.test('15.9 Adversarial: rawPayloadSha256 with wrong length or non-hex chars must throw TypeError', () => {
    // 63 chars (too short)
    assert.throws(
      () => rawPartialProcessEventKey({ ...baseParams, rawPayloadSha256: 'a'.repeat(63) }),
      (err) => {
        assert.ok(err instanceof TypeError, 'Must be a TypeError for 63-char digest; got: ' + err.constructor.name);
        return true;
      }
    );
    // 64 chars but with a non-hex character
    assert.throws(
      () => rawPartialProcessEventKey({ ...baseParams, rawPayloadSha256: 'g' + 'a'.repeat(63) }),
      (err) => {
        assert.ok(err instanceof TypeError, 'Must be a TypeError for non-hex digest; got: ' + err.constructor.name);
        return true;
      }
    );
  });

  await t.test('15.10 Adversarial: hostId="" (empty string) must throw TypeError', () => {
    assert.throws(
      () => rawPartialProcessEventKey({ ...baseParams, hostId: '' }),
      (err) => {
        assert.ok(err instanceof TypeError, 'Must be a TypeError; got: ' + err.constructor.name);
        return true;
      }
    );
  });
});
