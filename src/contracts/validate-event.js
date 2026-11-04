'use strict';

/**
 * SENTINEL RUNTIME — EVENT VALIDATOR V1 (HARDENED - PHASE 001A-R2)
 *
 * Implementa validación estructural determinista conforme a Draft 2020-12
 * utilizando Ajv2020 con endurecimiento de seguridad:
 * - Cota estricta uint64 (0 <= n <= 2^64 - 1).
 * - Rechazo de NUL byte (U+0000) en rutas.
 * - Límites DoS por campo (maxLength, maxItems).
 * - Consistencia semántica HOST_PROCESS (container_id: null).
 * - Warnings estructurados de procedencia (unknown_source, other_provider, unauthenticated, synthetic transport).
 *
 * REGLAS NORMATIVAS:
 * 1. La entrada original NUNCA se modifica (inmutabilidad estricta).
 * 2. NO emite veredictos de amenaza ni propaga taint.
 * 3. NO ejecuta enforcement ni altera timestamps.
 * 4. NO elimina campos desconocidos silenciosamente.
 * 5. Determina conformidad estructural estricta.
 */

const fs = require('fs');
const path = require('path');
const Ajv2020 = require('ajv/dist/2020');
const {
  SCHEMA_VERSION_V1,
  SourceProvider,
  TransportProtocol,
  MAX_SAFE_INTEGER,
  MAX_UINT64,
  CANONICAL_UINT64_REGEX
} = require('./event-types');

// Cargar esquema normativo Draft 2020-12
const schemaPath = path.resolve(__dirname, '../../schemas/runtime-event-v1.schema.json');
const schemaContent = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

// Instanciar Ajv2020 sin mutación de objetos y con captura de todos los errores
const ajv = new Ajv2020({
  allErrors: true,
  strict: false,
  validateFormats: false // Patrones regex nativos en $defs
});

const compiledValidator = ajv.compile(schemaContent);

/**
 * Lista de rutas canónicas de campos uint64 para auditoría de rango estricto
 */
function checkUint64Field(val, fieldPath, errors) {
  if (val === undefined || val === null) return;

  if (typeof val === 'number') {
    if (val < 0) {
      errors.push({
        path: fieldPath,
        message: 'uint64 value cannot be negative',
        keyword: 'minimum',
        params: { minimum: 0, received: val }
      });
    } else if (val > MAX_SAFE_INTEGER) {
      errors.push({
        path: fieldPath,
        message: `${fieldPath} exceeds MAX_SAFE_INTEGER (${MAX_SAFE_INTEGER}). Pass as canonical decimal string to prevent precision loss.`,
        keyword: 'precisionRisk',
        params: { value: val }
      });
    }
  } else if (typeof val === 'string') {
    // Si no es una ruta (ej. cgroup path)
    if (val.startsWith('/')) return;

    if (!CANONICAL_UINT64_REGEX.test(val)) {
      errors.push({
        path: fieldPath,
        message: `${fieldPath} is not a canonical uint64 decimal string (no leading zeros permitted, max 20 digits)`,
        keyword: 'pattern',
        params: { pattern: '^(0|[1-9][0-9]{0,19})$', received: val }
      });
      return;
    }

    try {
      const b = BigInt(val);
      if (b > MAX_UINT64) {
        errors.push({
          path: fieldPath,
          message: `${fieldPath} exceeds maximum uint64 range (${MAX_UINT64.toString()})`,
          keyword: 'maximumUint64',
          params: { maximum: MAX_UINT64.toString(), received: val }
        });
      }
    } catch (_) {
      errors.push({
        path: fieldPath,
        message: `${fieldPath} could not be parsed as BigInt`,
        keyword: 'type',
        params: { received: val }
      });
    }
  }
}

/**
 * Valida un evento contra el contrato normativo Sentinel Runtime v1.
 *
 * @param {object} event - Objeto de evento entrante a validar
 * @param {object} [options]
 * @param {boolean} [options.allowSynthetic=true] - Permitir eventos marcados como synthetic_lab
 * @returns {object} Resultado determinista: { valid, schema_version, event_family, errors, warnings }
 */
function validateEvent(event, options = {}) {
  const allowSynthetic = options.allowSynthetic !== false;

  // Garantía de estructura base
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return {
      valid: false,
      schema_version: null,
      event_family: null,
      errors: [
        {
          path: '#',
          message: 'Event must be a non-null object',
          keyword: 'type',
          params: { expected: 'object', received: event === null ? 'null' : typeof event }
        }
      ],
      warnings: []
    };
  }

  const warnings = [];
  const errors = [];

  // Snapshot de verificación de inmutabilidad (congelación simbólica o chequeo)
  const initialKeys = Object.keys(event);

  // Ejecución de validación de esquema con Ajv2020
  const isValidSchema = compiledValidator(event);

  if (!isValidSchema && compiledValidator.errors) {
    for (const err of compiledValidator.errors) {
      errors.push({
        path: err.instancePath || '#',
        message: err.message || 'Validation error',
        keyword: err.keyword,
        params: err.params || {}
      });
    }
  }

  // Verificaciones semánticas adicionales no mutativas:

  // 1. Auditoría de rango numérico estricto uint64 (P-01)
  checkUint64Field(event.source_timestamp, '#/source_timestamp', errors);
  checkUint64Field(event.observed_timestamp, '#/observed_timestamp', errors);
  if (event.monotonic_timestamp !== null) {
    checkUint64Field(event.monotonic_timestamp, '#/monotonic_timestamp', errors);
  }

  if (event.process_identity) {
    checkUint64Field(event.process_identity.process_start_time, '#/process_identity/process_start_time', errors);
    if (event.process_identity.process_namespace) {
      checkUint64Field(event.process_identity.process_namespace.pid_ns, '#/process_identity/process_namespace/pid_ns', errors);
      checkUint64Field(event.process_identity.process_namespace.mnt_ns, '#/process_identity/process_namespace/mnt_ns', errors);
      checkUint64Field(event.process_identity.process_namespace.net_ns, '#/process_identity/process_namespace/net_ns', errors);
    }
  }

  if (event.workload_context) {
    checkUint64Field(event.workload_context.cgroup_id, '#/workload_context/cgroup_id', errors);
    checkUint64Field(event.workload_context.mount_namespace, '#/workload_context/mount_namespace', errors);
    checkUint64Field(event.workload_context.pid_namespace, '#/workload_context/pid_namespace', errors);
    checkUint64Field(event.workload_context.network_namespace, '#/workload_context/network_namespace', errors);
  }

  if (event.provenance) {
    checkUint64Field(event.provenance.ingest_timestamp, '#/provenance/ingest_timestamp', errors);
  }

  if (event.payload) {
    if (event.payload.heartbeat_timestamp) {
      checkUint64Field(event.payload.heartbeat_timestamp, '#/payload/heartbeat_timestamp', errors);
    }
    if (event.payload.offset !== null && event.payload.offset !== undefined) {
      checkUint64Field(event.payload.offset, '#/payload/offset', errors);
    }
  }

  // 2. Control de procedencia y advertencias estructuradas (P-04)
  if (event.source_provider === SourceProvider.SYNTHETIC_LAB) {
    if (!allowSynthetic) {
      errors.push({
        path: '#/source_provider',
        message: 'Synthetic lab events are forbidden in production mode',
        keyword: 'sourceProvider',
        params: { provider: event.source_provider }
      });
    } else {
      warnings.push('Event source is SYNTHETIC_LAB. Causal engine must not use this for kernel-level claims.');
    }
  } else if (event.source_provider === SourceProvider.UNKNOWN_SOURCE) {
    warnings.push('Event source is UNKNOWN_SOURCE. Telemetry is uncalibrated and untrusted.');
  } else if (event.source_provider === SourceProvider.OTHER_PROVIDER) {
    warnings.push('Event source is OTHER_PROVIDER. Uncalibrated provider telemetry.');
  }

  // Verificación de autenticidad de transporte (P-04)
  if (event.provenance) {
    if (event.provenance.transport_authenticated === false) {
      warnings.push('Transport is unauthenticated (transport_authenticated: false). Integrity cannot be cryptographically verified.');
    }
    if (event.source_provider === SourceProvider.TETRAGON &&
        event.provenance.transport_protocol === TransportProtocol.SYNTHETIC_MEMORY) {
      warnings.push('Tetragon telemetry claimed over SYNTHETIC_MEMORY transport. Source authenticity is unverified.');
    }
  }

  // 3. Auditoría de compatibilidad de versión
  if (event.schema_version && !event.schema_version.startsWith('1.')) {
    errors.push({
      path: '#/schema_version',
      message: `Unsupported schema major version: ${event.schema_version}. Only 1.x is supported.`,
      keyword: 'schema_version',
      params: { received: event.schema_version, supported: '1.x' }
    });
  }

  // 4. Advertencia de completitud degradada
  if (event.completeness === 'DEGRADED' || event.completeness === 'INCOMPLETE') {
    warnings.push(`Event completeness is ${event.completeness}. Confidence level must be capped.`);
  }

  // 5. Advertencia ante pérdida de telemetría reportada
  if (event.loss_metrics) {
    const totalDrops =
      (event.loss_metrics.loss_ebpf_kernel || 0) +
      (event.loss_metrics.loss_tetragon_throttle || 0) +
      (event.loss_metrics.loss_grpc_transport || 0) +
      (event.loss_metrics.loss_log_rotation || 0) +
      (event.loss_metrics.loss_parser_reject || 0) +
      (event.loss_metrics.loss_runtime_queue || 0) +
      (event.loss_metrics.loss_storage_drop || 0);

    if (totalDrops > 0) {
      warnings.push(`Event reports telemetry loss: total_drops=${totalDrops}. Workload state must be degraded.`);
    }
  }

  // 6. Garantía de que la entrada no fue mutada
  const currentKeys = Object.keys(event);
  if (currentKeys.length !== initialKeys.length) {
    throw new Error('FATAL: Validator violated non-mutation invariant. Keys were altered!');
  }

  const valid = errors.length === 0;

  return {
    valid,
    schema_version: event.schema_version || SCHEMA_VERSION_V1,
    event_family: event.event_type || null,
    errors,
    warnings
  };
}

module.exports = {
  validateEvent,
  schema: schemaContent
};
