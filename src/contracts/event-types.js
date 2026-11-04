'use strict';

/**
 * SENTINEL RUNTIME — EVENT CONTRACT V1: TYPE DEFINITIONS (HARDENED)
 *
 * Definiciones normativas y enumeraciones inmutables según SPEC-EVENT-V1r2.
 * Implementa control de cota estricta uint64 y representación decimal canónica.
 */

const SCHEMA_VERSION_V1 = '1.0.0';

/**
 * Familias de eventos canónicas (14 familias documentadas)
 */
const EventFamily = Object.freeze({
  PROCESS_EXEC: 'PROCESS_EXEC',
  PROCESS_EXIT: 'PROCESS_EXIT',
  FILE_OPEN_ATTEMPT: 'FILE_OPEN_ATTEMPT',
  FILE_OPEN_RESULT: 'FILE_OPEN_RESULT',
  FILE_READ: 'FILE_READ',
  NETWORK_CONNECT_ATTEMPT: 'NETWORK_CONNECT_ATTEMPT',
  NETWORK_CONNECT_RESULT: 'NETWORK_CONNECT_RESULT',
  NETWORK_SEND_ATTEMPT: 'NETWORK_SEND_ATTEMPT',
  NETWORK_SEND_RESULT: 'NETWORK_SEND_RESULT',
  SOCKET_STATE_CHANGE: 'SOCKET_STATE_CHANGE',
  IDENTITY_CHANGE: 'IDENTITY_CHANGE',
  CAPABILITY_CHANGE: 'CAPABILITY_CHANGE',
  EVENT_LOSS: 'EVENT_LOSS',
  SENSOR_HEALTH: 'SENSOR_HEALTH'
});

/**
 * Proveedores de telemetría soportados
 */
const SourceProvider = Object.freeze({
  TETRAGON: 'tetragon',
  EBPF_CUSTOM: 'ebpf_custom',
  LINUX_AUDIT: 'linux_audit',
  SYNTHETIC_LAB: 'synthetic_lab',
  OTHER_PROVIDER: 'other_provider',
  UNKNOWN_SOURCE: 'unknown_source'
});

/**
 * Calidad de la identidad de proceso reportada
 */
const IdentityQuality = Object.freeze({
  VERIFIED_OPAQUE: 'VERIFIED_OPAQUE',
  DEGRADED_FALLBACK: 'DEGRADED_FALLBACK',
  PARTIAL_ORPHAN: 'PARTIAL_ORPHAN'
});

/**
 * Tipos de Workload
 */
const WorkloadType = Object.freeze({
  HOST_PROCESS: 'HOST_PROCESS',
  CONTAINER: 'CONTAINER',
  KUBERNETES_POD: 'KUBERNETES_POD'
});

/**
 * Protocolos de Transporte de telemetría
 */
const TransportProtocol = Object.freeze({
  UNIX_DOMAIN_SOCKET: 'UNIX_DOMAIN_SOCKET',
  GRPC_TLS: 'GRPC_TLS',
  JSON_FILE_STREAM: 'JSON_FILE_STREAM',
  SYNTHETIC_MEMORY: 'SYNTHETIC_MEMORY'
});

/**
 * Taxonomía de Veredictos de Red (5 niveles - AR-03)
 */
const NetworkVerdict = Object.freeze({
  OUTBOUND_ATTEMPT: 'OUTBOUND_ATTEMPT',
  OUTBOUND_ACTIVITY_OBSERVED: 'OUTBOUND_ACTIVITY_OBSERVED',
  OUTBOUND_TRANSFER_CORRELATED: 'OUTBOUND_TRANSFER_CORRELATED',
  SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED: 'SENSITIVE_ACCESS_AND_OUTBOUND_TRANSFER_CORRELATED',
  SENSITIVE_DATA_EXFILTRATION_CONFIRMED: 'SENSITIVE_DATA_EXFILTRATION_CONFIRMED'
});

/**
 * Fuentes de pérdida de eventos (7 subsistemas independientes)
 */
const LossSource = Object.freeze({
  EBPF_KERNEL: 'ebpf_kernel',
  TETRAGON_THROTTLE: 'tetragon_throttle',
  GRPC_TRANSPORT: 'grpc_transport',
  LOG_ROTATION: 'log_rotation',
  PARSER_REJECT: 'parser_reject',
  RUNTIME_QUEUE: 'runtime_queue',
  STORAGE_DROP: 'storage_drop'
});

/**
 * Estado de salud del sensor
 */
const SensorStatus = Object.freeze({
  HEALTHY: 'HEALTHY',
  DEGRADED: 'DEGRADED',
  RECOVERING: 'RECOVERING',
  UNAVAILABLE: 'UNAVAILABLE'
});

/**
 * Límite superior para enteros seguros en JS (IEEE 754 float64).
 * 2^53 - 1 = 9007199254740991
 */
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

/**
 * Límite superior absoluto para enteros sin signo de 64 bits.
 * 2^64 - 1 = 18446744073709551615
 */
const MAX_UINT64 = 18446744073709551615n;

/**
 * Patrón canónico para cadenas decimales de uint64:
 * Sin ceros iniciales (excepto "0") y con longitud máxima de 20 dígitos.
 */
const CANONICAL_UINT64_REGEX = /^(0|[1-9][0-9]{0,19})$/;

/**
 * Normaliza y valida de forma segura un identificador o timestamp de 64 bits
 * a su representación canónica en string decimal sin pérdida de precisión.
 *
 * Dominio estricto: 0 <= n <= 18446744073709551615 (2^64 - 1).
 *
 * @param {string|number|bigint} val
 * @returns {string} representación decimal canónica única
 * @throws {TypeError} Si el formato o tipo no es representable en uint64
 * @throws {RangeError} Si el valor desborda 2^64 - 1 o si un Number supera MAX_SAFE_INTEGER
 */
function toSafeUint64String(val) {
  if (typeof val === 'bigint') {
    if (val < 0n) {
      throw new TypeError(`uint64 value cannot be negative: ${val}`);
    }
    if (val > MAX_UINT64) {
      throw new RangeError(`uint64 value ${val} exceeds 2^64 - 1 (${MAX_UINT64})`);
    }
    return val.toString();
  }

  if (typeof val === 'string') {
    if (!CANONICAL_UINT64_REGEX.test(val)) {
      throw new TypeError(`Invalid uint64 decimal string (must be canonical decimal without leading zeros): ${val}`);
    }
    const b = BigInt(val);
    if (b > MAX_UINT64) {
      throw new RangeError(`uint64 decimal string ${val} exceeds 2^64 - 1 (${MAX_UINT64})`);
    }
    return val;
  }

  if (typeof val === 'number') {
    if (!Number.isInteger(val) || val < 0) {
      throw new TypeError(`Invalid uint64 number: ${val}`);
    }
    if (val > MAX_SAFE_INTEGER) {
      throw new RangeError(`Number ${val} exceeds MAX_SAFE_INTEGER (2^53 - 1). Pass as canonical decimal string or BigInt to prevent precision loss.`);
    }
    return val.toString();
  }

  throw new TypeError(`Unsupported uint64 type: ${typeof val}`);
}

module.exports = {
  SCHEMA_VERSION_V1,
  EventFamily,
  SourceProvider,
  IdentityQuality,
  WorkloadType,
  TransportProtocol,
  NetworkVerdict,
  LossSource,
  SensorStatus,
  MAX_SAFE_INTEGER,
  MAX_UINT64,
  CANONICAL_UINT64_REGEX,
  toSafeUint64String
};
