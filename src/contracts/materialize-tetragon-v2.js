'use strict';

const crypto = require('node:crypto');
const { validateEventV2 } = require('./validate-event-v2');

const COLLECTOR_ID = 'sentinel-runtime-tetragon-v2';
const LOSS_DOMAINS = Object.freeze([
  'ebpf_kernel', 'sensor_throttle', 'grpc_transport', 'log_rotation', 'parser_reject', 'runtime_queue', 'storage_drop',
  'tetragon_bpf_missed_events', 'tetragon_listener_overflow', 'tetragon_field_filter_drops',
  'tetragon_observer_queue_drops', 'tetragon_aggregation_buffer_drops'
]);
const VALID_TRANSPORTS = new Set(['JSON_FILE_STREAM', 'GRPC_UNIX_SOCKET', 'GRPC_TCP']);
const VALID_AUTH = new Set(['MUTUAL_TLS', 'LOCAL_SOCKET_PEERCRED', 'NOT_APPLICABLE_LOCAL_FILE', 'NONE_UNAUTHENTICATED', 'TLS_SERVER_AUTH']);
const MAX_UINT32 = 0xffffffff;

class EventMaterializationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'EventMaterializationError';
    this.code = code;
  }
}

function materializeTetragonEventV2(normalized, context = {}) {
  if (!normalized || normalized.supported !== true) throw new EventMaterializationError('UNSUPPORTED_INPUT', 'A supported normalized Tetragon event is required');
  const hostId = requiredString(context.hostId, 'hostId');
  const bootId = requiredString(context.bootId, 'bootId');
  const sourceTimestamp = uint64(normalized.timestamp, 'source timestamp');
  const observedAt = uint64(context.providerObservationTimestamp || nowNanoseconds(), 'provider observation timestamp');
  const ingestAt = uint64(context.ingestTimestamp || nowNanoseconds(), 'ingest timestamp');
  const sourceHash = sha256String(normalized.rawPayloadSha256, 'raw payload hash');
  const sourceEventKey = sha256String(normalized.sourceEventKey, 'source event key');
  const sourceCursor = buildSourceCursor(context.sourceCursor, sourceHash);
  const transport = context.transportProtocol;
  const authentication = context.transportAuthentication;
  if (!VALID_TRANSPORTS.has(transport)) throw new EventMaterializationError('TRANSPORT_UNSUPPORTED', 'Event Contract v2 requires a recognized source transport');
  if (!VALID_AUTH.has(authentication)) throw new EventMaterializationError('TRANSPORT_AUTH_UNSUPPORTED', 'Event Contract v2 requires a recognized transport authentication state');

  const processIdentity = toProcessIdentity(normalized.processIdentity);
  const workload = toWorkloadContext(normalized.processIdentity);
  const providerEventTimestamp = normalized.data?.providerEventTime === null || normalized.data?.providerEventTime === undefined
    ? null : uint64(normalized.data.providerEventTime, 'provider event timestamp');
  const sensorVersion = boundedString(context.sensorVersion || 'unknown', 'sensor version', 128);
  const sourceEventType = normalized.sourceFunction
    ? `${normalized.sourceType}:${normalized.sourceFunction}` : normalized.sourceType;
  if (sourceEventType.length > 128) throw new EventMaterializationError('SOURCE_TYPE_TOO_LONG', 'Normalized provider source type exceeds Event Contract v2 limit');

  const payload = toPayload(normalized.eventType, normalized.data || {}, {
    captureProcessArguments: context.captureProcessArguments === true,
    processFlags: processIdentity.debugFlags,
    environmentVariablesPresent: normalized.processIdentity?.environmentVariablesPresent === true
  });
  const lossMetrics = createUnknownLossMetrics(observedAt, context.aggregationDisabled === true);
  const nodeName = optionalBoundedString(context.nodeName, 255);
  const nodeNameStatus = nodeName
    ? (context.nodeNameStatus === 'STATIC_CONFIGURED' ? 'STATIC_CONFIGURED' : 'OBSERVED_IN_SENSOR')
    : 'ABSENT_IN_SENSOR';
  const metadata = {
    collector_id: boundedString(context.collectorId || COLLECTOR_ID, 'collector ID', 128),
    collector_session_id: context.collectorSessionId || crypto.randomUUID(),
    sensor_version: sensorVersion,
    transport_protocol: transport,
    transport_authentication: authentication,
    debug_process_flags: processIdentity.debugFlags,
    debug_refcnt: processIdentity.debugRefcnt
  };

  const event = {
    schema_version: '2.0.0',
    event_id: crypto.randomUUID(),
    source_event_key: sourceEventKey,
    event_type: normalized.eventType,
    source_provider: 'tetragon',
    source_event_type: sourceEventType,
    source_event_id: sourceHash,
    host_identity: { host_id: hostId, boot_id: bootId, node_name: nodeName, node_name_status: nodeNameStatus },
    timestamps: {
      source_timestamp: sourceTimestamp,
      provider_observation_timestamp: observedAt,
      provider_event_timestamp: providerEventTimestamp,
      ingest_timestamp: ingestAt
    },
    sensor_metadata: metadata,
    process_identity: processIdentity.contract,
    workload_context: workload,
    source_cursor: sourceCursor,
    loss_metrics: lossMetrics,
    payload
  };
  const validation = validateEventV2(event);
  if (!validation.valid) {
    const detail = validation.errors.map(item => `${item.path}: ${item.message}`).join('; ');
    throw new EventMaterializationError('EVENT_CONTRACT_VIOLATION', detail);
  }
  return event;
}

function toPayload(eventType, data, options) {
  switch (eventType) {
    case 'PROCESS_EXEC': return processExecPayload(data, options);
    case 'PROCESS_EXIT': return processExitPayload(data);
    case 'FILE_OPEN_ATTEMPT': return {
      path: requiredLinuxPath(data.path, 'open path'), dfd: signedInt32(data.dfd),
      flags: null, mode: null, flags_capture_status: 'UNAVAILABLE_POINTER_NOT_DEREFERENCED'
    };
    case 'FILE_OPEN_RESULT': {
      const returnCode = safeInteger(data.return_code, 'open return code');
      if (returnCode >= 0 && returnCode > MAX_UINT32) throw new EventMaterializationError('FD_OUT_OF_RANGE', 'Kernel file descriptor exceeds uint32');
      return {
        path: requiredLinuxPath(data.path, 'open result path'), return_code: returnCode,
        fd: returnCode >= 0 ? returnCode : null, errno: returnCode < 0 ? -returnCode : null
      };
    }
    case 'FILE_READ': {
      const returnCode = safeInteger(data.return_code, 'read return code');
      return {
        fd: null, path: requiredLinuxPath(data.path, 'read path'),
        bytes_read: returnCode >= 0 ? uint64(data.bytes_read, 'bytes read') : '0',
        bytes_requested: uint64(data.bytes_requested, 'bytes requested'),
        return_code: returnCode, offset: null
      };
    }
    case 'NETWORK_CONNECT_ATTEMPT':
      return networkEndpoint(data);
    case 'NETWORK_CONNECT_RESULT': {
      const returnCode = safeInteger(data.return_code, 'connect return code');
      return {
        ...networkEndpoint(data), return_code: returnCode,
        errno: returnCode < 0 ? -returnCode : null,
        socket_state: optionalBoundedString(data.socket_state, 64)
      };
    }
    case 'NETWORK_SEND_ATTEMPT':
      return {
        socket_fd: null, source_ip: optionalIp(data.source_ip), source_port: optionalPort(data.source_port),
        destination_ip: requiredString(data.destination_ip, 'send destination IP'),
        destination_port: requiredPort(data.destination_port), family: familyFromIp(data.destination_ip),
        protocol: requiredString(data.protocol, 'send protocol'), socket_state: optionalBoundedString(data.socket_state, 64),
        bytes_requested: uint64(data.bytes_requested, 'bytes requested')
      };
    case 'NETWORK_SEND_RESULT': {
      const returnCode = safeInteger(data.return_code, 'send return code');
      const accepted = returnCode > 0 ? String(returnCode) : '0';
      if (String(data.bytes_accepted_by_kernel) !== accepted) throw new EventMaterializationError('SEND_RETURN_MISMATCH', 'Accepted byte count does not match raw tcp_sendmsg return');
      return {
        socket_fd: null, source_ip: optionalIp(data.source_ip), source_port: optionalPort(data.source_port),
        destination_ip: requiredString(data.destination_ip, 'send destination IP'),
        destination_port: requiredPort(data.destination_port), family: familyFromIp(data.destination_ip),
        protocol: requiredString(data.protocol, 'send protocol'), socket_state: optionalBoundedString(data.socket_state, 64),
        bytes_requested: uint64(data.bytes_requested, 'bytes requested'),
        bytes_accepted_by_kernel: accepted, return_code: returnCode,
        evidence_semantics: data.evidence_semantics === 'LOCAL_STACK_ACCEPTED_BYTES' && returnCode > 0
          ? 'LOCAL_STACK_ACCEPTED_BYTES' : 'LOCAL_SEND_RETURN'
      };
    }
    case 'CAPABILITY_CHECK': {
      const capability = safeInteger(data.capability_value, 'capability value');
      const returnCode = safeInteger(data.return_code, 'capability check return code');
      if (capability < 0 || capability > 63) throw new EventMaterializationError('CAPABILITY_OUT_OF_RANGE', 'Capability value must be between 0 and 63');
      if (returnCode > 0) throw new EventMaterializationError('CAPABILITY_RETURN_INVALID', 'cap_capable return must be zero or negative');
      const auditResult = returnCode === 0 ? 'GRANTED' : 'DENIED';
      if (data.audit_result !== auditResult) throw new EventMaterializationError('CAPABILITY_RESULT_MISMATCH', 'Audit result does not match the raw kernel return');
      return {
        capability_value: capability,
        capability_name: optionalBoundedString(data.capability_name, 64),
        audit_result: auditResult,
        return_code: returnCode
      };
    }
    default:
      throw new EventMaterializationError('EVENT_FAMILY_UNSUPPORTED', `No Event Contract v2 payload mapping exists for ${String(eventType)}`);
  }
}

function processExecPayload(data, options) {
  const raw = typeof data.argumentsRaw === 'string' ? data.argumentsRaw : null;
  const flags = options.processFlags || [];
  let status;
  let stored = raw;
  if (flags.includes('errorArgs')) { status = 'CAPTURE_ERROR'; stored = null; }
  else if (flags.includes('miss')) { status = 'UNAVAILABLE_PARENT_MISS'; stored = null; }
  else if (flags.includes('truncArgs')) { status = 'TRUNCATED'; stored = options.captureProcessArguments ? raw : null; }
  else if (raw === null) { status = 'EMPTY_STRING_OR_NO_ARGS'; stored = ''; }
  else if (!options.captureProcessArguments) { status = 'REDACTED_BY_POLICY'; stored = null; }
  else if (raw.length === 0) status = 'EMPTY_STRING_OR_NO_ARGS';
  else status = 'RAW_STRING_ONLY';
  if (stored !== null && Array.from(stored).length > 131072) {
    stored = Array.from(stored).slice(0, 131072).join('');
    status = 'TRUNCATED';
  }
  return {
    arguments_raw: stored,
    argv: null,
    arguments_capture_status: status,
    environment_variables: null,
    env_capture_status: options.environmentVariablesPresent ? 'REDACTED_BY_POLICY' : 'UNAVAILABLE'
  };
}

function processExitPayload(data) {
  const signal = typeof data.signal === 'string' && data.signal.length > 0 ? data.signal : null;
  const status = data.exitStatus;
  if (signal && status !== null && status !== undefined && status > 0) {
    return { termination: { kind: 'AMBIGUOUS', exit_status: safeInteger(status, 'exit status'), signal_name: boundedString(signal, 'signal name', 32), status_origin: 'CONTRADICTORY_DATA' } };
  }
  if (signal) return { termination: { kind: 'SIGNALED', exit_status: null, signal_name: boundedString(signal, 'signal name', 32), status_origin: 'NOT_APPLICABLE_SIGNALED' } };
  if (status === null || status === undefined || status === 0) {
    return { termination: { kind: 'EXITED', exit_status: 0, signal_name: null, status_origin: 'PROTO3_SCALAR_ZERO_INFERRED' } };
  }
  const exitStatus = safeInteger(status, 'exit status');
  if (exitStatus < 0 || exitStatus > MAX_UINT32) throw new EventMaterializationError('EXIT_STATUS_OUT_OF_RANGE', 'Process exit status is outside uint32 range');
  return { termination: { kind: 'EXITED', exit_status: exitStatus, signal_name: null, status_origin: 'EXPLICIT_NONZERO' } };
}

function toProcessIdentity(source) {
  if (!source || typeof source !== 'object') throw new EventMaterializationError('PROCESS_IDENTITY_MISSING', 'Tetragon process identity is required');
  const execId = source.execId === null || source.execId === undefined ? null : boundedString(source.execId, 'exec_id', 512);
  const pid = uint32OrNull(source.pid);
  if (execId === null && pid === null) throw new EventMaterializationError('PROCESS_INSTANCE_IDENTITY_MISSING', 'A partial process identity requires an observed PID');
  const start = uint64(source.startTime, 'process start time');
  const executable = source.executablePath === null || source.executablePath === undefined
    ? null : requiredLinuxPath(source.executablePath, 'executable path');
  const processUid = uint32OrNull(source.processUidRaw);
  const credentialsEuid = uint32OrNull(source.credentialsEuidRaw);
  const ruid = uint32OrNull(source.ruid);
  const collision = processUid !== null && credentialsEuid !== null && processUid !== credentialsEuid;
  const euid = collision ? null : (credentialsEuid ?? processUid);
  const euidStatus = collision ? 'EUID_COLLISION_FLAGGED'
    : credentialsEuid !== null ? 'OBSERVED_EXTENDED_CRED'
      : processUid !== null ? 'OBSERVED_PROCESS_UID' : 'UNAVAILABLE_ABSENT_IN_SENSOR';
  const ruidStatus = ruid !== null ? 'OBSERVED_EXTENDED_CRED'
    : source.credentialsPresent ? 'UNAVAILABLE_ABSENT_IN_SENSOR' : 'UNAVAILABLE_BASE_SENSOR';
  const captureStatus = collision ? 'COLLISION_UNRESOLVED'
    : euid !== null && ruid !== null ? 'REAL_AND_EFFECTIVE'
      : euid !== null ? 'EFFECTIVE_ONLY' : 'ABSENT_IN_SENSOR';
  const flags = typeof source.flags === 'string' ? source.flags : null;
  if (flags !== null && flags.length > 1024) throw new EventMaterializationError('PROCESS_FLAGS_TOO_LONG', 'Tetragon process flags exceed the Event Contract v2 limit');
  const debugFlags = flags === null ? null : flags.trim().split(/\s+/).filter(Boolean);
  if (debugFlags && (debugFlags.length > 64 || debugFlags.some(flag => flag.length > 64))) {
    throw new EventMaterializationError('PROCESS_FLAGS_INVALID', 'Tetragon process flags exceed the Event Contract v2 item limits');
  }
  const cwd = typeof source.workingDir === 'string' && isLinuxPath(source.workingDir) ? source.workingDir : null;
  let cwdStatus = cwd ? 'CAPTURED' : 'UNAVAILABLE';
  let workingDir = cwd;
  if (!cwd && debugFlags?.includes('rootCWD')) { workingDir = '/'; cwdStatus = 'ROOT_CWD_INFERRED'; }
  else if (!cwd && debugFlags?.includes('noCWDSupport')) cwdStatus = 'REMOVED_BUFFER_FULL';
  else if (!cwd && debugFlags?.includes('errorCWD')) cwdStatus = 'RESOLUTION_ERROR';
  const quality = execId === null ? 'PARTIAL_RECONSTRUCTED'
    : debugFlags?.includes('procFS') ? 'INITIAL_PROCFS_LOAD'
    : debugFlags?.some(flag => ['miss', 'unknown', 'taskWalk'].includes(flag)) ? 'PARTIAL_RECONSTRUCTED'
      : debugFlags?.includes('execve') ? 'PROBED_KERNEL' : 'UNVERIFIED';
  const contract = {
    exec_id: execId,
    exec_id_capture_status: execId === null ? 'UNAVAILABLE_IN_SENSOR' : 'CAPTURED',
    parent_exec_id: optionalBoundedString(source.parentExecId, 512),
    pid,
    tid: uint32OrNull(source.tid),
    process_start_time: start,
    executable_path: executable,
    executable_path_capture_status: executable === null ? 'UNAVAILABLE_IN_SENSOR' : 'CAPTURED',
    executable_digest: null,
    euid,
    ruid,
    euid_capture_status: euidStatus,
    ruid_capture_status: ruidStatus,
    credentials_capture_status: captureStatus,
    working_dir: workingDir,
    working_dir_capture_status: cwdStatus,
    flags,
    flags_capture_status: flags === null ? 'UNAVAILABLE' : (flags.length === 0 ? 'NO_FLAGS_SET' : 'CAPTURED'),
    identity_quality: quality
  };
  if (collision) {
    contract.process_uid_raw = processUid;
    contract.credentials_euid_raw = credentialsEuid;
  }
  return {
    contract,
    debugFlags,
    debugRefcnt: uint32OrNull(source.refcnt),
    workload: source
  };
}

function toWorkloadContext(identity) {
  const pod = identity?.pod && typeof identity.pod === 'object' ? identity.pod : null;
  const podName = optionalBoundedString(pod?.name, 256);
  const namespaceName = optionalBoundedString(pod?.namespace, 256);
  const fullContainerId = optionalBoundedString(pod?.container?.id, 128);
  const shortContainerId = typeof identity?.docker === 'string' && identity.docker.length > 0
    ? boundedString(identity.docker, 'container ID prefix', 128) : null;
  const containerId = fullContainerId || shortContainerId;
  const containerStatus = fullContainerId ? 'FULL' : shortContainerId ? 'TRUNCATED' : 'UNAVAILABLE';
  const contextType = podName || namespaceName ? 'KUBERNETES_POD' : containerId ? 'CONTAINER' : 'UNKNOWN';
  const namespaces = identity?.namespaces && typeof identity.namespaces === 'object' ? identity.namespaces : null;
  const nsValue = key => {
    const value = namespaces?.[key]?.inum;
    return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32 ? value : null;
  };
  return {
    context_type: contextType,
    container_id: containerId,
    container_id_capture_status: containerStatus,
    pod_name: podName,
    namespace_name: namespaceName,
    cgroup_path: null,
    namespaces_capture_status: namespaces ? 'CAPTURED' : 'UNAVAILABLE_IN_BASE_SENSOR',
    pid_ns: nsValue('pid'),
    mnt_ns: nsValue('mnt'),
    net_ns: nsValue('net')
  };
}

function networkEndpoint(data) {
  const destinationIp = requiredString(data.destination_ip, 'network destination IP');
  const family = familyFromIp(destinationIp);
  return {
    family,
    source_ip: optionalIp(data.source_ip),
    source_port: optionalPort(data.source_port),
    destination_ip: destinationIp,
    destination_port: requiredPort(data.destination_port),
    protocol: requiredString(data.protocol, 'network protocol'),
    socket_fd: null
  };
}

function createUnknownLossMetrics(observedAt, aggregationDisabled) {
  return Object.fromEntries(LOSS_DOMAINS.map(domain => [domain,
    domain === 'tetragon_aggregation_buffer_drops' && aggregationDisabled
      ? { state: 'NOT_APPLICABLE', count: null, source: 'GETEVENTS_AGGREGATION_OPTIONS_NOT_REQUESTED', observed_at: observedAt, scope: null, window_seconds: null }
      : { state: 'UNKNOWN', count: null, source: null, observed_at: observedAt, scope: null, window_seconds: null }
  ]));
}

function buildSourceCursor(cursor, expectedHash) {
  if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)) throw new EventMaterializationError('SOURCE_CURSOR_MISSING', 'Provider source cursor is required');
  if (sha256String(cursor.raw_payload_sha256, 'cursor payload hash') !== expectedHash) {
    throw new EventMaterializationError('SOURCE_CURSOR_HASH_MISMATCH', 'Source cursor hash must match the exact provider payload bytes');
  }
  return { ...cursor };
}

function familyFromIp(value) {
  const net = require('node:net');
  const family = net.isIP(value);
  if (family === 4) return 'AF_INET';
  if (family === 6) return 'AF_INET6';
  throw new EventMaterializationError('IP_INVALID', 'Network endpoint IP must be a valid IPv4 or IPv6 address');
}

function optionalIp(value) {
  if (value === null || value === undefined) return null;
  familyFromIp(value);
  return value;
}

function optionalPort(value) {
  if (value === null || value === undefined) return null;
  return requiredPort(value);
}

function requiredPort(value) {
  if (!Number.isInteger(value) || value < 0 || value > 65535) throw new EventMaterializationError('PORT_INVALID', 'Network port must be between 0 and 65535');
  return value;
}

function signedInt32(value) {
  if (value === null || value === undefined) return null;
  if (!Number.isInteger(value) || value < -2147483648 || value > 2147483647) throw new EventMaterializationError('INTEGER_OUT_OF_RANGE', 'Directory file descriptor is outside int32 range');
  return value;
}

function uint32OrNull(value) {
  return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32 ? value : null;
}

function safeInteger(value, label) {
  if (!Number.isSafeInteger(value)) throw new EventMaterializationError('INTEGER_UNSAFE', `${label} must be an exact safe integer`);
  return value;
}

function uint64(value, label) {
  let parsed;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) parsed = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value)) parsed = BigInt(value);
  else throw new EventMaterializationError('UINT64_INVALID', `${label} must be a canonical non-negative integer`);
  if (parsed > 18446744073709551615n) throw new EventMaterializationError('UINT64_OUT_OF_RANGE', `${label} exceeds uint64`);
  return parsed.toString();
}

function sha256String(value, label) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/i.test(value)) throw new EventMaterializationError('HASH_INVALID', `${label} must be a SHA-256 hex digest`);
  return value.toLowerCase();
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new EventMaterializationError('FIELD_UNAVAILABLE', `${label} is missing`);
  return value;
}

function boundedString(value, label, maximum) {
  const string = requiredString(value, label);
  if (string.length > maximum) throw new EventMaterializationError('FIELD_TOO_LONG', `${label} exceeds ${maximum} characters`);
  return string;
}

function optionalBoundedString(value, maximum) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (value.length > maximum) throw new EventMaterializationError('FIELD_TOO_LONG', `Optional string exceeds ${maximum} characters`);
  return value;
}

function requiredLinuxPath(value, label) {
  const path = boundedString(value, label, 4096);
  if (!isLinuxPath(path)) throw new EventMaterializationError('PATH_INVALID', `${label} must be an absolute Linux path without NUL bytes`);
  return path;
}

function isLinuxPath(value) {
  return typeof value === 'string' && value.startsWith('/') && value.length > 0 && value.length <= 4096 && !value.includes('\0');
}

function nowNanoseconds() { return (BigInt(Date.now()) * 1000000n).toString(); }

module.exports = { materializeTetragonEventV2, EventMaterializationError, createUnknownLossMetrics };
