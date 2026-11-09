'use strict';

const crypto = require('node:crypto');
const net = require('node:net');
const { EventType } = require('../types');
const { rawProviderEventKey, rawPartialProcessEventKey } = require('../contracts/event-keys');

function normalizeTetragonJson(record, rawPayload, context = {}) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new TypeError('Tetragon record must be a JSON object');
  if (typeof context.hostId !== 'string' || !context.hostId) throw new TypeError('hostId must be supplied from trusted collector configuration');
  if (typeof context.bootId !== 'string' || !context.bootId) throw new TypeError('bootId must be supplied from trusted host identity configuration');
  const nativeKinds = ['process_exec', 'process_exit', 'process_kprobe'];
  const present = nativeKinds.filter(kind => Object.hasOwn(record, kind));
  if (present.length !== 1) return unsupported(record, rawPayload, present.length ? 'AMBIGUOUS_NATIVE_EVENT' : 'UNSUPPORTED_NATIVE_EVENT');

  const sourceType = present[0];
  const body = record[sourceType];
  const process = body?.process;
  if (!process || typeof process !== 'object') return unsupported(record, rawPayload, 'PROCESS_IDENTITY_MISSING');

  const rawHash = sha256(rawPayload);
  const timestamp = timestampNs(record.time);
  const processStart = timestampNs(process.start_time);
  if (timestamp === null) return unsupported(record, rawPayload, 'NATIVE_TIMESTAMP_MISSING');
  if (processStart === null) return unsupported(record, rawPayload, 'PROCESS_START_TIME_MISSING');
  if (!hasProviderProcessIdentity(process)) return unsupported(record, rawPayload, 'PROCESS_INSTANCE_IDENTITY_UNAVAILABLE');
  if (sourceType === 'process_kprobe') {
    return normalizeKprobe(record, body, process, rawPayload, rawHash, timestamp, processStart, context);
  }
  const eventType = sourceType === 'process_exec' ? EventType.PROCESS_EXEC : EventType.PROCESS_EXIT;
  const sourceEventKey = providerProcessEventKey({
    context, process, processStart, eventType, sourceTimestamp: timestamp, rawPayloadSha256: rawHash
  });

  return {
    supported: true,
    provider: 'tetragon',
    sourceType,
    sourceEventKey,
    eventId: rawHash,
    rawPayloadSha256: rawHash,
    timestamp,
    workloadId: context.workloadId || 'unassigned',
    hostIdentity: { hostId: context.hostId, bootId: context.bootId },
    processIdentity: processIdentity(process, processStart),
    eventType,
    data: sourceType === 'process_exec'
      ? { binary: typeof process.binary === 'string' ? process.binary : '', argumentsRaw: typeof process.arguments === 'string' ? process.arguments : null }
      : { exitStatus: body.status ?? null, signal: body.signal || null, providerEventTime: timestampNs(body.time) },
    provenance: {
      rawPayloadSha256: rawHash,
      providerObservationTime: timestamp,
      processStartTime: processStart,
      rawArgumentsPreserved: sourceType === 'process_exec'
    }
  };
}

function normalizeKprobe(record, body, process, rawPayload, rawHash, timestamp, processStart, context) {
  const functionName = body.function_name;
  const args = Array.isArray(body.args) ? body.args : [];
  const labeled = label => {
    const matches = args.filter(argument => argument && typeof argument === 'object' && argument.label === label);
    return matches.length === 1 ? matches[0] : null;
  };
  const unlabeledArgument = field => {
    const matches = args.filter(argument => argument && typeof argument === 'object' && Object.hasOwn(argument, field) && (argument.label === undefined || argument.label === null || argument.label === ''));
    return matches.length === 1 ? matches[0] : null;
  };
  const hasReturn = body.return !== undefined && body.return !== null;
  if (typeof functionName !== 'string' || functionName.length === 0) return unsupported(record, rawPayload, 'KPROBE_FUNCTION_NAME_MISSING');
  if (timestamp === null) return unsupported(record, rawPayload, 'KPROBE_TIMESTAMP_MISSING');

  let eventType;
  let data;
  if (functionName === 'do_sys_openat2') {
    const dfdArgument = labeled('sentinel_dfd');
    const filenameArgument = labeled('sentinel_filename');
    const filename = stringArgument(filenameArgument);
    if (filename !== null && !validPathValue(filename)) return unsupported(record, rawPayload, 'KPROBE_PATH_INVALID');
    if (hasReturn) {
      if (filename === null) return unsupported(record, rawPayload, 'KPROBE_FILENAME_UNAVAILABLE');
      const returnCode = signedArgument(body.return, ['long_arg', 'int_arg']);
      if (returnCode === null) return unsupported(record, rawPayload, 'KPROBE_RETURN_UNAVAILABLE');
      eventType = EventType.FILE_OPEN_RESULT;
      data = {
        path: filename,
        return_code: returnCode,
        fd: returnCode >= 0 ? returnCode : null,
        errno: returnCode < 0 ? -returnCode : null
      };
    } else {
      if (filename === null) return unsupported(record, rawPayload, 'KPROBE_FILENAME_UNAVAILABLE');
      const dfd = signedArgument(dfdArgument, ['int_arg']);
      if (dfd === null) return unsupported(record, rawPayload, 'KPROBE_DFD_UNAVAILABLE');
      eventType = EventType.FILE_OPEN_ATTEMPT;
      data = {
        path: filename,
        dfd,
        flags: null,
        mode: null,
        flags_capture_status: 'UNAVAILABLE_POINTER_NOT_DEREFERENCED'
      };
    }
  } else if (functionName === 'vfs_read') {
    const path = filePathArgument(labeled('sentinel_file'));
    const requested = unsignedArgument(labeled('sentinel_count'), ['size_arg', 'uint_arg']);
    if (path === null || !validPathValue(path)) return unsupported(record, rawPayload, 'KPROBE_FILE_PATH_UNAVAILABLE');
    if (requested === null) return unsupported(record, rawPayload, 'KPROBE_READ_SIZE_UNAVAILABLE');
    eventType = EventType.FILE_READ;
    if (!hasReturn) return unsupported(record, rawPayload, 'KPROBE_READ_RETURN_UNAVAILABLE');
    const returnCode = signedArgument(body.return, ['long_arg', 'int_arg']);
    if (returnCode === null) return unsupported(record, rawPayload, 'KPROBE_RETURN_UNAVAILABLE');
    data = {
      path,
      bytes_requested: requested,
      bytes_read: returnCode >= 0 ? String(returnCode) : '0',
      return_code: returnCode,
      errno: returnCode !== null && returnCode < 0 ? -returnCode : null,
      read_status: 'RETURN_OBSERVED'
    };
  } else if (functionName === 'tcp_v4_connect' || functionName === 'tcp_v6_connect') {
    const endpoint = connectEndpoint(
      labeled('sentinel_socket') || unlabeledArgument('sock_arg'),
      labeled('sentinel_sockaddr') || unlabeledArgument('sockaddr_arg'),
      functionName
    );
    if (!endpoint) return unsupported(record, rawPayload, 'KPROBE_CONNECT_DESTINATION_UNAVAILABLE');
    if (hasReturn) {
      const returnCode = signedArgument(body.return, ['int_arg', 'long_arg']);
      if (returnCode === null) return unsupported(record, rawPayload, 'KPROBE_RETURN_UNAVAILABLE');
      eventType = EventType.NETWORK_CONNECT_RESULT;
      data = { ...endpoint, return_code: returnCode, errno: returnCode < 0 ? -returnCode : null };
    } else {
      eventType = EventType.NETWORK_CONNECT_ATTEMPT;
      data = endpoint;
    }
  } else if (functionName === 'tcp_sendmsg') {
    const endpoint = socketEndpoint(labeled('sentinel_socket'));
    const requested = unsignedArgument(labeled('sentinel_size'), ['size_arg', 'uint_arg']);
    if (!endpoint) return unsupported(record, rawPayload, 'KPROBE_SOCKET_DESTINATION_UNAVAILABLE');
    if (requested === null) return unsupported(record, rawPayload, 'KPROBE_SEND_SIZE_UNAVAILABLE');
    if (hasReturn) {
      const returnCode = signedArgument(body.return, ['long_arg', 'int_arg']);
      if (returnCode === null) return unsupported(record, rawPayload, 'KPROBE_RETURN_UNAVAILABLE');
      eventType = EventType.NETWORK_SEND_RESULT;
      data = {
        ...endpoint,
        bytes_requested: requested,
        return_code: returnCode,
        bytes_accepted_by_kernel: returnCode > 0 ? String(returnCode) : '0',
        evidence_semantics: returnCode > 0 ? 'LOCAL_STACK_ACCEPTED_BYTES' : 'LOCAL_SEND_RETURN'
      };
    } else {
      eventType = EventType.NETWORK_SEND_ATTEMPT;
      data = { ...endpoint, bytes_requested: requested };
    }
  } else if (functionName === 'cap_capable') {
    if (!hasReturn) return unsupported(record, rawPayload, 'KPROBE_CAPABILITY_RETURN_UNAVAILABLE');
    const argument = labeled('sentinel_capability');
    const capabilityObject = argumentValue(argument, ['capability_arg']);
    const rawCapability = capabilityObject
      ? wrapperValue(capabilityObject.value)
      : argumentValue(argument, ['int_arg']);
    const capabilityValue = parseCapabilityValue(rawCapability);
    if (capabilityValue === null) return unsupported(record, rawPayload, 'KPROBE_CAPABILITY_VALUE_UNAVAILABLE');
    const returnCode = signedArgument(body.return, ['int_arg', 'long_arg']);
    if (returnCode === null || returnCode > 0) return unsupported(record, rawPayload, 'KPROBE_CAPABILITY_RETURN_INVALID');
    const capabilityName = capabilityObject && typeof capabilityObject.name === 'string' && capabilityObject.name.length <= 64
      ? capabilityObject.name : null;
    eventType = EventType.CAPABILITY_CHECK;
    data = {
      capability_value: capabilityValue,
      capability_name: capabilityName,
      return_code: returnCode,
      audit_result: returnCode === 0 ? 'GRANTED' : 'DENIED'
    };
  } else {
    return unsupported(record, rawPayload, 'UNSUPPORTED_KPROBE_FUNCTION');
  }

  const sourceEventKey = providerProcessEventKey({
    context, process, processStart, eventType, sourceTimestamp: timestamp, rawPayloadSha256: rawHash
  });
  return {
    supported: true,
    provider: 'tetragon',
    sourceType: 'process_kprobe',
    sourceFunction: functionName,
    policyName: typeof body.policy_name === 'string' ? body.policy_name : null,
    sourceEventKey,
    eventId: rawHash,
    rawPayloadSha256: rawHash,
    timestamp,
    workloadId: context.workloadId || 'unassigned',
    hostIdentity: { hostId: context.hostId, bootId: context.bootId },
    processIdentity: processIdentity(process, processStart),
    eventType,
    data,
    provenance: { rawPayloadSha256: rawHash, providerObservationTime: timestamp, processStartTime: processStart, rawArgumentsPreserved: false }
  };
}

function processIdentity(process, processStart) {
  const credentials = process.process_credentials && typeof process.process_credentials === 'object'
    ? process.process_credentials : null;
  return {
    execId: typeof process.exec_id === 'string' && process.exec_id.length > 0 ? process.exec_id : null,
    parentExecId: typeof process.parent_exec_id === 'string' && process.parent_exec_id.length ? process.parent_exec_id : null,
    pid: wrapperValue(process.pid),
    tid: wrapperValue(process.tid),
    startTime: processStart,
    executablePath: typeof process.binary === 'string' ? process.binary : null,
    processUidRaw: wrapperValue(process.uid),
    credentialsEuidRaw: wrapperValue(credentials?.euid),
    ruid: wrapperValue(credentials?.uid),
    credentialsPresent: credentials !== null,
    environmentVariablesPresent: Array.isArray(process.environment_variables) && process.environment_variables.length > 0,
    workingDir: typeof process.cwd === 'string' ? process.cwd : null,
    flags: typeof process.flags === 'string' ? process.flags : null,
    refcnt: process.refcnt ?? null,
    docker: typeof process.docker === 'string' ? process.docker : null,
    pod: process.pod && typeof process.pod === 'object' ? process.pod : null,
    namespaces: process.ns && typeof process.ns === 'object' ? process.ns : null
  };
}

function hasProviderProcessIdentity(process) {
  if (typeof process.exec_id === 'string' && process.exec_id.length > 0) return true;
  const pid = wrapperValue(process.pid);
  return Number.isSafeInteger(pid) && pid >= 0 && pid <= 0xffffffff;
}

function providerProcessEventKey({ context, process, processStart, eventType, sourceTimestamp, rawPayloadSha256 }) {
  if (typeof process.exec_id === 'string' && process.exec_id.length > 0) {
    return rawProviderEventKey({
      hostId: context.hostId, bootId: context.bootId, execId: process.exec_id,
      eventType, sourceTimestamp, rawPayloadSha256
    });
  }
  return rawPartialProcessEventKey({
    hostId: context.hostId, bootId: context.bootId, pid: wrapperValue(process.pid),
    processStartTime: processStart, eventType, sourceTimestamp, rawPayloadSha256
  });
}

function argumentValue(argument, fields) {
  if (!argument || typeof argument !== 'object' || Array.isArray(argument)) return null;
  for (const field of fields) {
    if (Object.hasOwn(argument, field)) return argument[field];
  }
  return null;
}

function stringArgument(argument) {
  const value = argumentValue(argument, ['string_arg']);
  return typeof value === 'string' ? value : null;
}

function filePathArgument(argument) {
  const file = argumentValue(argument, ['file_arg', 'path_arg']);
  return typeof file?.path === 'string' ? file.path : null;
}

function signedArgument(argument, fields) {
  const value = argumentValue(argument, fields);
  if (typeof value === 'number') return Number.isSafeInteger(value) ? value : null;
  if (typeof value !== 'string' || !/^-?(0|[1-9][0-9]*)$/.test(value)) return null;
  const parsed = BigInt(value);
  if (parsed < -9223372036854775808n || parsed > 9223372036854775807n) return null;
  const number = Number(parsed);
  return Number.isSafeInteger(number) ? number : null;
}

function unsignedArgument(argument, fields) {
  const value = argumentValue(argument, fields);
  let parsed;
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) parsed = BigInt(value);
  else if (typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value)) parsed = BigInt(value);
  else return null;
  if (parsed > 18446744073709551615n) return null;
  return parsed.toString();
}

function parseCapabilityValue(value) {
  const parsed = typeof value === 'number' ? value
    : typeof value === 'string' && /^(0|[1-9][0-9]{0,2})$/.test(value) ? Number(value) : null;
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 63 ? parsed : null;
}

function validPathValue(value) {
  return typeof value === 'string' && value.length > 0 && !value.includes('\0') && Buffer.byteLength(value, 'utf8') <= 4096;
}

function connectEndpoint(socketArgument, sockaddrArgument, functionName) {
  const socket = argumentValue(socketArgument, ['sock_arg']);
  const address = argumentValue(sockaddrArgument, ['sockaddr_arg']);
  const ip = typeof address?.addr === 'string' ? address.addr : null;
  const port = address?.port;
  const family = functionName === 'tcp_v6_connect' ? 6 : 4;
  if (!ip || net.isIP(ip) !== family || !Number.isInteger(port) || port < 0 || port > 65535) return null;
  return {
    source_ip: typeof socket?.saddr === 'string' && net.isIP(socket.saddr) ? socket.saddr : null,
    source_port: Number.isInteger(socket?.sport) && socket.sport >= 0 && socket.sport <= 65535 ? socket.sport : null,
    destination_ip: ip,
    destination_port: port,
    family: family === 6 ? 'AF_INET6' : 'AF_INET',
    protocol: 'TCP',
    socket_fd: null,
    socket_state: typeof socket?.state === 'string' ? socket.state : null
  };
}

function socketEndpoint(argument) {
  const socket = argumentValue(argument, ['sock_arg']);
  if (!socket || typeof socket.daddr !== 'string' || net.isIP(socket.daddr) === 0 ||
      !Number.isInteger(socket.dport) || socket.dport < 0 || socket.dport > 65535) return null;
  return {
    source_ip: typeof socket.saddr === 'string' && net.isIP(socket.saddr) ? socket.saddr : null,
    source_port: Number.isInteger(socket.sport) && socket.sport >= 0 && socket.sport <= 65535 ? socket.sport : null,
    destination_ip: socket.daddr,
    destination_port: socket.dport,
    family: net.isIP(socket.daddr) === 6 ? 'AF_INET6' : 'AF_INET',
    protocol: 'TCP',
    socket_fd: null,
    socket_state: typeof socket.state === 'string' ? socket.state : null
  };
}

function summarizeEventData(data) {
  const fields = [
    'binary', 'exitStatus', 'signal', 'path', 'dfd', 'flags', 'mode', 'flags_capture_status',
    'fd', 'return_code', 'errno', 'bytes_requested', 'bytes_read', 'read_status',
    'source_ip', 'source_port', 'destination_ip', 'destination_port', 'protocol',
    'socket_fd', 'socket_state', 'bytes_accepted_by_kernel', 'evidence_semantics',
    'capability_value', 'capability_name', 'audit_result'
  ];
  const summary = {};
  for (const field of fields) if (data && Object.hasOwn(data, field)) summary[field] = data[field];
  return summary;
}

function unsupported(record, rawPayload, reason) {
  return {
    supported: false,
    provider: 'tetragon',
    reason,
    sourceType: Object.keys(record).find(key => key.startsWith('process_')) || 'unknown',
    sourceFunction: typeof record.process_kprobe?.function_name === 'string' ? record.process_kprobe.function_name : null,
    rawPayloadSha256: sha256(rawPayload)
  };
}

function wrapperValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'object' && Object.hasOwn(value, 'value')) return value.value;
  return value;
}

function timestampNs(value) {
  if (!value) return null;
  if (typeof value === 'string') {
    const match = value.match(/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)$/);
    if (!match) return null;
    const [year, month, day, hour, minute, secondOfMinute] = match[1].match(/\d+/g).map(Number);
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || secondOfMinute > 59) return null;
    const calendar = new Date(0);
    calendar.setUTCFullYear(year, month - 1, day);
    calendar.setUTCHours(hour, minute, secondOfMinute, 0);
    if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) return null;
    const second = Date.parse(`${match[1]}${match[3]}`);
    if (!Number.isFinite(second)) return null;
    const fraction = BigInt((match[2] || '').padEnd(9, '0') || '0');
    return (BigInt(second) * 1000000n + fraction).toString();
  }
  if (typeof value === 'object' && value !== null) {
    let seconds;
    if (typeof value.seconds === 'number' && Number.isSafeInteger(value.seconds)) seconds = BigInt(value.seconds);
    else if (typeof value.seconds === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value.seconds)) seconds = BigInt(value.seconds);
    if (seconds === undefined) return null;
    const nanos = Number.isInteger(value.nanos) ? value.nanos : 0;
    if (nanos < 0 || nanos > 999999999) return null;
    return (seconds * 1000000000n + BigInt(nanos)).toString();
  }
  return null;
}

function sha256(rawPayload) {
  return crypto.createHash('sha256').update(Buffer.isBuffer(rawPayload) ? rawPayload : Buffer.from(String(rawPayload), 'utf8')).digest('hex');
}

module.exports = { normalizeTetragonJson, timestampNs, summarizeEventData };
