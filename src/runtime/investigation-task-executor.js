'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { Worker } = require('node:worker_threads');
const { canonicalJson } = require('../contracts/canonical-json');

const PLAYBOOKS = Object.freeze({
  'LINUX.PROCESS.IDENTITY': { timeout: 5000, output: 16 * 1024 },
  'LINUX.PROCESS.TREE': { timeout: 5000, output: 32 * 1024 },
  'LINUX.PROCESS.HISTORY': { timeout: 8000, output: 64 * 1024 },
  'LINUX.NETWORK.SOCKETS': { timeout: 5000, output: 32 * 1024 },
  'LINUX.NETWORK.CONNECTIONS': { timeout: 8000, output: 32 * 1024 },
  'LINUX.NETWORK.CONNECTION_HISTORY': { timeout: 8000, output: 64 * 1024 },
  'LINUX.CONTAINER.NAMESPACES': { timeout: 5000, output: 16 * 1024 },
  'LINUX.CONTAINER.MOUNTS': { timeout: 5000, output: 32 * 1024 },
  'LINUX.FILE.METADATA': { timeout: 3000, output: 8192 },
  'LINUX.FILE.ACCESS_HISTORY': { timeout: 8000, output: 32 * 1024 },
  'LINUX.SENSOR.HEALTH': { timeout: 5000, output: 16 * 1024 },
  'LINUX.EVIDENCE.VERIFY': { timeout: 15000, output: 16 * 1024 },
});

const FIELD_KEYS = new Set(['Name', 'State', 'Tgid', 'Pid', 'PPid', 'TracerPid', 'Uid', 'Gid', 'Threads', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'Seccomp_filters']);
const NS_TYPES = ['cgroup', 'ipc', 'mnt', 'net', 'pid', 'time', 'user', 'uts'];
const SOCKET_TABLES = ['tcp', 'tcp6', 'udp', 'udp6'];

class InvestigationTaskExecutor {
  constructor(options = {}) {
    if (!options.client || typeof options.client.pollInvestigationTasks !== 'function' || typeof options.client.sendInvestigationTaskResult !== 'function') {
      throw new TypeError('A Cloud client with durable Runtime task methods is required');
    }
    if (!options.ledger || typeof options.ledger.append !== 'function' || typeof options.ledger.getRecords !== 'function') {
      throw new TypeError('Evidence ledger is required for Runtime task execution');
    }
    this.client = options.client;
    this.ledger = options.ledger;
    this.hostId = options.hostId;
    this.bootId = options.bootId;
    this.intervalMs = options.intervalMs || 15000;
    this.onStatus = typeof options.onStatus === 'function' ? options.onStatus : () => {};
    this.enabled = options.enabled === true;
    if (!Number.isSafeInteger(this.intervalMs) || this.intervalMs < 5000 || this.intervalMs > 300000) throw new RangeError('Task polling interval must be between 5000 and 300000 ms');
  }

  capabilities() {
    return { investigation_tasks: this.enabled, playbooks: this.enabled ? Object.keys(PLAYBOOKS) : [] };
  }

  async run(signal) {
    if (!this.enabled) return;
    while (!signal.aborted) {
      try {
        const response = await this.client.pollInvestigationTasks({
          agentVersion: '0.2.0',
          capabilities: this.capabilities(),
        });
        if (!response.ok) this.onStatus({ type: 'task_poll_failed', error: response.error || 'TASK_POLL_FAILED', status: response.status || null });
        else {
          this.onStatus({ type: 'task_poll', state: response.data.state, task_count: response.data.tasks.length });
          for (const task of response.data.tasks) {
            if (signal.aborted) break;
            await this.executeAndSubmit(task, signal);
          }
        }
      } catch (error) {
        this.onStatus({ type: 'task_runner_error', error: safeMessage(error) });
      }
      await delay(this.intervalMs, signal);
    }
  }

  async executeAndSubmit(task, signal) {
    const startedAt = new Date().toISOString();
    const started = process.hrtime.bigint();
    let status = 'COMPLETED';
    let output;
    let errorCode = null;
    let errorReason = null;
    const taskId = typeof task?.task_id === 'string' ? task.task_id : 'invalid-task';
    try {
      this.validateTask(task);
      const prior = this.findPriorResult(task);
      if (prior) {
        this.onStatus({ type: 'task_result_retry', task_id: taskId, reason: 'REUSING_DURABLE_LOCAL_RESULT' });
        await this.client.sendInvestigationTaskResult(prior.payload);
        return;
      }
      const requestRecord = this.ledger.append('investigation_task_received', {
        timestamp: new Date().toISOString(),
        task: { task_id: task.task_id, incident_id: task.incident_id, playbook_id: task.playbook_id, playbook_version: task.playbook_version, nonce: task.nonce, scope: task.scope },
        provenance: { origin: 'AUTHENTICATED_SENTINEL_CLOUD_TASK_POLL', host_id: this.hostId, boot_id: this.bootId },
      });
      const maxDuration = Math.min(Number(task.timeout_ms) || PLAYBOOKS[task.playbook_id].timeout, PLAYBOOKS[task.playbook_id].timeout);
      output = await withTimeout(this.runPlaybook(task), maxDuration, signal);
      const outputLimit = Math.min(Number(task.max_output_bytes) || PLAYBOOKS[task.playbook_id].output, PLAYBOOKS[task.playbook_id].output);
      output = fitOutputToLimit(output, outputLimit);
      const outputBytes = Buffer.byteLength(canonicalJson(output), 'utf8');
      if (outputBytes > outputLimit) throw taskError('TASK_OUTPUT_LIMIT_EXCEEDED', `Output was ${outputBytes} bytes; playbook limit is ${outputLimit}.`);
      const hash = sha256(canonicalJson(output));
      const duration = Number(process.hrtime.bigint() - started) / 1e6;
      const completedAt = new Date().toISOString();
      const resultRecord = this.ledger.append('investigation_task_result', {
        timestamp: completedAt,
        task: { task_id: task.task_id, incident_id: task.incident_id, playbook_id: task.playbook_id, nonce: task.nonce },
        status: 'COMPLETED', execution_duration_ms: duration, result_hash: hash, output,
        provenance: { origin: 'SENTINEL_RUNTIME_READ_ONLY_PLAYBOOK', host_id: this.hostId, boot_id: this.bootId, ledger_sequence: requestRecord.sequence },
      });
      const payload = {
        task_id: task.task_id,
        nonce: task.nonce,
        status: 'COMPLETED',
        started_at: startedAt,
        completed_at: completedAt,
        execution_duration_ms: duration,
        output_data: output,
        result_hash: hash,
        evidence_sequence: resultRecord.sequence,
        evidence_record_hash: resultRecord.record_hash,
        agent_version: '0.2.0',
      };
      const submitted = await this.client.sendInvestigationTaskResult(payload);
      this.onStatus({ type: submitted.ok ? 'task_result_submitted' : 'task_result_submit_failed', task_id: task.task_id, playbook_id: task.playbook_id, status: submitted.status || null, error: submitted.error || null });
    } catch (error) {
      status = 'FAILED';
      errorCode = error?.code || 'TASK_EXECUTION_FAILED';
      errorReason = safeMessage(error);
      const duration = Number(process.hrtime.bigint() - started) / 1e6;
      const completedAt = new Date().toISOString();
      let record = null;
      if (/^inv_task_[a-f0-9]{24}$/.test(taskId) && /^[a-f0-9]{32}$/.test(String(task?.nonce || ''))) {
        try {
          record = this.ledger.append('investigation_task_result', {
            timestamp: completedAt,
            task: { task_id: taskId, incident_id: task.incident_id || null, playbook_id: task.playbook_id || null, nonce: task.nonce },
            status, error_code: errorCode, error_reason: errorReason, execution_duration_ms: duration,
            provenance: { origin: 'SENTINEL_RUNTIME_TASK_GUARD', host_id: this.hostId, boot_id: this.bootId },
          });
        } catch { /* Keep task reporting best-effort if local ledger storage is unavailable. */ }
        const payload = {
          task_id: taskId, nonce: task.nonce, status, started_at: startedAt, completed_at: completedAt,
          execution_duration_ms: Math.min(duration, 30_000), error_code: errorCode, error_reason: errorReason,
          ...(record ? { evidence_sequence: record.sequence, evidence_record_hash: record.record_hash } : {}), agent_version: '0.2.0',
        };
        try {
          const submitted = await this.client.sendInvestigationTaskResult(payload);
          this.onStatus({ type: submitted.ok ? 'task_failed_result_submitted' : 'task_result_submit_failed', task_id: taskId, error: submitted.error || errorCode });
        } catch { this.onStatus({ type: 'task_result_submit_failed', task_id: taskId, error: errorCode }); }
      } else this.onStatus({ type: 'task_rejected', error: errorCode, reason: errorReason });
    }
  }

  validateTask(task) {
    if (!task || typeof task !== 'object' || !/^inv_task_[a-f0-9]{24}$/.test(task.task_id || '')) throw taskError('INVALID_TASK', 'Task identity is malformed.');
    if (!/^[a-f0-9]{32}$/.test(task.nonce || '')) throw taskError('INVALID_TASK_NONCE', 'Task nonce is malformed.');
    if (task.governance_level !== 'L0_PASSIVE_READ' || task.authorization?.level && task.authorization.level !== 'L0_PASSIVE_READ') throw taskError('UNSUPPORTED_GOVERNANCE_LEVEL', 'Runtime accepts only L0 read-only tasks.');
    if (!Object.hasOwn(PLAYBOOKS, task.playbook_id)) throw taskError('PLAYBOOK_NOT_REGISTERED', 'The playbook is not enabled in this Runtime build.');
    if (typeof task.expires_at !== 'string' || !Number.isFinite(Date.parse(task.expires_at)) || Date.parse(task.expires_at) <= Date.now()) throw taskError('TASK_EXPIRED', 'Task expired before execution.');
    if (task.expected_boot_id && String(task.expected_boot_id).toLowerCase() !== this.bootId.toLowerCase()) throw taskError('HOST_BOOT_ID_MISMATCH', 'The incident belongs to a different host boot; current PID inspection is blocked to prevent PID reuse.');
    if ((PID_BOUND_PLAYBOOKS.has(task.playbook_id) || task.scope?.pid !== undefined) && !task.expected_boot_id) throw taskError('EXPECTED_BOOT_ID_REQUIRED', 'PID-bound investigation requires the incident boot ID.');
    if (!task.scope || typeof task.scope !== 'object' || Array.isArray(task.scope)) throw taskError('INVALID_SCOPE', 'Task scope must be an object.');
    const allowed = allowedKeysFor(task.playbook_id);
    for (const [key, value] of Object.entries(task.scope)) {
      if (!allowed.has(key)) throw taskError('UNSUPPORTED_SCOPE_FIELD', `Scope field ${key} is not allowed.`);
      if (value === null || value === undefined) throw taskError('INVALID_SCOPE_VALUE', `Scope field ${key} must not be null.`);
    }
    if (PID_BOUND_PLAYBOOKS.has(task.playbook_id)) assertPid(task.scope.pid);
    if (task.playbook_id === 'LINUX.FILE.METADATA' && (typeof task.scope.path !== 'string' || !path.isAbsolute(task.scope.path) || task.scope.path.length > 4096)) throw taskError('INVALID_FILE_PATH', 'An absolute bounded file path is required.');
    if (['LINUX.FILE.ACCESS_HISTORY'].includes(task.playbook_id) && task.scope.path !== undefined && (typeof task.scope.path !== 'string' || !path.isAbsolute(task.scope.path))) throw taskError('INVALID_FILE_PATH', 'An absolute file path is required.');
    if (task.playbook_id === 'LINUX.NETWORK.CONNECTIONS') {
      if (task.scope.pid === undefined && task.scope.destination_ip === undefined && task.scope.destination_port === undefined) throw taskError('NETWORK_FILTER_REQUIRED', 'At least one evidence-derived network filter is required.');
      if (task.scope.pid !== undefined) assertPid(task.scope.pid);
      if (task.scope.destination_ip !== undefined && net.isIP(String(task.scope.destination_ip)) === 0) throw taskError('INVALID_DESTINATION_IP', 'Destination must be a literal IP address.');
      if (task.scope.destination_port !== undefined && (!Number.isInteger(task.scope.destination_port) || task.scope.destination_port < 1 || task.scope.destination_port > 65535)) throw taskError('INVALID_DESTINATION_PORT', 'Destination port must be 1..65535.');
    }
    if (task.playbook_id === 'LINUX.SENSOR.HEALTH' && Object.keys(task.scope).length) throw taskError('INVALID_SCOPE', 'Sensor health does not accept a host-supplied scope.');
    if (!Number.isSafeInteger(task.timeout_ms) || task.timeout_ms < 250 || task.timeout_ms > 30000) throw taskError('INVALID_TIMEOUT', 'Task timeout is outside the Runtime safety limits.');
    if (!Number.isSafeInteger(task.max_output_bytes) || task.max_output_bytes < 1024 || task.max_output_bytes > PLAYBOOKS[task.playbook_id].output) throw taskError('INVALID_OUTPUT_LIMIT', 'Task output limit exceeds the registered playbook limit.');
    this.assertIncidentScope(task);
  }

  assertIncidentScope(task) {
    if (!['LINUX.PROCESS.IDENTITY','LINUX.PROCESS.TREE','LINUX.PROCESS.HISTORY','LINUX.NETWORK.SOCKETS','LINUX.NETWORK.CONNECTIONS','LINUX.NETWORK.CONNECTION_HISTORY','LINUX.CONTAINER.NAMESPACES','LINUX.CONTAINER.MOUNTS','LINUX.FILE.METADATA','LINUX.FILE.ACCESS_HISTORY'].includes(task.playbook_id)) return;
    const records = this.ledger.getRecords({ limit: 4096 });
    const observed = records.filter((row) => row.record_type === 'event').map(parseLedgerRow).filter(Boolean);
    const sameBoot = observed.filter((event) => String(event.host_identity?.boot_id || '').toLowerCase() === this.bootId.toLowerCase());
    const scopedPid = task.scope.pid;
    if (scopedPid !== undefined && !sameBoot.some((event) => Number(event.process_identity?.pid) === scopedPid)) throw taskError('PID_NOT_IN_LOCAL_EVIDENCE', 'Requested PID is not present in the local ledger for this boot.');
    if (typeof task.scope.path === 'string' && !sameBoot.some((event) => collectStrings(event.payload).includes(task.scope.path))) throw taskError('PATH_NOT_IN_LOCAL_EVIDENCE', 'Requested path is not present in the local ledger for this boot.');
    if (typeof task.scope.destination_ip === 'string' && !sameBoot.some((event) => event.payload?.network_endpoint?.destination_ip === task.scope.destination_ip)) throw taskError('DESTINATION_NOT_IN_LOCAL_EVIDENCE', 'Requested destination is not present in the local ledger for this boot.');
  }

  findPriorResult(task) {
    const rows = this.ledger.getRecords({ limit: 4096 });
    for (const row of rows) {
      if (row.record_type !== 'investigation_task_result') continue;
      const payload = parseLedgerRow(row);
      if (payload?.task?.task_id === task.task_id && payload.task.nonce === task.nonce && payload.status === 'COMPLETED') {
        const output = payload.output;
        const resultHash = sha256(canonicalJson(output));
        return { payload: {
          task_id: task.task_id, nonce: task.nonce, status: 'COMPLETED', started_at: row.timestamp,
          completed_at: payload.timestamp, execution_duration_ms: payload.execution_duration_ms,
          output_data: output, result_hash: resultHash, evidence_sequence: Number(row.sequence),
          evidence_record_hash: row.record_hash, agent_version: '0.2.0',
        } };
      }
    }
    return null;
  }

  async runPlaybook(task) {
    const scope = task.scope;
    switch (task.playbook_id) {
      case 'LINUX.PROCESS.IDENTITY': return inspectProcessIdentity(scope.pid);
      case 'LINUX.PROCESS.TREE': return inspectProcessTree(scope.pid);
      case 'LINUX.PROCESS.HISTORY': return queryLedger(this.ledger, task, 'PROCESS', this.bootId);
      case 'LINUX.NETWORK.SOCKETS': return inspectProcessSockets(scope.pid);
      case 'LINUX.NETWORK.CONNECTIONS': return inspectConnections(scope);
      case 'LINUX.NETWORK.CONNECTION_HISTORY': return queryLedger(this.ledger, task, 'NETWORK', this.bootId);
      case 'LINUX.CONTAINER.NAMESPACES': return inspectNamespaces(scope.pid);
      case 'LINUX.CONTAINER.MOUNTS': return inspectMounts(scope.pid);
      case 'LINUX.FILE.METADATA': return inspectFileMetadata(scope.path);
      case 'LINUX.FILE.ACCESS_HISTORY': return queryLedger(this.ledger, task, 'FILE', this.bootId);
      case 'LINUX.SENSOR.HEALTH': return inspectSensorHealth(this.ledger, this.hostId, this.bootId);
      case 'LINUX.EVIDENCE.VERIFY': return verifyLedgerInWorker(this.ledger.path);
      default: throw taskError('PLAYBOOK_NOT_REGISTERED', 'No Runtime handler is registered for this playbook.');
    }
  }
}

const PID_BOUND_PLAYBOOKS = new Set(['LINUX.PROCESS.IDENTITY','LINUX.PROCESS.TREE','LINUX.PROCESS.HISTORY','LINUX.NETWORK.SOCKETS','LINUX.CONTAINER.NAMESPACES','LINUX.CONTAINER.MOUNTS']);

function allowedKeysFor(id) {
  const map = {
    'LINUX.PROCESS.IDENTITY': ['pid','host_pid','boot_id'], 'LINUX.PROCESS.TREE': ['pid','pids','boot_id'],
    'LINUX.PROCESS.HISTORY': ['pid','exec_id','boot_id'], 'LINUX.NETWORK.SOCKETS': ['pid'],
    'LINUX.NETWORK.CONNECTIONS': ['pid','destination_ip','destination_port'],
    'LINUX.NETWORK.CONNECTION_HISTORY': ['pid','destination_ip','destination_port'],
    'LINUX.CONTAINER.NAMESPACES': ['pid','container_id'], 'LINUX.CONTAINER.MOUNTS': ['pid','container_id'],
    'LINUX.FILE.METADATA': ['path','pid'], 'LINUX.FILE.ACCESS_HISTORY': ['path','pid'],
    'LINUX.SENSOR.HEALTH': [], 'LINUX.EVIDENCE.VERIFY': [],
  };
  return new Set(map[id] || []);
}

function assertPid(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2_147_483_647) throw taskError('INVALID_PID', 'PID must be an integer in the Linux PID range.');
}

async function inspectProcessIdentity(pid) {
  const status = await readProcStatus(pid);
  if (!status) return { observation_status: 'UNAVAILABLE', pid, reason: 'PROCESS_NOT_READABLE_OR_ALREADY_EXITED' };
  const stat = await readProcStat(pid);
  const executable = await safeReadlink(`/proc/${pid}/exe`);
  const namespaces = await readNamespaces(`/proc/${pid}/ns`);
  const credentials = {};
  for (const key of ['Uid','Gid']) if (status[key]) credentials[key.toLowerCase()] = status[key].split(/\s+/).map(Number);
  return {
    observation_status: 'OBSERVED', observed_at: new Date().toISOString(), pid,
    name: status.Name || null, state: status.State || null,
    ppid: integerField(status.PPid), tgid: integerField(status.Tgid), threads: integerField(status.Threads),
    credentials,
    security: Object.fromEntries(['CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters'].filter((key) => status[key] !== undefined).map((key) => [key, status[key]])),
    executable_path: executable, process_start_time_ticks: stat?.start_time_ticks ?? null,
    namespaces,
    capture_limits: ['No argv or environment variables were read.', 'No file contents or network payloads were read.'],
  };
}

async function inspectProcessTree(pid) {
  const ancestors = [];
  const visited = new Set();
  let current = pid;
  for (let depth = 0; depth < 16 && current > 0 && !visited.has(current); depth++) {
    visited.add(current);
    const status = await readProcStatus(current);
    const stat = await readProcStat(current);
    if (!status || !stat) break;
    const item = {
      pid: current, ppid: integerField(status.PPid), name: status.Name || null,
      state: status.State || null, process_start_time_ticks: stat.start_time_ticks,
      executable_path: await safeReadlink(`/proc/${current}/exe`),
      credentials: status.Uid ? { uid: status.Uid.split(/\s+/).map(Number) } : null,
    };
    ancestors.push(item);
    current = item.ppid || 0;
  }
  return { observation_status: ancestors.length ? 'OBSERVED' : 'UNAVAILABLE', observed_at: new Date().toISOString(), requested_pid: pid, ancestors, max_depth: 16, argv_collected: false, environment_collected: false };
}

async function inspectNamespaces(pid) {
  const subject = await readNamespaces(`/proc/${pid}/ns`);
  const host = await readNamespaces('/proc/1/ns');
  const comparisons = {};
  for (const name of NS_TYPES) {
    if (!subject[name] || !host[name]) comparisons[name] = { available: false, same_as_host_pid1: null };
    else comparisons[name] = { available: true, subject: subject[name], host_pid1: host[name], same_as_host_pid1: subject[name] === host[name] };
  }
  return { observation_status: Object.values(subject).some(Boolean) ? 'OBSERVED' : 'UNAVAILABLE', observed_at: new Date().toISOString(), pid, comparisons, interpretation_limit: 'Namespace differences are normal for containers and do not prove breakout.' };
}

async function inspectMounts(pid) {
  const filename = `/proc/${pid}/mountinfo`;
  try {
    const text = await readBoundedText(filename, 1024 * 1024);
    const mounts = [];
    const indicators = [];
    for (const line of text.split('\n').slice(0, 512)) {
      if (!line) continue;
      const [left, right] = line.split(' - ');
      if (!left || !right) continue;
      const l = left.split(' '); const r = right.split(' ');
      const mountPoint = unescapeMount(l[4] || '');
      const source = unescapeMount(r[1] || '');
      const fsType = r[0] || '';
      const row = { mount_id: Number(l[0]) || null, parent_id: Number(l[1]) || null, device: l[2] || null, root: unescapeMount(l[3] || ''), mount_point: mountPoint, mount_options: l[5] || '', fs_type: fsType, source };
      mounts.push(row);
      if (/(^|\/)(docker\.sock|containerd\.sock)$/.test(mountPoint) || /\/(docker|containerd)\.sock$/.test(source)) indicators.push({ code: 'CONTAINER_RUNTIME_SOCKET_MOUNT', mount_point: mountPoint, source });
      if (mountPoint === '/proc' && fsType === 'proc') indicators.push({ code: 'PROCFS_MOUNT_PRESENT', mount_point: mountPoint, source });
      if (mountPoint === '/' && /\b(rw|shared):/.test(l.slice(5).join(' '))) indicators.push({ code: 'ROOT_MOUNT_WRITABLE_OR_SHARED', mount_point: '/', options: l[5] || '' });
    }
    return { observation_status: 'OBSERVED', observed_at: new Date().toISOString(), pid, mount_count_returned: mounts.length, mounts, risk_indicators: indicators, truncated: text.split('\n').length > 513 };
  } catch (error) { return { observation_status: 'UNAVAILABLE', observed_at: new Date().toISOString(), pid, reason: procErrorCode(error) }; }
}

async function inspectFileMetadata(target) {
  try {
    const stat = await fs.promises.lstat(target, { bigint: true });
    const type = stat.isFile() ? 'REGULAR_FILE' : stat.isDirectory() ? 'DIRECTORY' : stat.isSymbolicLink() ? 'SYMLINK' : stat.isSocket() ? 'SOCKET' : stat.isFIFO() ? 'FIFO' : stat.isBlockDevice() ? 'BLOCK_DEVICE' : stat.isCharacterDevice() ? 'CHARACTER_DEVICE' : 'OTHER';
    const result = {
      observation_status: 'OBSERVED', observed_at: new Date().toISOString(), exists: true,
      path: target, type, device: stat.dev.toString(), inode: stat.ino.toString(),
      uid: Number(stat.uid), gid: Number(stat.gid), mode_octal: `0${Number(stat.mode & 0o7777n).toString(8)}`,
      size_bytes: stat.size.toString(), modified_at: stat.mtime.toISOString(), changed_at: stat.ctime.toISOString(),
      content_read: false, hash_computed: false,
    };
    if (stat.isSymbolicLink()) result.symlink = true;
    return result;
  } catch (error) { return { observation_status: 'UNAVAILABLE', observed_at: new Date().toISOString(), exists: false, path: target, reason: fsErrorCode(error), content_read: false }; }
}

async function inspectProcessSockets(pid) {
  const descriptorPath = `/proc/${pid}/fd`;
  const inodeToFd = new Map();
  try {
    const entries = (await fs.promises.readdir(descriptorPath)).slice(0, 2048);
    for (const fd of entries) {
      const link = await safeReadlink(`${descriptorPath}/${fd}`);
      const match = link?.match(/^socket:\[(\d+)\]$/);
      if (match) inodeToFd.set(match[1], Number(fd));
    }
  } catch (error) { return { observation_status: 'UNAVAILABLE', observed_at: new Date().toISOString(), pid, sockets: [], reason: procErrorCode(error) }; }
  const sockets = [];
  for (const table of SOCKET_TABLES) {
    let content;
    try { content = await readBoundedText(`/proc/${pid}/net/${table}`, 1024 * 1024); }
    catch { continue; }
    for (const row of parseSocketTable(content, table)) {
      if (!inodeToFd.has(row.inode)) continue;
      sockets.push({ ...row, fd: inodeToFd.get(row.inode), ownership: 'PID_FD_INODE_MATCH' });
    }
  }
  return { observation_status: 'OBSERVED', observed_at: new Date().toISOString(), pid, sockets: sockets.slice(0, 256), socket_count: sockets.length, truncated: sockets.length > 256, payload_captured: false };
}

async function inspectConnections(scope) {
  const base = scope.pid ? `/proc/${scope.pid}/net` : '/proc';
  const sockets = [];
  for (const table of SOCKET_TABLES) {
    let content;
    try { content = await readBoundedText(`${base}/${table}`, 1024 * 1024); }
    catch { continue; }
    for (const row of parseSocketTable(content, table)) {
      if (scope.destination_ip && row.remote.ip !== scope.destination_ip) continue;
      if (scope.destination_port && row.remote.port !== scope.destination_port) continue;
      sockets.push(row);
    }
  }
  return { observation_status: 'OBSERVED', observed_at: new Date().toISOString(), namespace_source: scope.pid ? `/proc/${scope.pid}/net` : 'Runtime network namespace (/proc/net)', process_socket_ownership: 'NOT_ESTABLISHED', sockets: sockets.slice(0, 256), socket_count: sockets.length, truncated: sockets.length > 256, payload_captured: false, interpretation_limit: 'Procfs socket state is a point-in-time view and does not prove a connection completed or bytes were transferred.' };
}

function parseSocketTable(text, table) {
  const rows = [];
  for (const line of text.split('\n').slice(1, 2049)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 10) continue;
    const local = parseProcEndpoint(parts[1], table.endsWith('6'));
    const remote = parseProcEndpoint(parts[2], table.endsWith('6'));
    if (!local || !remote) continue;
    const stateCode = parts[3];
    rows.push({ protocol: table.startsWith('tcp') ? 'TCP' : 'UDP', family: table.endsWith('6') ? 'IPv6' : 'IPv4', state: table.startsWith('tcp') ? TCP_STATES[stateCode] || `UNKNOWN_${stateCode}` : 'DATAGRAM', local, remote, tx_queue_bytes: parseInt(parts[4]?.split(':')[0] || '0', 16) || 0, rx_queue_bytes: parseInt(parts[4]?.split(':')[1] || '0', 16) || 0, uid: Number(parts[7]) || 0, inode: parts[9] });
  }
  return rows;
}

const TCP_STATES = { '01':'ESTABLISHED', '02':'SYN_SENT', '03':'SYN_RECV', '04':'FIN_WAIT1', '05':'FIN_WAIT2', '06':'TIME_WAIT', '07':'CLOSE', '08':'CLOSE_WAIT', '09':'LAST_ACK', '0A':'LISTEN', '0B':'CLOSING' };
function parseProcEndpoint(value, ipv6) {
  const [rawAddress, rawPort] = String(value).split(':');
  if (!/^[0-9a-f]+$/i.test(rawAddress || '') || !/^[0-9a-f]{4}$/i.test(rawPort || '')) return null;
  const address = decodeProcAddress(rawAddress, ipv6);
  return address ? { ip: address, port: parseInt(rawPort, 16) } : null;
}
function decodeProcAddress(hex, ipv6) {
  if (!ipv6 && hex.length === 8) return hex.match(/../g).reverse().map((byte) => parseInt(byte, 16)).join('.');
  if (ipv6 && hex.length === 32) {
    const bytes = hex.match(/../g);
    const reordered = [];
    for (let i = 0; i < bytes.length; i += 4) reordered.push(...bytes.slice(i, i + 4).reverse());
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push((parseInt(reordered[i], 16) * 256 + parseInt(reordered[i + 1], 16)).toString(16));
    let bestStart = -1; let bestLength = 1;
    for (let i = 0; i < groups.length;) {
      if (groups[i] !== '0') { i++; continue; }
      let end = i; while (end < groups.length && groups[end] === '0') end++;
      if (end - i > bestLength) { bestStart = i; bestLength = end - i; }
      i = end;
    }
    if (bestStart < 0) return groups.join(':');
    const left = groups.slice(0, bestStart).join(':'); const right = groups.slice(bestStart + bestLength).join(':');
    return `${left}::${right}`;
  }
  return null;
}

function queryLedger(ledger, task, family, bootId) {
  const scope = task.scope;
  const rows = ledger.getRecords({ limit: 4096 });
  const records = [];
  for (const row of rows) {
    if (row.record_type !== 'event') continue;
    const event = parseLedgerRow(row);
    if (!event || !matchesHistoryFamily(event, family)) continue;
    if (String(event.host_identity?.boot_id || '').toLowerCase() !== String(bootId).toLowerCase()) continue;
    if (scope.pid !== undefined && Number(event.process_identity?.pid) !== scope.pid) continue;
    if (scope.exec_id && event.process_identity?.exec_id !== scope.exec_id) continue;
    if (scope.path && !collectStrings(event.payload).includes(scope.path)) continue;
    const network = event.payload?.network_endpoint;
    if (scope.destination_ip && network?.destination_ip !== scope.destination_ip) continue;
    if (scope.destination_port && Number(network?.destination_port) !== scope.destination_port) continue;
    records.push({ sequence: Number(row.sequence), record_timestamp: row.timestamp, record_hash: row.record_hash, source_event_key: event.source_event_key || null, source_timestamp: event.timestamps?.source_timestamp || null, event_type: event.event_type || 'UNKNOWN', pid: event.process_identity?.pid ?? null, exec_id: event.process_identity?.exec_id ?? null, executable_path: event.process_identity?.executable_path || null, file_path: event.payload?.file_path || event.payload?.path || null, network_endpoint: network ? { protocol: network.protocol || null, source_ip: network.source_ip || null, source_port: network.source_port ?? null, destination_ip: network.destination_ip || null, destination_port: network.destination_port ?? null } : null, return_code: event.payload?.return_code ?? null, event_semantics: historySemantics(event.event_type) });
    if (records.length >= 100) break;
  }
  return { observation_status: 'OBSERVED', observed_at: new Date().toISOString(), query: { family, ...scope }, ledger_window_records_examined: rows.length, returned: records.length, truncated: records.length === 100, records: records.reverse(), history_source: 'LOCAL_TAMPER_EVIDENT_RUNTIME_LEDGER', argv_collected: false, environment_collected: false };
}

function matchesHistoryFamily(event, family) {
  const type = String(event.event_type || '');
  if (family === 'PROCESS') return type.startsWith('PROCESS_');
  if (family === 'FILE') return type.startsWith('FILE_');
  if (family === 'NETWORK') return type.startsWith('NETWORK_');
  return false;
}
function historySemantics(type) {
  const normalized = String(type || '');
  if (normalized.endsWith('_ATTEMPT')) return 'ATTEMPT_OBSERVED_SUCCESS_NOT_ESTABLISHED';
  if (normalized.endsWith('_RESULT')) return 'RESULT_EVENT_REPORTED';
  return 'EVENT_TYPE_SEMANTICS_PRESERVED';
}

async function inspectSensorHealth(ledger, hostId, bootId) {
  const rows = ledger.getRecords({ limit: 2048 });
  const sensor = []; const loss = []; const transitions = [];
  for (const row of rows) {
    if (row.record_type === 'event') {
      const event = parseLedgerRow(row);
      if (!event || String(event.host_identity?.boot_id || '').toLowerCase() !== bootId.toLowerCase()) continue;
      if (event.event_type === 'SENSOR_HEALTH') sensor.push({ sequence: Number(row.sequence), record_hash: row.record_hash, source_timestamp: event.timestamps?.source_timestamp || null, event: event.payload });
      if (event.event_type === 'EVENT_LOSS') loss.push({ sequence: Number(row.sequence), record_hash: row.record_hash, source_timestamp: event.timestamps?.source_timestamp || null, loss_metrics: event.loss_metrics });
    } else if (row.record_type === 'sensor_health') {
      const payload = parseLedgerRow(row);
      if (payload) transitions.push({ sequence: Number(row.sequence), record_hash: row.record_hash, timestamp: payload.timestamp, event_type: payload.event?.event_type || null, details: payload.details || null });
    }
    if (sensor.length + loss.length >= 8 && transitions.length >= 8) break;
  }
  const current = await readProcStatus('self');
  const memory = await readBoundedText('/proc/self/statm', 128).catch(() => null);
  const latestHealth = sensor[0] || null; const latestLoss = loss[0] || null;
  return {
    observation_state: latestHealth ? 'REPORTED_BY_LAST_METRICS_SAMPLE' : transitions.length ? 'COLLECTOR_STATE_REPORTED_NO_METRICS_SAMPLE' : 'UNKNOWN',
    observed_at: new Date().toISOString(), host_id: hostId, boot_id: bootId,
    runtime_process: { pid: process.pid, name: current?.Name || 'sentinel-runtime', state: current?.State || null, threads: integerField(current?.Threads), statm_pages: memory?.trim().split(/\s+/).slice(0, 7) || null },
    telemetry_coverage: { latest_sample_at: latestHealth?.source_timestamp || null, last_health_record_hash: latestHealth?.record_hash || null, latest_loss_sample_at: latestLoss?.source_timestamp || null, loss_domains: latestLoss?.loss_metrics || null, recent_collector_transitions: transitions.reverse() },
    ledger_window_records_examined: rows.length,
    limitations: ['Counters absent in the latest metric event remain UNKNOWN, not zero.', 'Tetragon daemon health is based on locally recorded Runtime observations; no direct privileged daemon query is made.', 'This result is an agent report and is not independently verified by Cloud.'],
  };
}

function verifyLedgerInWorker(dbPath) {
  if (typeof dbPath !== 'string' || dbPath === ':memory:') return Promise.resolve({ verification: { valid: false, checked: 0, reason: 'PERSISTENT_LEDGER_REQUIRED' }, evidence_status: 'AGENT_REPORTED' });
  return new Promise((resolve, reject) => {
    const worker = new Worker(path.join(__dirname, 'ledger-verify-worker.js'), { workerData: { dbPath } });
    const timer = setTimeout(() => { worker.terminate(); reject(taskError('LEDGER_VERIFY_TIMEOUT', 'Ledger chain verification exceeded the bounded worker duration.')); }, 12000);
    worker.once('message', (message) => { clearTimeout(timer); resolve(message); });
    worker.once('error', (error) => { clearTimeout(timer); reject(taskError('LEDGER_VERIFY_FAILED', safeMessage(error))); });
    worker.once('exit', (code) => { if (code !== 0) { clearTimeout(timer); reject(taskError('LEDGER_VERIFY_FAILED', `Ledger verification worker exited ${code}.`)); } });
  });
}

async function readProcStatus(pid) {
  try {
    const text = await readBoundedText(`/proc/${pid}/status`, 64 * 1024);
    const result = {};
    for (const line of text.split('\n')) {
      const colon = line.indexOf(':'); if (colon < 1) continue;
      const name = line.slice(0, colon);
      if (FIELD_KEYS.has(name)) result[name] = line.slice(colon + 1).trim();
    }
    return result;
  } catch { return null; }
}

async function readProcStat(pid) {
  try {
    const text = await readBoundedText(`/proc/${pid}/stat`, 16 * 1024);
    const close = text.lastIndexOf(')'); const fields = text.slice(close + 1).trim().split(/\s+/);
    if (close < 0 || fields.length < 20) return null;
    return { state: fields[0], ppid: Number(fields[1]), start_time_ticks: Number(fields[19]) };
  } catch { return null; }
}

async function readNamespaces(root) {
  const result = {};
  for (const name of NS_TYPES) result[name] = await safeReadlink(`${root}/${name}`);
  return result;
}

async function safeReadlink(filename) { try { return await fs.promises.readlink(filename); } catch { return null; } }
async function readBoundedText(filename, maxBytes) {
  const handle = await fs.promises.open(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > maxBytes) throw taskError('PROC_FILE_LIMIT', 'Procfs file is not regular or exceeds its read bound.');
    const bytes = await handle.readFile();
    if (bytes.length > maxBytes) throw taskError('PROC_FILE_LIMIT', 'Procfs read exceeded its byte bound.');
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  } finally { await handle.close(); }
}
function integerField(value) { if (typeof value !== 'string' || !/^-?[0-9]+$/.test(value)) return null; const number = Number(value); return Number.isSafeInteger(number) ? number : null; }
function parseLedgerRow(row) { try { return JSON.parse(row.payload_json); } catch { return null; } }
function collectStrings(value, key = '') {
  const result = [];
  if (!value || typeof value !== 'object') return result;
  if (Array.isArray(value)) { for (const item of value.slice(0, 500)) result.push(...collectStrings(item, key)); return result; }
  for (const [name, item] of Object.entries(value)) {
    if (/^(path|file_path|filename|target_path)$/i.test(name) && typeof item === 'string') result.push(item);
    else if (item && typeof item === 'object') result.push(...collectStrings(item, name));
  }
  return result;
}
function unescapeMount(value) { return value.replace(/\\(040|011|012|134)/g, (_, octal) => String.fromCharCode(parseInt(octal, 8))); }
function procErrorCode(error) { return error?.code === 'EACCES' ? 'PERMISSION_DENIED' : error?.code === 'ENOENT' ? 'PROCESS_OR_PROC_ENTRY_GONE' : error?.code || 'PROCFS_UNAVAILABLE'; }
function fsErrorCode(error) { return error?.code === 'EACCES' ? 'PERMISSION_DENIED' : error?.code === 'ENOENT' ? 'PATH_NOT_FOUND' : error?.code || 'STAT_FAILED'; }
function taskError(code, message) { const error = new Error(message); error.code = code; return error; }
function safeMessage(error) { return String(error?.message || 'Task operation failed').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 512); }
function sha256(text) { return crypto.createHash('sha256').update(text, 'utf8').digest('hex'); }
function fitOutputToLimit(value, maximumBytes) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const output = { ...value };
  let bytes = () => Buffer.byteLength(canonicalJson(output), 'utf8');
  const listKeys = ['records', 'mounts', 'sockets', 'ancestors', 'risk_indicators'];
  while (bytes() > maximumBytes) {
    const key = listKeys.filter((name) => Array.isArray(output[name]) && output[name].length > 0)
      .sort((left, right) => output[right].length - output[left].length)[0];
    if (!key) break;
    const list = output[key];
    const remove = Math.max(1, Math.ceil(list.length / 4));
    output[key] = list.slice(0, Math.max(0, list.length - remove));
    output.truncated_by_playbook_output_limit = true;
    if (key === 'records') output.returned = output[key].length;
    if (key === 'sockets') output.socket_count_returned = output[key].length;
    if (key === 'mounts') output.mount_count_returned = output[key].length;
  }
  return output;
}
function delay(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const timer = setTimeout(finish, ms);
    const abort = () => finish();
    function finish() { clearTimeout(timer); signal.removeEventListener('abort', abort); resolve(); }
    signal.addEventListener('abort', abort, { once: true });
  });
}
function withTimeout(promise, ms, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(taskError('TASK_EXECUTION_TIMEOUT', 'Runtime playbook exceeded its execution deadline.')), ms);
    const abort = () => reject(taskError('RUNTIME_STOPPING', 'Runtime stopped while the task was running.'));
    signal.addEventListener('abort', abort, { once: true });
    promise.then(resolve, reject).finally(() => { clearTimeout(timer); signal.removeEventListener('abort', abort); });
  });
}

module.exports = { InvestigationTaskExecutor, PLAYBOOKS, inspectProcessIdentity, inspectProcessTree, inspectProcessSockets, inspectConnections, inspectNamespaces, inspectMounts, inspectFileMetadata, queryLedger, parseSocketTable, decodeProcAddress, fitOutputToLimit };
