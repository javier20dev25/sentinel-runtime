'use strict';

const { ContainmentLevel } = require('../types');

/**
 * Local process containment adapter using POSIX signals (SIGSTOP / SIGKILL).
 * Designed for single-host Linux execution with strict safety guards.
 */
class LocalProcessContainmentAdapter {
  constructor(options = {}) {
    this.dryRun = options.dryRun === true;
    this.signalSender = options.signalSender || ((pid, sig) => process.kill(pid, sig));
  }

  async execute({ level, targetIdentity }) {
    const pid = targetIdentity?.pid;
    if (!Number.isInteger(pid) || pid <= 1) {
      throw new Error(`Invalid process target PID: ${pid}. PID 1 and non-positive PIDs are protected.`);
    }

    if (pid === process.pid) {
      throw new Error(`Self-containment blocked: Runtime cannot target its own PID ${pid}.`);
    }

    if (this.dryRun) {
      return {
        success: true,
        actionTaken: `${level}_SIMULATED`,
        targetPid: pid,
        timestamp: new Date().toISOString()
      };
    }

    let signal = null;
    if (level === ContainmentLevel.R2_PROCESS_SUSPEND) {
      signal = 'SIGSTOP';
    } else if (level === ContainmentLevel.R3_PROCESS_TERMINATE) {
      signal = 'SIGKILL';
    } else {
      throw new Error(`Unsupported containment level for process adapter: ${level}`);
    }

    try {
      this.signalSender(pid, signal);
      return {
        success: true,
        actionTaken: signal,
        targetPid: pid,
        timestamp: new Date().toISOString()
      };
    } catch (err) {
      if (err.code === 'ESRCH') {
        // Process already terminated / exited naturally
        return {
          success: true,
          actionTaken: 'ALREADY_EXITED',
          targetPid: pid,
          details: 'Target process exited prior to signal delivery',
          timestamp: new Date().toISOString()
        };
      }
      throw err;
    }
  }
}

module.exports = {
  LocalProcessContainmentAdapter
};