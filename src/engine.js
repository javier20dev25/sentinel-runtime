'use strict';

const { EventType, ThreatLevel, EnforcementAction } = require('./types');

/**
 * BehavioralSequenceEngine: Correlaciona secuencias de eventos causales.
 * No utiliza IA como autoridad de bloqueo; utiliza FSM determinista y DAG de linaje.
 */
class BehavioralSequenceEngine {
  constructor(options = {}) {
    this.profiles = new Map();
    this.processChains = new Map(); // PID -> estado de la cadena causal
    this.onEnforce = options.onEnforce || (() => {});
  }

  registerProfile(workloadId, profile) {
    this.profiles.set(workloadId, profile);
  }

  /**
   * Procesa un evento estructurado y decide el nivel de amenaza y contención requerida.
   */
  processEvent(event) {
    const { workloadId, pid, ppid, eventType, timestamp, data } = event;
    const profile = this.profiles.get(workloadId);

    if (!profile) {
      return { threatLevel: ThreatLevel.NORMAL, action: EnforcementAction.RECORD_ONLY };
    }

    // Inicializar o recuperar estado causal del proceso
    if (!this.processChains.has(pid)) {
      this.processChains.set(pid, {
        pid,
        ppid,
        workloadId,
        stages: [],
        score: 0,
        timeline: []
      });
    }

    const chain = this.processChains.get(pid);
    chain.timeline.push({ eventType, timestamp, data });

    let decision = {
      pid,
      workloadId,
      threatLevel: ThreatLevel.NORMAL,
      action: EnforcementAction.RECORD_ONLY,
      reason: 'Normal operation'
    };

    // ETAPA 1: Detección de binario o subproceso inesperado (Spawn Anomaly)
    if (eventType === EventType.PROCESS_EXEC) {
      const binary = data.binary || '';
      if (!profile.isBinaryAllowed(binary)) {
        chain.stages.push('UNEXPECTED_SPAWN');
        chain.score += 25;
        decision = {
          pid,
          workloadId,
          threatLevel: ThreatLevel.ELEVATED_WATCH,
          action: EnforcementAction.INCREASE_LOGGING,
          reason: `Proceso no catalogado en baseline: ${binary}`
        };
      }
    }

    // ETAPA 2: Acceso a variables de entorno o archivos restringidos
    if (eventType === EventType.FILE_READ) {
      const targetPath = data.path || '';
      if (profile.isPathRestricted(targetPath)) {
        chain.stages.push('RESTRICTED_FILE_READ');
        chain.score += 35;

        // Si ya precedido por un spawn inesperado -> Escalar a sospechoso
        if (chain.stages.includes('UNEXPECTED_SPAWN')) {
          decision = {
            pid,
            workloadId,
            threatLevel: ThreatLevel.SUSPICIOUS,
            action: EnforcementAction.SUSPEND_PROCESS,
            reason: `Secuencia: Subproceso no autorizado intentó acceder a archivo restringido: ${targetPath}`
          };
        }
      }
    }

    // ETAPA 3: Conexión de red saliente hacia host no catalogado
    if (eventType === EventType.NETWORK_CONNECT) {
      const { host, port } = data;
      const isAllowed = profile.isNetworkDestinationAllowed(host, port);

      if (!isAllowed) {
        chain.stages.push('UNAUTHORIZED_EGRESS');
        chain.score += 30;

        // Si ya hay Spawn Inesperado + Lectura de Credenciales -> VIOLACIÓN CONFIRMADA
        if (chain.stages.includes('UNEXPECTED_SPAWN') && chain.stages.includes('RESTRICTED_FILE_READ')) {
          decision = {
            pid,
            workloadId,
            threatLevel: ThreatLevel.CONFIRMED_VIOLATION,
            action: EnforcementAction.TERMINATE_PROCESS,
            reason: `Cadena de Exfiltración Crítica: Spawn inesperado -> Lectura de secretos -> Conexión C2 a ${host}:${port}`
          };
        } else {
          decision = {
            pid,
            workloadId,
            threatLevel: ThreatLevel.SUSPICIOUS,
            action: EnforcementAction.ISOLATE_NETWORK,
            reason: `Conexión de red fuera de baseline: ${host}:${port}`
          };
        }
      }
    }

    // Si la cadena acumula un puntaje crítico >= 80 -> Contención total
    if (chain.score >= 80 && decision.threatLevel < ThreatLevel.CONFIRMED_VIOLATION) {
      decision.threatLevel = ThreatLevel.CONFIRMED_VIOLATION;
      decision.action = EnforcementAction.TERMINATE_PROCESS;
    }

    // Despachar acción si requiere intervención
    if (decision.action !== EnforcementAction.RECORD_ONLY) {
      this.onEnforce(decision);
    }

    return decision;
  }
}

module.exports = { BehavioralSequenceEngine };
