'use strict';

/**
 * WorkloadProfile: Define los límites esperados de comportamiento para un servicio.
 */
class WorkloadProfile {
  constructor(config = {}) {
    this.name = config.name || 'generic-service';
    this.type = config.type || 'nodejs'; // nodejs, python, go, worker, database
    this.version = config.version || '1.0.0';
    
    // Binarios permitidos para ejecución directa o hijos
    this.allowedBinaries = new Set(config.allowedBinaries || ['node', 'npm']);
    
    // Rutas del sistema de archivos permitidas para lectura
    this.allowedReadPrefixes = config.allowedReadPrefixes || [
      '/app',
      '/usr',
      '/lib',
      '/etc/resolv.conf',
      '/etc/hosts'
    ];

    // Rutas sensibles que NUNCA deben leerse sin autorización explícita
    this.restrictedPaths = [
      '/proc/self/environ',
      '/etc/shadow',
      '/etc/passwd',
      '/.ssh',
      '/.aws',
      '/var/run/secrets/kubernetes.io/serviceaccount'
    ];

    // Puertos y destinos externos autorizados
    this.allowedDestinations = new Set(config.allowedDestinations || []);
  }

  isBinaryAllowed(binaryPath) {
    const base = binaryPath.split(/[/\\]/).pop();
    return this.allowedBinaries.has(base);
  }

  isPathRestricted(filePath) {
    const normalized = filePath.replace(/\\/g, '/');
    return this.restrictedPaths.some(restricted => normalized.includes(restricted));
  }

  isNetworkDestinationAllowed(host, port) {
    const target = `${host}:${port}`;
    return this.allowedDestinations.has(target) || this.allowedDestinations.has(host);
  }
}

module.exports = { WorkloadProfile };
