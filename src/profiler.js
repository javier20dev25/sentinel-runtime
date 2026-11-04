'use strict';

const path = require('node:path');
const net = require('node:net');

/**
 * WorkloadProfile: Define los límites esperados de comportamiento para un servicio.
 */
class WorkloadProfile {
  constructor(config = {}) {
    this.name = config.name || 'generic-service';
    this.type = config.type || 'nodejs'; // nodejs, python, go, worker, database
    this.version = config.version || '1.0.0';
    
    // Binarios permitidos para ejecución directa o hijos
    // Entries must be absolute paths or sha256:<hex>. Basename trust is unsafe.
    this.allowedBinaries = new Set((config.allowedBinaries || []).map(normalizeBinaryRule));
    this.allowedBinaryDigests = new Set((config.allowedBinaryDigests || []).map(v => String(v).toLowerCase()));
    
    // Rutas del sistema de archivos permitidas para lectura
    this.allowedReadPrefixes = (config.allowedReadPrefixes || [
      '/app',
      '/usr',
      '/lib',
      '/etc/resolv.conf',
      '/etc/hosts'
    ]).map(normalizeLinuxPath);

    // Rutas sensibles que NUNCA deben leerse sin autorización explícita
    this.restrictedPaths = [
      '/proc/self/environ',
      '/etc/shadow',
      '/etc/passwd',
      '/.ssh',
      '/.aws',
      '/var/run/secrets/kubernetes.io/serviceaccount',
      ...(config.restrictedPaths || [])
    ].map(normalizeLinuxPath);

    // Puertos y destinos externos autorizados
    this.allowedDestinations = new Set((config.allowedDestinations || []).map(normalizeDestinationRule));
  }

  isBinaryAllowed(binaryPath, digest = null) {
    if (typeof binaryPath !== 'string' || binaryPath.includes('\0') || !path.posix.isAbsolute(binaryPath)) return false;
    const normalized = normalizeLinuxPath(binaryPath);
    if (this.allowedBinaries.has(normalized)) return true;
    if (digest && /^[a-f0-9]{64}$/i.test(digest)) {
      return this.allowedBinaryDigests.has(digest.toLowerCase()) || this.allowedBinaries.has(`sha256:${digest.toLowerCase()}`);
    }
    return false;
  }

  isPathRestricted(filePath) {
    if (typeof filePath !== 'string' || filePath.includes('\0') || !path.posix.isAbsolute(filePath)) return true;
    const normalized = normalizeLinuxPath(filePath);
    return this.restrictedPaths.some(restricted => isPathWithin(normalized, restricted)) ||
      !this.allowedReadPrefixes.some(prefix => isPathWithin(normalized, prefix));
  }

  isNetworkDestinationAllowed(host, port) {
    if (typeof host !== 'string' || host.length === 0 || !Number.isInteger(Number(port)) || Number(port) < 0 || Number(port) > 65535) return false;
    const normalizedHost = normalizeHost(host);
    const target = `${formatHost(normalizedHost)}:${Number(port)}`;
    return this.allowedDestinations.has(target) || this.allowedDestinations.has(normalizedHost) ||
      [...this.allowedDestinations].some(rule => matchesIpv4Cidr(normalizedHost, rule));
  }
}

function normalizeBinaryRule(rule) {
  if (typeof rule !== 'string') throw new TypeError('Binary allowlist rules must be strings');
  if (/^sha256:[a-f0-9]{64}$/i.test(rule)) return `sha256:${rule.slice(7).toLowerCase()}`;
  if (!path.posix.isAbsolute(rule) || rule.includes('\0')) throw new TypeError(`Binary allowlist entries must be absolute paths or sha256 digests: ${rule}`);
  return normalizeLinuxPath(rule);
}

function normalizeLinuxPath(value) {
  const normalized = String(value).replace(/\\/g, '/');
  if (normalized.includes('\0')) throw new TypeError('Paths cannot contain NUL bytes');
  return path.posix.normalize(normalized);
}

function isPathWithin(candidate, prefix) {
  return candidate === prefix || candidate.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}

function normalizeHost(host) {
  let value = host.trim().toLowerCase();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  if (net.isIP(value)) return value;
  if (value.endsWith('.')) value = value.slice(0, -1);
  return value;
}

function normalizeDestinationRule(rule) {
  const value = String(rule).trim().toLowerCase();
  const slash = value.lastIndexOf('/');
  if (slash > 0) {
    const address = value.slice(0, slash);
    const bits = Number(value.slice(slash + 1));
    if (net.isIP(address) !== 4 || !/^\d{1,2}$/.test(value.slice(slash + 1)) || bits < 0 || bits > 32) {
      throw new TypeError(`CIDR allowlist entries must be valid IPv4 CIDRs: ${rule}`);
    }
    return `${address}/${bits}`;
  }
  const match = value.match(/^(.+):([0-9]{1,5})$/);
  if (match && Number(match[2]) <= 65535) return `${formatHost(normalizeHost(match[1]))}:${Number(match[2])}`;
  return normalizeHost(value);
}

function formatHost(host) {
  return net.isIP(host) === 6 ? `[${host}]` : host;
}

function matchesIpv4Cidr(host, rule) {
  const match = rule.match(/^([^/]+)\/(\d{1,2})$/);
  if (!match || net.isIP(host) !== 4 || net.isIP(match[1]) !== 4) return false;
  const bits = Number(match[2]);
  if (bits < 0 || bits > 32) return false;
  const toInt = address => address.split('.').reduce((value, octet) => ((value << 8) | Number(octet)) >>> 0, 0);
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (toInt(host) & mask) === (toInt(match[1]) & mask);
}

module.exports = { WorkloadProfile };
