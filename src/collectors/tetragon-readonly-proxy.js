'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createTetragonConnection, getAgentVersion, SUPPORTED_TETRAGON_VERSION } = require('./tetragon-grpc');
const { loadTetragonApi, getRawResponseBytes } = require('./tetragon-proto');

const DEFAULT_LISTEN_ADDRESS = 'unix:///run/sentinel-runtime/tetragon-readonly.sock';
const DEFAULT_SOCKET_MODE = 0o600;
const MAX_SHUTDOWN_WAIT_MS = 30000;

function parseUnixSocketAddress(address, platform = process.platform) {
  if (platform !== 'linux') throw new Error('The read-only Tetragon proxy requires Linux Unix-domain sockets');
  if (typeof address !== 'string' || !address.startsWith('unix:///') || address.length > 512 || address.includes('\0')) {
    throw new TypeError('Proxy listener must be an absolute unix:///path address');
  }
  const requestedPath = address.slice('unix://'.length);
  const socketPath = path.posix.normalize(requestedPath);
  if (!path.posix.isAbsolute(socketPath) || socketPath === '/' || socketPath.endsWith('/') || socketPath !== requestedPath || Buffer.byteLength(socketPath) > 100) {
    throw new TypeError('Proxy socket path must be canonical, absolute, file-like, and at most 100 UTF-8 bytes');
  }
  return socketPath;
}

function parseSocketMode(value = '0600') {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0 || value > 0o777) throw new RangeError('Socket mode must be an octal permission value');
  } else if (typeof value === 'string' && /^0?[0-7]{3}$/.test(value)) {
    value = Number.parseInt(value, 8);
  } else {
    throw new TypeError('Socket mode must be a three- or four-digit octal string');
  }
  if ((value & 0o600) !== 0o600 || (value & 0o117) !== 0) {
    throw new RangeError('Socket mode must grant owner read/write, must not grant execute, and must not grant other-user access');
  }
  return value;
}

function prepareSocketPath(socketPath) {
  const parent = fs.realpathSync(path.dirname(socketPath));
  const parentStat = fs.statSync(parent);
  if (!parentStat.isDirectory()) throw new TypeError('Proxy socket parent must be a directory');
  if ((parentStat.mode & 0o022) !== 0) throw new Error('Proxy socket parent must not be group- or world-writable');
  const resolvedPath = path.join(parent, path.basename(socketPath));
  try {
    fs.lstatSync(resolvedPath);
    throw new Error(`Proxy socket path already exists; remove it only after confirming it is stale: ${resolvedPath}`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return resolvedPath;
}

function createReadOnlyServiceDefinition(api) {
  const fullService = api.service.service;
  const getEvents = fullService.GetEvents;
  const getVersion = fullService.GetVersion;
  if (!getEvents || !getVersion || getEvents.originalName !== 'getEvents' || getVersion.originalName !== 'getVersion') {
    throw new Error('Pinned Tetragon API is missing the expected read-only RPC methods');
  }
  const passthroughEvents = Object.assign({}, getEvents, {
    responseSerialize(response) {
      return getRawResponseBytes(response) || getEvents.responseSerialize(response);
    }
  });
  return Object.freeze({ GetEvents: Object.freeze(passthroughEvents), GetVersion: getVersion });
}

async function startTetragonReadOnlyProxy(options = {}) {
  const listenAddress = options.listenAddress || DEFAULT_LISTEN_ADDRESS;
  const socketMode = parseSocketMode(options.socketMode ?? '0600');
  const socketPath = prepareSocketPath(parseUnixSocketAddress(listenAddress, options.platform || process.platform));
  const api = loadTetragonApi();
  const upstream = (options.connectionFactory || createTetragonConnection)({
    address: options.upstreamAddress || 'unix:///var/run/tetragon/tetragon.sock',
    tlsCa: options.tlsCa,
    tlsClientCert: options.tlsClientCert,
    tlsClientKey: options.tlsClientKey
  });
  let bound = false;
  let ownedSocket = null;
  const server = new api.grpc.Server({ 'grpc.max_concurrent_streams': 128 });
  try {
    const currentUmask = process.umask();
    if ((currentUmask & 0o022) !== 0o022) {
      throw new Error('Process umask must prevent group/world socket write access before the listener mode is applied (use 0022 or stricter)');
    }
    const version = await getAgentVersion(upstream.client, options.versionTimeoutMs || 5000);
    if (!SUPPORTED_TETRAGON_VERSION.test(version)) throw new Error(`Unsupported Tetragon version ${version}; this proxy is pinned to v1.8.0`);

    server.addService(createReadOnlyServiceDefinition(api), {
      getVersion(call, callback) {
        const deadline = call.getDeadline?.();
        if (deadline === undefined || deadline === Infinity) upstream.client.getVersion(call.request, callback);
        else upstream.client.getVersion(call.request, { deadline }, callback);
      },
      getEvents(call) {
        let upstreamStream;
        try { upstreamStream = upstream.client.getEvents(call.request); }
        catch (error) { call.destroy(error); return; }
        let ended = false;
        const stopUpstream = () => {
          if (!ended) {
            ended = true;
            try { upstreamStream.cancel(); } catch { /* stream may already be closed */ }
          }
        };
        const onDrain = () => upstreamStream.resume?.();
        call.on('cancelled', stopUpstream);
        call.on('close', stopUpstream);
        upstreamStream.on('data', message => {
          if (!call.write(message)) {
            upstreamStream.pause?.();
            call.once('drain', onDrain);
          }
        });
        upstreamStream.once('error', error => {
          if (!ended) {
            ended = true;
            call.removeListener('drain', onDrain);
            call.destroy(error);
          }
        });
        upstreamStream.once('end', () => {
          if (!ended) {
            ended = true;
            call.removeListener('drain', onDrain);
            call.end();
          }
        });
      }
    });

    await new Promise((resolve, reject) => {
      server.bindAsync(`unix://${socketPath}`, api.grpc.ServerCredentials.createInsecure(), error => error ? reject(error) : resolve());
    });
    bound = true;
    const stat = fs.lstatSync(socketPath);
    if (!stat.isSocket()) throw new Error('gRPC proxy listener did not create a Unix-domain socket');
    ownedSocket = { dev: stat.dev, ino: stat.ino };
    fs.chmodSync(socketPath, socketMode);
    const securedStat = fs.lstatSync(socketPath);
    if (!securedStat.isSocket() || securedStat.dev !== ownedSocket.dev || securedStat.ino !== ownedSocket.ino || (securedStat.mode & 0o777) !== socketMode) {
      throw new Error('Proxy Unix socket identity or permission mode changed during listener setup');
    }
  } catch (error) {
    if (bound) server.forceShutdown();
    try { upstream.close(); } catch { /* best-effort cleanup */ }
    removeOwnedSocket(socketPath, ownedSocket);
    throw error;
  }

  let closing;
  const close = (timeoutMs = 10000) => {
    if (closing) return closing;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_SHUTDOWN_WAIT_MS) {
      throw new RangeError(`Shutdown timeout must be between 1 and ${MAX_SHUTDOWN_WAIT_MS} ms`);
    }
    closing = new Promise((resolve, reject) => {
      let finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        try {
          try { upstream.close(); } catch { /* best-effort cleanup */ }
          removeOwnedSocket(socketPath, ownedSocket);
          resolve();
        } catch (error) { reject(error); }
      };
      const timer = setTimeout(() => { server.forceShutdown(); finish(); }, timeoutMs);
      timer.unref?.();
      server.tryShutdown(finish);
    });
    return closing;
  };

  return Object.freeze({
    listenAddress: `unix://${socketPath}`,
    socketPath,
    socketMode,
    upstreamAddress: options.upstreamAddress || 'unix:///var/run/tetragon/tetragon.sock',
    tetragonVersion: 'v1.8.0',
    allowedMethods: Object.freeze(['GetVersion', 'GetEvents']),
    close
  });
}

function removeOwnedSocket(socketPath, ownedSocket) {
  if (!ownedSocket) return;
  try {
    const current = fs.lstatSync(socketPath);
    if (current.isSocket() && current.dev === ownedSocket.dev && current.ino === ownedSocket.ino) fs.unlinkSync(socketPath);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

module.exports = {
  DEFAULT_LISTEN_ADDRESS,
  DEFAULT_SOCKET_MODE,
  parseUnixSocketAddress,
  parseSocketMode,
  createReadOnlyServiceDefinition,
  startTetragonReadOnlyProxy
};
