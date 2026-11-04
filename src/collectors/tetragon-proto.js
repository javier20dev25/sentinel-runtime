'use strict';

const path = require('node:path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const TETRAGON_API_ROOT = path.resolve(__dirname, '../../vendor/tetragon/v1.8.0/api/v1');
const TETRAGON_SENSORS_PROTO = path.join(TETRAGON_API_ROOT, 'tetragon/sensors.proto');
const RAW_RESPONSE_BYTES = new WeakMap();

let cachedApi;

function loadTetragonApi() {
  if (cachedApi) return cachedApi;
  const definition = protoLoader.loadSync(TETRAGON_SENSORS_PROTO, {
    keepCase: true,
    longs: String,
    enums: String,
    oneofs: true,
    defaults: false,
    arrays: false,
    objects: false,
    includeDirs: [TETRAGON_API_ROOT]
  });
  const getEvents = definition['tetragon.FineGuidanceSensors']?.GetEvents;
  if (!getEvents || typeof getEvents.responseDeserialize !== 'function') {
    throw new Error('Pinned Tetragon API is missing FineGuidanceSensors.GetEvents');
  }
  const decodeResponse = getEvents.responseDeserialize;
  getEvents.responseDeserialize = bytes => {
    const response = decodeResponse(bytes);
    RAW_RESPONSE_BYTES.set(response, Buffer.from(bytes));
    return response;
  };

  const packageObject = grpc.loadPackageDefinition(definition);
  const service = packageObject?.tetragon?.FineGuidanceSensors;
  if (!service?.service?.GetEvents || !service?.service?.GetVersion) {
    throw new Error('Pinned Tetragon API did not load the required RPC methods');
  }
  cachedApi = Object.freeze({ grpc, packageObject, service, definition });
  return cachedApi;
}

function getRawResponseBytes(response) {
  const bytes = response && typeof response === 'object' ? RAW_RESPONSE_BYTES.get(response) : undefined;
  return bytes ? Buffer.from(bytes) : null;
}

function getRawResponseByteLength(response) {
  const bytes = response && typeof response === 'object' ? RAW_RESPONSE_BYTES.get(response) : undefined;
  return bytes ? bytes.length : null;
}

module.exports = { loadTetragonApi, getRawResponseBytes, getRawResponseByteLength, TETRAGON_API_ROOT };
