#!/usr/bin/env node
'use strict';

// Retired synthetic uploader. Real Cloud telemetry must come from the pinned
// Tetragon collector so observations, decisions, action receipts, and ledger
// references share one provenance chain.
console.error('Synthetic Cloud upload is disabled. For real host telemetry use:');
console.error('  sentinel-runtime collect-tetragon --cloud --host-id <stable-id> (--boot-id <uuid> | --boot-id-file <path>)');
console.error('Cloud credentials are read from SENTINEL_RUNTIME_API_KEY or /etc/sentinel/runtime.conf and are never printed.');
process.exitCode = 2;
