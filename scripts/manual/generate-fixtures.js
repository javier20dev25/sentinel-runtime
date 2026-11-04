'use strict';

const fs = require('fs');
const path = require('path');

const baseDir = path.resolve(__dirname, '../../test/fixtures/events/v1');

const families = [
  'PROCESS_EXEC',
  'PROCESS_EXIT',
  'FILE_OPEN_ATTEMPT',
  'FILE_OPEN_RESULT',
  'FILE_READ',
  'NETWORK_CONNECT_ATTEMPT',
  'NETWORK_CONNECT_RESULT',
  'NETWORK_SEND_ATTEMPT',
  'NETWORK_SEND_RESULT',
  'SOCKET_STATE_CHANGE',
  'IDENTITY_CHANGE',
  'CAPABILITY_CHANGE',
  'EVENT_LOSS',
  'SENSOR_HEALTH'
];

function createBaseEvent(family, overrides = {}) {
  return {
    schema_version: '1.0.0',
    event_id: '018f4a12-89b0-7d34-9214-e0b5f8842101',
    event_type: family,
    source_provider: 'tetragon',
    source_event_type: 'PROCESS_KPROBE',
    source_event_id: '9482014',
    host_id: 'worker-node-01',
    boot_id: 'a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d',
    source_timestamp: '1793628400123456789',
    observed_timestamp: '1793628400125000000',
    monotonic_timestamp: '84920491823',
    sensor_version: 'tetragon-1.1.2',
    policy_id: 'tp-default-security',
    policy_version: 'sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
    completeness: 'COMPLETE',
    process_identity: {
      exec_id: 'd29ya2VyLXByb2QtYXoxOjE4OTI4MTkyMzQ6NDAwMg==',
      parent_exec_id: 'd29ya2VyLXByb2QtYXoxOjE4OTI4MTkyMDA6NDAwMQ==',
      pid: 4002,
      tid: 4002,
      process_start_time: '1793628399000000000',
      executable_path: '/usr/local/bin/node',
      executable_digest: {
        algorithm: 'sha256',
        hex: 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      },
      uid: 1000,
      euid: 1000,
      process_namespace: {
        pid_ns: '4026531836',
        mnt_ns: '4026532210',
        net_ns: '4026532215'
      },
      identity_quality: 'VERIFIED_OPAQUE'
    },
    workload_context: {
      workload_type: 'CONTAINER',
      container_id: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      cgroup_id: '4096',
      mount_namespace: '4026532210',
      pid_namespace: '4026531836',
      network_namespace: '4026532215',
      workload_id: 'production-api',
      k8s_metadata: {
        pod_name: 'payment-api-7b8f9c-v28',
        namespace: 'production',
        container_name: 'api'
      }
    },
    payload: {},
    provenance: {
      sensor_id: 'tetragon-daemon-node-01',
      transport_protocol: 'UNIX_DOMAIN_SOCKET',
      transport_authenticated: true,
      collector_id: 'sentinel-runtime-agent-01',
      ingest_timestamp: '1793628400124000000',
      raw_payload_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'
    },
    loss_metrics: {
      loss_ebpf_kernel: 0,
      loss_tetragon_throttle: 0,
      loss_grpc_transport: 0,
      loss_log_rotation: 0,
      loss_parser_reject: 0,
      loss_runtime_queue: 0,
      loss_storage_drop: 0
    },
    ...overrides
  };
}

const familyPayloads = {
  PROCESS_EXEC: {
    valid: {
      binary: '/usr/local/bin/node',
      arguments: ['node', 'server.js'],
      env_sensitive: null,
      working_dir: '/app'
    },
    incomplete: {
      binary: '/bin/bash',
      arguments: ['bash']
    },
    invalid: {
      binary: 12345
    }
  },
  PROCESS_EXIT: {
    valid: {
      exit_code: 0,
      signal: null
    },
    incomplete: {
      exit_code: 137,
      signal: 9
    },
    invalid: {}
  },
  FILE_OPEN_ATTEMPT: {
    valid: {
      path: '/etc/shadow',
      flags: 0,
      mode: null
    },
    incomplete: {
      path: '/app/config.json',
      flags: ['O_RDONLY']
    },
    invalid: {
      path: ''
    }
  },
  FILE_OPEN_RESULT: {
    valid: {
      fd: 3,
      return_code: 3,
      errno: null
    },
    incomplete: {
      fd: null,
      return_code: -2,
      errno: 2
    },
    invalid: {
      return_code: 'not-an-integer'
    }
  },
  FILE_READ: {
    valid: {
      fd: 3,
      path: '/etc/shadow',
      bytes_read: 1024,
      return_code: 1024,
      offset: '0'
    },
    incomplete: {
      bytes_read: 512,
      return_code: 512
    },
    invalid: {
      bytes_read: -50,
      return_code: 0
    }
  },
  NETWORK_CONNECT_ATTEMPT: {
    valid: {
      family: 'AF_INET',
      destination_ip: '198.51.100.24',
      destination_port: 443,
      protocol: 'IPPROTO_TCP',
      socket_fd: 5
    },
    incomplete: {
      family: 'AF_INET',
      destination_ip: '10.0.0.1',
      destination_port: 80,
      protocol: 6,
      socket_fd: null
    },
    invalid: {
      destination_port: 999999
    }
  },
  NETWORK_CONNECT_RESULT: {
    valid: {
      socket_fd: 5,
      return_code: 0,
      errno: null,
      socket_state: 'TCP_ESTABLISHED'
    },
    incomplete: {
      return_code: -115,
      errno: 115,
      socket_state: 'TCP_SYN_SENT'
    },
    invalid: {
      socket_state: 'TCP_ESTABLISHED'
    }
  },
  NETWORK_SEND_ATTEMPT: {
    valid: {
      socket_fd: 5,
      destination_ip: '198.51.100.24',
      destination_port: 443,
      bytes_requested: 2048
    },
    incomplete: {
      bytes_requested: 1024
    },
    invalid: {
      bytes_requested: -1
    }
  },
  NETWORK_SEND_RESULT: {
    valid: {
      socket_fd: 5,
      bytes_accepted_by_kernel: 2048,
      return_code: 2048,
      destination_ip: '198.51.100.24',
      destination_port: 443,
      socket_state: 'TCP_ESTABLISHED',
      correlation_verdict: 'OUTBOUND_TRANSFER_CORRELATED'
    },
    incomplete: {
      bytes_accepted_by_kernel: 512,
      return_code: 512
    },
    invalid: {
      bytes_accepted_by_kernel: 'invalid_type'
    }
  },
  SOCKET_STATE_CHANGE: {
    valid: {
      socket_fd: 5,
      old_state: 'TCP_SYN_SENT',
      new_state: 'TCP_ESTABLISHED'
    },
    incomplete: {
      socket_fd: null,
      old_state: 'TCP_ESTABLISHED',
      new_state: 'TCP_CLOSE'
    },
    invalid: {
      old_state: ''
    }
  },
  IDENTITY_CHANGE: {
    valid: {
      old_uid: 1000,
      new_uid: 0,
      old_euid: 1000,
      new_euid: 0,
      mechanism: 'setuid'
    },
    incomplete: {
      old_uid: 0,
      new_uid: 1000,
      old_euid: 0,
      new_euid: 1000,
      mechanism: 'seteuid'
    },
    invalid: {
      mechanism: 'setuid'
    }
  },
  CAPABILITY_CHANGE: {
    valid: {
      capability: 'CAP_SYS_ADMIN',
      action: 'ADDED',
      cap_value: 21
    },
    incomplete: {
      capability: 'CAP_NET_RAW',
      action: 'DROPPED',
      cap_value: '0'
    },
    invalid: {
      capability: 'CAP_SYS_ADMIN',
      action: 'INVALID_ACTION'
    }
  },
  EVENT_LOSS: {
    valid: {
      loss_source: 'ebpf_kernel',
      dropped_count: 142,
      window_seconds: 1.0,
      scope: 'GLOBAL',
      cgroup_path: null
    },
    incomplete: {
      loss_source: 'tetragon_throttle',
      dropped_count: 15,
      window_seconds: 5.0,
      scope: 'CGROUP',
      cgroup_path: '/docker/abc'
    },
    invalid: {
      loss_source: 'unknown_source',
      dropped_count: 0
    }
  },
  SENSOR_HEALTH: {
    valid: {
      sensor_status: 'HEALTHY',
      uptime_seconds: 3600,
      heartbeat_timestamp: '1793628400000000000',
      active_tracing_policies: ['tp-network', 'tp-file']
    },
    incomplete: {
      sensor_status: 'DEGRADED',
      uptime_seconds: 120,
      heartbeat_timestamp: '1793628400000000000'
    },
    invalid: {
      sensor_status: 'INVALID_STATUS'
    }
  }
};

families.forEach((fam) => {
  const dirName = fam.toLowerCase();
  const targetDir = path.join(baseDir, dirName);
  fs.mkdirSync(targetDir, { recursive: true });

  const pData = familyPayloads[fam];

  // 1. Valid fixture
  const validEvent = createBaseEvent(fam, { payload: pData.valid });
  fs.writeFileSync(path.join(targetDir, 'valid.json'), JSON.stringify(validEvent, null, 2));

  // 2. Incomplete fixture (valid schema, but degraded/partial metadata)
  const incompleteEvent = createBaseEvent(fam, {
    completeness: 'DEGRADED',
    source_provider: 'synthetic_lab',
    process_identity: {
      exec_id: 'fallback_a1b2c3d4_8912_1793628300',
      parent_exec_id: null,
      pid: 8912,
      tid: 8912,
      process_start_time: '1793628300000000000',
      executable_path: '/usr/bin/python3',
      executable_digest: null,
      uid: 0,
      euid: 0,
      process_namespace: {
        pid_ns: '4026531836',
        mnt_ns: '4026531840',
        net_ns: '4026531845'
      },
      identity_quality: 'PARTIAL_ORPHAN'
    },
    payload: pData.incomplete,
    loss_metrics: {
      loss_ebpf_kernel: 142,
      loss_tetragon_throttle: 15,
      loss_grpc_transport: 0,
      loss_log_rotation: 0,
      loss_parser_reject: 0,
      loss_runtime_queue: 0,
      loss_storage_drop: 0
    }
  });
  fs.writeFileSync(path.join(targetDir, 'incomplete.json'), JSON.stringify(incompleteEvent, null, 2));

  // 3. Invalid fixture (violates schema)
  const invalidEvent = createBaseEvent(fam, { payload: pData.invalid });
  fs.writeFileSync(path.join(targetDir, 'invalid.json'), JSON.stringify(invalidEvent, null, 2));
});

console.log(`Successfully generated 3 fixtures across ${families.length} families (42 total JSON files).`);
