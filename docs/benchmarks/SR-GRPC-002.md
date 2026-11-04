# SR-GRPC-002 — Tetragon v1.8.0 gRPC collector benchmark

**Status:** reproducible synthetic integration benchmark; not a production capacity claim.

## Results

Runs used Ubuntu 26.04 on WSL2 (`6.18.54.1-microsoft-standard-WSL2`), Node.js v24.21.0, x64, AMD Ryzen 3 7320U, Tetragon v1.8.0 protobuf definitions, a 128-event ledger batch, and a 64 MiB queue byte cap. The runs were sequential single measurements.

| Artifact | Events | Events/s | Elapsed | Peak sampled RSS | Local queue loss | Ledger records verified | Manifest SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---|
| [`SR-GRPC-002-10K-20261103.json`](../../bench/results/SR-GRPC-002-10K-20261103.json) | 10,000 | 3,293.71 | 3.04 s | 128,622,592 B | 0 | 10,082 | `d3a0bb9eb108a8fff98803a3ceb8ed750c21c61e6af6f1c41267608efc361892` |
| [`SR-GRPC-002-100K-20261103.json`](../../bench/results/SR-GRPC-002-100K-20261103.json) | 100,000 | 3,995.68 | 25.03 s | 227,151,872 B | 0 | 100,785 | `9736f77bfc755445fafe2a0f3ad51fd565fac196bd96c451ac4073b749249921` |

Both manifests passed seal verification, deterministic protobuf wire-corpus verification, and current source-tree hash verification. Each hashes all five vendored protobuf dependencies, along with the collector, normalizer, engine, ledger, benchmark harness, CLI, and dependency manifests. The worktree was dirty; the target Git revision is a base reference and the source hashes identify the measured code.

## Scope and limitations

The harness starts a loopback gRPC server using the vendored Tetragon v1.8.0 protobuf definitions and sends deterministic `PROCESS_EXEC` responses through the gRPC decoder, bounded collector queue, normalizer, correlation engine, and SQLite hash-chain ledger. The 100,000-event run persisted and verified the full corpus without local queue overflow.

These synthetic runs do not measure a Tetragon process, eBPF probes, kernel event generation, remote transport, sensor or kernel loss, or detection quality. Memory is sampled every 25 ms and may miss short peaks. The small sample count and WSL2 environment make the rates unsuitable as an SLO or production sizing claim. Repeat multiple runs on pinned Linux hosts with representative event mixes, load, policies, storage, and TLS before setting capacity targets.

## Reproduction

Use a new output path for each run; the harness refuses to overwrite a sealed artifact.

```powershell
$guard = 'C:/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js'
$revision = (git rev-parse HEAD).Trim()
wsl.exe -d Ubuntu -e /mnt/c/Users/sleyt/Documents/Codex/2026-11-02/est/work/wsl-node24.21.0/node-v24.21.0-linux-x64/bin/node --require=/mnt/c/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js /mnt/c/Users/sleyt/sentinel-runtime/bench/tetragon-grpc.js --revision $revision --events 10000 --output /mnt/c/Users/sleyt/sentinel-runtime/bench/results/SR-GRPC-002-10K-20261103.json
wsl.exe -d Ubuntu -e /mnt/c/Users/sleyt/Documents/Codex/2026-11-02/est/work/wsl-node24.21.0/node-v24.21.0-linux-x64/bin/node --require=/mnt/c/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js /mnt/c/Users/sleyt/sentinel-runtime/bench/tetragon-grpc.js --revision $revision --events 100000 --output /mnt/c/Users/sleyt/sentinel-runtime/bench/results/SR-GRPC-002-100K-20261103.json
wsl.exe -d Ubuntu -e /mnt/c/Users/sleyt/Documents/Codex/2026-11-02/est/work/wsl-node24.21.0/node-v24.21.0-linux-x64/bin/node --require=/mnt/c/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js /mnt/c/Users/sleyt/sentinel-runtime/bench/verify-tetragon-grpc.js /mnt/c/Users/sleyt/sentinel-runtime/bench/results/SR-GRPC-002-10K-20261103.json
wsl.exe -d Ubuntu -e /mnt/c/Users/sleyt/Documents/Codex/2026-11-02/est/work/wsl-node24.21.0/node-v24.21.0-linux-x64/bin/node --require=/mnt/c/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js /mnt/c/Users/sleyt/sentinel-runtime/bench/verify-tetragon-grpc.js /mnt/c/Users/sleyt/sentinel-runtime/bench/results/SR-GRPC-002-100K-20261103.json
```

The immutable SR-GRPC-001 artifacts remain the historical v1.7.1 benchmark. SR-GRPC-002 is the active v1.8.0 result set.
