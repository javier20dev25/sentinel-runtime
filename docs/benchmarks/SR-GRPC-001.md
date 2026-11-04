# SR-GRPC-001 — Tetragon protobuf collector benchmark

**Status:** reproducible synthetic integration benchmark; not a production capacity claim.

## Results

Both runs used Ubuntu 26.04 on WSL2 (`6.18.54.1-microsoft-standard-WSL2`), Node.js v24.21.0, x64, AMD Ryzen 3 7320U, Tetragon v1.7.1 wire definitions, a 128-event ledger batch, and a 64 MiB queue byte cap. Each is a single run.

| Artifact | Events | Events/s | Elapsed | Peak sampled RSS | Queue loss | Ledger records verified | Manifest SHA-256 |
|---|---:|---:|---:|---:|---:|---:|---|
| [`SR-GRPC-001-10K-R2-20261102.json`](../../bench/results/SR-GRPC-001-10K-R2-20261102.json) | 10,000 | 3,577.52 | 2.80 s | 157,425,664 B | 0 | 10,082 | `e9afe557794f49268ebb9b5d86f37135ca15e5d8f2cae84afa5cc0b4767de4cd` |
| [`SR-GRPC-001-100K-R2-20261102.json`](../../bench/results/SR-GRPC-001-100K-R2-20261102.json) | 100,000 | 1,175.66 | 85.06 s | 224,026,624 B | 0 | 100,787 | `ff09b92f368744041b907dcdceb55327e02987bd835e626f407a7d83e7bd18f2` |

## Scope

The harness starts a loopback gRPC server using the vendored Tetragon v1.7.1 protobuf definitions and sends deterministic `PROCESS_EXEC` responses through the real gRPC decoder, bounded collector queue, normalizer, correlation engine, and SQLite hash-chain ledger. Each run records the encoded wire corpus hash, source-file hashes, resource sample, event counts, and ledger head.

The elapsed time includes server-side protobuf generation and local gRPC transmission. The benchmark does not run Tetragon, an eBPF program, or a Linux kernel sensor; it does not measure detection precision/recall, loss under real host load, or upstream service behavior. Memory is sampled every 25 ms and can miss short peaks. Run on a pinned Linux host before setting production limits.

## Run

Use a new output path for each run. The harness refuses to overwrite a sealed artifact.

```powershell
$guard = 'C:/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js'
$revision = (git rev-parse HEAD).Trim()
node "--require=$guard" bench/tetragon-grpc.js --revision $revision --events 10000 --output bench/results/SR-GRPC-001-10K-R2-20261102.json
node "--require=$guard" bench/tetragon-grpc.js --revision $revision --events 100000 --output bench/results/SR-GRPC-001-100K-R2-20261102.json
node "--require=$guard" bench/verify-tetragon-grpc.js bench/results/SR-GRPC-001-10K-R2-20261102.json
node "--require=$guard" bench/verify-tetragon-grpc.js bench/results/SR-GRPC-001-100K-R2-20261102.json
```

The artifact's `manifest_sha256` seals its canonical JSON. `source_hashes` cover the benchmark harness, CLI, collector, normalizer, engine, evidence ledger, dependencies, and pinned protobuf files. `measured_worktree_dirty` is true because these results are captured before commit; `target_revision` names the base Git revision, while source hashes identify the actual measured files.

At creation, both final-source manifests had valid seals and wire corpora, and their recorded source hashes matched the v1.7.1 worktree. The active collector has since moved to v1.8.0; the retained source hashes intentionally differ from the current runtime files. Throughput varied substantially between the initial and final-source 100,000-event runs on WSL2, so these single-run numbers are noisy and not an SLO. The final-source 100,000-event run persisted all events and verified 100,787 ledger records without local queue overflow. It does not show zero kernel or network loss because no Tetragon sensor or kernel was producing the data. The low final-source result is a concrete performance gate: repeat and profile on a pinned Linux host, then tune batch and queue settings before making capacity claims.

