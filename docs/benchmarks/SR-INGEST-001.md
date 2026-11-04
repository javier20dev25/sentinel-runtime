# SR-INGEST-001 — Offline ingestion and evidence ledger benchmark

**Run date:** 2026-11-02  
**Measured worktree:** `fb4c5d638810e6a63cd35f68c50f5740e8db8d75` plus the sealed source hashes in each result  
**Status:** reproducible engineering baseline; not a production capacity claim

## Scope

This benchmark measures the implemented offline path for deterministic, synthetic Tetragon-shaped `process_exec` JSONL records: bounded framing, duplicate-key rejection, JSON parsing, normalization, process correlation, batched SQLite evidence writes with `synchronous=FULL`, and a complete post-run hash-chain verification.

It does **not** measure an eBPF program, a live Tetragon gRPC stream, kernel event generation, unsupported event families, detection recall/precision, peer receipt of network bytes, active prevention, or multi-tenant operation. The generated corpus is shaped like the adapter's supported input; it is not a captured production trace or a public threat corpus.

## Environment and method

- Windows `10.0.26200`, Node.js `v24.20.0`, AMD Ryzen 3 7320U with Radeon Graphics.
- Ubuntu 26.04 on WSL2, Linux kernel `6.18.54.1-microsoft-standard-WSL2`, Node.js `v24.21.0` downloaded from the official Node.js release archive and checked against its published `SHASUMS256.txt` before execution. The source checkout was on `/mnt/c`; temporary SQLite databases were under the Linux `/tmp` filesystem. This is a Linux runtime smoke benchmark, not a dedicated Linux host result.
- File-backed SQLite, WAL, `synchronous=FULL`, foreign keys enabled.
- The 2,000-event runs used 250 warmup events and three measured repetitions. Reported throughput is the median; the range shows observed min/max.
- The 100,000-event runs used 1,000 warmup events and one measured repetition each. Treat these as directional sustained-load observations; repeat on deployment hardware before setting an SLO.
- The 100,000-event deterministic input is 26,684,000 bytes. Corpus generation is excluded from the timed pipeline. The benchmark records the corpus hash, source hashes, environment, stage timings, ledger head, and a SHA-256 manifest seal.
- The six manifests are historical snapshots from the earlier implementation phase. Their seals and generated corpora remain independently verifiable, but the current worktree has changed since then, so their source hashes are not a current-build match.

## Results

| Platform | Events | Batch | Repetitions | Median events/s | Observed range | Full ledger verify |
|---|---:|---:|---:|---:|---:|---:|
| Windows | 2,000 | 1 | 3 | 384.88 | 282.53–599.68 | 127 ms |
| Windows | 2,000 | 16 | 3 | 2,760.23 | 2,381.48–2,761.99 | 128 ms |
| Windows | 2,000 | 128 | 3 | 5,051.71 | 4,712.92–5,171.92 | 131 ms |
| Windows | 2,000 | 512 | 3 | 5,348.93 | 5,235.12–6,633.85 | 135 ms |
| Windows | 100,000 | 512 | 1 | 2,843.11 | single run | 6,063 ms |
| Windows | 100,000 | 4,096 | 1 | 3,773.60 | single run | 6,184 ms |
| Ubuntu on WSL2 | 100,000 | 128 | 1 | 4,715.24 | single run | 9,416 ms |

For the 100,000-event batch-4,096 run, measured ledger commit work was 18,789.63 ms: 4,171.11 ms canonicalization, 874.03 ms chain hashing, 4,766.03 ms SQLite inserts, and 7,648.79 ms commit time. Full integrity verification took another 6,184.41 ms. Stage subtotals are instrumentation measurements and need not sum exactly to wall-clock time because of measurement boundaries and runtime overhead.

The 2,000-event median increased about 13.1× from per-event commits to batches of 128. Going from 128 to 512 added only about 5.9% at this workload. At 100,000 events, a single batch-4,096 run was about 32.7% faster than the single batch-512 run. Larger batches improve throughput by amortizing durable commit cost but increase the maximum uncommitted window on process failure; batch 128 remains the default as an operational compromise, not a universally optimal setting.

## Sealed run artifacts

Each JSON file contains full per-run stage and ledger timings, corpus and source SHA-256 hashes, and its own canonical manifest seal.

| Artifact | Manifest SHA-256 |
|---|---|
| [`SR-INGEST-001-B1-20261102.json`](../../bench/results/SR-INGEST-001-B1-20261102.json) | `a32b33996c85ca6a28b090a7e688dac8cf2659efa00efb7a760cf8d77a1a9fe3` |
| [`SR-INGEST-001-B16-20261102.json`](../../bench/results/SR-INGEST-001-B16-20261102.json) | `6be94a8a5bc0ef2ebdd3a7475c8015ae5eab633af62679536f2226b7831fcf88` |
| [`SR-INGEST-001-B128-20261102.json`](../../bench/results/SR-INGEST-001-B128-20261102.json) | `0a42038b584f651ebbd378e24771c27eaa888fbfb5c024f6be5f74b1c63e6edf` |
| [`SR-INGEST-001-B512-20261102.json`](../../bench/results/SR-INGEST-001-B512-20261102.json) | `9b5ab690bf0e216d0ad424399cfd48c02f02c2459fbaba8031efab4e03b942e6` |
| [`SR-INGEST-001-B512-100K-20261102.json`](../../bench/results/SR-INGEST-001-B512-100K-20261102.json) | `13a849e8b086efc7de2e72fca23743dded24777a3f23b41efa81e751ebd0305e` |
| [`SR-INGEST-001-B4096-100K-20261102.json`](../../bench/results/SR-INGEST-001-B4096-100K-20261102.json) | `bb853f2ee7a82b81cda41f586d96d9d3863c668ac0ae434ac1cbacebc7af9922` |
| [`SR-INGEST-001-WSL-B128-100K-20261102.json`](../../bench/results/SR-INGEST-001-WSL-B128-100K-20261102.json) | `68fb02f84027170253cb6b4251631438e5b09b34464679f3277212994d4bc3e9` |

Re-run a configuration with the exact SHA of the target checkout:

```powershell
$guard = 'C:/Users/sleyt/Documents/Codex/2026-09-08/b/outputs/runtime-generalization/runtime-guard.js'
$revision = (git rev-parse HEAD).Trim()
node "--require=$guard" bench/runtime-ingest.js --revision $revision --events 2000 --warmup 250 --repetitions 3 --batch-size 128 --output bench/results/SR-INGEST-001-local.json
node "--require=$guard" bench/runtime-ingest.js --verify bench/results/SR-INGEST-001-local.json
```

The output path must not already exist. Use a new path for each run so the sealed evidence artifact is not overwritten.

## Interpretation and next benchmark gate

These measurements show that bounded batching materially improves this implementation's offline ledger throughput. They do not show how many events per second the future sensor can safely sustain or whether Sentinel detects real attacks. Before publishing a product capacity or detection claim, run repeated tests on pinned Linux hosts with the actual Tetragon collector, representative event mixes, loss injection, crash/replay scenarios, resource ceilings, and labeled public or internally authorized traces. Report false positives and false negatives separately from throughput.

The current collector has a separate loopback-wire benchmark in [`SR-GRPC-001.md`](SR-GRPC-001.md); it deliberately does not replace these offline JSONL results.
