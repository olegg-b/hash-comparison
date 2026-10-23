# hash-bench

Benchmark comparing whole-file hashing approaches for file integrity verification.

## Candidates

| Algorithm | Library | Notes |
| --- | --- | --- |
| CRC-64/NVME | [aws-checksums v1.0.1](https://github.com/awslabs/aws-checksums) (+aws-c-common v1.0.3) | Hardware PCLMUL/AVX512/PMULL paths; `combine(crc1, crc2, len2)` composes independent checksums in byte order |
| XXH3-128 | [xxHash v0.8.4](https://github.com/Cyan4973/xxHash) | Runtime SIMD dispatch (SSE2/AVX2/AVX512), no composable combine |
| BLAKE3 (256-bit) | [BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3) | Cryptographic; canonical-tree parallelism not used here (single-threaded calls) |
| SHA-256 | OpenSSL 3.x | `EVP` API, SHA-NI accelerated; optional at build time (`libssl-dev`) |

## Modes

- `read` — sequential read only. IO baseline (page-cache warm by default, `--direct` for O_DIRECT cold-cache measurement).
- `inmem` — hash a page-cache-warmed mmap. Pure hashing cost with no extra IO. For crc64nvme the input is split into N worker chunks and the per-chunk checksums are combined in file order — this models hashing output buffers inside a pipeline (no second read). Other algorithms are one-shot single-threaded.
- `iohash` — sequential read + hash interleaved on one thread. The "separate pass with a full file read" cost.
- `iohash_pipe` — producer thread delivers chunks into a ring; hashing workers consume them. Parallel for crc64nvme (index-tagged results, folded in file order — pipeline-style arbitrary arrival order). Single in-order hasher for the non-composable algorithms (streaming state is inherently sequential). `--shuffle` has the producer deliver chunks in a random file order, showing that nondeterministic completion order does not change the final checksum.

Every mode prints the digest; for a given algorithm the digest must be identical across all modes — that invariant is exactly "the checksum does not depend on how the work was partitioned". `--selftest` verifies this plus CRC combine associativity and identity rules on a synthetic file.

## Build

```sh
./build.sh            # cmake + ninja/make, FetchContent downloads deps
cmake -B build -DCMAKE_BUILD_TYPE=Release -DNATIVE=ON  # optional -march=native
```

Dependencies are fetched at configure time from GitHub (network required). OpenSSL is optional: without it, `sha256` is disabled and the build still works.

## Usage

```sh
build/hash-bench FILE --mode all --algo all
build/hash-bench FILE --selftest
```

Options: `--algo all,crc64nvme,xxh3_128,blake3,sha256` · `--mode all,read,inmem,iohash,iohash_pipe` · `--threads N` (default: hardware concurrency) · `--chunk-mib N` (default 4) · `--repeat N` (default 3, reports best/median) · `--warmup N` (default 1: one untimed full read to warm the page cache) · `--direct` (O_DIRECT) · `--shuffle` · `--selftest`.

## How to use it and interpret the results

Each output line is `key=value` (greppable). The first line prints the CPU model, core count and the SIMD level xxHash dispatched to — check it before quoting numbers, and quote it with the numbers when comparing machines.

```sh
build/hash-bench FILE                          # everything, defaults
build/hash-bench FILE --selftest               # correctness first, always
build/hash-bench FILE --mode all --algo all --threads 16
build/hash-bench FILE --mode inmem,iohash,read --algo crc64nvme --threads 1   # CRC serial baseline
build/hash-bench FILE --mode read,iohash --direct --warmup 0   # cold-cache IO numbers
```

What to compare, and what each comparison decides:

| Comparison | Question it answers |
| --- | --- |
| `inmem` across algorithms | Pure hashing throughput per core-count. Is the composable CRC-64/NVME (with combine) competitive with XXH3/BLAKE3/SHA-256? |
| `inmem crc64nvme --threads 1` vs `--threads N` | Parallel scaling of the pipeline-style approach (per-chunk CRC + ordered combine). "Hashing must be quickly parallel" is verified here. |
| `read` vs `iohash` | Marginal cost of a separate full-file hashing pass. If `iohash ≈ read`, the pass is essentially free (hashing hides under IO). If `iohash ≫ read`, hashing dominates and an on-flight/parallel strategy matters. |
| `iohash_pipe` vs `iohash` | Value of overlapping reads with hashing threads. For crc64nvme, workers also process out of order (`--shuffle`) without changing the digest. |
| `--direct` vs default | Cold vs warm page cache. Warm matches "verify a file just written"; direct approximates verifying an old file from disk. |
| digest across modes | Must be identical per algorithm. This is the format-level guarantee "checksum independent of block boundaries/partitioning", verified empirically. |

What this benchmark deliberately does NOT tell you:

- CPU contention with a real writer workload (e.g., compression on CPU workers); hashing competes for CPU cycles there. Once a hash is picked, re-measure the writer pipeline end-to-end with the hash enabled.
- BLAKE3's canonical-tree multithreading (oneTBB path) — called single-threaded here on purpose.
- Multi-GB/s NVMe queue-depth effects beyond simple sequential reads.

Thread and chunk sweeps (thread scaling and IO buffer sensitivity):

```sh
for t in 1 2 4 8 16; do build/hash-bench FILE --mode inmem --algo crc64nvme --threads $t --repeat 1; done
for c in 1 4 16 64; do build/hash-bench FILE --mode iohash,read --chunk-mib $c --repeat 1; done
```

## Hyperfine matrix (suggested)

```sh
F=<your-file-or-big-file>
hyperfine --warmup 2 --min-runs 5 "build/hash-bench $F --mode read --repeat 1 --warmup 0"
for a in crc64nvme xxh3_128 blake3 sha256; do
  hyperfine --warmup 2 --min-runs 5 "build/hash-bench $F --mode inmem --algo $a --repeat 1 --warmup 0"
  hyperfine --warmup 2 --min-runs 5 "build/hash-bench $F --mode iohash --algo $a --repeat 1 --warmup 0"
  hyperfine --warmup 2 --min-runs 5 "build/hash-bench $F --mode iohash_pipe --algo $a --repeat 1 --warmup 0"
done
# parallel-in-memory CRC (pipeline-style, no second read):
hyperfine --warmup 2 --min-runs 5 "build/hash-bench $F --mode inmem --algo crc64nvme --repeat 1 --warmup 0"
```

`inmem` uses mmap, so arbitrarily large files are fine (pages must fit in the page cache for the numbers to represent pure in-memory hashing; otherwise it degrades to IO, which is honest). For reference numbers on NVMe, also run the `--direct` variants.

## Results table template

| Metric (GiB/s) | read | inmem | iohash | iohash_pipe |
| --- | --- | --- | --- | --- |
| crc64nvme (parallel/combine, N threads) | | | | |
| crc64nvme serial (`--threads 1`) | | | | |
| xxh3_128 | | | | |
| blake3 256 | | | | |
| sha256 | | | | |

Repeat on cold cache (`--direct`) in a second table if storage conclusions are needed.

## Notes

- CRC-64/NVME checksum convention (confirmed against an independent Python implementation and the `123456789` check value `0xae8b14860a799888`): reflected polynomial `0x9A6C9329AC4BC9B5`, init `0xFFFF…FFFF`, xorout `0xFFFF…FFFF`. `aws_checksums_crc64nvme_ex(data, len, prev)` continues a running checksum (zlib-style); `aws_checksums_crc64nvme_combine(crc1, crc2, len2)` returns the checksum of the concatenation, where `len2` is the byte length of the span hashed by `crc2` — when `crc2` is itself a summary of several ranges, pass their combined length.
- Zero is NOT a valid published checksum: the file format reserves all-zero for "absent checksum".
- BLAKE3 is called single-threaded here; its oneTBB path is out of scope.
- `iohash`/`iohash_pipe` default to page-cache-warm reads; use `--direct` for cold-cache numbers.

## Correctness verification performed

- `--selftest`: ALL PASS — per-algorithm digest equality across every mode (in-memory parallel, streaming, pipelined in-order, pipelined shuffled-producer), CRC combine associativity and identity on random 3-way splits of a 32 MiB file.
- CRC-64/NVME: matches aws-checksums' own CI vector (`KNOWN_CRC64NVME_TEST_VECTOR = 0xAE8B14860A799888` for `123456789`) and an independent Python bitwise implementation on random files (e.g. 1 MiB → `7e54c5c6fc7b946f`).
- XXH3-128: matches the official `xxhsum -H2` CLI on a 64 MiB random file (`7bfcd74158eb72d8871e7896200bb831`).
- BLAKE3-256: matches the official C implementation on a 700 KiB random file (`b3ff6127482d76b9489a1a6e1aee3a246d4e96dfc8309026a9d8e84b60535487`).
- Corruption detection: flipping a single byte changes the whole-file digest (e.g. `4396ac1437d5f569` → `4757e46e2680ab79`).
- SHA-256: compiled only when OpenSSL is present (install `libssl-dev`); verify with `sha256sum` once enabled.