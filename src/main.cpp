// hash-bench: compare whole-file hashing approaches for file integrity verification.
//
// Algorithms:
//   crc64nvme  CRC-64/NVME via aws-checksums, with combine() for parallel fold
//   xxh3_128   XXH3-128 via xxHash (runtime SIMD dispatch)
//   blake3     BLAKE3, 256-bit output, official C implementation
//   sha256     SHA-256 via OpenSSL EVP (optional at build time)
//
// Modes:
//   read        sequential read only; IO baseline
//   inmem       hash a page-cache-warm mmap; hashing cost with no extra IO.
//               crc64nvme uses N worker chunks + ordered combine fold (models
//               hashing output buffers in a pipeline, no second read).
//   iohash      sequential read + hash on one thread; the "separate pass" cost
//   iohash_pipe producer thread + hashing workers on a ring; parallel for
//               crc64nvme (index-tagged results folded in file order), single
//               in-order hasher for the non-composable algorithms

#include <CLI/CLI.hpp>

#define XXH_STATIC_LINKING_ONLY 1
#include <xxhash.h>
#include <xxh_x86dispatch.h>  // reroutes XXH3 entry points to the runtime dispatcher

#include <aws/checksums/crc.h>
#include <blake3.h>
#ifdef HASH_BENCH_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

enum class Algo { crc64nvme, xxh3_128, blake3, sha256 };
enum class Mode { read, inmem, iohash, iohash_pipe };

constexpr const char* algo_name(Algo a) {
    switch (a) {
        case Algo::crc64nvme: return "crc64nvme";
        case Algo::xxh3_128: return "xxh3_128";
        case Algo::blake3: return "blake3";
        case Algo::sha256: return "sha256";
    }
    return "?";
}

constexpr const char* mode_name(Mode m) {
    switch (m) {
        case Mode::read: return "READ";
        case Mode::inmem: return "INMEM";
        case Mode::iohash: return "IOHASH";
        case Mode::iohash_pipe: return "IOHASH_PIPE";
    }
    return "?";
}

struct Options {
    std::string file;
    std::vector<Algo> algos;
    std::vector<Mode> modes;
    int threads = 0;  // 0 = hardware_concurrency
    size_t chunk_mib = 4;
    int repeat = 3;
    int warmup = 1;
    bool direct = false;
    bool shuffle = false;
    bool selftest = false;
};

struct Digest {
    uint8_t bytes[32]{};
    size_t len = 0;

    bool operator==(const Digest& o) const {
        return len == o.len && std::memcmp(bytes, o.bytes, len) == 0;
    }
    bool operator!=(const Digest& o) const { return !(*this == o); }

    std::string hex() const {
        static const char* digits = "0123456789abcdef";
        std::string s;
        s.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            s.push_back(digits[bytes[i] >> 4]);
            s.push_back(digits[bytes[i] & 15]);
        }
        return s;
    }
};

void store_be64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = uint8_t(v >> (56 - 8 * i));
}

// ---------------------------------------------------------------- streaming

class StreamHasher {
public:
    virtual ~StreamHasher() = default;
    virtual void update(const uint8_t* p, size_t n) = 0;
    virtual Digest finalize() = 0;
};

class Crc64NvmeStream final : public StreamHasher {
public:
    void update(const uint8_t* p, size_t n) override {
        crc_ = aws_checksums_crc64nvme_ex(p, n, crc_);
    }
    Digest finalize() override {
        Digest d;
        d.len = 8;
        store_be64(d.bytes, crc_);
        return d;
    }

private:
    uint64_t crc_ = 0;
};

class Xxh3_128Stream final : public StreamHasher {
public:
    Xxh3_128Stream() : state_(XXH3_createState()) {
        if (!state_ || XXH3_128bits_reset(state_) != XXH_OK) throw std::runtime_error("xxh3 init");
    }
    ~Xxh3_128Stream() override { XXH3_freeState(state_); }
    void update(const uint8_t* p, size_t n) override {
        if (XXH3_128bits_update(state_, p, n) != XXH_OK) throw std::runtime_error("xxh3 update");
    }
    Digest finalize() override {
        XXH128_hash_t h = XXH3_128bits_digest(state_);
        Digest d;
        d.len = 16;
        store_be64(d.bytes, h.high64);
        store_be64(d.bytes + 8, h.low64);
        return d;
    }

private:
    XXH3_state_t* state_ = nullptr;
};

class Blake3Stream final : public StreamHasher {
public:
    Blake3Stream() { blake3_hasher_init(&state_); }
    void update(const uint8_t* p, size_t n) override { blake3_hasher_update(&state_, p, n); }
    Digest finalize() override {
        Digest d;
        d.len = 32;
        blake3_hasher_finalize(&state_, d.bytes, BLAKE3_OUT_LEN);
        return d;
    }

private:
    blake3_hasher state_{};
};

#ifdef HASH_BENCH_HAVE_OPENSSL
class Sha256Stream final : public StreamHasher {
public:
    Sha256Stream() : ctx_(EVP_MD_CTX_new()) {
        if (!ctx_ || EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("sha256 init");
        }
    }
    ~Sha256Stream() override { EVP_MD_CTX_free(ctx_); }
    void update(const uint8_t* p, size_t n) override {
        if (EVP_DigestUpdate(ctx_, p, n) != 1) throw std::runtime_error("sha256 update");
    }
    Digest finalize() override {
        Digest d;
        d.len = 32;
        unsigned int olen = 0;
        if (EVP_DigestFinal_ex(ctx_, d.bytes, &olen) != 1) throw std::runtime_error("sha256 final");
        return d;
    }

private:
    EVP_MD_CTX* ctx_ = nullptr;
};
#endif

std::unique_ptr<StreamHasher> make_stream_hasher(Algo a) {
    switch (a) {
        case Algo::crc64nvme: return std::make_unique<Crc64NvmeStream>();
        case Algo::xxh3_128: return std::make_unique<Xxh3_128Stream>();
        case Algo::blake3: return std::make_unique<Blake3Stream>();
        case Algo::sha256:
#ifdef HASH_BENCH_HAVE_OPENSSL
            return std::make_unique<Sha256Stream>();
#else
            throw std::runtime_error("sha256 disabled: built without OpenSSL");
#endif
    }
    throw std::logic_error("unreachable");
}

Digest one_shot(Algo a, const uint8_t* p, size_t n) {
    Digest d;
    switch (a) {
        case Algo::crc64nvme: {
            d.len = 8;
            store_be64(d.bytes, aws_checksums_crc64nvme_ex(p, n, 0));
            return d;
        }
        case Algo::xxh3_128: {
            XXH128_hash_t h = XXH3_128bits(p, n);
            d.len = 16;
            store_be64(d.bytes, h.high64);
            store_be64(d.bytes + 8, h.low64);
            return d;
        }
        case Algo::blake3: {
            blake3_hasher h;
            blake3_hasher_init(&h);
            blake3_hasher_update(&h, p, n);
            d.len = 32;
            blake3_hasher_finalize(&h, d.bytes, BLAKE3_OUT_LEN);
            return d;
        }
        case Algo::sha256:
#ifdef HASH_BENCH_HAVE_OPENSSL
        {
            d.len = 32;
            unsigned int olen = 0;
            if (EVP_Digest(p, n, d.bytes, &olen, EVP_sha256(), nullptr) != 1) {
                throw std::runtime_error("sha256 one-shot");
            }
            return d;
        }
#else
            throw std::runtime_error("sha256 disabled: built without OpenSSL");
#endif
    }
    throw std::logic_error("unreachable");
}

// ------------------------------------------------------------------ helpers

double now_s() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

uint64_t fold_sink(const uint8_t* p, size_t n, uint64_t s) {
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t x;
        std::memcpy(&x, p + i, 8);
        s ^= x;
        s *= 0x9e3779b97f4a7c15ULL;
    }
    if (i < n) {
        uint64_t x = 0;
        std::memcpy(&x, p + i, n - i);
        s ^= x;
        s *= 0x9e3779b97f4a7c15ULL;
    }
    return s;
}

volatile uint64_t g_sink = 0;

struct AlignedBuf {
    uint8_t* p = nullptr;
    explicit AlignedBuf(size_t n) {
        if (posix_memalign(reinterpret_cast<void**>(&p), 4096, n) != 0 || !p) {
            throw std::runtime_error("out of memory");
        }
    }
    ~AlignedBuf() { free(p); }
    AlignedBuf(const AlignedBuf&) = delete;
    AlignedBuf& operator=(const AlignedBuf&) = delete;
    uint8_t* get() const { return p; }
};

size_t pread_full(int fd, uint8_t* dst, size_t n, uint64_t off) {
    size_t done = 0;
    while (done < n) {
        ssize_t r = ::pread(fd, dst + done, n - done, static_cast<off_t>(off + done));
        if (r < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("pread failed: ") + std::strerror(errno));
        }
        if (r == 0) throw std::runtime_error("unexpected EOF");
        done += static_cast<size_t>(r);
    }
    return done;
}

// Sequential read pass; returns fold sink. Used for warmup and the READ mode.
uint64_t read_pass(int fd, size_t size, size_t chunk, uint8_t* buf, int fd_tail) {
    uint64_t sink = 0x123456789abcdefULL;
    size_t off = 0;
    while (off < size) {
        size_t n = std::min(chunk, size - off);
        bool tail = off + n == size && n % 4096 != 0;
        pread_full(tail && fd_tail >= 0 ? fd_tail : fd, buf, n, off);
        sink = fold_sink(buf, n, sink);
        off += n;
    }
    return sink;
}

// ---------------------------------------------------------------- file prep

struct FileCtx {
    std::string path;
    int fd = -1;         // normal fd
    int fd_direct = -1;  // O_DIRECT fd, -1 when unused
    size_t size = 0;
    uint8_t* map = nullptr;  // mmap for INMEM, nullptr otherwise

    ~FileCtx() {
        if (map) munmap(map, size);
        if (fd >= 0) close(fd);
        if (fd_direct >= 0) close(fd_direct);
    }
};

void open_file(FileCtx& f, const Options& o, bool need_map) {
    f.path = o.file;
    f.fd = ::open(o.file.c_str(), O_RDONLY);
    if (f.fd < 0) throw std::runtime_error(std::string("open failed: ") + std::strerror(errno));
    struct stat st{};
    if (::fstat(f.fd, &st) != 0) throw std::runtime_error("fstat failed");
    f.size = static_cast<size_t>(st.st_size);
    if (f.size == 0) throw std::runtime_error("file is empty");
    if (o.direct) {
        f.fd_direct = ::open(o.file.c_str(), O_RDONLY | O_DIRECT);
        if (f.fd_direct < 0) {
            throw std::runtime_error(std::string("O_DIRECT open failed: ") + std::strerror(errno));
        }
    }
    if (need_map) {
        void* m = mmap(nullptr, f.size, PROT_READ, MAP_PRIVATE, f.fd, 0);
        if (m == MAP_FAILED) throw std::runtime_error("mmap failed");
        f.map = static_cast<uint8_t*>(m);
    }
}

// ------------------------------------------------------------------- timing

struct RunResult {
    std::vector<double> times;
    Digest digest;
};

void report(const char* mode, const char* algo, int threads, size_t chunk_mib, size_t bytes,
            const RunResult& r, bool show_digest) {
    std::vector<double> t = r.times;
    std::sort(t.begin(), t.end());
    double best = t.front();
    double median = t[t.size() / 2];
    double gibps = static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0) / best;
    printf("mode=%-12s algo=%-9s threads=%-2d chunk_mib=%-3zu bytes=%-14zu best_s=%.4f "
           "median_s=%.4f gibps=%8.2f",
           mode, algo, threads, chunk_mib, bytes, best, median, gibps);
    if (show_digest) printf(" digest=%s", r.digest.hex().c_str());
    printf("\n");
    fflush(stdout);
}

// -------------------------------------------------------------------- modes

RunResult run_read(const Options& o, FileCtx& f, size_t chunk, uint8_t* buf) {
    RunResult r;
    int src = o.direct && f.fd_direct >= 0 ? f.fd_direct : f.fd;
    for (int rep = 0; rep < o.repeat; ++rep) {
        double t0 = now_s();
        g_sink ^= read_pass(src, f.size, chunk, buf, f.fd);
        r.times.push_back(now_s() - t0);
    }
    return r;
}

// Parallel CRC-64/NVME over disjoint index-tagged chunks of an mmap'd file +
// ordered combine fold. Workers may claim chunks out of order (thread
// scheduling); the fold is always in file-offset order, so the result equals
// the one-shot whole-file CRC.
Digest crc_parallel(const uint8_t* base, size_t size, size_t chunk, int workers) {
    const size_t nchunks = chunk >= size ? 1 : (size + chunk - 1) / chunk;
    workers = std::max(1, std::min<int>(workers, static_cast<int>(nchunks)));
    std::vector<uint64_t> crcs(nchunks);
    std::atomic<size_t> next{0};

    auto worker = [&] {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= nchunks) break;
            uint64_t off = i * chunk;
            size_t n = static_cast<size_t>(std::min<uint64_t>(chunk, size - off));
            crcs[i] = aws_checksums_crc64nvme_ex(base + off, n, 0);
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(workers);
    for (int w = 0; w < workers; ++w) pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    uint64_t acc = 0;
    for (size_t i = 0; i < nchunks; ++i) {
        size_t n = static_cast<size_t>(std::min<uint64_t>(chunk, size - i * chunk));
        acc = aws_checksums_crc64nvme_combine(acc, crcs[i], n);
    }

    Digest d;
    d.len = 8;
    store_be64(d.bytes, acc);
    return d;
}

RunResult run_inmem(const Options& o, FileCtx& f, Algo a, int threads) {
    RunResult r;
    const uint8_t* base = f.map;
    size_t size = f.size;

    if (a == Algo::crc64nvme && threads > 1) {
        size_t chunk = (size + threads * 4 - 1) / (threads * 4);
        chunk = (chunk + 4095) & ~size_t{4095};
        if (chunk == 0) chunk = 4096;
        for (int rep = 0; rep < o.repeat; ++rep) {
            double t0 = now_s();
            r.digest = crc_parallel(base, size, chunk, threads);
            r.times.push_back(now_s() - t0);
        }
        return r;
    }

    for (int rep = 0; rep < o.repeat; ++rep) {
        double t0 = now_s();
        r.digest = one_shot(a, base, size);
        r.times.push_back(now_s() - t0);
    }
    return r;
}

RunResult run_iohash(const Options& o, FileCtx& f, Algo a, size_t chunk, uint8_t* buf) {
    RunResult r;
    int src = o.direct && f.fd_direct >= 0 ? f.fd_direct : f.fd;
    for (int rep = 0; rep < o.repeat; ++rep) {
        auto hasher = make_stream_hasher(a);
        double t0 = now_s();
        size_t off = 0;
        while (off < f.size) {
            size_t n = std::min(chunk, f.size - off);
            bool tail = off + n == f.size && n % 4096 != 0;
            pread_full(tail && f.fd_direct >= 0 ? f.fd : src, buf, n, off);
            hasher->update(buf, n);
            off += n;
        }
        r.digest = hasher->finalize();
        r.times.push_back(now_s() - t0);
    }
    return r;
}

struct PipeSlot {
    std::unique_ptr<AlignedBuf> buf;
    size_t len = 0;
    std::atomic<uint64_t> state{UINT64_MAX};  // kFree or the chunk index it holds
    static constexpr uint64_t kFree = UINT64_MAX;
};

RunResult run_pipe(const Options& o, FileCtx& f, Algo a, size_t chunk, int threads) {
    RunResult r;
    const bool composable = a == Algo::crc64nvme;
    const size_t nchunks = f.size < chunk ? 1 : (f.size + chunk - 1) / chunk;
    const int workers = composable ? std::max(1, std::min(threads, static_cast<int>(nchunks))) : 1;
    const size_t nslots = std::min(nchunks, static_cast<size_t>(workers) + 1);

    std::vector<PipeSlot> slots(nslots);
    for (auto& s : slots) s.buf = std::make_unique<AlignedBuf>(chunk);

    // With --shuffle the producer delivers chunks in arbitrary file order
    // (models nondeterministic write/data-block completion). Workers hash in
    // arrival order; results stay index-tagged and are folded in file order.
    // Without it both producer and workers run in file order.
    std::vector<size_t> perm;
    if (composable && o.shuffle) {
        perm.resize(nchunks);
        std::iota(perm.begin(), perm.end(), 0);
        std::mt19937_64 rng{0x5eed};
        std::shuffle(perm.begin(), perm.end(), rng);
    }

    for (int rep = 0; rep < o.repeat; ++rep) {
        for (auto& s : slots) s.state = PipeSlot::kFree;

        auto hasher = make_stream_hasher(a);
        std::vector<uint64_t> crc_results(composable ? nchunks : 0);
        std::atomic<size_t> next{0};

        auto producer = [&] {
            int src = o.direct && f.fd_direct >= 0 ? f.fd_direct : f.fd;
            for (size_t k = 0; k < nchunks; ++k) {
                size_t chunk_idx = perm.empty() ? k : perm[k];
                PipeSlot& s = slots[k % nslots];
                while (s.state.load(std::memory_order_acquire) != PipeSlot::kFree) {
                    std::this_thread::yield();
                }
                uint64_t off = chunk_idx * chunk;
                size_t n = static_cast<size_t>(std::min<uint64_t>(chunk, f.size - off));
                bool tail = off + n == f.size && n % 4096 != 0;
                pread_full(tail && f.fd_direct >= 0 ? f.fd : src, s.buf->get(), n, off);
                s.len = n;
                s.state.store(chunk_idx, std::memory_order_release);
            }
        };

        using Clock = std::chrono::steady_clock;
        auto t0 = Clock::now();

        std::vector<std::thread> pool;
        pool.reserve(1 + workers);

        pool.emplace_back(producer);
        for (int w = 0; w < workers; ++w) {
            pool.emplace_back([&] {
                for (;;) {
                    size_t claim = next.fetch_add(1);
                    if (claim >= nchunks) break;
                    size_t chunk_idx = perm.empty() ? claim : perm[claim];
                    PipeSlot& s = slots[claim % nslots];
                    while (s.state.load(std::memory_order_acquire) != chunk_idx) {
                        std::this_thread::yield();
                    }
                    if (composable) {
                        crc_results[chunk_idx] =
                            aws_checksums_crc64nvme_ex(s.buf->get(), s.len, 0);
                    } else {
                        hasher->update(s.buf->get(), s.len);
                    }
                    s.state.store(PipeSlot::kFree, std::memory_order_release);
                }
            });
        }

        for (auto& t : pool) t.join();

        if (composable) {
            uint64_t acc = 0;
            for (size_t i = 0; i < nchunks; ++i) {
                size_t n = static_cast<size_t>(std::min<uint64_t>(chunk, f.size - i * chunk));
                acc = aws_checksums_crc64nvme_combine(acc, crc_results[i], n);
            }
            r.digest.len = 8;
            store_be64(r.digest.bytes, acc);
        } else {
            r.digest = hasher->finalize();
        }
        r.times.push_back(
            std::chrono::duration<double>(Clock::now() - t0).count());
    }
    return r;
}

// ----------------------------------------------------------------- selftest

bool selftest(const Options& o) {
    namespace fs = std::filesystem;
    const size_t kSize = 32u * 1024 * 1024;
    fs::path path = fs::temp_directory_path() / "hash-bench-selftest.bin";
    {
        std::vector<uint8_t> data(kSize);
        uint64_t x = 0x243f6a8885a308d3ULL;
        for (size_t i = 0; i < kSize; ++i) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data[i] = uint8_t(x >> 24);
        }
        FILE* fp = std::fopen(path.c_str(), "wb");
        if (!fp) {
            fprintf(stderr, "selftest: cannot write %s\n", path.c_str());
            return false;
        }
        std::fwrite(data.data(), 1, kSize, fp);
        std::fclose(fp);
    }

    bool ok = true;
    auto check = [&](const char* what, bool cond) {
        printf("  %-52s %s\n", what, cond ? "PASS" : "FAIL");
        ok = ok && cond;
    };

    std::vector<Algo> algos = {Algo::crc64nvme, Algo::xxh3_128, Algo::blake3};
#ifdef HASH_BENCH_HAVE_OPENSSL
    algos.push_back(Algo::sha256);
#endif

    Options so = o;
    so.file = path.string();
    so.direct = false;
    so.repeat = 1;
    so.warmup = 1;

    FileCtx f;
    open_file(f, so, true);
    AlignedBuf buf(4u * 1024 * 1024);
    int hw = static_cast<int>(std::thread::hardware_concurrency());
    if (so.threads > 0) hw = so.threads;

    std::mt19937_64 rng{12345};
    for (Algo a : algos) {
        Digest ref = one_shot(a, f.map, f.size);

        if (a == Algo::crc64nvme) {
            RunResult r = run_inmem(so, f, a, hw);
            check("inmem parallel combine == one-shot", r.digest == ref);
        }

        RunResult ri = run_iohash(so, f, a, 4u * 1024 * 1024, buf.get());
        check("iohash streaming == one-shot", ri.digest == ref);

        RunResult rp = run_pipe(so, f, a, 1024 * 1024, hw);
        check("pipe in-order == one-shot", rp.digest == ref);

        so.shuffle = true;
        RunResult rps = run_pipe(so, f, a, 1024 * 1024, hw);
        so.shuffle = false;
        check("pipe shuffled producer == one-shot", rps.digest == ref);

        if (a == Algo::crc64nvme) {
            // random 3-way split: (A||B||C) via combine, associativity, identity
            for (int t = 0; t < 8; ++t) {
                size_t p1 = size_t(rng() % (kSize + 1));
                size_t p2 = size_t(rng() % (kSize + 1));
                size_t s1 = std::min(p1, p2), s2 = std::max(p1, p2);
                uint64_t c1 = aws_checksums_crc64nvme_ex(f.map, s1, 0);
                uint64_t c2 = aws_checksums_crc64nvme_ex(f.map + s1, s2 - s1, 0);
                uint64_t c3 = aws_checksums_crc64nvme_ex(f.map + s2, kSize - s2, 0);
                uint64_t left = aws_checksums_crc64nvme_combine(
                    aws_checksums_crc64nvme_combine(c1, c2, s2 - s1), c3, kSize - s2);
                // Combining a summary that itself spans multiple ranges: the
                // length argument is the total span of the second argument.
                uint64_t right = aws_checksums_crc64nvme_combine(
                    c1,
                    aws_checksums_crc64nvme_combine(c2, c3, kSize - s2),
                    (s2 - s1) + (kSize - s2));
                uint64_t whole = aws_checksums_crc64nvme_ex(f.map, kSize, 0);
                check("crc combine assoc + 3-way split == whole", left == right && left == whole);
            }
            uint64_t c = aws_checksums_crc64nvme_ex(f.map, kSize, 0);
            check("crc combine empty identity",
                  aws_checksums_crc64nvme_combine(c, 0, 0) == c &&
                      aws_checksums_crc64nvme_combine(0, c, kSize) == c);
        }
    }
    printf("selftest: %s\n", ok ? "ALL PASS" : "FAILED");
    return ok;
}

// -------------------------------------------------------------------- main

}  // namespace

int main(int argc, char** argv) {
    Options o;
    CLI::App app{"hash-bench: compare whole-file hashing approaches"};

    std::string algos = "all";
    std::string modes = "all";
    app.add_option("FILE", o.file, "input file")
        ->check(CLI::ExistingFile)
        ->required(false)
        ->capture_default_str();
    app.add_option("--algo", algos,
                   "csv: all,crc64nvme,xxh3_128,blake3,sha256"
#ifdef HASH_BENCH_HAVE_OPENSSL
    );
#else
                   " (sha256 disabled: built without OpenSSL)");
#endif
    app.add_option("--mode", modes, "csv: all,read,inmem,iohash,iohash_pipe");
    app.add_option("--threads", o.threads, "worker threads (0 = hardware concurrency)");
    app.add_option("--chunk-mib", o.chunk_mib, "IO chunk size in MiB")->capture_default_str();
    app.add_option("--repeat", o.repeat, "timed repetitions per run")->capture_default_str();
    app.add_option("--warmup", o.warmup, "untimed warmup passes (page cache)")
        ->capture_default_str();
    app.add_flag("--direct", o.direct, "use O_DIRECT (cold cache) for read/iohash/pipe");
    app.add_flag("--shuffle", o.shuffle, "iohash_pipe: workers claim chunks out of order");
    app.add_flag("--selftest", o.selftest, "run correctness self-test and exit");

    CLI11_PARSE(app, argc, argv);

    try {
        if (o.selftest) return selftest(o) ? 0 : 1;
        if (o.file.empty()) throw std::runtime_error("missing FILE (or use --selftest)");

        std::vector<Algo> algos_sel;
        std::vector<Mode> modes_sel;
        auto parse_algo = [&](const std::string& s) {
            if (s == "all") {
                algos_sel = {Algo::crc64nvme, Algo::xxh3_128, Algo::blake3};
#ifdef HASH_BENCH_HAVE_OPENSSL
                algos_sel.push_back(Algo::sha256);
#endif
            } else if (s == "crc64nvme") algos_sel.push_back(Algo::crc64nvme);
            else if (s == "xxh3_128") algos_sel.push_back(Algo::xxh3_128);
            else if (s == "blake3") algos_sel.push_back(Algo::blake3);
            else if (s == "sha256") {
#ifdef HASH_BENCH_HAVE_OPENSSL
                algos_sel.push_back(Algo::sha256);
#else
                throw std::runtime_error("sha256 disabled: built without OpenSSL");
#endif
            } else throw std::runtime_error("unknown algo: " + s);
        };
        auto parse_mode = [&](const std::string& s) {
            if (s == "all") modes_sel = {Mode::read, Mode::inmem, Mode::iohash, Mode::iohash_pipe};
            else if (s == "read") modes_sel.push_back(Mode::read);
            else if (s == "inmem") modes_sel.push_back(Mode::inmem);
            else if (s == "iohash") modes_sel.push_back(Mode::iohash);
            else if (s == "iohash_pipe") modes_sel.push_back(Mode::iohash_pipe);
            else throw std::runtime_error("unknown mode: " + s);
        };
        {
            std::string item;
            std::istringstream as(algos);
            while (std::getline(as, item, ',')) if (!item.empty()) parse_algo(item);
            std::istringstream ms(modes);
            while (std::getline(ms, item, ',')) if (!item.empty()) parse_mode(item);
        }
        o.algos = algos_sel;
        o.modes = modes_sel;
        if (o.algos.empty() || o.modes.empty()) throw std::runtime_error("empty --algo or --mode");

        int hw = o.threads > 0 ? o.threads : static_cast<int>(std::thread::hardware_concurrency());
        if (hw < 1) hw = 1;

        FileCtx f;
        bool need_map = std::find(o.modes.begin(), o.modes.end(), Mode::inmem) != o.modes.end();
        if (need_map && o.direct) {
            throw std::runtime_error("--direct is incompatible with inmem (mapping is page cache)");
        }
        open_file(f, o, need_map);

        size_t chunk = o.chunk_mib * 1024 * 1024;
        AlignedBuf buf(chunk);

        {
            std::string cpu_model;
            std::ifstream cpuinfo("/proc/cpuinfo");
            if (cpuinfo) {
                std::string line;
                while (std::getline(cpuinfo, line)) {
                    if (line.rfind("model name", 0) == 0) {
                        size_t colon = line.find(':');
                        if (colon != std::string::npos) {
                            cpu_model = line.substr(colon + 2);
                            break;
                        }
                    }
                }
            }
            const char* xxh_level = "?";
            switch (XXH_featureTest()) {
                case 0: xxh_level = "scalar"; break;
                case 1: xxh_level = "SSE2"; break;
                case 2: xxh_level = "AVX2"; break;
                case 3: xxh_level = "AVX512"; break;
            }
            printf("# cpu%s%s hw_concurrency=%d xxh3_dispatch=%s\n", cpu_model.empty() ? "" : " model=",
                   cpu_model.c_str(), hw, xxh_level);
        }

        for (Mode m : o.modes) {
            // One warmup pass per mode (page cache), untimed.
            for (int w = 0; w < o.warmup; ++w) {
                if (m == Mode::inmem) {
                    uint64_t sink = 0;
                    for (size_t off = 0; off < f.size; off += 4096) {
                        sink = fold_sink(f.map + off, std::min<size_t>(4096, f.size - off), sink);
                    }
                    g_sink ^= sink;
                } else {
                    int src = o.direct && f.fd_direct >= 0 ? f.fd_direct : f.fd;
                    g_sink ^= read_pass(src, f.size, chunk, buf.get(), f.fd);
                }
            }

            if (m == Mode::read) {
                RunResult r = run_read(o, f, chunk, buf.get());
                report(mode_name(m), "none", 1, o.chunk_mib, f.size, r, false);
                continue;
            }
            for (Algo a : o.algos) {
                RunResult r;
                switch (m) {
                    case Mode::inmem: r = run_inmem(o, f, a, hw); break;
                    case Mode::iohash: r = run_iohash(o, f, a, chunk, buf.get()); break;
                    case Mode::iohash_pipe: r = run_pipe(o, f, a, chunk, hw); break;
                    case Mode::read: break;
                }
                report(mode_name(m), algo_name(a), hw, o.chunk_mib, f.size, r, true);
            }
        }
        printf("# note: digest must be identical for the same algo across modes\n");
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}
