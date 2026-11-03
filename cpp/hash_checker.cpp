#include "hash_checker.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <fstream>
#include <stdexcept>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <cpuid.h>
#include <immintrin.h>
#define ATTT_X86_SIMD 1
#else
#define ATTT_X86_SIMD 0
#endif

namespace hash_checker {

namespace {

bool g_sha_ni_enabled = true;

inline std::uint32_t rotr32(std::uint32_t x, unsigned int n) noexcept {
    return (x >> n) | (x << (32U - n));
}

inline std::uint64_t rotl64(std::uint64_t x, unsigned int n) noexcept {
    return (x << n) | (x >> (64U - n));
}

std::string bytes_to_hex(const std::uint8_t* bytes, std::size_t len) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out(len * 2, '\0');
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i]     = HEX[(bytes[i] >> 4) & 0x0FU];
        out[2 * i + 1] = HEX[bytes[i] & 0x0FU];
    }
    return out;
}

std::string trim_ascii(const std::string& s) {
    std::size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    std::size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

constexpr std::uint32_t SHA256_K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

void sha256_transform_soft(std::uint32_t state[8], const std::uint8_t* data, std::size_t num_blocks) noexcept {
    for (std::size_t blk = 0; blk < num_blocks; ++blk, data += 64) {
        std::uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<std::uint32_t>(data[4 * i]) << 24) |
                   (static_cast<std::uint32_t>(data[4 * i + 1]) << 16) |
                   (static_cast<std::uint32_t>(data[4 * i + 2]) << 8) |
                   (static_cast<std::uint32_t>(data[4 * i + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
            std::uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
            W[i] = W[i - 16] + s0 + W[i - 7] + s1;
        }

        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

        for (int i = 0; i < 64; ++i) {
            std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            std::uint32_t ch = (e & f) ^ ((~e) & g);
            std::uint32_t temp1 = h + S1 + ch + SHA256_K[i] + W[i];
            std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
}

#if ATTT_X86_SIMD && defined(__SHA__)
void sha256_transform_shani(std::uint32_t state[8], const std::uint8_t* data, std::size_t num_blocks) noexcept {
    const __m128i shuf_mask = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    __m128i tmp = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[0]));
    __m128i st1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&state[4]));
    tmp = _mm_shuffle_epi32(tmp, 0xB1);
    st1 = _mm_shuffle_epi32(st1, 0x1B);
    __m128i st0 = _mm_alignr_epi8(tmp, st1, 8);
    st1 = _mm_blend_epi16(st1, tmp, 0xF0);

    for (std::size_t blk = 0; blk < num_blocks; ++blk, data += 64) {
        __m128i abef_save = st0;
        __m128i cdgh_save = st1;

        __m128i msg0 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data +  0)), shuf_mask);
        __m128i msg1 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 16)), shuf_mask);
        __m128i msg2 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 32)), shuf_mask);
        __m128i msg3 = _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i*>(data + 48)), shuf_mask);

        __m128i wk;
        #define SHA256_RNDS4(m_cur, k_idx) \
            wk = _mm_add_epi32(m_cur, _mm_loadu_si128(reinterpret_cast<const __m128i*>(&SHA256_K[k_idx]))); \
            st1 = _mm_sha256rnds2_epu32(st1, st0, wk); \
            wk = _mm_shuffle_epi32(wk, 0x0E); \
            st0 = _mm_sha256rnds2_epu32(st0, st1, wk)

        SHA256_RNDS4(msg0,  0);
        SHA256_RNDS4(msg1,  4);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);
        SHA256_RNDS4(msg2,  8);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        SHA256_RNDS4(msg3, 12);
        msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        SHA256_RNDS4(msg0, 16);
        msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        SHA256_RNDS4(msg1, 20);
        msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        SHA256_RNDS4(msg2, 24);
        msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        SHA256_RNDS4(msg3, 28);
        msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        SHA256_RNDS4(msg0, 32);
        msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        SHA256_RNDS4(msg1, 36);
        msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        SHA256_RNDS4(msg2, 40);
        msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        SHA256_RNDS4(msg3, 44);
        msg0 = _mm_add_epi32(msg0, _mm_alignr_epi8(msg3, msg2, 4));
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        SHA256_RNDS4(msg0, 48);
        msg1 = _mm_add_epi32(msg1, _mm_alignr_epi8(msg0, msg3, 4));
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        SHA256_RNDS4(msg1, 52);
        msg2 = _mm_add_epi32(msg2, _mm_alignr_epi8(msg1, msg0, 4));
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);

        SHA256_RNDS4(msg2, 56);
        msg3 = _mm_add_epi32(msg3, _mm_alignr_epi8(msg2, msg1, 4));
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);

        SHA256_RNDS4(msg3, 60);
        #undef SHA256_RNDS4

        st0 = _mm_add_epi32(st0, abef_save);
        st1 = _mm_add_epi32(st1, cdgh_save);
    }

    tmp = _mm_shuffle_epi32(st0, 0x1B);
    st1 = _mm_shuffle_epi32(st1, 0xB1);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[0]), _mm_blend_epi16(tmp, st1, 0xF0));
    _mm_storeu_si128(reinterpret_cast<__m128i*>(&state[4]), _mm_alignr_epi8(st1, tmp, 8));
}
#endif

class Sha256Hasher {
public:
    Sha256Hasher() noexcept { reset(); }

    void reset() noexcept {
        state_[0] = 0x6a09e667UL; state_[1] = 0xbb67ae85UL;
        state_[2] = 0x3c6ef372UL; state_[3] = 0xa54ff53aUL;
        state_[4] = 0x510e527fUL; state_[5] = 0x9b05688cUL;
        state_[6] = 0x1f83d9abUL; state_[7] = 0x5be0cd19UL;
        total_bytes_ = 0;
        buf_len_ = 0;
        use_shani_ = g_sha_ni_enabled && cpu_supports_sha_ni();
    }

    void update(const std::uint8_t* data, std::size_t len) noexcept {
        if (len == 0) return;
        total_bytes_ += len;
        if (buf_len_ > 0) {
            std::size_t take = std::min<std::size_t>(64 - buf_len_, len);
            std::memcpy(buf_ + buf_len_, data, take);
            buf_len_ += take;
            data += take;
            len -= take;
            if (buf_len_ == 64) {
                transform(buf_, 1);
                buf_len_ = 0;
            }
        }
        if (len >= 64) {
            std::size_t blocks = len / 64;
            transform(data, blocks);
            data += blocks * 64;
            len -= blocks * 64;
        }
        if (len > 0) {
            std::memcpy(buf_, data, len);
            buf_len_ = len;
        }
    }

    std::string hexdigest() noexcept {
        std::uint64_t total_bits = total_bytes_ * 8ULL;
        buf_[buf_len_++] = 0x80U;
        if (buf_len_ > 56) {
            std::memset(buf_ + buf_len_, 0, 64 - buf_len_);
            transform(buf_, 1);
            buf_len_ = 0;
        }
        std::memset(buf_ + buf_len_, 0, 56 - buf_len_);
        for (int i = 0; i < 8; ++i) {
            buf_[56 + i] = static_cast<std::uint8_t>((total_bits >> (56 - 8 * i)) & 0xFFU);
        }
        transform(buf_, 1);

        std::uint8_t out[32];
        for (int i = 0; i < 8; ++i) {
            out[4 * i]     = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFFU);
            out[4 * i + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFFU);
            out[4 * i + 2] = static_cast<std::uint8_t>((state_[i] >>  8) & 0xFFU);
            out[4 * i + 3] = static_cast<std::uint8_t>(state_[i] & 0xFFU);
        }
        return bytes_to_hex(out, 32);
    }

private:
    void transform(const std::uint8_t* data, std::size_t blocks) noexcept {
#if ATTT_X86_SIMD && defined(__SHA__)
        if (use_shani_) {
            sha256_transform_shani(state_, data, blocks);
            return;
        }
#endif
        sha256_transform_soft(state_, data, blocks);
    }

    std::uint32_t state_[8]{};
    std::uint8_t buf_[64]{};
    std::uint64_t total_bytes_ = 0;
    std::size_t buf_len_ = 0;
    bool use_shani_ = false;
};

constexpr std::uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

constexpr unsigned int KECCAK_RHO[24] = {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

constexpr int KECCAK_PI[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

void keccak_f1600(std::uint64_t A[25]) noexcept {
    for (int round = 0; round < 24; ++round) {
        std::uint64_t C[5], D[5];
        #pragma GCC unroll 5
        for (int x = 0; x < 5; ++x) {
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        }
        #pragma GCC unroll 5
        for (int x = 0; x < 5; ++x) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        #pragma GCC unroll 25
        for (int i = 0; i < 25; ++i) {
            A[i] ^= D[i % 5];
        }

        std::uint64_t current = A[1];
        #pragma GCC unroll 24
        for (int i = 0; i < 24; ++i) {
            int j = KECCAK_PI[i];
            std::uint64_t tmp = A[j];
            A[j] = rotl64(current, KECCAK_RHO[i]);
            current = tmp;
        }

        #pragma GCC unroll 5
        for (int y = 0; y < 25; y += 5) {
            std::uint64_t t0 = A[y + 0], t1 = A[y + 1], t2 = A[y + 2], t3 = A[y + 3], t4 = A[y + 4];
            A[y + 0] = t0 ^ ((~t1) & t2);
            A[y + 1] = t1 ^ ((~t2) & t3);
            A[y + 2] = t2 ^ ((~t3) & t4);
            A[y + 3] = t3 ^ ((~t4) & t0);
            A[y + 4] = t4 ^ ((~t0) & t1);
        }

        A[0] ^= KECCAK_RC[round];
    }
}

class Sha3_256Hasher {
public:
    static constexpr std::size_t RATE_BYTES = 136;

    Sha3_256Hasher() noexcept { reset(); }

    void reset() noexcept {
        std::memset(state_, 0, sizeof(state_));
        std::memset(buf_, 0, sizeof(buf_));
        buf_len_ = 0;
    }

    void update(const std::uint8_t* data, std::size_t len) noexcept {
        if (len == 0) return;
        if (buf_len_ > 0) {
            std::size_t take = std::min<std::size_t>(RATE_BYTES - buf_len_, len);
            std::memcpy(buf_ + buf_len_, data, take);
            buf_len_ += take;
            data += take;
            len -= take;
            if (buf_len_ == RATE_BYTES) {
                absorb_block(buf_);
                buf_len_ = 0;
            }
        }
        while (len >= RATE_BYTES) {
            absorb_block(data);
            data += RATE_BYTES;
            len -= RATE_BYTES;
        }
        if (len > 0) {
            std::memcpy(buf_, data, len);
            buf_len_ = len;
        }
    }

    std::string hexdigest() noexcept {
        std::memset(buf_ + buf_len_, 0, RATE_BYTES - buf_len_);
        buf_[buf_len_] ^= 0x06U;
        buf_[RATE_BYTES - 1] ^= 0x80U;
        absorb_block(buf_);

        std::uint8_t out[32];
        std::memcpy(out, state_, 32);
        return bytes_to_hex(out, 32);
    }

private:
    void absorb_block(const std::uint8_t* block) noexcept {
        const auto* lanes = reinterpret_cast<const std::uint64_t*>(block);
        for (std::size_t i = 0; i < RATE_BYTES / 8; ++i) {
            state_[i] ^= lanes[i];
        }
        keccak_f1600(state_);
    }

    std::uint64_t state_[25]{};
    std::uint8_t buf_[RATE_BYTES]{};
    std::size_t buf_len_ = 0;
};

} // namespace

bool cpu_supports_sha_ni() noexcept {
#if ATTT_X86_SIMD
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & (1U << 29)) != 0;
    }
#endif
    return false;
}

void set_sha_ni_enabled(bool enabled) noexcept {
    g_sha_ni_enabled = enabled;
}

bool is_sha_ni_enabled() noexcept {
    return g_sha_ni_enabled;
}

std::string canonical_algorithm_name(const std::string& algorithm) {
    std::string trimmed = trim_ascii(algorithm);
    std::string lower(trimmed.size(), '\0');
    std::transform(trimmed.begin(), trimmed.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "sha-256" || lower == "sha256") {
        return "SHA-256";
    }
    if (lower == "sha3-256" || lower == "sha3_256") {
        return "SHA3-256";
    }
    throw std::invalid_argument("Unsupported hash algorithm: " + algorithm + ". Choose SHA-256 or SHA3-256.");
}

bool constant_time_equal(const std::string& a, const std::string& b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    volatile unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

std::string compute_digest_bytes(const std::uint8_t* data, std::size_t len, const std::string& algorithm) {
    std::string alg = canonical_algorithm_name(algorithm);
    if (alg == "SHA-256") {
        Sha256Hasher hasher;
        hasher.update(data, len);
        return hasher.hexdigest();
    }
    Sha3_256Hasher hasher;
    hasher.update(data, len);
    return hasher.hexdigest();
}

std::string compute_digest_bytes(const std::vector<std::uint8_t>& data, const std::string& algorithm) {
    return compute_digest_bytes(data.data(), data.size(), algorithm);
}

std::string compute_digest_file(
    const std::filesystem::path& file_path,
    const std::string& algorithm,
    std::size_t chunk_size
) {
    std::string alg = canonical_algorithm_name(algorithm);
    std::ifstream f(file_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot open file for hashing: " + file_path.string());
    }
    std::vector<std::uint8_t> buf(chunk_size > 0 ? chunk_size : DEFAULT_CHUNK_SIZE);
    if (alg == "SHA-256") {
        Sha256Hasher hasher;
        while (f) {
            f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
            std::streamsize got = f.gcount();
            if (got > 0) {
                hasher.update(buf.data(), static_cast<std::size_t>(got));
            }
        }
        return hasher.hexdigest();
    }
    Sha3_256Hasher hasher;
    while (f) {
        f.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = f.gcount();
        if (got > 0) {
            hasher.update(buf.data(), static_cast<std::size_t>(got));
        }
    }
    return hasher.hexdigest();
}

std::vector<std::uint8_t> read_raw_bytes(const std::filesystem::path& file_path) {
    std::ifstream f(file_path, std::ios::binary | std::ios::ate);
    if (!f) {
        throw std::runtime_error("Cannot open file: " + file_path.string());
    }
    auto end_pos = f.tellg();
    if (end_pos <= 0) {
        return {};
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(end_pos));
    f.seekg(0, std::ios::beg);
    f.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
    return data;
}

std::string read_digest_file(const std::filesystem::path& digest_path) {
    std::ifstream f(digest_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot open digest file: " + digest_path.string());
    }
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string text = trim_ascii(content);
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (text.size() != 64) {
        throw std::invalid_argument("Invalid 256-bit hex digest length in " + digest_path.string());
    }
    for (char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            throw std::invalid_argument("Invalid hex character in " + digest_path.string());
        }
    }
    return text;
}

VerificationResult verify_bytes(
    const std::vector<std::uint8_t>& payload_bytes,
    const std::string& expected_digest,
    const std::string& algorithm,
    const std::string& digest_source,
    bool metadata_changed
) {
    std::string alg = canonical_algorithm_name(algorithm);
    std::string clean_expected = trim_ascii(expected_digest);
    std::transform(clean_expected.begin(), clean_expected.end(), clean_expected.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto t0 = std::chrono::steady_clock::now();
    std::string computed = compute_digest_bytes(payload_bytes, alg);
    bool matched = constant_time_equal(computed, clean_expected);
    auto t1 = std::chrono::steady_clock::now();
    auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

    std::string status;
    std::string note;
    if (!matched) {
        status = "REJECT";
        note = "Digest mismatch: payload bytes differ from reference digest.";
    } else if (digest_source == "UNTRUSTED_CHANNEL") {
        status = "ACCEPT_UNTRUSTED";
        note = "Digest matches recalculated value from untrusted channel; plain hash cannot detect simultaneous replacement of payload and digest.";
    } else if (metadata_changed) {
        status = "ACCEPT_METADATA_OUTSIDE_SCOPE";
        note = "File digest matches reference; external metadata is outside file-only hash scope.";
    } else {
        status = "ACCEPT";
        note = "Digest matches trusted reference.";
    }

    return VerificationResult{
        alg,
        computed,
        clean_expected,
        matched,
        digest_source,
        metadata_changed,
        status,
        elapsed_ns,
        note
    };
}

int hamming_distance_hex(const std::string& hex_a, const std::string& hex_b) {
    if (hex_a.size() != 64 || hex_b.size() != 64) {
        throw std::invalid_argument("Expected 64-char hex strings for 256-bit Hamming distance.");
    }
    auto hex_val = [](char c) -> unsigned int {
        if (c >= '0' && c <= '9') return static_cast<unsigned int>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned int>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned int>(c - 'A' + 10);
        throw std::invalid_argument("Invalid hex char");
    };
    int dist = 0;
    for (std::size_t i = 0; i < 64; ++i) {
        unsigned int x = hex_val(hex_a[i]) ^ hex_val(hex_b[i]);
        while (x) {
            dist += static_cast<int>(x & 1U);
            x >>= 1U;
        }
    }
    return dist;
}

} // namespace hash_checker
