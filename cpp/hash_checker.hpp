#ifndef ATTT_N18_HASH_CHECKER_HPP
#define ATTT_N18_HASH_CHECKER_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace hash_checker {

inline constexpr std::size_t DEFAULT_CHUNK_SIZE = 64 * 1024;

struct VerificationResult {
    std::string algorithm;
    std::string computed_digest;
    std::string expected_digest;
    bool digest_match;
    std::string digest_source;
    bool metadata_changed;
    std::string status;
    std::int64_t elapsed_ns;
    std::string notes;
};

bool cpu_supports_sha_ni() noexcept;
void set_sha_ni_enabled(bool enabled) noexcept;
bool is_sha_ni_enabled() noexcept;

std::string canonical_algorithm_name(const std::string& algorithm);
bool constant_time_equal(const std::string& a, const std::string& b) noexcept;

std::string compute_digest_bytes(const std::uint8_t* data, std::size_t len, const std::string& algorithm = "SHA-256");
std::string compute_digest_bytes(const std::vector<std::uint8_t>& data, const std::string& algorithm = "SHA-256");

std::string compute_digest_file(
    const std::filesystem::path& file_path,
    const std::string& algorithm = "SHA-256",
    std::size_t chunk_size = DEFAULT_CHUNK_SIZE
);

std::vector<std::uint8_t> read_raw_bytes(const std::filesystem::path& file_path);
std::string read_digest_file(const std::filesystem::path& digest_path);

VerificationResult verify_bytes(
    const std::vector<std::uint8_t>& payload_bytes,
    const std::string& expected_digest,
    const std::string& algorithm = "SHA-256",
    const std::string& digest_source = "TRUSTED_REFERENCE",
    bool metadata_changed = false
);

int hamming_distance_hex(const std::string& hex_a, const std::string& hex_b);

} // namespace hash_checker

#endif // ATTT_N18_HASH_CHECKER_HPP
