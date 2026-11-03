// Module kiểm tra tính toàn vẹn tệp bằng hàm băm mật mã thuần (SHA-256 & SHA3-256) — C++17.
// Phụ trách: Thành viên A — Hash thuần và đo tốc độ (Đề tài 18).
#ifndef ATTT_N18_HASH_CHECKER_HPP
#define ATTT_N18_HASH_CHECKER_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace hash_checker {

inline constexpr std::size_t DEFAULT_CHUNK_SIZE = 64 * 1024; // 64 KiB

struct VerificationResult {
    std::string algorithm;        // "SHA-256" hoặc "SHA3-256"
    std::string computed_digest;  // 64 ký tự hex chữ thường
    std::string expected_digest;  // 64 ký tự hex chữ thường
    bool digest_match;
    std::string digest_source;    // "TRUSTED_REFERENCE" hoặc "UNTRUSTED_CHANNEL"
    bool metadata_changed;
    std::string status;           // ACCEPT, REJECT, ACCEPT_UNTRUSTED, ACCEPT_METADATA_OUTSIDE_SCOPE, NOT_APPLICABLE
    std::int64_t elapsed_ns;
    std::string notes;
};

// Kiểm tra CPU có hỗ trợ tập lệnh phần cứng SHA-NI hay không và bật/tắt khi chạy thực nghiệm đối chứng.
bool cpu_supports_sha_ni() noexcept;
void set_sha_ni_enabled(bool enabled) noexcept;
bool is_sha_ni_enabled() noexcept;

// Chuẩn hóa tên thuật toán về "SHA-256" hoặc "SHA3-256".
std::string canonical_algorithm_name(const std::string& algorithm);

// So sánh hai chuỗi ở thời gian hằng (Constant-Time Comparison) để tránh rò rỉ kênh kề thời gian.
bool constant_time_equal(const std::string& a, const std::string& b) noexcept;

// Tính giá trị băm 256-bit (64 ký tự hex chữ thường) trực tiếp trên vùng nhớ byte.
std::string compute_digest_bytes(const std::uint8_t* data, std::size_t len, const std::string& algorithm = "SHA-256");
std::string compute_digest_bytes(const std::vector<std::uint8_t>& data, const std::string& algorithm = "SHA-256");

// Tính giá trị băm của tệp bằng cách đọc nhị phân nguyên bản theo khối 64 KiB.
std::string compute_digest_file(
    const std::filesystem::path& file_path,
    const std::string& algorithm = "SHA-256",
    std::size_t chunk_size = DEFAULT_CHUNK_SIZE
);

// Đọc toàn bộ byte nguyên bản của tệp.
std::vector<std::uint8_t> read_raw_bytes(const std::filesystem::path& file_path);

// Đọc chuỗi hex 64 ký tự từ tệp .sha256.
std::string read_digest_file(const std::filesystem::path& digest_path);

// Kiểm tra tính toàn vẹn của mảng byte so với mã băm kỳ vọng và phân loại trạng thái đầu ra.
VerificationResult verify_bytes(
    const std::vector<std::uint8_t>& payload_bytes,
    const std::string& expected_digest,
    const std::string& algorithm = "SHA-256",
    const std::string& digest_source = "TRUSTED_REFERENCE",
    bool metadata_changed = false
);

// Tính khoảng cách Hamming (số bit khác nhau trên 256 bit) giữa hai chuỗi hex 64 ký tự.
int hamming_distance_hex(const std::string& hex_a, const std::string& hex_b);

} // namespace hash_checker

#endif // ATTT_N18_HASH_CHECKER_HPP

