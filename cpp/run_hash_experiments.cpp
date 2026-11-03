#include "hash_checker.hpp"
#include "manifest_io.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace hash_checker;

struct CaseEvalResult {
    std::string case_id;
    std::string sample_id;
    std::string expected_status;
    std::string actual_status;
    bool applicable_to_detection = false;
    bool detected = false;
    std::int64_t elapsed_ns = 0;
    std::string evidence_path;
};

std::string get_cpp_tool_versions() {
    std::ostringstream oss;
    oss << "C++17 (GCC " << __VERSION__ << "); SHA-NI=" << (cpu_supports_sha_ni() ? "supported" : "none");
#ifdef _WIN32
    oss << "; Windows-x86_64";
#endif
    return oss.str();
}

CaseEvalResult evaluate_hash_case_cpp(
    const TestCaseSpec& tc,
    const SampleRecord& rec,
    const fs::path& data_root,
    const std::string& algorithm = "SHA-256"
) {
    const std::string& cid = tc.case_id;
    const std::string& expected_st = tc.expected_hash;
    std::string trusted_digest = (algorithm == "SHA-256") ? rec.sha256 : rec.sha3_256;

    if (expected_st == "NOT_APPLICABLE") {
        return CaseEvalResult{cid, rec.sample_id, expected_st, "NOT_APPLICABLE", false, false, 0, rec.path};
    }
    if (cid == "TC09" && rec.size_bytes == 0) {
        return CaseEvalResult{cid, rec.sample_id, "NOT_APPLICABLE", "NOT_APPLICABLE", false, false, 0, rec.path};
    }

    auto orig_bytes = read_raw_bytes(data_root / rec.path);

    if (cid == "TC01") {
        std::string ref_digest = (algorithm == "SHA-256")
            ? read_digest_file(data_root / rec.reference_digest_path)
            : trusted_digest;
        auto res = verify_bytes(orig_bytes, ref_digest, algorithm, "TRUSTED_REFERENCE", false);
        return CaseEvalResult{
            cid, rec.sample_id, expected_st, res.status, false, false, res.elapsed_ns,
            rec.path + "|" + rec.reference_digest_path
        };
    }

    if (cid == "TC02") {
        auto tamp_bytes = read_raw_bytes(data_root / rec.tampered_path);
        std::string ref_digest = (algorithm == "SHA-256")
            ? read_digest_file(data_root / rec.reference_digest_path)
            : trusted_digest;
        auto res = verify_bytes(tamp_bytes, ref_digest, algorithm, "TRUSTED_REFERENCE", false);
        return CaseEvalResult{
            cid, rec.sample_id, expected_st, res.status, true, res.status == "REJECT", res.elapsed_ns,
            rec.tampered_path + "|" + rec.reference_digest_path
        };
    }

    if (cid == "TC03") {
        auto tamp_bytes = read_raw_bytes(data_root / rec.tampered_path);
        std::string attacker_digest = (algorithm == "SHA-256")
            ? read_digest_file(data_root / rec.attacker_digest_path)
            : compute_digest_bytes(tamp_bytes, "SHA3-256");
        auto res = verify_bytes(tamp_bytes, attacker_digest, algorithm, "UNTRUSTED_CHANNEL", false);
        return CaseEvalResult{
            cid, rec.sample_id, expected_st, res.status, true, res.status == "REJECT", res.elapsed_ns,
            rec.tampered_path + "|" + rec.attacker_digest_path
        };
    }

    if (cid == "TC07") {
        auto aad = read_raw_bytes(data_root / rec.metadata_path);
        auto tamp_aad = read_raw_bytes(data_root / rec.tampered_metadata_path);
        std::string ref_digest = (algorithm == "SHA-256")
            ? read_digest_file(data_root / rec.reference_digest_path)
            : trusted_digest;
        bool metadata_differs = (aad != tamp_aad);
        auto res = verify_bytes(orig_bytes, ref_digest, algorithm, "TRUSTED_REFERENCE", metadata_differs);
        return CaseEvalResult{
            cid, rec.sample_id, expected_st, res.status, false, false, res.elapsed_ns,
            rec.path + "|" + rec.tampered_metadata_path
        };
    }

    if (cid == "TC09") {
        std::vector<std::uint8_t> truncated(orig_bytes.begin(), orig_bytes.end() - 1);
        std::string ref_digest = (algorithm == "SHA-256")
            ? read_digest_file(data_root / rec.reference_digest_path)
            : trusted_digest;
        auto res = verify_bytes(truncated, ref_digest, algorithm, "TRUSTED_REFERENCE", false);
        return CaseEvalResult{
            cid, rec.sample_id, expected_st, res.status, true, res.status == "REJECT", res.elapsed_ns,
            rec.path + "[:-1]|" + rec.reference_digest_path
        };
    }

    throw std::runtime_error("Unhandled test case: " + cid);
}

int run_all_experiments_cpp(
    const fs::path& data_root = "data",
    const fs::path& output_dir = "results/hash",
    const std::string& run_id = "HASH-N18-CPP01"
) {
    fs::create_directories(output_dir);
    auto samples = load_dataset_samples(data_root);
    auto cases = load_test_cases(data_root);
    std::string tool_versions = get_cpp_tool_versions();

    std::ostringstream log;
    log << std::string(88, '=') << "\n"
        << "NHẬT KÝ THỰC NGHIỆM KIỂM TRA TOÀN VẸN TỆP BẰNG HÀM BĂM THUẦN — C++17 (THÀNH VIÊN A)\n"
        << "Run ID        : " << run_id << "\n"
        << "Dataset Ver   : 1.0.0 (seed: ATTT-N18-shared-data-v1)\n"
        << "Environment   : " << tool_versions << "\n"
        << std::string(88, '=') << "\n\n";

    log << "[PHẦN 1] ĐỐI CHIẾU GIÁ TRỊ BĂM THAM CHIẾU VÀ HIỆU ỨNG THÁC ĐỔ (18 MẪU S01–S18)\n"
        << std::string(88, '-') << "\n";

    std::ofstream av_csv(output_dir / "avalanche_analysis.csv", std::ios::binary);
    av_csv << "sample_id,path,size_bytes,mutation_op,mutation_offset,"
           << "sha256_original,sha256_tampered,sha256_hamming_bits,sha256_hamming_pct,"
           << "sha3_256_original,sha3_256_tampered,sha3_256_hamming_bits,sha3_256_hamming_pct\n";

    double sum_hd256 = 0.0;
    double sum_hd3 = 0.0;

    for (const auto& rec : samples) {
        auto orig_bytes = read_raw_bytes(data_root / rec.path);
        auto tamp_bytes = read_raw_bytes(data_root / rec.tampered_path);

        std::string sha256_orig = compute_digest_bytes(orig_bytes, "SHA-256");
        std::string sha256_tamp = compute_digest_bytes(tamp_bytes, "SHA-256");
        std::string sha3_orig   = compute_digest_bytes(orig_bytes, "SHA3-256");
        std::string sha3_tamp   = compute_digest_bytes(tamp_bytes, "SHA3-256");

        if (sha256_orig != rec.sha256 || sha256_tamp != rec.tampered_sha256 || sha3_orig != rec.sha3_256) {
            throw std::runtime_error("Digest mismatch against manifest on sample " + rec.sample_id);
        }

        int hd256 = hamming_distance_hex(sha256_orig, sha256_tamp);
        int hd3   = hamming_distance_hex(sha3_orig, sha3_tamp);
        sum_hd256 += hd256;
        sum_hd3   += hd3;

        double pct256 = hd256 / 256.0 * 100.0;
        double pct3   = hd3 / 256.0 * 100.0;

        av_csv << rec.sample_id << "," << rec.path << "," << rec.size_bytes << ","
               << rec.mutation_op << "," << rec.mutation_offset << ","
               << sha256_orig << "," << sha256_tamp << "," << hd256 << ","
               << std::fixed << std::setprecision(2) << pct256 << ","
               << sha3_orig << "," << sha3_tamp << "," << hd3 << ","
               << std::fixed << std::setprecision(2) << pct3 << "\n";

        log << "  " << rec.sample_id << " (" << std::setw(4) << rec.size_bytes << " B | "
            << std::left << std::setw(15) << rec.mutation_op << std::right << "): "
            << "SHA-256 HD = " << std::setw(3) << hd256 << "/256 bits ("
            << std::fixed << std::setprecision(1) << std::setw(5) << pct256 << "%), "
            << "SHA3-256 HD = " << std::setw(3) << hd3 << "/256 bits ("
            << std::fixed << std::setprecision(1) << std::setw(5) << pct3 << "%)\n";
    }

    double avg256 = sum_hd256 / samples.size();
    double avg3   = sum_hd3 / samples.size();
    log << std::string(88, '-') << "\n"
        << "  Trung bình khoảng cách Hamming (18 mẫu): SHA-256 = "
        << std::fixed << std::setprecision(2) << avg256 << "/256 bits (" << (avg256 / 256.0 * 100.0) << "%), "
        << "SHA3-256 = " << avg3 << "/256 bits (" << (avg3 / 256.0 * 100.0) << "%)\n\n";

    log << "[PHẦN 2] MA TRẬN TC01–TC09 — PROFILE CHÍNH SHA-256(file_bytes) (SHA3-256 xem dòng 4 Phần 3)\n"
        << std::string(88, '-') << "\n";

    std::ofstream res_csv(output_dir / "hash_verification_results.csv", std::ios::binary);
    std::ofstream sha3_csv(output_dir / "hash_sha3_cross_check.csv", std::ios::binary);
    std::ofstream sum_csv(output_dir / "hash_case_summary.csv", std::ios::binary);

    const std::string header = "run_id,case_id,sample_id,mechanism,expected_status,actual_status,"
                               "applicable_to_detection,detected,elapsed_ns,evidence_path,tool_versions\n";
    res_csv << header;
    sha3_csv << header;
    sum_csv << "case_id,name,operation,is_control,expected_hash_status,samples_evaluated,"
               "matched_expectation,applicable_to_detection,detected_count,detection_rate_pct,status_breakdown\n";

    int tc02_9_total = 0, tc02_9_detected = 0;
    int tc03_total = 0, tc03_detected = 0, tc03_untrusted = 0;
    int sha3_total = 0, sha3_matched = 0;

    for (const auto& tc : cases) {
        int applicable_cnt = 0;
        int detected_cnt = 0;
        int matched_exp_cnt = 0;
        int total_eval = 0;
        std::map<std::string, int> status_counts;

        for (const auto& rec : samples) {
            auto ev = evaluate_hash_case_cpp(tc, rec, data_root, "SHA-256");
            ++total_eval;
            status_counts[ev.actual_status]++;
            if (ev.actual_status == ev.expected_status) {
                ++matched_exp_cnt;
            }
            if (ev.applicable_to_detection) {
                ++applicable_cnt;
                if (ev.detected) ++detected_cnt;
                if (tc.case_id == "TC02" || tc.case_id == "TC09") {
                    ++tc02_9_total;
                    if (ev.detected) ++tc02_9_detected;
                }
            }
            if (tc.case_id == "TC03") {
                ++tc03_total;
                if (ev.detected) ++tc03_detected;
                if (ev.actual_status == "ACCEPT_UNTRUSTED") ++tc03_untrusted;
            }

            res_csv << run_id << "," << tc.case_id << "," << rec.sample_id << ",SHA-256,"
                    << ev.expected_status << "," << ev.actual_status << ","
                    << (ev.applicable_to_detection ? "True" : "False") << ","
                    << (ev.detected ? "True" : "False") << ","
                    << ev.elapsed_ns << "," << ev.evidence_path << ",\"" << tool_versions << "\"\n";

            auto ev3 = evaluate_hash_case_cpp(tc, rec, data_root, "SHA3-256");
            ++sha3_total;
            if (ev3.actual_status == ev3.expected_status) {
                ++sha3_matched;
            }
            sha3_csv << run_id << "," << tc.case_id << "," << rec.sample_id << ",SHA3-256,"
                     << ev3.expected_status << "," << ev3.actual_status << ","
                     << (ev3.applicable_to_detection ? "True" : "False") << ","
                     << (ev3.detected ? "True" : "False") << ","
                     << ev3.elapsed_ns << "," << ev3.evidence_path << ",\"" << tool_versions << "\"\n";
        }

        std::ostringstream st_sum;
        bool first = true;
        for (const auto& [k, v] : status_counts) {
            if (!first) st_sum << ", ";
            first = false;
            st_sum << k << ":" << v;
        }
        std::ostringstream det_str;
        std::ostringstream det_pct_csv;
        if (applicable_cnt > 0) {
            double pct = detected_cnt * 100.0 / applicable_cnt;
            det_str << detected_cnt << "/" << applicable_cnt << " (" << std::fixed << std::setprecision(1) << pct << "%)";
            det_pct_csv << std::fixed << std::setprecision(2) << pct;
        } else {
            det_str << "N/A";
        }

        sum_csv << tc.case_id << ",\"" << tc.name << "\"," << tc.operation << ","
                << (tc.is_control ? "True" : "False") << "," << tc.expected_hash << ","
                << total_eval << "," << matched_exp_cnt << "/" << total_eval << ","
                << applicable_cnt << "," << detected_cnt << "," << det_pct_csv.str() << ",\""
                << st_sum.str() << "\"\n";

        log << "  " << tc.case_id << " (" << std::left << std::setw(38) << tc.name << std::right << "): "
            << "status=[" << std::left << std::setw(35) << st_sum.str() << std::right << "] | "
            << "expectation_match=" << matched_exp_cnt << "/" << total_eval << " | "
            << "detection=" << det_str.str() << "\n";
    }

    log << std::string(88, '-') << "\n"
        << "[PHẦN 3] TỔNG HỢP TỶ LỆ PHÁT HIỆN THEO QUY ƯỚC ĐỀ TÀI (data/README.md)\n"
        << "  1. Tập sửa nội dung có bằng chứng tham chiếu tin cậy (TC02 + TC09): "
        << tc02_9_detected << "/" << tc02_9_total << " ("
        << std::fixed << std::setprecision(2) << (tc02_9_detected * 100.0 / tc02_9_total) << "%)\n"
        << "  2. TC03 (thay cả tệp và hash đi kèm, trình bày RIÊNG, không gộp vào tỷ lệ chung): "
        << "phát hiện " << tc03_detected << "/" << tc03_total << "; "
        << tc03_untrusted << "/" << tc03_total << " mẫu ACCEPT_UNTRUSTED "
        << "(đúng kỳ vọng — đây là minh chứng giới hạn của hash thuần, không phải lỗi chương trình)\n"
        << "  3. Không đưa vào mẫu số: TC01 (control), TC07 (metadata ngoài phạm vi file-only), "
        << "TC04/TC05/TC06/TC08 (NOT_APPLICABLE), TC09 trên S01 rỗng.\n"
        << "  4. Đối chiếu SHA3-256 trên cùng 162 ca: " << sha3_matched << "/" << sha3_total
        << " ca có trạng thái đúng kỳ vọng (chi tiết: hash_sha3_cross_check.csv)\n"
        << std::string(88, '=') << "\n";

    std::ofstream log_out(output_dir / "hash_experiment.log", std::ios::binary);
    log_out << log.str();
    std::cout << log.str();
    std::cout << "Saved verification CSV to: " << (output_dir / "hash_verification_results.csv").generic_string() << "\n";
    return 0;
}

#ifndef ATTT_EXPERIMENTS_AS_LIBRARY
int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    return run_all_experiments_cpp();
}
#endif

