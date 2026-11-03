// Bộ kiểm thử đơn vị (Unit Tests) cho mô-đun Hash thuần C++17 — Thành viên A.
#define ATTT_DEMO_TAMPER_AS_LIBRARY
#define ATTT_EXPERIMENTS_AS_LIBRARY
#include "demo_tamper_hash.cpp"
#include "run_hash_experiments.cpp"

#include <cassert>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace hash_checker;

#define REQUIRE(cond, msg) \
    do { \
        if (!(cond)) { \
            throw std::runtime_error(std::string("Assertion failed: ") + (msg)); \
        } \
    } while (0)

void test_01_algorithm_normalization() {
    REQUIRE(canonical_algorithm_name("sha256") == "SHA-256", "sha256 normalization");
    REQUIRE(canonical_algorithm_name("SHA-256") == "SHA-256", "SHA-256 normalization");
    REQUIRE(canonical_algorithm_name("sha3_256") == "SHA3-256", "sha3_256 normalization");
    REQUIRE(canonical_algorithm_name("SHA3-256") == "SHA3-256", "SHA3-256 normalization");
    bool threw = false;
    try {
        (void)canonical_algorithm_name("MD5");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    REQUIRE(threw, "MD5 must throw invalid_argument");
}

void test_02_manifest_matches_both_shani_and_soft() {
    auto samples = load_dataset_samples("data");
    REQUIRE(samples.size() == 18, "Expected 18 samples");

    for (bool shani : {true, false}) {
        set_sha_ni_enabled(shani);
        for (const auto& rec : samples) {
            auto orig = read_raw_bytes(fs::path("data") / rec.path);
            auto tamp = read_raw_bytes(fs::path("data") / rec.tampered_path);
            REQUIRE(compute_digest_bytes(orig, "SHA-256") == rec.sha256, "SHA-256 mismatch on " + rec.sample_id);
            REQUIRE(compute_digest_file(fs::path("data") / rec.path, "SHA-256") == rec.sha256, "File SHA-256 mismatch on " + rec.sample_id);
            REQUIRE(compute_digest_bytes(tamp, "SHA-256") == rec.tampered_sha256, "Tampered SHA-256 mismatch on " + rec.sample_id);
            REQUIRE(compute_digest_bytes(orig, "SHA3-256") == rec.sha3_256, "SHA3-256 mismatch on " + rec.sample_id);
            REQUIRE(compute_digest_file(fs::path("data") / rec.path, "SHA3-256") == rec.sha3_256, "File SHA3-256 mismatch on " + rec.sample_id);
        }
    }
    set_sha_ni_enabled(true);
}

void test_03_tc01_intact_accepted() {
    auto samples = load_dataset_samples("data");
    auto cases = load_test_cases("data");
    const auto& tc01 = cases[0];
    for (const auto& rec : samples) {
        auto ev256 = evaluate_hash_case_cpp(tc01, rec, "data", "SHA-256");
        auto ev3   = evaluate_hash_case_cpp(tc01, rec, "data", "SHA3-256");
        REQUIRE(ev256.actual_status == "ACCEPT", "TC01 SHA-256 ACCEPT");
        REQUIRE(ev3.actual_status == "ACCEPT", "TC01 SHA3-256 ACCEPT");
    }
}

void test_04_tc02_tampered_rejected() {
    auto samples = load_dataset_samples("data");
    auto cases = load_test_cases("data");
    const auto& tc02 = cases[1];
    for (const auto& rec : samples) {
        auto ev256 = evaluate_hash_case_cpp(tc02, rec, "data", "SHA-256");
        auto ev3   = evaluate_hash_case_cpp(tc02, rec, "data", "SHA3-256");
        REQUIRE(ev256.actual_status == "REJECT" && ev256.detected, "TC02 SHA-256 REJECT");
        REQUIRE(ev3.actual_status == "REJECT" && ev3.detected, "TC02 SHA3-256 REJECT");
    }
}

void test_05_tc03_replace_both_accepted_untrusted() {
    auto samples = load_dataset_samples("data");
    auto cases = load_test_cases("data");
    const auto& tc03 = cases[2];
    for (const auto& rec : samples) {
        auto ev256 = evaluate_hash_case_cpp(tc03, rec, "data", "SHA-256");
        auto ev3   = evaluate_hash_case_cpp(tc03, rec, "data", "SHA3-256");
        REQUIRE(ev256.actual_status == "ACCEPT_UNTRUSTED" && !ev256.detected, "TC03 SHA-256 ACCEPT_UNTRUSTED");
        REQUIRE(ev3.actual_status == "ACCEPT_UNTRUSTED" && !ev3.detected, "TC03 SHA3-256 ACCEPT_UNTRUSTED");
    }
}

void test_06_tc07_metadata_outside_scope() {
    auto samples = load_dataset_samples("data");
    auto cases = load_test_cases("data");
    const auto& tc07 = cases[6];
    for (const auto& rec : samples) {
        auto ev = evaluate_hash_case_cpp(tc07, rec, "data", "SHA-256");
        REQUIRE(ev.actual_status == "ACCEPT_METADATA_OUTSIDE_SCOPE", "TC07 ACCEPT_METADATA_OUTSIDE_SCOPE");
    }
}

void test_07_tc09_truncation_detected() {
    auto samples = load_dataset_samples("data");
    auto cases = load_test_cases("data");
    const auto& tc09 = cases[8];
    for (const auto& rec : samples) {
        auto ev = evaluate_hash_case_cpp(tc09, rec, "data", "SHA-256");
        if (rec.size_bytes == 0) {
            REQUIRE(ev.actual_status == "NOT_APPLICABLE", "TC09 S01 NOT_APPLICABLE");
        } else {
            REQUIRE(ev.actual_status == "REJECT" && ev.detected, "TC09 non-empty REJECT");
        }
    }
}

void test_08_keyed_cases_not_applicable() {
    auto samples = load_dataset_samples("data");
    auto cases = load_test_cases("data");
    for (int idx : {3, 4, 5, 7}) { // TC04, TC05, TC06, TC08
        for (const auto& rec : samples) {
            auto ev = evaluate_hash_case_cpp(cases[idx], rec, "data", "SHA-256");
            REQUIRE(ev.actual_status == "NOT_APPLICABLE", "Keyed/AEAD case NOT_APPLICABLE");
        }
    }
}

void test_09_avalanche_hamming_distance() {
    auto samples = load_dataset_samples("data");
    for (const auto& rec : samples) {
        auto orig = read_raw_bytes(fs::path("data") / rec.path);
        auto tamp = read_raw_bytes(fs::path("data") / rec.tampered_path);
        int hd256 = hamming_distance_hex(compute_digest_bytes(orig, "SHA-256"), compute_digest_bytes(tamp, "SHA-256"));
        int hd3   = hamming_distance_hex(compute_digest_bytes(orig, "SHA3-256"), compute_digest_bytes(tamp, "SHA3-256"));
        REQUIRE(hd256 >= 90 && hd256 <= 166, "SHA-256 avalanche within binomial bounds");
        REQUIRE(hd3 >= 90 && hd3 <= 166, "SHA3-256 avalanche within binomial bounds");
    }
}

void test_10_benchmark_targets_match_manifest() {
    auto targets = load_benchmark_targets("data", false);
    REQUIRE(targets.size() == 5, "Expected 5 standard benchmark files");
    for (const auto& t : targets) {
        auto data = read_raw_bytes(t.full_path);
        REQUIRE(data.size() == t.size_bytes, "Benchmark size match");
        REQUIRE(compute_digest_bytes(data, "SHA-256") == t.sha256, "Benchmark SHA-256 match");
        REQUIRE(compute_digest_bytes(data, "SHA3-256") == t.sha3_256, "Benchmark SHA3-256 match");
    }
}

void test_11_cli_and_manifest_security() {
    std::ostringstream out, err;
    REQUIRE(run_cli_command({"verify", "data/samples/S03_ascii.txt", "--digest-file", "data/digests/S03.sha256"}, out, err) == 0,
            "CLI verify intact S03");
    REQUIRE(run_cli_command({"verify", "data/tampered/S03_ascii.txt", "--digest-file", "data/digests/S03.sha256"}, out, err) == 1,
            "CLI verify tampered S03");

    bool threw = false;
    try {
        (void)parse_manifest("SHA-256 " + std::string(64, '0') + " ../escape.txt\n");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    REQUIRE(threw, "Manifest path traversal must throw");
}

void test_12_live_tamper_demo() {
    fs::path tmp_dir = "results/hash/test_demo_tmp";
    auto codes = run_demo_cpp("data", tmp_dir);
    fs::remove_all(tmp_dir);
    REQUIRE(codes["B1_intact"] == 0, "Demo B1 intact == 0");
    REQUIRE(codes["B2_tamper_keep_manifest"] == 1, "Demo B2 tamper keep manifest == 1");
    REQUIRE(codes["B3_tamper_and_replace_manifest"] == 0, "Demo B3 tamper and replace manifest == 0");
    REQUIRE(codes["B4_trusted_reference"] == 1, "Demo B4 trusted reference == 1");
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    struct TestEntry {
        const char* name;
        void (*fn)();
    };
    const std::vector<TestEntry> tests = {
        {"test_01_algorithm_normalization", test_01_algorithm_normalization},
        {"test_02_manifest_matches_both_shani_and_soft", test_02_manifest_matches_both_shani_and_soft},
        {"test_03_tc01_intact_accepted", test_03_tc01_intact_accepted},
        {"test_04_tc02_tampered_rejected", test_04_tc02_tampered_rejected},
        {"test_05_tc03_replace_both_accepted_untrusted", test_05_tc03_replace_both_accepted_untrusted},
        {"test_06_tc07_metadata_outside_scope", test_06_tc07_metadata_outside_scope},
        {"test_07_tc09_truncation_detected", test_07_tc09_truncation_detected},
        {"test_08_keyed_cases_not_applicable", test_08_keyed_cases_not_applicable},
        {"test_09_avalanche_hamming_distance", test_09_avalanche_hamming_distance},
        {"test_10_benchmark_targets_match_manifest", test_10_benchmark_targets_match_manifest},
        {"test_11_cli_and_manifest_security", test_11_cli_and_manifest_security},
        {"test_12_live_tamper_demo", test_12_live_tamper_demo},
    };

    int passed = 0;
    for (const auto& t : tests) {
        std::cout << "[ RUN      ] " << t.name << " ... ";
        t.fn();
        std::cout << "OK\n";
        ++passed;
    }
    std::cout << std::string(70, '-') << "\n";
    std::cout << "Ran " << passed << "/" << tests.size() << " C++17 unit tests successfully (SHA-NI="
              << (cpu_supports_sha_ni() ? "supported" : "none") << ").\n";
    return 0;
}

