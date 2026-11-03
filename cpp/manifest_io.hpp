#ifndef ATTT_N18_MANIFEST_IO_HPP
#define ATTT_N18_MANIFEST_IO_HPP

#include "hash_checker.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace hash_checker {

struct ManifestEntry {
    std::string algorithm;
    std::string digest;
    std::string rel_path;
};

struct SampleRecord {
    std::string sample_id;
    std::string path;
    std::size_t size_bytes = 0;
    std::string sha256;
    std::string sha3_256;
    std::string metadata_path;
    std::string metadata_sha256;
    std::string tampered_path;
    std::string tampered_sha256;
    std::string tampered_metadata_path;
    std::string tampered_metadata_sha256;
    std::string reference_digest_path;
    std::string attacker_digest_path;
    std::string mutation_op;
    std::size_t mutation_offset = 0;
};

struct BenchmarkTarget {
    std::string rel_path;
    std::filesystem::path full_path;
    std::size_t size_bytes = 0;
    std::string sha256;
    std::string sha3_256;
};

struct TestCaseSpec {
    std::string case_id;
    std::string name;
    std::string applies_to;
    std::string operation;
    std::string expected_hash;
    bool is_control = false;
};

inline std::vector<ManifestEntry> create_manifest(
    const std::filesystem::path& directory,
    const std::string& algorithm = "SHA-256"
) {
    std::string alg = canonical_algorithm_name(algorithm);
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    std::vector<ManifestEntry> entries;
    entries.reserve(files.size());
    for (const auto& path : files) {
        std::string rel = std::filesystem::relative(path, directory).generic_string();
        entries.push_back(ManifestEntry{alg, compute_digest_file(path, alg), rel});
    }
    return entries;
}

inline std::string format_manifest(const std::vector<ManifestEntry>& entries) {
    std::ostringstream oss;
    for (const auto& e : entries) {
        oss << e.algorithm << ' ' << e.digest << ' ' << e.rel_path << '\n';
    }
    return oss.str();
}

inline std::vector<ManifestEntry> parse_manifest(const std::string& text) {
    std::vector<ManifestEntry> entries;
    std::istringstream iss(text);
    std::string line;
    int lineno = 0;
    while (std::getline(iss, line)) {
        ++lineno;
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        bool all_space = true;
        for (char c : line) {
            if (!std::isspace(static_cast<unsigned char>(c))) {
                all_space = false;
                break;
            }
        }
        if (all_space || line[0] == '#') {
            continue;
        }
        std::size_t sp1 = line.find(' ');
        std::size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) {
            throw std::invalid_argument("Manifest line " + std::to_string(lineno) + ": expected '<algorithm> <hex> <path>'");
        }
        std::string alg = canonical_algorithm_name(line.substr(0, sp1));
        std::string digest = line.substr(sp1 + 1, sp2 - sp1 - 1);
        std::string rel = line.substr(sp2 + 1);

        std::transform(digest.begin(), digest.end(), digest.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (digest.size() != 64) {
            throw std::invalid_argument("Manifest line " + std::to_string(lineno) + ": invalid 256-bit hex digest");
        }
        for (char c : digest) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                throw std::invalid_argument("Manifest line " + std::to_string(lineno) + ": invalid hex char");
            }
        }
        if (rel.empty() || rel[0] == '/' || rel[0] == '\\' || rel.find("..") != std::string::npos) {
            throw std::invalid_argument("Manifest line " + std::to_string(lineno) + ": path must be relative and stay inside base directory");
        }
        entries.push_back(ManifestEntry{alg, digest, rel});
    }
    return entries;
}

inline std::vector<std::pair<std::string, std::string>> check_manifest(
    const std::vector<ManifestEntry>& entries,
    const std::filesystem::path& base_dir
) {
    std::vector<std::pair<std::string, std::string>> out;
    out.reserve(entries.size());
    for (const auto& e : entries) {
        std::filesystem::path p = base_dir / e.rel_path;
        if (!std::filesystem::is_regular_file(p)) {
            out.emplace_back(e.rel_path, "MISSING");
            continue;
        }
        bool ok = constant_time_equal(compute_digest_file(p, e.algorithm), e.digest);
        out.emplace_back(e.rel_path, ok ? "OK" : "FAILED");
    }
    return out;
}

inline std::string json_get_string(const std::string& block, const std::string& key) {
    std::string pattern = "\"" + key + "\":";
    std::size_t pos = block.find(pattern);
    if (pos == std::string::npos) {
        return "";
    }
    std::size_t q1 = block.find('"', pos + pattern.size());
    if (q1 == std::string::npos) {
        return "";
    }
    std::size_t q2 = block.find('"', q1 + 1);
    if (q2 == std::string::npos) {
        return "";
    }
    return block.substr(q1 + 1, q2 - q1 - 1);
}

inline std::size_t json_get_uint(const std::string& block, const std::string& key) {
    std::string pattern = "\"" + key + "\":";
    std::size_t pos = block.find(pattern);
    if (pos == std::string::npos) {
        return 0;
    }
    pos += pattern.size();
    while (pos < block.size() && std::isspace(static_cast<unsigned char>(block[pos]))) {
        ++pos;
    }
    std::size_t end = pos;
    while (end < block.size() && std::isdigit(static_cast<unsigned char>(block[end]))) {
        ++end;
    }
    if (end == pos) {
        return 0;
    }
    return static_cast<std::size_t>(std::stoull(block.substr(pos, end - pos)));
}

inline std::string read_text_utf8(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot open file: " + p.string());
    }
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

inline std::vector<SampleRecord> load_dataset_samples(const std::filesystem::path& data_root) {
    std::string text = read_text_utf8(data_root / "manifest.json");
    std::size_t samples_pos = text.find("\"samples\"");
    std::size_t bench_pos = text.find("\"benchmarks\"");
    if (samples_pos == std::string::npos || bench_pos == std::string::npos) {
        throw std::runtime_error("Invalid manifest.json format");
    }
    std::string samples_sec = text.substr(samples_pos, bench_pos - samples_pos);

    std::vector<SampleRecord> samples;
    std::size_t pos = 0;
    while (true) {
        std::size_t id_pos = samples_sec.find("\"sample_id\"", pos);
        if (id_pos == std::string::npos) {
            break;
        }
        std::size_t next_id = samples_sec.find("\"sample_id\"", id_pos + 11);
        std::string blk = (next_id == std::string::npos)
            ? samples_sec.substr(id_pos)
            : samples_sec.substr(id_pos, next_id - id_pos);

        SampleRecord rec;
        rec.sample_id                = json_get_string(blk, "sample_id");
        rec.path                     = json_get_string(blk, "path");
        rec.size_bytes               = json_get_uint(blk, "size_bytes");
        rec.sha256                   = json_get_string(blk, "sha256");
        rec.sha3_256                 = json_get_string(blk, "sha3_256");
        rec.metadata_path            = json_get_string(blk, "metadata_path");
        rec.metadata_sha256          = json_get_string(blk, "metadata_sha256");
        rec.tampered_path            = json_get_string(blk, "tampered_path");
        rec.tampered_sha256          = json_get_string(blk, "tampered_sha256");
        rec.tampered_metadata_path   = json_get_string(blk, "tampered_metadata_path");
        rec.tampered_metadata_sha256 = json_get_string(blk, "tampered_metadata_sha256");
        rec.reference_digest_path    = json_get_string(blk, "reference_digest_path");
        rec.attacker_digest_path     = json_get_string(blk, "attacker_digest_path");
        rec.mutation_op              = json_get_string(blk, "operation");
        rec.mutation_offset          = json_get_uint(blk, "offset");
        samples.push_back(std::move(rec));

        if (next_id == std::string::npos) {
            break;
        }
        pos = next_id;
    }
    return samples;
}

inline std::vector<BenchmarkTarget> load_benchmark_targets(
    const std::filesystem::path& data_root,
    bool include_extended = true
) {
    std::string text = read_text_utf8(data_root / "manifest.json");
    std::size_t bench_pos = text.find("\"benchmarks\"");
    if (bench_pos == std::string::npos) {
        throw std::runtime_error("Missing benchmarks section in manifest.json");
    }
    std::string bench_sec = text.substr(bench_pos);

    std::vector<BenchmarkTarget> targets;
    std::size_t pos = 0;
    while (true) {
        std::size_t p_pos = bench_sec.find("\"path\"", pos);
        if (p_pos == std::string::npos) {
            break;
        }
        std::size_t next_p = bench_sec.find("\"path\"", p_pos + 6);
        std::string blk = (next_p == std::string::npos)
            ? bench_sec.substr(p_pos)
            : bench_sec.substr(p_pos, next_p - p_pos);

        BenchmarkTarget t;
        t.rel_path   = json_get_string(blk, "path");
        t.full_path  = data_root / t.rel_path;
        t.size_bytes = json_get_uint(blk, "size_bytes");
        t.sha256     = json_get_string(blk, "sha256");
        t.sha3_256   = json_get_string(blk, "sha3_256");
        targets.push_back(std::move(t));

        if (next_p == std::string::npos) {
            break;
        }
        pos = next_p;
    }

    if (include_extended) {
        std::filesystem::path ext_dir = data_root / "benchmark_extended";
        if (std::filesystem::exists(ext_dir)) {
            std::vector<std::filesystem::path> ext_files;
            for (const auto& entry : std::filesystem::directory_iterator(ext_dir)) {
                if (entry.is_regular_file() && entry.path().filename().string().find("_bytes.bin") != std::string::npos) {
                    ext_files.push_back(entry.path());
                }
            }
            std::sort(ext_files.begin(), ext_files.end());
            for (const auto& f : ext_files) {
                auto data = read_raw_bytes(f);
                targets.push_back(BenchmarkTarget{
                    "benchmark_extended/" + f.filename().string(),
                    f,
                    data.size(),
                    compute_digest_bytes(data, "SHA-256"),
                    compute_digest_bytes(data, "SHA3-256")
                });
            }
        }
    }

    std::sort(targets.begin(), targets.end(),
              [](const BenchmarkTarget& a, const BenchmarkTarget& b) { return a.size_bytes < b.size_bytes; });
    return targets;
}

inline std::vector<TestCaseSpec> load_test_cases(const std::filesystem::path& data_root) {
    std::string text = read_text_utf8(data_root / "test_cases.json");
    std::size_t cases_pos = text.find("\"cases\"");
    if (cases_pos == std::string::npos) {
        throw std::runtime_error("Missing cases section in test_cases.json");
    }
    std::string sec = text.substr(cases_pos);

    std::vector<TestCaseSpec> cases;
    std::size_t pos = 0;
    while (true) {
        std::size_t c_pos = sec.find("\"case_id\"", pos);
        if (c_pos == std::string::npos) {
            break;
        }
        std::size_t next_c = sec.find("\"case_id\"", c_pos + 9);
        std::string blk = (next_c == std::string::npos)
            ? sec.substr(c_pos)
            : sec.substr(c_pos, next_c - c_pos);

        TestCaseSpec tc;
        tc.case_id       = json_get_string(blk, "case_id");
        tc.name          = json_get_string(blk, "name");
        tc.applies_to    = json_get_string(blk, "applies_to");
        tc.operation     = json_get_string(blk, "operation");
        tc.expected_hash = json_get_string(blk, "hash");
        tc.is_control    = (blk.find("\"is_control\": true") != std::string::npos);
        cases.push_back(std::move(tc));

        if (next_c == std::string::npos) {
            break;
        }
        pos = next_c;
    }
    return cases;
}

} // namespace hash_checker

#endif // ATTT_N18_MANIFEST_IO_HPP
