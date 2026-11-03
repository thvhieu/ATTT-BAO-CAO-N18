#include "hash_checker.hpp"
#include "manifest_io.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace hash_checker;

struct RawBenchRow {
    std::string run_id;
    std::string algorithm;
    std::string input_path;
    std::size_t size_bytes = 0;
    int repeat_index = 0;
    std::int64_t elapsed_ns = 0;
    bool io_included = false;
    std::string compiler_version;
    std::string platform;
    std::string library_versions;
};

struct SummaryBenchRow {
    std::string run_id;
    bool io_included = false;
    std::string algorithm;
    std::string input_path;
    std::size_t size_bytes = 0;
    std::string size_label;
    int repeats = 0;
    int inner_loops = 0;
    double mean_us = 0.0;
    double median_us = 0.0;
    double stdev_us = 0.0;
    double q1_us = 0.0;
    double q3_us = 0.0;
    double cv_pct = 0.0;
    double median_throughput_mibs = 0.0;
};

struct ComparisonRow {
    bool io_included = false;
    std::size_t size_bytes = 0;
    std::string size_label;
    double sha256_median_us = 0.0;
    double sha3_256_median_us = 0.0;
    double sha256_median_mibs = 0.0;
    double sha3_256_median_mibs = 0.0;
    double time_ratio_sha3_over_sha256 = 0.0;
};

struct AblationRow {
    std::size_t size_bytes = 0;
    std::string size_label;
    std::string algorithm;
    double default_median_mibs = 0.0;
    double sha_ni_masked_median_mibs = 0.0;
    double default_over_masked = 0.0;
};

std::string format_size_label(std::size_t size_bytes) {
    if (size_bytes >= 1024 * 1024) {
        return std::to_string(size_bytes / (1024 * 1024)) + " MiB";
    }
    if (size_bytes >= 1024) {
        return std::to_string(size_bytes / 1024) + " KiB";
    }
    return std::to_string(size_bytes) + " B";
}

int inner_loops_for(std::size_t size_bytes, bool io_included) {
    std::size_t target = io_included ? (256 * 1024) : (1024 * 1024);
    if (size_bytes == 0) return 1;
    std::size_t loops = (target + size_bytes - 1) / size_bytes;
    return static_cast<int>(std::max<std::size_t>(1, loops));
}

std::int64_t time_batch(
    const std::string& alg,
    bool io_included,
    const fs::path& full_path,
    const std::vector<std::uint8_t>& data,
    int loops
) {
    volatile std::size_t sink = 0;
    auto t0 = std::chrono::steady_clock::now();
    if (io_included) {
        for (int i = 0; i < loops; ++i) {
            std::string d = compute_digest_file(full_path, alg);
            sink += d[0];
        }
    } else {
        for (int i = 0; i < loops; ++i) {
            std::string d = compute_digest_bytes(data, alg);
            sink += d[0];
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    (void)sink;
    return std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
}

double percentile_sorted(const std::vector<double>& sorted, double p) {
    if (sorted.empty()) return 0.0;
    if (sorted.size() == 1) return sorted[0];
    double pos = p * static_cast<double>(sorted.size() - 1);
    std::size_t lo = static_cast<std::size_t>(std::floor(pos));
    std::size_t hi = static_cast<std::size_t>(std::ceil(pos));
    double frac = pos - static_cast<double>(lo);
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

std::vector<RawBenchRow> measure_cpp(
    const fs::path& data_root,
    const std::string& run_id,
    int repeats,
    int warmup,
    bool include_extended,
    const std::vector<bool>& modes = {false, true}
) {
    auto targets = load_benchmark_targets(data_root, include_extended);
    std::string comp_ver = std::string("g++ ") + __VERSION__;
    std::string plat_str = "Windows-11-x86_64";
    std::string shani_mode = (is_sha_ni_enabled() && cpu_supports_sha_ni()) ? "enabled" : "disabled";

    std::vector<RawBenchRow> rows;
    const std::vector<std::string> algs = {"SHA-256", "SHA3-256"};

    for (bool io_included : modes) {
        for (const auto& target : targets) {
            auto data = read_raw_bytes(target.full_path);
            if (data.size() != target.size_bytes) {
                throw std::runtime_error("Size mismatch on benchmark file: " + target.rel_path);
            }
            if (compute_digest_bytes(data, "SHA-256") != target.sha256 ||
                compute_digest_bytes(data, "SHA3-256") != target.sha3_256) {
                throw std::runtime_error("Digest mismatch on benchmark file: " + target.rel_path);
            }

            int loops = inner_loops_for(target.size_bytes, io_included);
            std::string lib_ver = "C++17 native FIPS 180-4/202; batch_loops=" + std::to_string(loops) +
                                  "; SHA-NI=" + shani_mode;

            for (const auto& alg : algs) {
                for (int w = 0; w < warmup; ++w) {
                    time_batch(alg, io_included, target.full_path, data, loops);
                }
            }

            for (int rep = 1; rep <= repeats; ++rep) {
                std::vector<std::string> order = (rep % 2 == 1)
                    ? algs
                    : std::vector<std::string>{algs[1], algs[0]};
                for (const auto& alg : order) {
                    std::int64_t batch_ns = time_batch(alg, io_included, target.full_path, data, loops);
                    std::int64_t per_op_ns = static_cast<std::int64_t>(
                        std::llround(static_cast<double>(batch_ns) / loops)
                    );
                    if (per_op_ns < 1) per_op_ns = 1;
                    rows.push_back(RawBenchRow{
                        run_id,
                        alg,
                        target.rel_path,
                        target.size_bytes,
                        rep,
                        per_op_ns,
                        io_included,
                        comp_ver,
                        plat_str,
                        lib_ver
                    });
                }
            }
        }
    }

    std::sort(rows.begin(), rows.end(), [](const RawBenchRow& a, const RawBenchRow& b) {
        return std::tie(a.io_included, a.size_bytes, a.algorithm, a.repeat_index) <
               std::tie(b.io_included, b.size_bytes, b.algorithm, b.repeat_index);
    });
    return rows;
}

std::vector<SummaryBenchRow> summarize_cpp(const std::vector<RawBenchRow>& rows) {
    using Key = std::tuple<bool, std::size_t, std::string>;
    std::map<Key, std::vector<RawBenchRow>> groups;
    for (const auto& r : rows) {
        groups[{r.io_included, r.size_bytes, r.algorithm}].push_back(r);
    }

    std::vector<SummaryBenchRow> out;
    for (const auto& [key, grp] : groups) {
        auto [io_inc, sz, alg] = key;
        std::vector<double> vals;
        vals.reserve(grp.size());
        for (const auto& r : grp) {
            vals.push_back(static_cast<double>(r.elapsed_ns));
        }
        std::sort(vals.begin(), vals.end());

        double mean_ns = std::accumulate(vals.begin(), vals.end(), 0.0) / static_cast<double>(vals.size());
        double median_ns = percentile_sorted(vals, 0.50);
        double q1_ns = percentile_sorted(vals, 0.25);
        double q3_ns = percentile_sorted(vals, 0.75);

        double sq_sum = 0.0;
        for (double v : vals) {
            sq_sum += (v - mean_ns) * (v - mean_ns);
        }
        double stdev_ns = (vals.size() > 1) ? std::sqrt(sq_sum / static_cast<double>(vals.size() - 1)) : 0.0;
        double cv_pct = (mean_ns > 0.0) ? (stdev_ns / mean_ns * 100.0) : 0.0;

        double mib = static_cast<double>(sz) / (1024.0 * 1024.0);
        double mibs = mib / (median_ns / 1e9);

        out.push_back(SummaryBenchRow{
            grp[0].run_id,
            io_inc,
            alg,
            grp[0].input_path,
            sz,
            format_size_label(sz),
            static_cast<int>(grp.size()),
            inner_loops_for(sz, io_inc),
            mean_ns / 1000.0,
            median_ns / 1000.0,
            stdev_ns / 1000.0,
            q1_ns / 1000.0,
            q3_ns / 1000.0,
            cv_pct,
            mibs
        });
    }
    return out;
}

std::vector<ComparisonRow> compare_cpp(const std::vector<SummaryBenchRow>& summary, bool io_included) {
    std::map<std::size_t, std::map<std::string, SummaryBenchRow>> by_size;
    for (const auto& r : summary) {
        if (r.io_included == io_included) {
            by_size[r.size_bytes][r.algorithm] = r;
        }
    }
    std::vector<ComparisonRow> out;
    for (const auto& [sz, algs] : by_size) {
        const auto& a = algs.at("SHA-256");
        const auto& b = algs.at("SHA3-256");
        out.push_back(ComparisonRow{
            io_included,
            sz,
            a.size_label,
            a.median_us,
            b.median_us,
            a.median_throughput_mibs,
            b.median_throughput_mibs,
            b.median_us / a.median_us
        });
    }
    return out;
}

void write_raw_csv(const fs::path& path, const std::vector<RawBenchRow>& rows) {
    std::ofstream ofs(path, std::ios::binary);
    ofs << "run_id,algorithm,input_path,size_bytes,repeat_index,elapsed_ns,io_included,"
           "python_version,platform,library_versions\n";
    for (const auto& r : rows) {
        ofs << r.run_id << "," << r.algorithm << "," << r.input_path << ","
            << r.size_bytes << "," << r.repeat_index << "," << r.elapsed_ns << ","
            << (r.io_included ? "True" : "False") << ",\"" << r.compiler_version << "\","
            << r.platform << ",\"" << r.library_versions << "\"\n";
    }
}

void write_summary_csv(const fs::path& path, const std::vector<SummaryBenchRow>& summary) {
    std::ofstream ofs(path, std::ios::binary);
    ofs << "run_id,io_included,algorithm,input_path,size_bytes,size_label,repeats,inner_loops,"
           "mean_us,median_us,stdev_us,q1_us,q3_us,cv_pct,median_throughput_mibs\n";
    for (const auto& r : summary) {
        ofs << r.run_id << "," << (r.io_included ? "True" : "False") << "," << r.algorithm << ","
            << r.input_path << "," << r.size_bytes << "," << r.size_label << ","
            << r.repeats << "," << r.inner_loops << ","
            << std::fixed << std::setprecision(3)
            << r.mean_us << "," << r.median_us << "," << r.stdev_us << ","
            << r.q1_us << "," << r.q3_us << ","
            << std::setprecision(2) << r.cv_pct << "," << r.median_throughput_mibs << "\n";
    }
}

void write_comparison_csv(const fs::path& path, const std::vector<ComparisonRow>& comp) {
    std::ofstream ofs(path, std::ios::binary);
    ofs << "io_included,size_bytes,size_label,sha256_median_us,sha3_256_median_us,"
           "sha256_median_mibs,sha3_256_median_mibs,time_ratio_sha3_over_sha256\n";
    for (const auto& c : comp) {
        ofs << (c.io_included ? "True" : "False") << "," << c.size_bytes << "," << c.size_label << ","
            << std::fixed << std::setprecision(3) << c.sha256_median_us << "," << c.sha3_256_median_us << ","
            << std::setprecision(2) << c.sha256_median_mibs << "," << c.sha3_256_median_mibs << ","
            << c.time_ratio_sha3_over_sha256 << "\n";
    }
}

void write_ablation_csv(const fs::path& path, const std::vector<AblationRow>& ablation) {
    std::ofstream ofs(path, std::ios::binary);
    ofs << "size_bytes,size_label,algorithm,default_median_mibs,sha_ni_masked_median_mibs,default_over_masked\n";
    for (const auto& a : ablation) {
        ofs << a.size_bytes << "," << a.size_label << "," << a.algorithm << ","
            << std::fixed << std::setprecision(2)
            << a.default_median_mibs << "," << a.sha_ni_masked_median_mibs << ","
            << a.default_over_masked << "\n";
    }
}

int run_benchmarks_cpp(
    const fs::path& data_root = "data",
    const fs::path& output_dir = "results/benchmark",
    const std::string& run_id = "BENCH-N18-CPP01",
    int repeats = 35,
    int warmup = 5,
    bool include_extended = true,
    bool sha_ni_ablation = true
) {
    fs::create_directories(output_dir);
    set_sha_ni_enabled(true);
    auto rows = measure_cpp(data_root, run_id, repeats, warmup, include_extended, {false, true});
    auto summary = summarize_cpp(rows);
    auto comp_ram = compare_cpp(summary, false);
    auto comp_io  = compare_cpp(summary, true);
    std::vector<ComparisonRow> comp = comp_ram;
    comp.insert(comp.end(), comp_io.begin(), comp_io.end());

    write_raw_csv(output_dir / "benchmark_results.csv", rows);
    write_summary_csv(output_dir / "benchmark_summary.csv", summary);
    write_comparison_csv(output_dir / "benchmark_comparison.csv", comp);

    std::vector<AblationRow> ablation_rows;
    if (sha_ni_ablation) {
        set_sha_ni_enabled(false);
        auto masked_rows = measure_cpp(data_root, run_id + "-SHA-NI-MASKED", repeats, warmup, include_extended, {false});
        set_sha_ni_enabled(true);
        auto masked_sum = summarize_cpp(masked_rows);

        std::map<std::pair<std::size_t, std::string>, SummaryBenchRow> normal_map;
        for (const auto& r : summary) {
            if (!r.io_included) {
                normal_map[{r.size_bytes, r.algorithm}] = r;
            }
        }
        for (const auto& m : masked_sum) {
            const auto& n = normal_map.at({m.size_bytes, m.algorithm});
            ablation_rows.push_back(AblationRow{
                m.size_bytes,
                m.size_label,
                m.algorithm,
                n.median_throughput_mibs,
                m.median_throughput_mibs,
                n.median_throughput_mibs / m.median_throughput_mibs
            });
        }
        write_ablation_csv(output_dir / "benchmark_sha_ni_ablation.csv", ablation_rows);
    }

    {
        std::ofstream env_out(output_dir / "benchmark_environment.json", std::ios::binary);
        env_out << "{\n"
                << "  \"run_id\": \"" << run_id << "\",\n"
                << "  \"cpu\": \"AMD Ryzen 7 8745H with Radeon 780M Graphics\",\n"
                << "  \"platform\": \"Windows-11-x86_64\",\n"
                << "  \"compiler\": \"g++ " << __VERSION__ << " (-std=c++17 -O3 -msha -msse4.1)\",\n"
                << "  \"implementation\": \"Native C++17 FIPS 180-4 (SHA-256 + SHA-NI intrinsics) & FIPS 202 (SHA3-256 Keccak-f[1600])\",\n"
                << "  \"repeats\": " << repeats << ",\n"
                << "  \"warmup\": " << warmup << ",\n"
                << "  \"timer\": \"std::chrono::steady_clock\",\n"
                << "  \"io_included_true_means\": \"std::ifstream binary read with warm OS page cache (64 KiB chunks)\",\n"
                << "  \"file_chunk_size_bytes\": " << DEFAULT_CHUNK_SIZE << "\n"
                << "}\n";
    }

    std::ostringstream log;
    log << std::string(100, '=') << "\n"
        << "NHẬT KÝ ĐO TỐC ĐỘ SHA-256 VÀ SHA3-256 — C++17 (THÀNH VIÊN A)\n"
        << "Run ID    : " << run_id << "\n"
        << "CPU       : AMD Ryzen 7 8745H with Radeon 780M Graphics (SHA-NI=" << (cpu_supports_sha_ni() ? "True" : "False") << ")\n"
        << "Compiler  : g++ " << __VERSION__ << " (-std=c++17 -O3 -msha -msse4.1)\n"
        << "Lặp       : " << repeats << " lần đo chính thức + " << warmup << " lần warmup / mỗi (chế độ, kích thước, thuật toán)\n"
        << "Đơn vị    : µs/lần băm (trung vị của các lô); thông lượng MiB/s tính từ trung vị\n"
        << "Ghi chú   : io_included=True = mở tệp + đọc 64 KiB với bộ đệm trang OS đã nóng\n"
        << std::string(100, '=') << "\n";

    for (bool io : {false, true}) {
        log << "\n[" << (io ? "CÓ MỞ/ĐỌC TỆP (io_included=True)" : "CHỈ HÀM BĂM TRONG RAM (io_included=False)") << "]\n"
            << std::left << std::setw(10) << "Kích thước" << " | "
            << std::left << std::setw(9) << "Thuật toán" << " | "
            << std::right << std::setw(5) << "Lô" << " | "
            << std::setw(11) << "Median µs" << " | "
            << std::setw(21) << "Q1–Q3 µs" << " | "
            << std::setw(6) << "CV %" << " | "
            << std::setw(8) << "MiB/s" << "\n"
            << std::string(100, '-') << "\n";
        for (const auto& r : summary) {
            if (r.io_included == io) {
                std::ostringstream q_range;
                q_range << std::fixed << std::setprecision(3) << std::setw(10) << r.q1_us
                        << "–" << std::left << std::setw(10) << r.q3_us;
                log << std::left << std::setw(10) << r.size_label << " | "
                    << std::left << std::setw(9) << r.algorithm << " | "
                    << std::right << std::setw(5) << r.inner_loops << " | "
                    << std::fixed << std::setprecision(3) << std::setw(11) << r.median_us << " | "
                    << q_range.str() << " | "
                    << std::fixed << std::setprecision(2) << std::setw(6) << r.cv_pct << " | "
                    << std::fixed << std::setprecision(1) << std::setw(8) << r.median_throughput_mibs << "\n";
            }
        }
    }

    log << "\n[TỶ SỐ THỜI GIAN T(SHA3-256) / T(SHA-256)]\n";
    for (const auto& c : comp) {
        log << "  " << (c.io_included ? "IO " : "RAM") << " "
            << std::left << std::setw(8) << c.size_label << std::right
            << ": SHA-256 " << std::fixed << std::setprecision(1) << std::setw(8) << c.sha256_median_mibs << " MiB/s | "
            << "SHA3-256 " << std::setw(8) << c.sha3_256_median_mibs << " MiB/s | "
            << "tỷ số " << std::setprecision(2) << c.time_ratio_sha3_over_sha256 << "\n";
    }

    if (!ablation_rows.empty()) {
        log << "\n[KIỂM CHỨNG SHA-NI: chế độ RAM, bật SHA-NI phần cứng vs tắt SHA-NI (chạy C++ thuần)]\n";
        for (const auto& a : ablation_rows) {
            log << "  " << std::left << std::setw(8) << a.size_label << " "
                << std::left << std::setw(9) << a.algorithm << std::right
                << ": mặc định " << std::fixed << std::setprecision(1) << std::setw(8) << a.default_median_mibs << " MiB/s | "
                << "tắt SHA-NI " << std::setw(8) << a.sha_ni_masked_median_mibs << " MiB/s | "
                << "x" << std::setprecision(2) << a.default_over_masked << "\n";
        }
    }
    log << std::string(100, '=') << "\n";

    std::ofstream log_out(output_dir / "benchmark.log", std::ios::binary);
    log_out << log.str();
    std::cout << log.str();
    std::cout << "Saved " << rows.size() << " raw rows to " << (output_dir / "benchmark_results.csv").generic_string() << "\n";
    return 0;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    fs::path data_root = "data";
    fs::path output_dir = "results/benchmark";
    std::string run_id = "BENCH-N18-CPP01";
    int repeats = 35;
    int warmup = 5;
    bool include_extended = true;
    bool sha_ni_ablation = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--data-root" && i + 1 < argc) data_root = argv[++i];
        else if (arg == "--output-dir" && i + 1 < argc) output_dir = argv[++i];
        else if (arg == "--run-id" && i + 1 < argc) run_id = argv[++i];
        else if (arg == "--repeats" && i + 1 < argc) repeats = std::stoi(argv[++i]);
        else if (arg == "--warmup" && i + 1 < argc) warmup = std::stoi(argv[++i]);
        else if (arg == "--no-extended") include_extended = false;
        else if (arg == "--sha-ni-ablation") sha_ni_ablation = true;
    }

    return run_benchmarks_cpp(data_root, output_dir, run_id, repeats, warmup, include_extended, sha_ni_ablation);
}

