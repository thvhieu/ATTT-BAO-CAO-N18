#include "hash_checker.hpp"
#include "manifest_io.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;
using namespace hash_checker;

constexpr int EXIT_OK = 0;
constexpr int EXIT_MISMATCH = 1;
constexpr int EXIT_ERROR = 2;

int run_cli_command(const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
    if (args.empty()) {
        err << "ERROR: Missing subcommand (digest | verify | manifest-create | manifest-check)\n";
        return EXIT_ERROR;
    }
    const std::string& cmd = args[0];

    try {
        if (cmd == "digest") {
            std::string algo = "SHA-256";
            std::vector<fs::path> files;
            for (std::size_t i = 1; i < args.size(); ++i) {
                if (args[i] == "--algo" && i + 1 < args.size()) {
                    algo = args[++i];
                } else {
                    files.emplace_back(args[i]);
                }
            }
            if (files.empty()) {
                err << "ERROR: digest requires at least one file\n";
                return EXIT_ERROR;
            }
            std::string alg = canonical_algorithm_name(algo);
            for (const auto& f : files) {
                out << compute_digest_file(f, alg) << "  " << f.generic_string() << "\n";
            }
            return EXIT_OK;
        }

        if (cmd == "verify") {
            if (args.size() < 2) {
                err << "ERROR: verify requires a file path\n";
                return EXIT_ERROR;
            }
            fs::path file = args[1];
            std::string algo = "SHA-256";
            std::string expected;
            fs::path digest_file;
            for (std::size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--algo" && i + 1 < args.size()) {
                    algo = args[++i];
                } else if (args[i] == "--expected" && i + 1 < args.size()) {
                    expected = args[++i];
                } else if (args[i] == "--digest-file" && i + 1 < args.size()) {
                    digest_file = args[++i];
                }
            }
            if (expected.empty() && digest_file.empty()) {
                err << "ERROR: verify requires --expected or --digest-file\n";
                return EXIT_ERROR;
            }
            std::string alg = canonical_algorithm_name(algo);
            std::string exp_hex = !digest_file.empty() ? read_digest_file(digest_file) : expected;
            std::transform(exp_hex.begin(), exp_hex.end(), exp_hex.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::string actual = compute_digest_file(file, alg);
            bool ok = constant_time_equal(actual, exp_hex);
            out << (ok ? "OK" : "FAILED") << ": " << file.generic_string() << " (" << alg << ")\n";
            out << "  expected: " << exp_hex << "\n  actual  : " << actual << "\n";
            return ok ? EXIT_OK : EXIT_MISMATCH;
        }

        if (cmd == "manifest-create") {
            if (args.size() < 2) {
                err << "ERROR: manifest-create requires a directory\n";
                return EXIT_ERROR;
            }
            fs::path dir = args[1];
            fs::path output;
            std::string algo = "SHA-256";
            for (std::size_t i = 2; i < args.size(); ++i) {
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.size()) {
                    output = args[++i];
                } else if (args[i] == "--algo" && i + 1 < args.size()) {
                    algo = args[++i];
                }
            }
            if (output.empty()) {
                err << "ERROR: manifest-create requires -o/--output\n";
                return EXIT_ERROR;
            }
            auto entries = create_manifest(dir, algo);
            std::ofstream ofs(output, std::ios::binary);
            if (!ofs) {
                err << "ERROR: Cannot write manifest to " << output.generic_string() << "\n";
                return EXIT_ERROR;
            }
            ofs << format_manifest(entries);
            out << "Wrote " << entries.size() << " entries to " << output.generic_string() << "\n";
            return EXIT_OK;
        }

        if (cmd == "manifest-check") {
            if (args.size() < 2) {
                err << "ERROR: manifest-check requires a manifest path\n";
                return EXIT_ERROR;
            }
            fs::path manifest_path = args[1];
            fs::path base_dir;
            for (std::size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--base-dir" && i + 1 < args.size()) {
                    base_dir = args[++i];
                }
            }
            if (base_dir.empty()) {
                base_dir = manifest_path;
                base_dir.replace_extension("");
            }
            auto entries = parse_manifest(read_text_utf8(manifest_path));
            auto results = check_manifest(entries, base_dir);
            int bad = 0;
            for (const auto& [rel, st] : results) {
                out << std::left << std::setw(7) << st << " " << rel << "\n";
                if (st != "OK") {
                    ++bad;
                }
            }
            out << "Summary: " << (static_cast<int>(results.size()) - bad) << "/" << results.size() << " OK\n";
            return bad == 0 ? EXIT_OK : EXIT_MISMATCH;
        }

        err << "ERROR: Unknown subcommand: " << cmd << "\n";
        return EXIT_ERROR;
    } catch (const std::exception& ex) {
        err << "ERROR: " << ex.what() << "\n";
        return EXIT_ERROR;
    }
}

#ifndef ATTT_HASH_CLI_AS_LIBRARY
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    return run_cli_command(args, std::cout, std::cerr);
}
#endif
