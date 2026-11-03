// Demo thực tế bằng C++17: sửa tệp, rồi sửa cả tệp lẫn manifest đi kèm (Thành viên A).
#define ATTT_HASH_CLI_AS_LIBRARY
#include "hash_cli.cpp"

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

int invoke_and_log(const std::vector<std::string>& args, std::vector<std::string>& log) {
    std::ostringstream out_buf;
    int code = run_cli_command(args, out_buf, out_buf);
    std::string cmd_line = "$ ./build/hash_cli";
    for (const auto& a : args) {
        cmd_line += " " + a;
    }
    log.push_back(cmd_line);

    std::istringstream iss(out_buf.str());
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        log.push_back("  " + line);
    }
    log.push_back("  [exit code = " + std::to_string(code) + "]");
    return code;
}

std::map<std::string, int> run_demo_cpp(
    const fs::path& data_root = "data",
    const fs::path& work = "results/hash/demo"
) {
    if (fs::exists(work)) {
        fs::remove_all(work);
    }
    fs::path pkg = work / "goi_gui";
    fs::path trusted = work / "kenh_tin_cay";
    fs::create_directories(pkg);
    fs::create_directories(trusted);

    fs::copy_file(data_root / "samples/S08_order_synthetic.json", pkg / "don_hang.json", fs::copy_options::overwrite_existing);
    fs::copy_file(data_root / "samples/S09_students_synthetic.csv", pkg / "sinh_vien.csv", fs::copy_options::overwrite_existing);

    std::vector<std::string> log = {
        "DEMO SỬA TỆP VÀ THAY HASH ĐI KÈM (SHA-256 thuần — C++17)",
        std::string(80, '=')
    };
    std::map<std::string, int> codes;

    log.push_back("\n[B0] Bên gửi tạo manifest; bản đi kèm gói + bản tham chiếu tách riêng");
    fs::path accompanying = work / "goi_gui.manifest";
    invoke_and_log({"manifest-create", pkg.generic_string(), "-o", accompanying.generic_string()}, log);
    fs::copy_file(accompanying, trusted / "goi_gui.manifest", fs::copy_options::overwrite_existing);
    std::string man_text = hash_checker::read_text_utf8(accompanying);
    while (!man_text.empty() && (man_text.back() == '\n' || man_text.back() == '\r')) {
        man_text.pop_back();
    }
    log.push_back(man_text);

    log.push_back("\n[B1] Kiểm tra gói nguyên vẹn bằng manifest đi kèm");
    codes["B1_intact"] = invoke_and_log({"manifest-check", accompanying.generic_string()}, log);

    log.push_back("\n[B2] Kẻ tấn công sửa amount 120000 -> 920000, KHÔNG sửa manifest");
    fs::path order = pkg / "don_hang.json";
    std::string orig_str = hash_checker::read_text_utf8(order);
    std::string target = "\"amount\":120000";
    std::string repl = "\"amount\":920000";
    std::size_t pos = orig_str.find(target);
    if (pos == std::string::npos) {
        throw std::runtime_error("Demo precondition failed: amount field not found in S08");
    }
    std::string tampered_str = orig_str;
    tampered_str.replace(pos, target.size(), repl);
    {
        std::ofstream ofs(order, std::ios::binary);
        ofs.write(tampered_str.data(), static_cast<std::streamsize>(tampered_str.size()));
    }
    std::string trimmed = tampered_str;
    while (!trimmed.empty() && (trimmed.back() == '\n' || trimmed.back() == '\r')) {
        trimmed.pop_back();
    }
    log.push_back("  nội dung mới: " + trimmed);
    codes["B2_tamper_keep_manifest"] = invoke_and_log({"manifest-check", accompanying.generic_string()}, log);

    log.push_back("\n[B3] Kẻ tấn công tính lại hash và GHI ĐÈ manifest đi kèm gói");
    invoke_and_log({"manifest-create", pkg.generic_string(), "-o", accompanying.generic_string()}, log);
    codes["B3_tamper_and_replace_manifest"] = invoke_and_log({"manifest-check", accompanying.generic_string()}, log);

    log.push_back("\n[B4] Người nhận kiểm tra bằng manifest tham chiếu lưu tách riêng");
    codes["B4_trusted_reference"] = invoke_and_log(
        {"manifest-check", (trusted / "goi_gui.manifest").generic_string(), "--base-dir", pkg.generic_string()},
        log
    );

    log.push_back("\n" + std::string(80, '='));
    log.push_back("TÓM TẮT (exit 0 = chấp nhận, 1 = phát hiện sai khác)");
    std::map<std::string, int> expect = {
        {"B1_intact", 0},
        {"B2_tamper_keep_manifest", 1},
        {"B3_tamper_and_replace_manifest", 0},
        {"B4_trusted_reference", 1}
    };
    for (const auto& [k, exp] : expect) {
        int v = codes[k];
        std::ostringstream line;
        line << "  " << std::left << std::setw(32) << k
             << " exit=" << v << " | kỳ vọng=" << exp
             << " | " << (v == exp ? "ĐÚNG" : "SAI");
        log.push_back(line.str());
    }
    log.push_back("Kết luận: B3 cho thấy hash đi cùng kênh với tệp không chứng minh nguồn gốc;"
                  " B4 cho thấy hash chỉ có giá trị khi tham chiếu được bảo vệ độc lập.");

    fs::path log_path = work.parent_path() / "demo_tamper.log";
    std::ofstream log_out(log_path, std::ios::binary);
    for (const auto& l : log) {
        log_out << l << "\n";
    }
    return codes;
}

#ifndef ATTT_DEMO_TAMPER_AS_LIBRARY
int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    run_demo_cpp();
    std::cout << hash_checker::read_text_utf8("results/hash/demo_tamper.log");
    return 0;
}
#endif

