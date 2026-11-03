from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
BUILD = ROOT / "build"
CXX_FLAGS = ["-std=c++17", "-O3", "-msha", "-msse4.1", "-mssse3"]


def run_cmd(title: str, cmd: list[str]) -> None:
    print(f"\n=== {title} ===", flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def build_cpp_binaries() -> None:
    print("\n=== Biên dịch bộ chương trình C++17 (g++) ===", flush=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    targets = [
        ("test_hash_checker.exe", ["cpp/hash_checker.cpp", "cpp/test_hash_checker.cpp"]),
        ("hash_cli.exe", ["cpp/hash_checker.cpp", "cpp/hash_cli.cpp"]),
        ("demo_tamper_hash.exe", ["cpp/hash_checker.cpp", "cpp/demo_tamper_hash.cpp"]),
        ("run_hash_experiments.exe", ["cpp/hash_checker.cpp", "cpp/run_hash_experiments.cpp"]),
        ("benchmark_hash.exe", ["cpp/hash_checker.cpp", "cpp/benchmark_hash.cpp"]),
    ]
    for exe_name, sources in targets:
        out_path = BUILD / exe_name
        cmd = ["g++", *CXX_FLAGS, *sources, "-o", str(out_path)]
        subprocess.run(cmd, cwd=ROOT, check=True)
        print(f"  [OK] {out_path.relative_to(ROOT)}")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true")
    a = parser.parse_args()
    repeats, warmup = ("5", "1") if a.quick else ("35", "5")

    run_cmd("Kiểm tra bộ dữ liệu", [PY, "tools/generate_dataset.py", "--check"])
    run_cmd("Sinh tệp benchmark mở rộng 4/16 MiB", [PY, "tools/generate_dataset.py", "--extended"])
    build_cpp_binaries()
    run_cmd("Unit test C++17 (12 tests)", [str(BUILD / "test_hash_checker.exe")])
    run_cmd("Thực nghiệm TC01–TC09 (C++17)", [str(BUILD / "run_hash_experiments.exe")])
    run_cmd("Demo sửa tệp/thay manifest (C++17)", [str(BUILD / "demo_tamper_hash.exe")])
    run_cmd(
        "Benchmark tốc độ SHA-256 & SHA3-256 (C++17)",
        [str(BUILD / "benchmark_hash.exe"), "--repeats", repeats, "--warmup", warmup, "--sha-ni-ablation"],
    )
    run_cmd("Vẽ biểu đồ PNG", [PY, "tools/plot_hash_results.py"])

    evidence = ROOT / "docs" / "evidence" / "hash"
    figures = ROOT / "docs" / "figures"
    evidence.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    for src in [
        *(ROOT / "results" / "hash").glob("*.csv"),
        *(ROOT / "results" / "hash").glob("*.log"),
        *(ROOT / "results" / "benchmark").glob("*.csv"),
        *(ROOT / "results" / "benchmark").glob("*.log"),
        *(ROOT / "results" / "benchmark").glob("*.json"),
    ]:
        shutil.copy2(src, evidence / src.name)
    for png in (ROOT / "results" / "charts").glob("*.png"):
        shutil.copy2(png, figures / png.name)
    print(f"\nĐã gom minh chứng C++17 vào {evidence.relative_to(ROOT)} và biểu đồ vào {figures.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
