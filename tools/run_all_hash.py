"""Chạy toàn bộ phần việc A và gom minh chứng bàn giao vào docs/evidence/hash/.

    python tools/run_all_hash.py            # đầy đủ: 35 lần lặp, có kiểm chứng SHA-NI
    python tools/run_all_hash.py --quick    # chạy nhanh để thử (5 lần lặp)

`results/` bị Git bỏ qua theo quy ước nhóm; thư mục docs/evidence/hash/ là bản minh chứng đã chọn để bàn giao.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def step(title: str, args: list[str]) -> None:
    print(f"\n=== {title} ===", flush=True)
    subprocess.run([PY, *args], cwd=ROOT, check=True)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true")
    a = parser.parse_args()
    repeats, warmup = ("5", "1") if a.quick else ("35", "5")

    step("Kiểm tra bộ dữ liệu", ["tools/generate_dataset.py", "--check"])
    step("Sinh tệp benchmark mở rộng 4/16 MiB", ["tools/generate_dataset.py", "--extended"])
    step("Unit test", ["-m", "unittest", "discover", "-s", "tests"])
    step("Thực nghiệm TC01–TC09", ["tools/run_hash_experiments.py"])
    step("Demo sửa tệp/thay manifest", ["tools/demo_tamper_hash.py"])
    step("Benchmark", ["tools/benchmark_hash.py", "--repeats", repeats, "--warmup", warmup, "--sha-ni-ablation"])
    step("Vẽ biểu đồ", ["tools/plot_hash_results.py"])

    evidence = ROOT / "docs" / "evidence" / "hash"
    figures = ROOT / "docs" / "figures"
    evidence.mkdir(parents=True, exist_ok=True)
    figures.mkdir(parents=True, exist_ok=True)
    for src in [*(ROOT / "results" / "hash").glob("*.csv"), *(ROOT / "results" / "hash").glob("*.log"),
                *(ROOT / "results" / "benchmark").glob("*.csv"), *(ROOT / "results" / "benchmark").glob("*.log"),
                *(ROOT / "results" / "benchmark").glob("*.json")]:
        shutil.copy2(src, evidence / src.name)
    for png in (ROOT / "results" / "charts").glob("*.png"):
        shutil.copy2(png, figures / png.name)
    print(f"\nĐã gom minh chứng vào {evidence.relative_to(ROOT)} và biểu đồ vào {figures.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

