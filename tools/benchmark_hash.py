"""Đo tốc độ (Benchmark) SHA-256 và SHA3-256 trên nhiều kích thước tệp (Thành viên A).

Quy ước thực nghiệm (theo data/README.md):
- Đo SHA-256 và SHA3-256 trên cùng từng tệp benchmark:
  + Mặc định (trong Git): 1 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB (`data/benchmark/`).
  + Mở rộng (nếu có): 4 MiB và 16 MiB (`data/benchmark_extended/`, sinh bằng generate_dataset.py --extended).
- Ghi rõ thuật toán, số lần lặp, đơn vị, phiên bản công cụ và `io_included`:
  + False: dữ liệu nạp sẵn vào RAM, chỉ đo hàm băm.
  + True : đo cả mở tệp + đọc (bộ đệm trang của OS đã "nóng" sau warmup, KHÔNG phải đọc đĩa vật lý).
- Mỗi lần đo (repeat) gồm `inner_loops` lần băm liên tiếp để thời gian một mẫu đủ lớn so với
  độ phân giải đồng hồ (tệp 1 KiB chỉ mất vài µs/lần). `elapsed_ns` là tổng thời gian của cả lô;
  `ns_per_op = elapsed_ns / inner_loops`. 10 cột đầu giữ đúng thứ tự `data/benchmark_results_template.csv`.
- Thứ tự SHA-256/SHA3-256 được đảo xen kẽ giữa các lần lặp để giảm sai lệch do trôi nhiệt/tần số CPU.
- Tùy chọn `--sha-ni-ablation`: chạy lại chế độ RAM trong tiến trình con với biến môi trường
  `OPENSSL_ia32cap=":~0x20000000"` (cơ chế chính thức của OpenSSL để che bit CPUID SHA extensions)
  nhằm kiểm chứng ảnh hưởng của tập lệnh SHA-NI lên SHA-256.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import ssl
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.dataset_io import DATA_ROOT, load_manifest
from tools.hash_checker import compute_digest_bytes, compute_digest_file

BENCHMARK_CSV_HEADER = [
    "run_id",
    "algorithm",
    "input_path",
    "size_bytes",
    "repeat_index",
    "elapsed_ns",
    "io_included",
    "python_version",
    "platform",
    "library_versions",
]

ALGORITHMS = ("SHA-256", "SHA3-256")
SHA_NI_MASK_ENV = {"OPENSSL_ia32cap": ":~0x20000000"}


class BenchmarkDataError(RuntimeError):
    """Tệp benchmark không khớp kích thước/giá trị băm tham chiếu."""


def format_size_label(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes // (1024 * 1024)} MiB"
    if size_bytes >= 1024:
        return f"{size_bytes // 1024} KiB"
    return f"{size_bytes} B"


def cpu_name() -> str:
    if sys.platform.startswith("win"):
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"],
                capture_output=True, text=True, timeout=20,
            ).stdout.strip()
            if out:
                return out
        except (OSError, subprocess.SubprocessError):
            pass
    return platform.processor() or "unknown"


def collect_benchmark_targets(data_root: Path, include_extended: bool = True) -> list[dict[str, object]]:
    """Thu thập tệp benchmark (manifest + benchmark_extended nếu có)."""
    manifest = load_manifest(data_root)
    targets: list[dict[str, object]] = []
    for item in manifest["benchmarks"]:
        targets.append({
            "rel_path": item["path"],
            "full_path": data_root / item["path"],
            "size_bytes": item["size_bytes"],
            "sha256": item["sha256"],
            "sha3_256": item["sha3_256"],
        })
    if include_extended:
        ext_dir = data_root / "benchmark_extended"
        if ext_dir.exists():
            for ext_file in sorted(ext_dir.glob("*_bytes.bin")):
                data = ext_file.read_bytes()
                targets.append({
                    "rel_path": f"benchmark_extended/{ext_file.name}",
                    "full_path": ext_file,
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "sha3_256": hashlib.sha3_256(data).hexdigest(),
                })
    targets.sort(key=lambda x: int(x["size_bytes"]))
    return targets


def inner_loops_for(size_bytes: int, io_included: bool) -> int:
    """Số lần băm trong một lô: mục tiêu ~1 MiB dữ liệu/lô (RAM) hoặc ~256 KiB/lô (có I/O)."""
    target = 256 * 1024 if io_included else 1024 * 1024
    return max(1, math.ceil(target / size_bytes))


def _time_batch(alg: str, io_included: bool, full_path: Path, data: bytes, loops: int) -> int:
    if io_included:
        t0 = time.perf_counter_ns()
        for _ in range(loops):
            compute_digest_file(full_path, alg)
        return time.perf_counter_ns() - t0
    t0 = time.perf_counter_ns()
    for _ in range(loops):
        compute_digest_bytes(data, alg)
    return time.perf_counter_ns() - t0


def measure(
    data_root: Path,
    run_id: str,
    repeats: int,
    warmup: int,
    include_extended: bool,
    modes: tuple[bool, ...] = (False, True),
) -> list[dict[str, object]]:
    """Trả về danh sách dòng đo thô (đúng cột BENCHMARK_CSV_HEADER)."""
    targets = collect_benchmark_targets(data_root, include_extended)
    py_ver = sys.version.split()[0]
    plat_str = platform.platform()
    cap_env = os.environ.get("OPENSSL_ia32cap", "default")
    rows: list[dict[str, object]] = []

    for io_included in modes:
        for target in targets:
            full_path = Path(target["full_path"])
            size_bytes = int(target["size_bytes"])
            data = full_path.read_bytes()
            if len(data) != size_bytes:
                raise BenchmarkDataError(f"Size mismatch: {target['rel_path']}")
            if compute_digest_bytes(data, "SHA-256") != target["sha256"] or \
               compute_digest_bytes(data, "SHA3-256") != target["sha3_256"]:
                raise BenchmarkDataError(f"Digest mismatch: {target['rel_path']}")

            loops = inner_loops_for(size_bytes, io_included)
            lib_ver = f"{ssl.OPENSSL_VERSION}; batch_loops={loops}; OPENSSL_ia32cap={cap_env}"
            for alg in ALGORITHMS:
                for _ in range(warmup):
                    _time_batch(alg, io_included, full_path, data, loops)

            for rep_idx in range(1, repeats + 1):
                order = ALGORITHMS if rep_idx % 2 else tuple(reversed(ALGORITHMS))
                for alg in order:
                    batch_ns = _time_batch(alg, io_included, full_path, data, loops)
                    elapsed_per_op_ns = round(batch_ns / loops)
                    rows.append({
                        "run_id": run_id,
                        "algorithm": alg,
                        "input_path": target["rel_path"],
                        "size_bytes": size_bytes,
                        "repeat_index": rep_idx,
                        "elapsed_ns": elapsed_per_op_ns,
                        "io_included": io_included,
                        "python_version": py_ver,
                        "platform": plat_str,
                        "library_versions": lib_ver,
                    })
    rows.sort(key=lambda r: (r["io_included"], r["size_bytes"], r["algorithm"], r["repeat_index"]))
    return rows


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple, list[dict[str, object]]] = {}
    for r in rows:
        key = (str(r["io_included"]) == "True", int(r["size_bytes"]), str(r["algorithm"]))
        groups.setdefault(key, []).append(r)
    out: list[dict[str, object]] = []
    for (io_included, size_bytes, alg), grp in sorted(groups.items()):
        per_op = [float(r["elapsed_ns"]) for r in grp]
        median_ns = statistics.median(per_op)
        q = statistics.quantiles(per_op, n=4) if len(per_op) >= 2 else [median_ns] * 3
        mib = size_bytes / (1024 * 1024)
        mean_ns = statistics.fmean(per_op)
        loops = inner_loops_for(size_bytes, io_included)
        out.append({
            "run_id": grp[0]["run_id"],
            "io_included": io_included,
            "algorithm": alg,
            "input_path": grp[0]["input_path"],
            "size_bytes": size_bytes,
            "size_label": format_size_label(size_bytes),
            "repeats": len(grp),
            "inner_loops": loops,
            "mean_us": round(mean_ns / 1000, 3),
            "median_us": round(median_ns / 1000, 3),
            "stdev_us": round((statistics.stdev(per_op) if len(per_op) > 1 else 0.0) / 1000, 3),
            "q1_us": round(q[0] / 1000, 3),
            "q3_us": round(q[2] / 1000, 3),
            "cv_pct": round((statistics.stdev(per_op) / mean_ns * 100) if len(per_op) > 1 else 0.0, 2),
            "median_throughput_mibs": round(mib / (median_ns / 1e9), 2),
        })
    return out


def compare(summary: list[dict[str, object]], io_included: bool) -> list[dict[str, object]]:
    by_size: dict[int, dict[str, dict[str, object]]] = {}
    for r in summary:
        if r["io_included"] == io_included:
            by_size.setdefault(int(r["size_bytes"]), {})[str(r["algorithm"])] = r
    rows = []
    for size, algs in sorted(by_size.items()):
        a, b = algs["SHA-256"], algs["SHA3-256"]
        rows.append({
            "io_included": io_included,
            "size_bytes": size,
            "size_label": a["size_label"],
            "sha256_median_us": a["median_us"],
            "sha3_256_median_us": b["median_us"],
            "sha256_median_mibs": a["median_throughput_mibs"],
            "sha3_256_median_mibs": b["median_throughput_mibs"],
            "time_ratio_sha3_over_sha256": round(float(b["median_us"]) / float(a["median_us"]), 2),
        })
    return rows


def write_csv(path: Path, rows: list[dict[str, object]], header: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header or list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def run_sha_ni_ablation(data_root: Path, output_dir: Path, repeats: int, warmup: int, include_extended: bool) -> Path:
    """Chạy lại chế độ RAM trong tiến trình con với SHA-NI bị che qua OPENSSL_ia32cap."""
    raw_path = output_dir / "benchmark_sha_ni_masked_raw.csv"
    cmd = [sys.executable, str(Path(__file__).resolve()), "--internal-masked-run",
           "--data-root", str(data_root), "--output-dir", str(output_dir),
           "--repeats", str(repeats), "--warmup", str(warmup)]
    if not include_extended:
        cmd.append("--no-extended")
    subprocess.run(cmd, env={**os.environ, **SHA_NI_MASK_ENV}, check=True)
    return raw_path


def run_benchmarks(
    data_root: Path = DATA_ROOT,
    output_dir: Path = ROOT / "results" / "benchmark",
    run_id: str = "BENCH-N18-RUN02",
    repeats: int = 35,
    warmup: int = 5,
    include_extended: bool = True,
    sha_ni_ablation: bool = False,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = measure(data_root, run_id, repeats, warmup, include_extended)
    summary = summarize(rows)
    comp = compare(summary, False) + compare(summary, True)

    write_csv(output_dir / "benchmark_results.csv", rows, BENCHMARK_CSV_HEADER)
    write_csv(output_dir / "benchmark_summary.csv", summary)
    write_csv(output_dir / "benchmark_comparison.csv", comp)

    ablation_rows: list[dict[str, object]] = []
    if sha_ni_ablation:
        masked_raw = run_sha_ni_ablation(data_root, output_dir, repeats, warmup, include_extended)
        with masked_raw.open(encoding="utf-8") as f:
            masked_summary = summarize(list(csv.DictReader(f)))
        normal = {(r["size_bytes"], r["algorithm"]): r for r in summary if not r["io_included"]}
        for m in masked_summary:
            n = normal[(m["size_bytes"], m["algorithm"])]
            ablation_rows.append({
                "size_bytes": m["size_bytes"],
                "size_label": m["size_label"],
                "algorithm": m["algorithm"],
                "default_median_mibs": n["median_throughput_mibs"],
                "sha_ni_masked_median_mibs": m["median_throughput_mibs"],
                "default_over_masked": round(float(n["median_throughput_mibs"]) / float(m["median_throughput_mibs"]), 2),
            })
        write_csv(output_dir / "benchmark_sha_ni_ablation.csv", ablation_rows)

    env = {
        "run_id": run_id,
        "cpu": cpu_name(),
        "platform": platform.platform(),
        "python": sys.version,
        "openssl": ssl.OPENSSL_VERSION,
        "repeats": repeats,
        "warmup": warmup,
        "timer": "time.perf_counter_ns",
        "io_included_true_means": "open+read with warm OS page cache (not cold physical disk)",
        "file_chunk_size_bytes": 64 * 1024,
    }
    (output_dir / "benchmark_environment.json").write_text(json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")

    log = build_log(env, summary, comp, ablation_rows)
    (output_dir / "benchmark.log").write_text(log, encoding="utf-8")
    return {"raw_count": len(rows), "summary": summary, "comparison": comp, "ablation": ablation_rows,
            "raw_csv": output_dir / "benchmark_results.csv", "log_path": output_dir / "benchmark.log"}


def build_log(env: dict, summary: list[dict], comp: list[dict], ablation: list[dict]) -> str:
    L = ["=" * 100,
         "NHẬT KÝ ĐO TỐC ĐỘ SHA-256 VÀ SHA3-256 (THÀNH VIÊN A)",
         f"Run ID    : {env['run_id']}",
         f"CPU       : {env['cpu']}",
         f"Platform  : {env['platform']}",
         f"Python    : {env['python'].split()[0]} | {env['openssl']}",
         f"Lặp       : {env['repeats']} lần đo chính thức + {env['warmup']} lần warmup / mỗi (chế độ, kích thước, thuật toán)",
         "Đơn vị    : µs/lần băm (trung vị của các lô); thông lượng MiB/s tính từ trung vị",
         "Ghi chú   : io_included=True = mở tệp + đọc với bộ đệm trang OS đã nóng (không phải đĩa lạnh)",
         "=" * 100]
    for io in (False, True):
        L.append("")
        L.append("[" + ("CÓ MỞ/ĐỌC TỆP (io_included=True)" if io else "CHỈ HÀM BĂM TRONG RAM (io_included=False)") + "]")
        L.append(f"{'Kích thước':<10} | {'Thuật toán':<9} | {'Lô':>5} | {'Median µs':>11} | {'Q1–Q3 µs':>21} | {'CV %':>6} | {'MiB/s':>8}")
        L.append("-" * 100)
        for r in summary:
            if r["io_included"] == io:
                L.append(f"{r['size_label']:<10} | {r['algorithm']:<9} | {r['inner_loops']:>5} | {r['median_us']:>11.3f} | "
                         f"{r['q1_us']:>10.3f}–{r['q3_us']:<10.3f} | {r['cv_pct']:>6.2f} | {r['median_throughput_mibs']:>8.1f}")
    L.append("")
    L.append("[TỶ SỐ THỜI GIAN T(SHA3-256) / T(SHA-256)]")
    for c in comp:
        tag = "IO " if c["io_included"] else "RAM"
        L.append(f"  {tag} {c['size_label']:<8}: SHA-256 {c['sha256_median_mibs']:>8.1f} MiB/s | "
                 f"SHA3-256 {c['sha3_256_median_mibs']:>8.1f} MiB/s | tỷ số {c['time_ratio_sha3_over_sha256']:.2f}")
    if ablation:
        L.append("")
        L.append("[KIỂM CHỨNG SHA-NI: chế độ RAM, OPENSSL_ia32cap=\":~0x20000000\" che bit SHA extensions]")
        for a in ablation:
            L.append(f"  {a['size_label']:<8} {a['algorithm']:<9}: mặc định {a['default_median_mibs']:>8.1f} MiB/s | "
                     f"che SHA-NI {a['sha_ni_masked_median_mibs']:>8.1f} MiB/s | x{a['default_over_masked']:.2f}")
    L.append("=" * 100)
    return "\n".join(L) + "\n"


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-root", type=Path, default=DATA_ROOT)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results" / "benchmark")
    parser.add_argument("--run-id", default="BENCH-N18-RUN02")
    parser.add_argument("--repeats", type=int, default=35)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--no-extended", action="store_true")
    parser.add_argument("--sha-ni-ablation", action="store_true")
    parser.add_argument("--internal-masked-run", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.internal_masked_run:
        rows = measure(args.data_root, args.run_id + "-SHA-NI-MASKED", args.repeats, args.warmup,
                       not args.no_extended, modes=(False,))
        write_csv(args.output_dir / "benchmark_sha_ni_masked_raw.csv", rows, BENCHMARK_CSV_HEADER)
        return 0

    res = run_benchmarks(args.data_root, args.output_dir, args.run_id, args.repeats, args.warmup,
                         not args.no_extended, args.sha_ni_ablation)
    print(Path(res["log_path"]).read_text(encoding="utf-8"))
    print(f"Saved {res['raw_count']} raw rows to {res['raw_csv']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
