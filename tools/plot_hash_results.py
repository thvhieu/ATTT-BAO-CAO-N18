"""Sinh biểu đồ từ CSV kết quả thật của phần Hash thuần và benchmark (không gõ cứng số liệu)."""
from __future__ import annotations

import argparse
import csv
from pathlib import Path
import statistics
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]

plt.rcParams["font.sans-serif"] = ["Segoe UI", "Arial", "DejaVu Sans", "Tahoma"]
plt.rcParams["axes.unicode_minus"] = False
plt.rcParams["figure.dpi"] = 180

C256, C3 = "#1f77b4", "#ff7f0e"


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _select(rows, io: bool, alg: str):
    return sorted((r for r in rows if r["io_included"] == str(io) and r["algorithm"] == alg),
                  key=lambda r: int(r["size_bytes"]))


def _annotate(ax, bars, color, bold=False):
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.0f}", xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 3),
                    textcoords="offset points", ha="center", va="bottom", fontsize=8,
                    fontweight="bold" if bold else "normal", color=color)


def plot_throughput(summary, out_path: Path) -> None:
    """Hình 1: thông lượng trung vị theo kích thước, (a) chỉ băm trong RAM, (b) so với có mở/đọc tệp."""
    p256, p3 = _select(summary, False, "SHA-256"), _select(summary, False, "SHA3-256")
    i256, i3 = _select(summary, True, "SHA-256"), _select(summary, True, "SHA3-256")
    labels = [r["size_label"] for r in p256]
    x = np.arange(len(labels))
    y256 = [float(r["median_throughput_mibs"]) for r in p256]
    y3 = [float(r["median_throughput_mibs"]) for r in p3]
    top = max(y256 + y3) * 1.18

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.4))
    w = 0.36
    _annotate(ax1, ax1.bar(x - w / 2, y256, w, label="SHA-256", color=C256), "#103d5d", True)
    _annotate(ax1, ax1.bar(x + w / 2, y3, w, label="SHA3-256", color=C3), "#8a4100")
    ax1.set_title("(a) Chỉ hàm băm, dữ liệu đã nạp sẵn trong RAM", fontsize=11, fontweight="bold")
    ax1.set_ylabel("Thông lượng trung vị (MiB/s)")
    ax1.set_xlabel("Kích thước tệp")
    ax1.set_xticks(x, labels, rotation=20)
    ax1.set_ylim(0, top)
    ax1.grid(axis="y", linestyle="--", alpha=0.45)
    ax1.legend(loc="upper left", fontsize=9)

    ax2.plot(x, y256, "o-", lw=2.2, color=C256, label="SHA-256 — chỉ băm")
    ax2.plot(x, [float(r["median_throughput_mibs"]) for r in i256], "s--", lw=1.8, color="#5fa2ce",
             label="SHA-256 — mở + đọc tệp + băm")
    ax2.plot(x, y3, "^-", lw=2.2, color=C3, label="SHA3-256 — chỉ băm")
    ax2.plot(x, [float(r["median_throughput_mibs"]) for r in i3], "d--", lw=1.8, color="#ffae66",
             label="SHA3-256 — mở + đọc tệp + băm")
    ax2.set_title("(b) Ảnh hưởng của chi phí mở/đọc tệp (bộ đệm OS đã nóng)", fontsize=11, fontweight="bold")
    ax2.set_ylabel("Thông lượng trung vị (MiB/s)")
    ax2.set_xlabel("Kích thước tệp")
    ax2.set_xticks(x, labels, rotation=20)
    ax2.set_ylim(0, top)
    ax2.grid(True, linestyle="--", alpha=0.45)
    ax2.legend(loc="lower right", fontsize=8.5)

    fig.suptitle("Thông lượng SHA-256 và SHA3-256 theo kích thước tệp", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def plot_latency(summary, out_path: Path) -> None:
    """Hình 2: (a) thời gian/lần băm log–log kèm thanh Q1–Q3, (b) tỷ số T(SHA3-256)/T(SHA-256)."""
    p256, p3 = _select(summary, False, "SHA-256"), _select(summary, False, "SHA3-256")
    sizes = [int(r["size_bytes"]) / 1024 for r in p256]
    labels = [r["size_label"] for r in p256]

    def series(rows):
        med = np.array([float(r["median_us"]) for r in rows])
        lo = med - np.array([float(r["q1_us"]) for r in rows])
        hi = np.array([float(r["q3_us"]) for r in rows]) - med
        return med, np.vstack([np.maximum(lo, 0), np.maximum(hi, 0)])

    m256, e256 = series(p256)
    m3, e3 = series(p3)
    ratios = m3 / m256

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.2, 5.2))
    ax1.errorbar(sizes, m256, yerr=e256, fmt="o-", lw=2.2, capsize=3, color=C256, label="SHA-256")
    ax1.errorbar(sizes, m3, yerr=e3, fmt="^-", lw=2.2, capsize=3, color=C3, label="SHA3-256")
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xticks(sizes, labels, rotation=20)
    ax1.minorticks_off()
    ax1.set_title("(a) Thời gian trung vị mỗi lần băm (log–log, thanh lỗi Q1–Q3)", fontsize=11, fontweight="bold")
    ax1.set_xlabel("Kích thước tệp")
    ax1.set_ylabel("µs / lần băm")
    ax1.grid(True, which="both", linestyle="--", alpha=0.45)
    ax1.legend(loc="upper left")

    x = np.arange(len(labels))
    bars = ax2.bar(x, ratios, width=0.5, color="#2ca02c", alpha=0.88)
    ax2.axhline(1.0, color="#d62728", ls="--", lw=1.2, label="Bằng nhau (1,0)")
    for bar in bars:
        h = bar.get_height()
        ax2.annotate(f"{h:.2f}", xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 4),
                     textcoords="offset points", ha="center", fontsize=9, fontweight="bold")
    ax2.set_xticks(x, labels, rotation=20)
    ax2.set_ylim(0, max(ratios) * 1.2)
    ax2.set_title("(b) Tỷ số thời gian T(SHA3-256) / T(SHA-256), chỉ băm", fontsize=11, fontweight="bold")
    ax2.set_xlabel("Kích thước tệp")
    ax2.set_ylabel("Lần")
    ax2.grid(axis="y", linestyle="--", alpha=0.45)
    ax2.legend(loc="upper left")

    fig.suptitle("Độ trễ và tỷ số tốc độ SHA-256 / SHA3-256", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


STATUS_STYLE = [
    ("REJECT", "REJECT — phát hiện sửa đổi", "#2ca02c"),
    ("ACCEPT", "ACCEPT — tệp nguyên vẹn", C256),
    ("ACCEPT_UNTRUSTED", "ACCEPT_UNTRUSTED — chấp nhận hash do bên sửa gửi kèm", "#d62728"),
    ("ACCEPT_METADATA_OUTSIDE_SCOPE", "ACCEPT_METADATA_OUTSIDE_SCOPE — metadata ngoài phạm vi", "#9467bd"),
    ("NOT_APPLICABLE", "NOT_APPLICABLE — bỏ qua (S01 rỗng ở TC09)", "#bbbbbb"),
]


def plot_detection_and_avalanche(results_rows, avalanche_rows, out_path: Path) -> None:
    """Hình 3: (a) đếm trạng thái thực tế theo TC đọc từ hash_verification_results.csv, (b) khoảng cách Hamming."""
    focus = ["TC01", "TC02", "TC03", "TC07", "TC09"]
    names = {"TC01": "Nguyên vẹn", "TC02": "Sửa 1 bit,\ngiữ hash gốc", "TC03": "Thay tệp\n+ hash kèm",
             "TC07": "Sửa metadata", "TC09": "Cắt 1 byte\ncuối"}
    counts = {c: {} for c in focus}
    for r in results_rows:
        if r["case_id"] in counts:
            counts[r["case_id"]][r["actual_status"]] = counts[r["case_id"]].get(r["actual_status"], 0) + 1

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.8, 5.6))
    x = np.arange(len(focus))
    bottom = np.zeros(len(focus))
    for status, label, color in STATUS_STYLE:
        vals = np.array([counts[c].get(status, 0) for c in focus])
        if vals.any():
            ax1.bar(x, vals, 0.55, bottom=bottom, label=label, color=color)
            for i, v in enumerate(vals):
                if v:
                    ax1.text(x[i], bottom[i] + v / 2, str(v), ha="center", va="center",
                             color="white", fontsize=10, fontweight="bold")
            bottom += vals
    ax1.set_xticks(x, [f"{c}\n{names[c]}" for c in focus], fontsize=8.8)
    ax1.set_ylabel("Số mẫu (S01–S18)")
    ax1.set_ylim(0, 26)
    ax1.set_title("(a) Trạng thái thực tế của kiểm tra SHA-256 theo tình huống", fontsize=11, fontweight="bold")
    ax1.grid(axis="y", linestyle="--", alpha=0.45)
    ax1.legend(loc="upper center", fontsize=7.6, ncol=1, framealpha=0.95)

    ids = [r["sample_id"] for r in avalanche_rows]
    h256 = [int(r["sha256_hamming_bits"]) for r in avalanche_rows]
    h3 = [int(r["sha3_256_hamming_bits"]) for r in avalanche_rows]
    xs = np.arange(len(ids))
    ax2.fill_between([-0.5, len(ids) - 0.5], 112, 144, color="#888888", alpha=0.15,
                     label="128 ± 2σ (σ = 8 bit, phân phối nhị thức B(256; 0,5))")
    ax2.axhline(128, color="#333333", ls="--", lw=1.2, label="Kỳ vọng 128/256 bit")
    ax2.plot(xs, h256, "o-", color=C256, lw=1.6,
             label=f"SHA-256 (TB {statistics.fmean(h256):.1f} bit)")
    ax2.plot(xs, h3, "^-", color=C3, lw=1.6,
             label=f"SHA3-256 (TB {statistics.fmean(h3):.1f} bit)")
    ax2.set_xticks(xs, ids, rotation=45, fontsize=8.5)
    ax2.set_xlim(-0.5, len(ids) - 0.5)
    ax2.set_ylim(90, 175)
    ax2.set_ylabel("Số bit digest thay đổi / 256")
    ax2.set_title("(b) Hiệu ứng thác đổ: tệp gốc so với tệp sửa 1 bit", fontsize=11, fontweight="bold")
    ax2.grid(True, linestyle="--", alpha=0.45)
    ax2.legend(loc="upper right", fontsize=8)

    fig.suptitle("Khả năng phát hiện sửa đổi và giới hạn của hash thuần", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def plot_sha_ni(ablation_rows, out_path: Path) -> None:
    """Hình 4: thông lượng mặc định so với khi che SHA-NI bằng OPENSSL_ia32cap."""
    labels = sorted({(int(r["size_bytes"]), r["size_label"]) for r in ablation_rows})
    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(11.5, 5.0))
    w = 0.2
    styles = [("SHA-256", "default_median_mibs", C256, "SHA-256 mặc định"),
              ("SHA-256", "sha_ni_masked_median_mibs", "#9ecae1", "SHA-256 che SHA-NI"),
              ("SHA3-256", "default_median_mibs", C3, "SHA3-256 mặc định"),
              ("SHA3-256", "sha_ni_masked_median_mibs", "#fdd0a2", "SHA3-256 che SHA-NI")]
    max_val = 0.0
    for k, (alg, col, color, lab) in enumerate(styles):
        idx = {int(r["size_bytes"]): float(r[col]) for r in ablation_rows if r["algorithm"] == alg}
        vals = [idx[s] for s, _ in labels]
        max_val = max(max_val, max(vals, default=0.0))
        bars = ax.bar(x + (k - 1.5) * w, vals, w, color=color, label=lab)
        for b in bars:
            h = b.get_height()
            ax.text(b.get_x() + b.get_width() / 2, h + 18, f"{h:.0f}",
                    ha="center", va="bottom", fontsize=7.5, color="#1f2937")
    ax.set_ylim(0, max_val * 1.22)
    ax.set_xticks(x, [l for _, l in labels])
    ax.set_ylabel("Thông lượng trung vị (MiB/s)")
    ax.set_xlabel("Kích thước tệp (chỉ băm trong RAM)")
    ax.set_title('Kiểm chứng vai trò SHA-NI: OPENSSL_ia32cap=":~0x20000000"', fontsize=12, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.45)
    ax.legend(loc="upper left", fontsize=9, ncol=2)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hash-dir", type=Path, default=ROOT / "results" / "hash")
    parser.add_argument("--bench-dir", type=Path, default=ROOT / "results" / "benchmark")
    parser.add_argument("--charts-dir", type=Path, default=ROOT / "results" / "charts")
    args = parser.parse_args()
    args.charts_dir.mkdir(parents=True, exist_ok=True)

    summary = load_csv_rows(args.bench_dir / "benchmark_summary.csv")
    outputs = [args.charts_dir / "fig1_hash_throughput_comparison.png",
               args.charts_dir / "fig2_hash_latency_and_speedup.png",
               args.charts_dir / "fig3_hash_detection_and_avalanche.png"]
    plot_throughput(summary, outputs[0])
    plot_latency(summary, outputs[1])
    plot_detection_and_avalanche(load_csv_rows(args.hash_dir / "hash_verification_results.csv"),
                                 load_csv_rows(args.hash_dir / "avalanche_analysis.csv"), outputs[2])
    ablation = args.bench_dir / "benchmark_sha_ni_ablation.csv"
    if ablation.exists():
        outputs.append(args.charts_dir / "fig4_sha_ni_ablation.png")
        plot_sha_ni(load_csv_rows(ablation), outputs[3])
    print("Generated charts:\n" + "\n".join(f"  - {p}" for p in outputs))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
