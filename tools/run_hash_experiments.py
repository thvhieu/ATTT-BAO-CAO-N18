"""Thực thi bộ kiểm thử 9 tình huống (TC01–TC09) và thực nghiệm cho cơ chế Hash thuần (Thành viên A).

Sinh ra:
- results/hash/hash_verification_results.csv (theo đúng cấu trúc data/results_template.csv)
- results/hash/hash_sha3_cross_check.csv (đối chiếu bổ sung SHA3-256 trên 18 mẫu và các ca áp dụng)
- results/hash/hash_case_summary.csv (bảng tổng hợp theo từng TC01..TC09 và tỷ lệ phát hiện)
- results/hash/avalanche_analysis.csv (phân tích hiệu ứng thác đổ bit-level giữa tệp gốc và tệp sửa 1 bit)
- results/hash/hash_experiment.log (nhật ký chi tiết từng mẫu và từng ca kiểm thử)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import platform
import ssl
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.dataset_io import DATA_ROOT, load_manifest, load_sample
from tools.hash_checker import (
    VerificationResult,
    compute_digest_bytes,
    read_digest_file,
    verify_bytes,
)

RESULTS_CSV_HEADER = [
    "run_id",
    "case_id",
    "sample_id",
    "mechanism",
    "expected_status",
    "actual_status",
    "applicable_to_detection",
    "detected",
    "elapsed_ns",
    "evidence_path",
    "tool_versions",
]


def get_tool_versions() -> str:
    py_ver = f"Python {sys.version.split()[0]}"
    openssl_ver = ssl.OPENSSL_VERSION
    plat = platform.platform()
    return f"{py_ver}; {openssl_ver}; {plat}"


def hamming_distance_hex(hex_a: str, hex_b: str) -> int:
    """Tính khoảng cách Hamming (số bit khác nhau trên 256 bit) giữa hai chuỗi hex."""
    bytes_a = bytes.fromhex(hex_a)
    bytes_b = bytes.fromhex(hex_b)
    return sum((x ^ y).bit_count() for x, y in zip(bytes_a, bytes_b))


def evaluate_hash_case(
    case: dict,
    sample_id: str,
    data_root: Path = DATA_ROOT,
    algorithm: str = "SHA-256",
) -> dict[str, object]:
    """Đánh giá một ca kiểm thử (TC01–TC09) trên một mẫu `sample_id` cho cơ chế Hash thuần."""
    case_id = case["case_id"]
    expected_status = case["expected"]["hash"]
    sample = load_sample(sample_id, data_root)
    record = sample["record"]

    digest_key = "sha256" if algorithm == "SHA-256" else "sha3_256"
    trusted_digest = record[digest_key]

    # TC04, TC05, TC06, TC08: Không áp dụng cho Hash thuần (không có khóa, thẻ MAC hay nonce)
    if expected_status == "NOT_APPLICABLE":
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": expected_status,
            "actual_status": "NOT_APPLICABLE",
            "applicable_to_detection": False,
            "detected": False,
            "elapsed_ns": 0,
            "evidence_path": record["path"],
            "computed_digest": "",
            "reference_digest": "",
            "notes": f"Case {case_id} ({case['operation']}) is not applicable to keyless plain hash.",
        }

    # TC09 trên S01 (tệp rỗng 0 byte): bỏ qua theo quy ước ALL_NONEMPTY trong test_cases.json
    if case_id == "TC09" and record["size_bytes"] == 0:
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": "NOT_APPLICABLE",
            "actual_status": "NOT_APPLICABLE",
            "applicable_to_detection": False,
            "detected": False,
            "elapsed_ns": 0,
            "evidence_path": record["path"],
            "computed_digest": "",
            "reference_digest": "",
            "notes": "Skipped empty file S01 for TC09 (ALL_NONEMPTY).",
        }

    if case_id == "TC01":
        # Nguyên vẹn: kiểm tra sample["data"] với digest gốc trong manifest/digests
        ref_digest = (
            read_digest_file(data_root / record["reference_digest_path"])
            if algorithm == "SHA-256"
            else trusted_digest
        )
        res: VerificationResult = verify_bytes(
            sample["data"],
            ref_digest,
            algorithm=algorithm,
            digest_source="TRUSTED_REFERENCE",
        )
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": expected_status,
            "actual_status": res.status,
            "applicable_to_detection": False,  # Control case không tính vào mẫu số tỷ lệ phát hiện sửa đổi
            "detected": False,
            "elapsed_ns": res.elapsed_ns,
            "evidence_path": f"{record['path']}|{record['reference_digest_path']}",
            "computed_digest": res.computed_digest,
            "reference_digest": res.expected_digest,
            "notes": res.notes,
        }

    if case_id == "TC02":
        # Sửa nội dung giữ bằng chứng cũ: dùng tampered_data đối chiếu với digest gốc đáng tin cậy
        ref_digest = (
            read_digest_file(data_root / record["reference_digest_path"])
            if algorithm == "SHA-256"
            else trusted_digest
        )
        res = verify_bytes(
            sample["tampered_data"],
            ref_digest,
            algorithm=algorithm,
            digest_source="TRUSTED_REFERENCE",
        )
        detected = res.status == "REJECT"
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": expected_status,
            "actual_status": res.status,
            "applicable_to_detection": True,
            "detected": detected,
            "elapsed_ns": res.elapsed_ns,
            "evidence_path": f"{record['tampered_path']}|{record['reference_digest_path']}",
            "computed_digest": res.computed_digest,
            "reference_digest": res.expected_digest,
            "notes": res.notes,
        }

    if case_id == "TC03":
        # Thay cả tệp và SHA-256 được gửi kèm từ attacker_digest_path (kênh không xác thực)
        if algorithm == "SHA-256":
            attacker_digest = read_digest_file(data_root / record["attacker_digest_path"])
        else:
            attacker_digest = compute_digest_bytes(sample["tampered_data"], algorithm="SHA3-256")
        res = verify_bytes(
            sample["tampered_data"],
            attacker_digest,
            algorithm=algorithm,
            digest_source="UNTRUSTED_CHANNEL",
        )
        detected = res.status == "REJECT"
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": expected_status,
            "actual_status": res.status,
            "applicable_to_detection": True,
            "detected": detected,
            "elapsed_ns": res.elapsed_ns,
            "evidence_path": f"{record['tampered_path']}|{record['attacker_digest_path']}",
            "computed_digest": res.computed_digest,
            "reference_digest": res.expected_digest,
            "notes": res.notes,
        }

    if case_id == "TC07":
        # Metadata bị sửa (tampered_aad), nhưng tệp gốc giữ nguyên.
        # Profile mặc định: Hash chỉ bảo vệ byte của tệp, metadata nằm ngoài phạm vi.
        ref_digest = (
            read_digest_file(data_root / record["reference_digest_path"])
            if algorithm == "SHA-256"
            else trusted_digest
        )
        metadata_differs = sample["aad"] != sample["tampered_aad"]
        res = verify_bytes(
            sample["data"],
            ref_digest,
            algorithm=algorithm,
            digest_source="TRUSTED_REFERENCE",
            metadata_changed=metadata_differs,
        )
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": expected_status,
            "actual_status": res.status,
            "applicable_to_detection": False,  # Theo README: Không tính metadata ngoài phạm vi vào mẫu số phát hiện
            "detected": False,
            "elapsed_ns": res.elapsed_ns,
            "evidence_path": f"{record['path']}|{record['tampered_metadata_path']}",
            "computed_digest": res.computed_digest,
            "reference_digest": res.expected_digest,
            "notes": res.notes,
        }

    if case_id == "TC09":
        # Cắt ngắn 1 byte cuối của tệp gốc (chỉ áp dụng cho tệp khác rỗng)
        truncated_bytes = sample["data"][:-1]
        ref_digest = (
            read_digest_file(data_root / record["reference_digest_path"])
            if algorithm == "SHA-256"
            else trusted_digest
        )
        res = verify_bytes(
            truncated_bytes,
            ref_digest,
            algorithm=algorithm,
            digest_source="TRUSTED_REFERENCE",
        )
        detected = res.status == "REJECT"
        return {
            "case_id": case_id,
            "sample_id": sample_id,
            "expected_status": expected_status,
            "actual_status": res.status,
            "applicable_to_detection": True,
            "detected": detected,
            "elapsed_ns": res.elapsed_ns,
            "evidence_path": f"{record['path']}[:-1]|{record['reference_digest_path']}",
            "computed_digest": res.computed_digest,
            "reference_digest": res.expected_digest,
            "notes": res.notes,
        }

    raise ValueError(f"Unhandled test case: {case_id}")


def run_all_experiments(
    data_root: Path = DATA_ROOT,
    output_dir: Path = ROOT / "results" / "hash",
    run_id: str = "HASH-N18-RUN01",
) -> dict[str, object]:
    """Chạy toàn bộ thực nghiệm kiểm tra tệp và phân tích cho phần việc A."""
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(data_root)
    test_cases_doc = json.loads((data_root / "test_cases.json").read_text(encoding="utf-8"))
    cases = test_cases_doc["cases"]
    samples = manifest["samples"]
    tool_versions = get_tool_versions()

    results_rows: list[dict[str, object]] = []
    sha3_rows: list[dict[str, object]] = []
    log_lines: list[str] = []

    log_lines.append("=" * 88)
    log_lines.append("NHẬT KÝ THỰC NGHIỆM KIỂM TRA TOÀN VẸN TỆP BẰNG HÀM BĂM THUẦN (THÀNH VIÊN A)")
    log_lines.append(f"Run ID        : {run_id}")
    log_lines.append(f"Dataset Ver   : {manifest['dataset_version']} (seed: {manifest['seed']})")
    log_lines.append(f"Environment   : {tool_versions}")
    log_lines.append("=" * 88)
    log_lines.append("")

    # 1. Đối chiếu 18 mẫu gốc và hiệu ứng thác đổ (Avalanche Effect) trên cả SHA-256 và SHA3-256
    avalanche_rows: list[dict[str, object]] = []
    log_lines.append("[PHẦN 1] ĐỐI CHIẾU GIÁ TRỊ BĂM THAM CHIẾU VÀ HIỆU ỨNG THÁC ĐỔ (18 MẪU S01–S18)")
    log_lines.append("-" * 88)

    for rec in samples:
        sid = rec["sample_id"]
        sample = load_sample(sid, data_root)
        orig_bytes = sample["data"]
        tamp_bytes = sample["tampered_data"]

        sha256_orig = compute_digest_bytes(orig_bytes, "SHA-256")
        sha256_tamp = compute_digest_bytes(tamp_bytes, "SHA-256")
        sha3_orig = compute_digest_bytes(orig_bytes, "SHA3-256")
        sha3_tamp = compute_digest_bytes(tamp_bytes, "SHA3-256")

        for label, got, want in (
            ("SHA-256", sha256_orig, rec["sha256"]),
            ("Tampered SHA-256", sha256_tamp, rec["tampered_sha256"]),
            ("SHA3-256", sha3_orig, rec["sha3_256"]),
        ):
            if got != want:
                raise RuntimeError(f"{label} mismatch on {sid}: dataset may be modified; run generate_dataset.py --check")

        hd_sha256 = hamming_distance_hex(sha256_orig, sha256_tamp)
        hd_sha3 = hamming_distance_hex(sha3_orig, sha3_tamp)

        avalanche_rows.append(
            {
                "sample_id": sid,
                "path": rec["path"],
                "size_bytes": rec["size_bytes"],
                "mutation_op": rec["mutation"]["operation"],
                "mutation_offset": rec["mutation"]["offset"],
                "sha256_original": sha256_orig,
                "sha256_tampered": sha256_tamp,
                "sha256_hamming_bits": hd_sha256,
                "sha256_hamming_pct": round(hd_sha256 / 256.0 * 100.0, 2),
                "sha3_256_original": sha3_orig,
                "sha3_256_tampered": sha3_tamp,
                "sha3_256_hamming_bits": hd_sha3,
                "sha3_256_hamming_pct": round(hd_sha3 / 256.0 * 100.0, 2),
            }
        )
        log_lines.append(
            f"  {sid} ({rec['size_bytes']:>4} B | {rec['mutation']['operation']:<15}): "
            f"SHA-256 HD = {hd_sha256:>3}/256 bits ({hd_sha256/256*100:5.1f}%), "
            f"SHA3-256 HD = {hd_sha3:>3}/256 bits ({hd_sha3/256*100:5.1f}%)"
        )

    avg_hd_sha256 = sum(r["sha256_hamming_bits"] for r in avalanche_rows) / len(avalanche_rows)
    avg_hd_sha3 = sum(r["sha3_256_hamming_bits"] for r in avalanche_rows) / len(avalanche_rows)
    log_lines.append("-" * 88)
    log_lines.append(
        f"  Trung bình khoảng cách Hamming (18 mẫu): "
        f"SHA-256 = {avg_hd_sha256:.2f}/256 bits ({avg_hd_sha256/256*100:.2f}%), "
        f"SHA3-256 = {avg_hd_sha3:.2f}/256 bits ({avg_hd_sha3/256*100:.2f}%)"
    )
    log_lines.append("")

    # 2. Thực thi ma trận kiểm thử TC01–TC09 trên 18 mẫu
    log_lines.append("[PHẦN 2] MA TRẬN TC01–TC09 — PROFILE CHÍNH SHA-256(file_bytes) (SHA3-256 xem dòng 4 Phần 3)")
    log_lines.append("-" * 88)

    case_summary_rows: list[dict[str, object]] = []

    for case in cases:
        cid = case["case_id"]
        cname = case["name"]
        applicable_count = 0
        detected_count = 0
        matched_expectation_count = 0
        total_evaluated = 0
        status_counts: dict[str, int] = {}

        for rec in samples:
            sid = rec["sample_id"]
            # Chạy profile chuẩn SHA-256 (ghi vào hash_verification_results.csv)
            ev = evaluate_hash_case(case, sid, data_root, algorithm="SHA-256")
            total_evaluated += 1
            actual_st = str(ev["actual_status"])
            expected_st = str(ev["expected_status"])
            status_counts[actual_st] = status_counts.get(actual_st, 0) + 1

            if actual_st == expected_st:
                matched_expectation_count += 1
            if ev["applicable_to_detection"]:
                applicable_count += 1
                if ev["detected"]:
                    detected_count += 1

            results_rows.append(
                {
                    "run_id": run_id,
                    "case_id": cid,
                    "sample_id": sid,
                    "mechanism": "SHA-256",
                    "expected_status": expected_st,
                    "actual_status": actual_st,
                    "applicable_to_detection": ev["applicable_to_detection"],
                    "detected": ev["detected"],
                    "elapsed_ns": ev["elapsed_ns"],
                    "evidence_path": ev["evidence_path"],
                    "tool_versions": tool_versions,
                }
            )

            # Chạy đối chiếu tương đương trên SHA3-256
            ev_sha3 = evaluate_hash_case(case, sid, data_root, algorithm="SHA3-256")
            sha3_rows.append(
                {
                    "run_id": run_id,
                    "case_id": cid,
                    "sample_id": sid,
                    "mechanism": "SHA3-256",
                    "expected_status": ev_sha3["expected_status"],
                    "actual_status": ev_sha3["actual_status"],
                    "applicable_to_detection": ev_sha3["applicable_to_detection"],
                    "detected": ev_sha3["detected"],
                    "elapsed_ns": ev_sha3["elapsed_ns"],
                    "evidence_path": ev_sha3["evidence_path"],
                    "tool_versions": tool_versions,
                }
            )

        detection_rate_str = (
            f"{detected_count}/{applicable_count} ({detected_count/applicable_count*100:.1f}%)"
            if applicable_count > 0
            else "N/A"
        )
        status_summary = ", ".join(f"{k}:{v}" for k, v in sorted(status_counts.items()))
        case_summary_rows.append(
            {
                "case_id": cid,
                "name": cname,
                "operation": case["operation"],
                "is_control": case["is_control"],
                "expected_hash_status": case["expected"]["hash"],
                "samples_evaluated": total_evaluated,
                "matched_expectation": f"{matched_expectation_count}/{total_evaluated}",
                "applicable_to_detection": applicable_count,
                "detected_count": detected_count,
                "detection_rate_pct": round(detected_count / applicable_count * 100.0, 2)
                if applicable_count > 0
                else "",
                "status_breakdown": status_summary,
            }
        )
        log_lines.append(
            f"  {cid} ({cname:<38}): status=[{status_summary:<35}] | "
            f"expectation_match={matched_expectation_count}/{total_evaluated} | "
            f"detection={detection_rate_str}"
        )

    # 3. Tính tỷ lệ phát hiện theo quy ước của data/README.md
    tc02_9_rows = [
        r for r in results_rows if r["case_id"] in ("TC02", "TC09") and r["applicable_to_detection"]
    ]
    tc02_9_detected = sum(1 for r in tc02_9_rows if r["detected"])

    all_applicable_rows = [r for r in results_rows if r["applicable_to_detection"]]
    all_applicable_detected = sum(1 for r in all_applicable_rows if r["detected"])

    tc03_rows = [r for r in results_rows if r["case_id"] == "TC03"]
    tc03_detected = sum(1 for r in tc03_rows if r["detected"])

    log_lines.append("-" * 88)
    log_lines.append("[PHẦN 3] TỔNG HỢP TỶ LỆ PHÁT HIỆN THEO QUY ƯỚC ĐỀ TÀI (data/README.md)")
    log_lines.append(
        f"  1. Tập sửa nội dung có bằng chứng tham chiếu tin cậy (TC02 + TC09): "
        f"{tc02_9_detected}/{len(tc02_9_rows)} ({tc02_9_detected/len(tc02_9_rows)*100:.2f}%)"
    )
    log_lines.append(
        f"  2. TC03 (thay cả tệp và hash đi kèm, trình bày RIÊNG, không gộp vào tỷ lệ chung): "
        f"phát hiện {tc03_detected}/{len(tc03_rows)}; "
        f"{sum(1 for r in tc03_rows if r['actual_status'] == 'ACCEPT_UNTRUSTED')}/{len(tc03_rows)} mẫu ACCEPT_UNTRUSTED "
        f"(đúng kỳ vọng — đây là minh chứng giới hạn của hash thuần, không phải lỗi chương trình)"
    )
    log_lines.append(
        "  3. Không đưa vào mẫu số: TC01 (control), TC07 (metadata ngoài phạm vi file-only), "
        "TC04/TC05/TC06/TC08 (NOT_APPLICABLE), TC09 trên S01 rỗng."
    )
    sha3_mismatch = [r for r in sha3_rows if r["actual_status"] != r["expected_status"]]
    log_lines.append(
        f"  4. Đối chiếu SHA3-256 trên cùng 162 ca: {len(sha3_rows) - len(sha3_mismatch)}/{len(sha3_rows)} "
        f"ca có trạng thái đúng kỳ vọng (chi tiết: hash_sha3_cross_check.csv)"
    )
    log_lines.append("=" * 88)

    # Ghi các tệp CSV và log
    results_csv_path = output_dir / "hash_verification_results.csv"
    with results_csv_path.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.DictWriter(f, fieldnames=RESULTS_CSV_HEADER, lineterminator="\n")
        writer.writeheader()
        writer.writerows(results_rows)

    sha3_csv_path = output_dir / "hash_sha3_cross_check.csv"
    with sha3_csv_path.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.DictWriter(f, fieldnames=RESULTS_CSV_HEADER, lineterminator="\n")
        writer.writeheader()
        writer.writerows(sha3_rows)

    summary_csv_path = output_dir / "hash_case_summary.csv"
    with summary_csv_path.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(case_summary_rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(case_summary_rows)

    avalanche_csv_path = output_dir / "avalanche_analysis.csv"
    with avalanche_csv_path.open("w", encoding="utf-8", newline="\n") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(avalanche_rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(avalanche_rows)

    log_path = output_dir / "hash_experiment.log"
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    return {
        "results_csv": results_csv_path,
        "sha3_csv": sha3_csv_path,
        "summary_csv": summary_csv_path,
        "avalanche_csv": avalanche_csv_path,
        "log_path": log_path,
        "total_rows": len(results_rows),
        "tc02_9_detected": tc02_9_detected,
        "tc02_9_total": len(tc02_9_rows),
        "tc03_detected": tc03_detected,
        "tc03_total": len(tc03_rows),
        "all_applicable_detected": all_applicable_detected,
        "all_applicable_total": len(all_applicable_rows),
        "avg_hd_sha256": avg_hd_sha256,
        "avg_hd_sha3": avg_hd_sha3,
    }


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=DATA_ROOT)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results" / "hash")
    parser.add_argument("--run-id", type=str, default="HASH-N18-RUN01")
    args = parser.parse_args()

    summary = run_all_experiments(args.data_root, args.output_dir, args.run_id)
    print((args.output_dir / "hash_experiment.log").read_text(encoding="utf-8"))
    print(f"Saved verification CSV to: {summary['results_csv']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
