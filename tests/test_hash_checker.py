"""Bộ kiểm thử đơn vị (Unit Tests) cho phần việc A: Hash thuần (SHA-256 & SHA3-256) và đo tốc độ."""
from __future__ import annotations

import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

from tools import hash_cli
from tools.benchmark_hash import BENCHMARK_CSV_HEADER, run_benchmarks
from tools.demo_tamper_hash import run_demo
from tools.dataset_io import DATA_ROOT, load_manifest, load_sample
from tools.hash_checker import (
    canonical_algorithm_name,
    compute_digest_bytes,
    compute_digest_file,
    read_digest_file,
    verify_bytes,
)
from tools.run_hash_experiments import (
    RESULTS_CSV_HEADER,
    evaluate_hash_case,
    hamming_distance_hex,
    run_all_experiments,
)


class HashCheckerAndExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_manifest(DATA_ROOT)
        cls.test_cases = {
            c["case_id"]: c
            for c in json.loads((DATA_ROOT / "test_cases.json").read_text(encoding="utf-8"))["cases"]
        }

    def test_01_algorithm_normalization_and_validation(self) -> None:
        self.assertEqual(canonical_algorithm_name("sha256"), "SHA-256")
        self.assertEqual(canonical_algorithm_name("SHA-256"), "SHA-256")
        self.assertEqual(canonical_algorithm_name("sha3_256"), "SHA3-256")
        self.assertEqual(canonical_algorithm_name("SHA3-256"), "SHA3-256")
        with self.assertRaises(ValueError):
            canonical_algorithm_name("md5")

    def test_02_compute_digest_matches_manifest_for_all_samples(self) -> None:
        for rec in self.manifest["samples"]:
            sid = rec["sample_id"]
            sample = load_sample(sid, DATA_ROOT)
            file_path = DATA_ROOT / rec["path"]

            d256_mem = compute_digest_bytes(sample["data"], "SHA-256")
            d256_file = compute_digest_file(file_path, "SHA-256", chunk_size=7)
            d3_mem = compute_digest_bytes(sample["data"], "SHA3-256")
            d3_file = compute_digest_file(file_path, "SHA3-256", chunk_size=13)

            self.assertEqual(d256_mem, rec["sha256"])
            self.assertEqual(d256_file, rec["sha256"])
            self.assertEqual(d3_mem, rec["sha3_256"])
            self.assertEqual(d3_file, rec["sha3_256"])

    def test_03_tc01_intact_samples_accepted(self) -> None:
        tc01 = self.test_cases["TC01"]
        for rec in self.manifest["samples"]:
            sid = rec["sample_id"]
            for alg in ("SHA-256", "SHA3-256"):
                res = evaluate_hash_case(tc01, sid, DATA_ROOT, algorithm=alg)
                self.assertEqual(res["actual_status"], "ACCEPT")
                self.assertFalse(res["applicable_to_detection"])

    def test_04_tc02_tampered_payload_with_trusted_digest_rejected(self) -> None:
        tc02 = self.test_cases["TC02"]
        for rec in self.manifest["samples"]:
            sid = rec["sample_id"]
            for alg in ("SHA-256", "SHA3-256"):
                res = evaluate_hash_case(tc02, sid, DATA_ROOT, algorithm=alg)
                self.assertEqual(res["actual_status"], "REJECT")
                self.assertTrue(res["applicable_to_detection"])
                self.assertTrue(res["detected"])

    def test_05_tc03_replace_both_payload_and_digest_accepted_untrusted(self) -> None:
        tc03 = self.test_cases["TC03"]
        for rec in self.manifest["samples"]:
            sid = rec["sample_id"]
            # Kiểm tra rõ rằng hash của tệp bị sửa khác hoàn toàn hash gốc (không phải va chạm)
            self.assertNotEqual(rec["sha256"], rec["tampered_sha256"])
            attacker_digest = read_digest_file(DATA_ROOT / rec["attacker_digest_path"])
            self.assertEqual(attacker_digest, rec["tampered_sha256"])

            for alg in ("SHA-256", "SHA3-256"):
                res = evaluate_hash_case(tc03, sid, DATA_ROOT, algorithm=alg)
                self.assertEqual(res["actual_status"], "ACCEPT_UNTRUSTED")
                self.assertTrue(res["applicable_to_detection"])
                self.assertFalse(res["detected"])

    def test_06_tc07_metadata_tampering_outside_file_hash_scope(self) -> None:
        tc07 = self.test_cases["TC07"]
        for rec in self.manifest["samples"]:
            sid = rec["sample_id"]
            res = evaluate_hash_case(tc07, sid, DATA_ROOT, algorithm="SHA-256")
            self.assertEqual(res["actual_status"], "ACCEPT_METADATA_OUTSIDE_SCOPE")
            self.assertFalse(res["applicable_to_detection"])
            self.assertFalse(res["detected"])

    def test_07_tc09_truncation_detected_on_all_nonempty_samples(self) -> None:
        tc09 = self.test_cases["TC09"]
        for rec in self.manifest["samples"]:
            sid = rec["sample_id"]
            res = evaluate_hash_case(tc09, sid, DATA_ROOT, algorithm="SHA-256")
            if rec["size_bytes"] == 0:
                self.assertEqual(res["actual_status"], "NOT_APPLICABLE")
                self.assertFalse(res["applicable_to_detection"])
            else:
                self.assertEqual(res["actual_status"], "REJECT")
                self.assertTrue(res["applicable_to_detection"])
                self.assertTrue(res["detected"])

    def test_08_keyed_and_aead_only_cases_marked_not_applicable(self) -> None:
        for cid in ("TC04", "TC05", "TC06", "TC08"):
            case = self.test_cases[cid]
            res = evaluate_hash_case(case, "S03", DATA_ROOT, algorithm="SHA-256")
            self.assertEqual(res["actual_status"], "NOT_APPLICABLE")
            self.assertFalse(res["applicable_to_detection"])

    def test_09_avalanche_hamming_distance_is_substantial(self) -> None:
        for rec in self.manifest["samples"]:
            hd = hamming_distance_hex(rec["sha256"], rec["tampered_sha256"])
            # Với hàm băm mật mã 256 bit, sửa 1 bit luôn làm đổi hàng chục đến hơn trăm bit
            self.assertGreaterEqual(hd, 90)
            self.assertLessEqual(hd, 170)

    def test_10_end_to_end_csv_generation_and_schema_compliance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            exp_summary = run_all_experiments(DATA_ROOT, tmp_path / "hash", run_id="TEST-RUN")
            self.assertEqual(exp_summary["tc02_9_detected"], 35)
            self.assertEqual(exp_summary["tc02_9_total"], 35)
            self.assertEqual(exp_summary["tc03_detected"], 0)
            self.assertEqual(exp_summary["tc03_total"], 18)

            with (tmp_path / "hash" / "hash_verification_results.csv").open("r", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                rows = list(reader)
            self.assertEqual(header, RESULTS_CSV_HEADER)
            self.assertEqual(len(rows), 18 * 9)

            bench_res = run_benchmarks(
                DATA_ROOT,
                tmp_path / "bench",
                run_id="TEST-BENCH",
                repeats=2,
                warmup=1,
                include_extended=False,
            )
            with (tmp_path / "bench" / "benchmark_results.csv").open("r", encoding="utf-8") as f:
                b_reader = csv.reader(f)
                b_header = next(b_reader)
                b_rows = list(b_reader)
            self.assertEqual(b_header, BENCHMARK_CSV_HEADER)
            # Khớp chính xác 10 cột chuẩn của data/benchmark_results_template.csv
            template = (DATA_ROOT / "benchmark_results_template.csv").read_text(encoding="utf-8").strip().split(",")
            self.assertEqual(b_header, template)
            # 5 benchmark files * 2 algorithms * 2 io_included modes * 2 repeats = 40 rows
            self.assertEqual(len(b_rows), 40)
            self.assertEqual(bench_res["raw_count"], 40)

    def test_11_cli_verify_and_manifest(self) -> None:
        sample = DATA_ROOT / "samples/S03_ascii.txt"
        tampered = DATA_ROOT / "tampered/S03_ascii.txt"
        good = DATA_ROOT / "digests/S03.sha256"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(hash_cli.main(["verify", str(sample), "--digest-file", str(good)]), 0)
            self.assertEqual(hash_cli.main(["verify", str(tampered), "--digest-file", str(good)]), 1)
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            pkg.mkdir()
            (pkg / "a.bin").write_bytes(b"\x00\x01")
            man = Path(tmp) / "pkg.manifest"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(hash_cli.main(["manifest-create", str(pkg), "-o", str(man), "--algo", "SHA3-256"]), 0)
                self.assertEqual(hash_cli.main(["manifest-check", str(man)]), 0)
                (pkg / "a.bin").write_bytes(b"\x00\x02")
                self.assertEqual(hash_cli.main(["manifest-check", str(man)]), 1)
            self.assertTrue(man.read_text(encoding="utf-8").startswith("SHA3-256 "))
        with self.assertRaises(ValueError):
            hash_cli.parse_manifest("SHA-256 " + "0" * 64 + " ../escape.txt\n")

    def test_12_live_tamper_demo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codes = run_demo(Path(tmp) / "demo")
        self.assertEqual(codes, {"B1_intact": 0, "B2_tamper_keep_manifest": 1,
                                 "B3_tamper_and_replace_manifest": 0, "B4_trusted_reference": 1})


if __name__ == "__main__":
    unittest.main()

