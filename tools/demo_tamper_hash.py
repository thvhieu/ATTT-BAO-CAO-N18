"""Demo thực tế: sửa tệp, rồi sửa cả tệp lẫn manifest đi kèm (Thành viên A).

Kịch bản (chạy trên bản sao trong results/hash/demo/, không đụng tới data/):
  B0. Bên gửi tạo manifest SHA-256 cho thư mục `goi_gui/`; lưu 1 bản đi kèm gói và 1 bản tham chiếu
      tách riêng (mô phỏng kênh tin cậy, ví dụ trang HTTPS chính thức hoặc manifest đã ký).
  B1. Kiểm tra gói nguyên vẹn                          -> kỳ vọng OK.
  B2. Kẻ tấn công sửa số tiền trong đơn hàng, giữ manifest -> kỳ vọng FAILED (phát hiện).
  B3. Kẻ tấn công tính lại hash và ghi đè manifest đi kèm -> kỳ vọng OK  (hash thuần bị qua mặt).
  B4. Người nhận kiểm tra theo manifest tham chiếu tách riêng -> kỳ vọng FAILED.
Toàn bộ lệnh và đầu ra được ghi vào results/hash/demo_tamper.log.
"""
from __future__ import annotations

import contextlib
import io
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import hash_cli  # noqa: E402
from tools.dataset_io import DATA_ROOT  # noqa: E402


def run_cli(args: list[str], log: list[str]) -> int:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = hash_cli.main(args)
    log.append("$ python tools/hash_cli.py " + " ".join(args))
    log.extend("  " + line for line in buf.getvalue().rstrip().splitlines())
    log.append(f"  [exit code = {code}]")
    return code


def run_demo(work: Path = ROOT / "results" / "hash" / "demo") -> dict[str, int]:
    if work.exists():
        shutil.rmtree(work)
    pkg = work / "goi_gui"
    trusted = work / "kenh_tin_cay"
    pkg.mkdir(parents=True)
    trusted.mkdir()
    shutil.copyfile(DATA_ROOT / "samples/S08_order_synthetic.json", pkg / "don_hang.json")
    shutil.copyfile(DATA_ROOT / "samples/S09_students_synthetic.csv", pkg / "sinh_vien.csv")

    def rel(p: Path) -> str:
        try:
            return p.relative_to(ROOT).as_posix()
        except ValueError:
            return p.as_posix()
    log: list[str] = ["DEMO SỬA TỆP VÀ THAY HASH ĐI KÈM (SHA-256 thuần)", "=" * 80]
    codes: dict[str, int] = {}

    log.append("\n[B0] Bên gửi tạo manifest; bản đi kèm gói + bản tham chiếu tách riêng")
    accompanying = work / "goi_gui.manifest"
    run_cli(["manifest-create", rel(pkg), "-o", rel(accompanying)], log)
    shutil.copyfile(accompanying, trusted / "goi_gui.manifest")
    log.append(accompanying.read_text(encoding="utf-8").rstrip())

    log.append("\n[B1] Kiểm tra gói nguyên vẹn bằng manifest đi kèm")
    codes["B1_intact"] = run_cli(["manifest-check", rel(accompanying)], log)

    log.append("\n[B2] Kẻ tấn công sửa amount 120000 -> 920000, KHÔNG sửa manifest")
    order = pkg / "don_hang.json"
    original = order.read_bytes()
    tampered = original.replace(b'"amount":120000', b'"amount":920000')
    if tampered == original:
        raise RuntimeError("Demo precondition failed: amount field not found in S08")
    order.write_bytes(tampered)
    log.append(f"  nội dung mới: {tampered.decode('utf-8').rstrip()}")
    codes["B2_tamper_keep_manifest"] = run_cli(["manifest-check", rel(accompanying)], log)

    log.append("\n[B3] Kẻ tấn công tính lại hash và GHI ĐÈ manifest đi kèm gói")
    run_cli(["manifest-create", rel(pkg), "-o", rel(accompanying)], log)
    codes["B3_tamper_and_replace_manifest"] = run_cli(["manifest-check", rel(accompanying)], log)

    log.append("\n[B4] Người nhận kiểm tra bằng manifest tham chiếu lưu tách riêng")
    codes["B4_trusted_reference"] = run_cli(
        ["manifest-check", rel(trusted / "goi_gui.manifest"), "--base-dir", rel(pkg)], log)

    log.append("\n" + "=" * 80)
    log.append("TÓM TẮT (exit 0 = chấp nhận, 1 = phát hiện sai khác)")
    expect = {"B1_intact": 0, "B2_tamper_keep_manifest": 1,
              "B3_tamper_and_replace_manifest": 0, "B4_trusted_reference": 1}
    for k, v in codes.items():
        log.append(f"  {k:<32} exit={v} | kỳ vọng={expect[k]} | {'ĐÚNG' if v == expect[k] else 'SAI'}")
    log.append("Kết luận: B3 cho thấy hash đi cùng kênh với tệp không chứng minh nguồn gốc;"
               " B4 cho thấy hash chỉ có giá trị khi tham chiếu được bảo vệ độc lập.")
    (work.parent / "demo_tamper.log").write_text("\n".join(log) + "\n", encoding="utf-8")
    return codes


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    run_demo()
    print((ROOT / "results" / "hash" / "demo_tamper.log").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

