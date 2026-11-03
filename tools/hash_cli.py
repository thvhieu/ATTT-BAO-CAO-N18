"""Công cụ dòng lệnh kiểm tra tệp bằng hash thuần (SHA-256 / SHA3-256) — Thành viên A.

Ví dụ:
    python tools/hash_cli.py digest data/samples/S03_ascii.txt
    python tools/hash_cli.py verify data/samples/S03_ascii.txt --digest-file data/digests/S03.sha256
    python tools/hash_cli.py manifest-create thu_muc -o thu_muc.manifest --algo SHA3-256
    python tools/hash_cli.py manifest-check thu_muc.manifest

Định dạng manifest: mỗi dòng `<thuật toán> <hex 64 ký tự> <đường dẫn tương đối, dấu />`.
Ghi tên thuật toán vào từng dòng vì SHA-256 và SHA3-256 cùng dài 64 ký tự hex, không phân biệt được.

Mã thoát: 0 = khớp, 1 = không khớp / thiếu tệp, 2 = lỗi tham số hoặc định dạng.

GIỚI HẠN: "khớp" chỉ có nghĩa tệp trùng với giá trị hash được đưa vào. Nếu hash/manifest đi cùng kênh
với tệp và có thể bị bên thứ ba thay, kết quả khớp KHÔNG chứng minh nguồn gốc (xem TC03).
Hãy giữ manifest tham chiếu ở nơi đáng tin cậy, tách khỏi tệp được kiểm tra.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.hash_checker import (  # noqa: E402
    canonical_algorithm_name,
    compute_digest_file,
    read_digest_file,
)
import hmac  # noqa: E402

EXIT_OK, EXIT_MISMATCH, EXIT_ERROR = 0, 1, 2


@dataclass(frozen=True)
class ManifestEntry:
    algorithm: str
    digest: str
    rel_path: str


def create_manifest(directory: Path, algorithm: str = "SHA-256") -> list[ManifestEntry]:
    alg = canonical_algorithm_name(algorithm)
    entries = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        entries.append(ManifestEntry(alg, compute_digest_file(path, alg), path.relative_to(directory).as_posix()))
    return entries


def format_manifest(entries: list[ManifestEntry]) -> str:
    return "".join(f"{e.algorithm} {e.digest} {e.rel_path}\n" for e in entries)


def parse_manifest(text: str) -> list[ManifestEntry]:
    entries = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(" ", 2)
        if len(parts) != 3:
            raise ValueError(f"Manifest line {lineno}: expected '<algorithm> <hex> <path>'")
        alg, digest, rel = parts
        alg = canonical_algorithm_name(alg)
        digest = digest.lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"Manifest line {lineno}: invalid 256-bit hex digest")
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise ValueError(f"Manifest line {lineno}: path must be relative and stay inside base directory")
        entries.append(ManifestEntry(alg, digest, rel))
    return entries


def check_manifest(entries: list[ManifestEntry], base_dir: Path) -> list[tuple[str, str]]:
    """Trả về [(đường dẫn, OK|FAILED|MISSING)]."""
    out = []
    for e in entries:
        path = base_dir / e.rel_path
        if not path.is_file():
            out.append((e.rel_path, "MISSING"))
            continue
        ok = hmac.compare_digest(compute_digest_file(path, e.algorithm), e.digest)
        out.append((e.rel_path, "OK" if ok else "FAILED"))
    return out


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("digest", help="In giá trị hash của tệp")
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--algo", default="SHA-256")

    p = sub.add_parser("verify", help="So một tệp với giá trị hash kỳ vọng")
    p.add_argument("file", type=Path)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--expected")
    g.add_argument("--digest-file", type=Path)
    p.add_argument("--algo", default="SHA-256")

    p = sub.add_parser("manifest-create", help="Tạo manifest cho mọi tệp trong thư mục")
    p.add_argument("directory", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--algo", default="SHA-256")

    p = sub.add_parser("manifest-check", help="Kiểm tra thư mục theo manifest")
    p.add_argument("manifest", type=Path)
    p.add_argument("--base-dir", type=Path, help="Mặc định: thư mục cùng tên với manifest (bỏ đuôi .manifest)")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "digest":
            alg = canonical_algorithm_name(args.algo)
            for f in args.files:
                print(f"{compute_digest_file(f, alg)}  {f.as_posix()}")
            return EXIT_OK

        if args.cmd == "verify":
            alg = canonical_algorithm_name(args.algo)
            expected = read_digest_file(args.digest_file) if args.digest_file else args.expected.strip().lower()
            actual = compute_digest_file(args.file, alg)
            ok = hmac.compare_digest(actual, expected)
            print(f"{'OK' if ok else 'FAILED'}: {args.file.as_posix()} ({alg})")
            print(f"  expected: {expected}\n  actual  : {actual}")
            return EXIT_OK if ok else EXIT_MISMATCH

        if args.cmd == "manifest-create":
            entries = create_manifest(args.directory, args.algo)
            args.output.write_text(format_manifest(entries), encoding="utf-8", newline="\n")
            print(f"Wrote {len(entries)} entries to {args.output.as_posix()}")
            return EXIT_OK

        if args.cmd == "manifest-check":
            base = args.base_dir or args.manifest.with_suffix("")
            results = check_manifest(parse_manifest(args.manifest.read_text(encoding="utf-8")), base)
            for rel, status in results:
                print(f"{status:<7} {rel}")
            bad = sum(1 for _, s in results if s != "OK")
            print(f"Summary: {len(results) - bad}/{len(results)} OK")
            return EXIT_OK if bad == 0 else EXIT_MISMATCH
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

