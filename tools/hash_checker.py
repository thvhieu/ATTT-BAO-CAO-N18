"""Module kiểm tra tính toàn vẹn tệp bằng hàm băm mật mã thuần (SHA-256 & SHA3-256).

Phụ trách: Thành viên A — Hash thuần và đo tốc độ (Đề tài 18).
Quy ước:
- Đọc toàn bộ tệp và metadata ở dạng nguyên byte (raw bytes, read_bytes()).
- Không strip() dữ liệu tải, không chuẩn hóa Unicode, không tự đổi CRLF/LF.
- Phân biệt rõ nguồn lấy giá trị băm tham chiếu:
  + TRUSTED_MANIFEST / TRUSTED_DIGEST_FILE: nguồn tham chiếu độc lập, đáng tin cậy.
  + UNTRUSTED_ACCOMPANYING_DIGEST: giá trị băm đi kèm trên cùng kênh không xác thực (mô phỏng TC03).
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import time
from typing import Literal

SUPPORTED_ALGORITHMS: dict[str, str] = {
    "SHA-256": "sha256",
    "SHA3-256": "sha3_256",
    "sha256": "sha256",
    "sha3_256": "sha3_256",
    "sha3-256": "sha3_256",
}

CanonicalAlgorithm = Literal["SHA-256", "SHA3-256"]

StatusType = Literal[
    "ACCEPT",
    "REJECT",
    "ACCEPT_UNTRUSTED",
    "ACCEPT_METADATA_OUTSIDE_SCOPE",
    "NOT_APPLICABLE",
]

DigestSourceType = Literal[
    "TRUSTED_REFERENCE",
    "UNTRUSTED_CHANNEL",
]


def canonical_algorithm_name(algorithm: str) -> CanonicalAlgorithm:
    """Chuẩn hóa tên thuật toán về 'SHA-256' hoặc 'SHA3-256'."""
    key = algorithm.strip()
    if key not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm!r}. Choose SHA-256 or SHA3-256.")
    internal = SUPPORTED_ALGORITHMS[key]
    return "SHA-256" if internal == "sha256" else "SHA3-256"


def compute_digest_bytes(data: bytes, algorithm: str = "SHA-256") -> str:
    """Tính giá trị băm dạng hex (64 ký tự chữ thường) trực tiếp trên đối tượng bytes."""
    internal = SUPPORTED_ALGORITHMS[canonical_algorithm_name(algorithm)]
    hasher = hashlib.new(internal)
    hasher.update(data)
    return hasher.hexdigest()


DEFAULT_CHUNK_SIZE = 64 * 1024


def compute_digest_file(file_path: Path, algorithm: str = "SHA-256", chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Tính giá trị băm của tệp bằng cách đọc nhị phân theo khối (giữ nguyên mọi byte).

    Khối 64 KiB: đủ lớn để giảm số lần gọi read, nhưng tránh chi phí cấp phát bộ đệm lớn.
    Đo thực tế trên Windows: read(1 MiB) với tệp 1 KiB tốn ~670 µs, read(64 KiB) chỉ ~67 µs.
    """
    internal = SUPPORTED_ALGORITHMS[canonical_algorithm_name(algorithm)]
    hasher = hashlib.new(internal)
    with file_path.open("rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def read_digest_file(digest_path: Path) -> str:
    """Đọc chuỗi hex SHA-256/SHA3-256 từ tệp .sha256 (chỉ cắt ký tự xuống dòng của tệp chứa mã hex)."""
    text = digest_path.read_text(encoding="ascii").strip().lower()
    if len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError(f"Invalid 256-bit hex digest in {digest_path}: {text!r}")
    return text


@dataclass(frozen=True)
class VerificationResult:
    """Kết quả một phép kiểm tra tính toàn vẹn bằng hàm băm thuần."""

    algorithm: CanonicalAlgorithm
    computed_digest: str
    expected_digest: str
    digest_match: bool
    digest_source: DigestSourceType
    metadata_changed: bool
    status: StatusType
    elapsed_ns: int
    notes: str = ""


def verify_bytes(
    payload_bytes: bytes,
    expected_digest: str,
    *,
    algorithm: str = "SHA-256",
    digest_source: DigestSourceType = "TRUSTED_REFERENCE",
    metadata_changed: bool = False,
) -> VerificationResult:
    """Kiểm tra tính toàn vẹn của `payload_bytes` so với `expected_digest`.

    Lưu ý về ngữ nghĩa trạng thái trả về (khớp với `data/test_cases.json`):
    - Nếu giá trị băm không khớp -> `REJECT`.
    - Nếu giá trị băm khớp nhưng `digest_source == "UNTRUSTED_CHANNEL"` (như TC03, khi kẻ tấn công
      thay cả tệp lẫn mã băm đi kèm) -> `ACCEPT_UNTRUSTED` (băm thuần khớp về toán học nhưng không có
      xác thực nguồn gốc).
    - Nếu giá trị băm tệp khớp trên nguồn tin cậy nhưng `metadata_changed == True` (như TC07, khi
      metadata bên ngoài tệp bị sửa) -> `ACCEPT_METADATA_OUTSIDE_SCOPE`.
    - Nếu giá trị băm khớp trên nguồn tin cậy và phạm vi chuẩn -> `ACCEPT`.
    """
    alg = canonical_algorithm_name(algorithm)
    clean_expected = expected_digest.strip().lower()
    start_ns = time.perf_counter_ns()
    computed = compute_digest_bytes(payload_bytes, alg)
    matched = hmac.compare_digest(computed, clean_expected)
    elapsed_ns = time.perf_counter_ns() - start_ns

    if not matched:
        status: StatusType = "REJECT"
        note = "Digest mismatch: payload bytes differ from reference digest."
    elif digest_source == "UNTRUSTED_CHANNEL":
        status = "ACCEPT_UNTRUSTED"
        note = (
            "Digest matches recalculated value from untrusted channel; "
            "plain hash cannot detect simultaneous replacement of payload and digest."
        )
    elif metadata_changed:
        status = "ACCEPT_METADATA_OUTSIDE_SCOPE"
        note = "File digest matches reference; external metadata is outside file-only hash scope."
    else:
        status = "ACCEPT"
        note = "Digest matches trusted reference."

    return VerificationResult(
        algorithm=alg,
        computed_digest=computed,
        expected_digest=clean_expected,
        digest_match=matched,
        digest_source=digest_source,
        metadata_changed=metadata_changed,
        status=status,
        elapsed_ns=elapsed_ns,
        notes=note,
    )

