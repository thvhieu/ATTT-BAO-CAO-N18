# Dữ liệu dùng chung cho đề tài 18

Nhóm A/B/C dùng cùng các byte đầu vào trong [`data/`](data/README.md).
Đây là bộ đầu vào và kế hoạch kiểm thử, chưa phải kết quả thực nghiệm hoặc ba chương trình mật mã.

```bash
python tools/generate_dataset.py --check
python -m unittest discover -s tests -v
```

- A: tệp gốc, tệp bị sửa, hash tham chiếu và các tệp benchmark.
- B: cùng tệp gốc/bị sửa, khóa kiểm thử, ma trận tình huống và mẫu CSV kết quả.
- C: cùng tệp gốc, metadata gốc/bị sửa làm AAD và khóa kiểm thử. C tự sinh bản mã, thẻ và nonce bằng thư viện AEAD.

Đọc cách dùng và phạm vi bảo vệ tại [`data/README.md`](data/README.md).
Không sửa tệp gốc; ghi sản phẩm chạy thật vào `results/` (đã được Git bỏ qua).
