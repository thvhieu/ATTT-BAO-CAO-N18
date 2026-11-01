# Bộ dữ liệu dùng chung cho Hash HMAC và AEAD

## Mục đích và phạm vi

Ba thành viên dùng cùng bộ byte đầu vào để viết và kiểm thử ba cơ chế của đề tài 18.
Phiên bản dữ liệu là **1.0.0**. Chỉ có đầu vào tổng hợp, kỳ vọng kiểm thử và mẫu ghi kết quả.
Không có kết quả đo tốc độ, tỷ lệ phát hiện hay log thực nghiệm được điền sẵn.
Mã sinh và kiểm tra dữ liệu dùng thư viện chuẩn Python 3.10 trở lên, không cần cài thêm gói.

## Cấu trúc

| Đường dẫn | Dùng cho |
|---|---|
| `samples/` | 18 tệp gốc dùng chung cho A/B/C |
| `tampered/` | 18 bản sửa một bit; tệp rỗng được thêm một byte |
| `metadata/` | Metadata gốc và bị sửa, dùng nguyên byte làm AAD của AEAD |
| `digests/` | SHA-256 gốc và SHA-256 tính lại của tệp bị sửa |
| `benchmark/` | 5 kích thước: 1 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB |
| `manifest.json` | ID, đường dẫn, số byte, SHA-256/SHA3-256 và mô tả phép sửa |
| `test_cases.json` | 9 loại ca kiểm thử và kết quả mong đợi, chưa phải kết quả thực tế |
| `test_matrix.csv` | Bản bảng của các kỳ vọng để cả nhóm đối chiếu |
| `lab_parameters.json` | Khóa đúng/sai công khai dành cho thử nghiệm và quy ước AEAD |
| `results_template.csv` | Chỉ có tiêu đề cột; điền kết quả chạy thật vào bản sao |
| `benchmark_results_template.csv` | Chỉ có tiêu đề cột; ghi riêng từng lần đo |

Manifest là bảng kiểm kê đáng tin cậy của nhóm, không phải chữ ký số.
Giữ bản manifest tham chiếu độc lập với giá trị hash do bên sửa tệp cung cấp trong TC03.

## Các mẫu đầu vào

| ID | Nội dung |
|---|---|
| S01–S02 | Tệp rỗng và tệp một byte NUL |
| S03–S05 | ASCII, tiếng Việt UTF-8, emoji và ký hiệu |
| S06–S07 | Cùng văn bản nhưng khác xuống dòng LF/CRLF |
| S08–S09 | Đơn hàng JSON và danh sách sinh viên CSV hoàn toàn tổng hợp |
| S10 | Đủ các giá trị byte từ 0 đến 255 |
| S11–S13 | 1 KiB byte 0, chuỗi lặp và dữ liệu giả ngẫu nhiên tái tạo được |
| S14–S16 | Biên độ dài 15, 16, 17 byte |
| S17–S18 | Cùng văn bản tiếng Việt ở dạng Unicode NFC/NFD |

Tên tệp ASCII giúp chạy trên nhiều hệ điều hành; nội dung vẫn có Unicode.
S04 và S17 cố ý cùng byte UTF-8 để làm mẫu đối chiếu.
Dữ liệu giả ngẫu nhiên được sinh bằng SHAKE-256 từ seed công khai, chỉ làm dữ liệu tải.
Không dùng bộ sinh tái tạo này để sinh khóa hoặc nonce thực tế.

## Kiểm tra ngay sau khi clone

Chạy ở thư mục gốc repository:

```bash
python tools/generate_dataset.py --check
python -m unittest discover -s tests -v
```

Lệnh đầu chỉ đọc và so sánh byte. Nếu báo sai khác, kiểm tra việc sửa tệp hoặc chuyển đổi xuống dòng;
không tự thay manifest để hợp thức hóa dữ liệu đã bị sửa.
`.gitattributes` giữ nguyên byte fixture khi clone trên Windows/Linux/macOS.

Muốn sinh lại vào một thư mục mới để đối chiếu:

```bash
python tools/generate_dataset.py --output ../n18-data-copy
python tools/generate_dataset.py --output ../n18-data-copy --check
```

Trình sinh không ghi đè một fixture hiện có nếu byte đã khác.
Để thêm tệp benchmark 4 MiB và 16 MiB trên máy cá nhân:

```bash
python tools/generate_dataset.py --extended
```

Các tệp lớn được lưu ở `data/benchmark_extended/`, không được đưa vào Git theo mặc định.

## Cách đọc chung trong chương trình

Tạo hoặc chạy chương trình của nhóm ở thư mục gốc repository:

```python
from tools.dataset_io import load_sample

sample = load_sample("S04")
file_bytes = sample["data"]                 # cả A/B/C dùng cùng bytes
aad_bytes = sample["aad"]                   # C dùng trực tiếp làm AAD
changed_file = sample["tampered_data"]
changed_aad = sample["tampered_aad"]
reference_sha256 = sample["record"]["sha256"]
```

Đọc bằng `read_bytes()`. Không dùng `strip()`, tự đổi encoding, chuẩn hóa Unicode hoặc sửa xuống dòng.
Không parse rồi dump lại metadata trước khi xác minh AEAD: thao tác đó có thể đổi byte AAD.
Hai tệp trông giống nhau nhưng khác byte là tình huống thử có chủ ý, không phải lỗi dữ liệu.

## A phụ trách Hash và benchmark

1. Hash `sample["data"]` và đối chiếu với giá trị tham chiếu trong manifest.
2. Thử `sample["tampered_data"]` nhưng giữ hash gốc: kỳ vọng không khớp.
3. TC03 dùng tệp bị sửa cùng hash từ `attacker_digest_path`: phép kiểm tra hash thuần có thể chấp nhận.
   Không lấy hash gốc trong manifest để giả lập hash người nhận nhận được ở ca này.
4. TC03 không phải tìm va chạm: tệp khác có hash khác, bên sửa chỉ tính lại hash.
5. Đo SHA-256 và SHA3-256 trên cùng từng tệp benchmark. Ghi rõ tên thuật toán, số lần lặp, đơn vị,
   phiên bản công cụ và có/không tính thời gian đọc đĩa. Đọc trước dữ liệu nếu muốn đo riêng hàm băm.
6. Không điền số liệu ước đoán và không diễn giải tốc độ thành mức an toàn.

## B phụ trách HMAC và tổng hợp kiểm thử

1. Profile chung mặc định là **HMAC-SHA-256 trên byte của tệp**, không gồm metadata.
2. Đọc khóa đúng/sai từ `lab_parameters.json`, chuyển hex thành bytes.
3. Tự tính thẻ HMAC cho tệp gốc. Giữ thẻ đó khi thử tệp bị sửa, khóa sai hoặc thẻ bị lật một bit.
4. Metadata ngoài phạm vi HMAC trong profile này: thay metadata riêng sẽ không làm kiểm tra tệp thất bại.
   Nếu nhóm quyết định bảo vệ cả metadata bằng HMAC, phải đặc tả cách mã hóa thông điệp không nhập nhằng,
   cập nhật profile và kỳ vọng TC07 trước khi thử; không trộn hai profile trong một kết quả.
5. So sánh thẻ bằng API so sánh hằng thời gian của thư viện. Ghi cả ca chấp nhận đúng và từ chối đúng.
6. Tổng hợp kết quả A/C gửi về; các ca không áp dụng hoặc nằm ngoài phạm vi bảo vệ phải ghi rõ.

## C phụ trách AEAD và luồng demo

1. Dùng `sample["data"]` làm plaintext và **nguyên byte** `sample["aad"]` làm associated data.
2. Profile ví dụ trong bộ tham số là AES-256-GCM. Khóa mẫu dài 32 byte, nonce 12 byte và thẻ 16 byte.
   Nhóm có thể chọn AEAD khác nhưng phải thống nhất tham số, API và kỳ vọng trước.
3. Tự tạo nonce mới cho mỗi lần mã hóa, lưu nonce cùng gói mã hóa. Không có nonce cố định trong bộ dữ liệu.
   Khóa mẫu đã công khai và chỉ dành cho thử nghiệm. Mỗi lần chạy độc lập nên sinh khóa thử mới.
4. Với ca sửa đổi, tạo gói gốc **một lần**, rồi sửa bản mã/thẻ/nonce hoặc thay AAD lúc giải mã.
   Không mã hóa lại dữ liệu đã sửa rồi mong gói mới thất bại xác thực.
5. Với S01 rỗng, AES-GCM không có byte bản mã; nếu sửa byte gói thì đó là byte thẻ.
   Ghi rõ trường hợp này, không gọi nó là lật bit bản mã.
6. `tampered/` là plaintext bị sửa, không phải bản mã có sẵn. HMAC tag, AEAD ciphertext/tag và log chạy thật
   được chương trình của B/C sinh ra, không có sẵn trong fixture này.
7. Ghép demo chọn cơ chế và ca thử, nhưng không nối Hash rồi HMAC rồi AEAD thành cơ chế mật mã tự tạo.

## Kỳ vọng và cách ghi kết quả

`test_cases.json` là nguồn kỳ vọng. `test_matrix.csv` là bản tiện đọc.

- TC01: control nguyên vẹn; cả ba chấp nhận.
- TC02: thay nội dung nhưng giữ bằng chứng gốc; cả ba từ chối trong phạm vi tương ứng.
- TC03: thay tệp và hash đi kèm; hash thuần có thể chấp nhận dữ liệu không đáng tin.
- TC04: khóa sai; chỉ áp dụng HMAC/AEAD.
- TC05–TC06: thay thẻ tương ứng; chỉ áp dụng cơ chế có thẻ đó.
- TC07: thay metadata; hash/HMAC file-only không bao phủ metadata, AEAD AAD phải phát hiện.
- TC08: nonce sai; chỉ áp dụng AEAD, là ca bổ sung.
- TC09: cắt ngắn dữ liệu/gói mã hóa; bỏ qua tệp rỗng, là ca bổ sung.

Tỷ lệ phát hiện = số ca sửa đổi được phát hiện / tổng số ca sửa đổi thực sự áp dụng trong phạm vi bảo vệ.
Không đưa control, NOT_APPLICABLE hoặc metadata ngoài phạm vi vào mẫu số.
TC03 phải được trình bày riêng như minh chứng giới hạn của hash; không giấu nó bằng một con số tổng.
Có thể báo cáo thêm tỷ lệ phát hiện trên tập so sánh chung TC02/TC09, với cùng sample ID, rồi bảng đầy đủ từng ca.
Nếu đổi tập ca, phải nêu rõ tập và mẫu số; đừng gộp thành một tỷ lệ không có bối cảnh.

Sao chép các CSV mẫu vào `results/` trước khi ghi dữ liệu. Giữ dữ liệu gốc trong `data/` bất biến.
Gợi ý tên sản phẩm thật: `results/hash/`, `results/hmac/`, `results/aead/` và `results/benchmark/`.
Git đang bỏ qua `results/` để tránh commit log/khóa/gói chạy thử ngoài ý muốn;
nhóm rà soát rồi đưa minh chứng đã chọn vào báo cáo hoặc thư mục bàn giao riêng.

## Tài liệu kỹ thuật

- [Python hashlib](https://docs.python.org/3/library/hashlib.html)
- [Python hmac](https://docs.python.org/3/library/hmac.html)
- [cryptography AEAD](https://cryptography.io/en/latest/hazmat/primitives/aead/)

Các bài kiểm tra trong `tests/test_dataset.py` chỉ xác minh chất lượng và khả năng tái tạo dữ liệu.
Chúng không thay thế các kiểm thử của ba chương trình Hash/HMAC/AEAD do nhóm triển khai.
