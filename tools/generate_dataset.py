"""Reproducible input fixtures for topic 18. Python 3.10+, standard library only."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEED = 'ATTT-N18-shared-data-v1'
VERSION = '1.0.0'


def canonical_json(value: object) -> bytes:
    """UTF-8, sorted keys, compact separators, no BOM and no final newline."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def pretty_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def deterministic_bytes(label: str, size: int) -> bytes:
    return hashlib.shake_256(f'{SEED}:{label}'.encode('ascii')).digest(size)


def csv_bytes(rows: list[list[object]]) -> bytes:
    buf = io.StringIO(newline='')
    csv.writer(buf, lineterminator='\n').writerows(rows)
    return buf.getvalue().encode('utf-8')


def payloads() -> list[tuple[str, str, str, bytes]]:
    vietnamese = 'An toàn thông tin: toàn vẹn, xác thực và bí mật.\n'
    return [
        ('S01', 'empty.bin', 'application/octet-stream', b''),
        ('S02', 'one_byte.bin', 'application/octet-stream', b'\x00'),
        ('S03', 'ascii.txt', 'text/plain', b'ATTT group 18 shared input.\n'),
        ('S04', 'vietnamese_utf8.txt', 'text/plain', vietnamese.encode('utf-8')),
        ('S05', 'unicode_symbols.txt', 'text/plain', 'Dữ liệu 📁 kiểm thử 🔐 ✓\n'.encode('utf-8')),
        ('S06', 'lines_lf.txt', 'text/plain', b'line one\nline two\n'),
        ('S07', 'lines_crlf.txt', 'text/plain', b'line one\r\nline two\r\n'),
        ('S08', 'order_synthetic.json', 'application/json', canonical_json({
            'order_id': 'DEMO-001', 'items': [{'sku': 'SAMPLE-01', 'quantity': 2}],
            'amount': 120000, 'currency': 'VND', 'synthetic': True})),
        ('S09', 'students_synthetic.csv', 'text/csv', csv_bytes([
            ['student_id', 'display_name', 'score', 'synthetic'],
            ['DEMO001', 'Sinh viên mẫu A', '8.0', 'true'],
            ['DEMO002', 'Sinh viên mẫu B', '7.5', 'true']])),
        ('S10', 'all_byte_values.bin', 'application/octet-stream', bytes(range(256)) * 4),
        ('S11', 'zero_1k.bin', 'application/octet-stream', bytes(1024)),
        ('S12', 'repeated_1k.bin', 'application/octet-stream', b'ABCD' * 256),
        ('S13', 'deterministic_1k.bin', 'application/octet-stream', deterministic_bytes('sample13', 1024)),
        ('S14', 'boundary_15.bin', 'application/octet-stream', deterministic_bytes('boundary15', 15)),
        ('S15', 'boundary_16.bin', 'application/octet-stream', deterministic_bytes('boundary16', 16)),
        ('S16', 'boundary_17.bin', 'application/octet-stream', deterministic_bytes('boundary17', 17)),
        ('S17', 'unicode_nfc.txt', 'text/plain', unicodedata.normalize('NFC', vietnamese).encode('utf-8')),
        ('S18', 'unicode_nfd.txt', 'text/plain', unicodedata.normalize('NFD', vietnamese).encode('utf-8')),
    ]


def test_cases() -> list[dict[str, object]]:
    """Expected outcomes, not measured results. AEAD edits happen AFTER sealing."""
    specs = [
        ('TC01', 'Nguyên vẹn', 'ALL', 'none', 'ACCEPT', 'ACCEPT', 'ACCEPT',
         'Kiểm tra tệp/gói nguyên vẹn. Đây là control, không thuộc mẫu số tỷ lệ phát hiện.'),
        ('TC02', 'Sửa nội dung giữ bằng chứng cũ', 'ALL', 'flip_payload_bit', 'REJECT', 'REJECT', 'REJECT',
         'Hash/HMAC: dùng tampered_path với digest/tag gốc. AEAD: sửa bản mã sau encrypt, không mã hóa lại.'),
        ('TC03', 'Thay cả tệp và SHA-256 được gửi kèm', 'HASH', 'replace_payload_and_hash', 'ACCEPT_UNTRUSTED', 'NOT_APPLICABLE', 'NOT_APPLICABLE',
         'Mô phỏng nhận hash do bên sửa tệp cung cấp; không dùng trusted manifest làm giá trị nhận. Không phải va chạm.'),
        ('TC04', 'Khóa sai', 'KEYED', 'wrong_key', 'NOT_APPLICABLE', 'REJECT', 'REJECT',
         'Giữ thông điệp/gói và tag gốc; chỉ thay khóa lúc xác minh/giải mã.'),
        ('TC05', 'Thẻ HMAC bị sửa', 'HMAC', 'flip_hmac_tag_bit', 'NOT_APPLICABLE', 'REJECT', 'NOT_APPLICABLE',
         'B tự sinh thẻ gốc rồi lật một bit của thẻ; giữ tệp và khóa.'),
        ('TC06', 'Thẻ AEAD bị sửa', 'AEAD', 'flip_aead_tag_bit', 'NOT_APPLICABLE', 'NOT_APPLICABLE', 'REJECT',
         'C tự tạo gói gốc rồi lật một bit thẻ. Tách thẻ theo định dạng API thực tế.'),
        ('TC07', 'Metadata bị sửa', 'ALL', 'replace_aad', 'ACCEPT_METADATA_OUTSIDE_SCOPE', 'ACCEPT_METADATA_OUTSIDE_SCOPE', 'REJECT',
         'Profile mặc định hash/HMAC chỉ bảo vệ tệp. AEAD dùng bytes metadata làm AAD. Không tính metadata ngoài phạm vi là lỗi phát hiện.'),
        ('TC08', 'Nonce AEAD sai', 'AEAD', 'wrong_nonce', 'NOT_APPLICABLE', 'NOT_APPLICABLE', 'REJECT',
         'Giữ bản mã/thẻ và khóa; thay nonce lúc decrypt. Đây là ca bổ sung.'),
        ('TC09', 'Cắt ngắn nội dung', 'ALL_NONEMPTY', 'truncate_one_byte', 'REJECT', 'REJECT', 'REJECT',
         'Bỏ một byte cuối của tệp cho hash/HMAC hoặc của gói mã hóa cho AEAD. Bỏ qua tệp rỗng. Đây là ca bổ sung.'),
    ]
    cases=[]
    for cid, name, applies, op, h, m, a, note in specs:
        cases.append({'case_id': cid, 'name': name, 'applies_to': applies,
                      'operation': op, 'expected': {'hash': h, 'hmac': m, 'aead': a},
                      'is_control': cid=='TC01', 'notes': note})
    return cases


def build_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    entries=[]
    for sid, name, media, content in payloads():
        prefix=f'{sid}_{name}'
        source=f'samples/{prefix}'
        changed=f'tampered/{prefix}'
        aad=f'metadata/{sid}.aad.json'
        bad_aad=f'metadata/{sid}.tampered.aad.json'
        meta={'sample_id': sid, 'filename': name, 'media_type': media, 'version': 1, 'synthetic': True}
        bad_meta={**meta, 'version': 2}
        if content:
            i=len(content)//2
            edited=content[:i]+bytes([content[i]^1])+content[i+1:]
            mutation={'operation':'flip_one_bit', 'offset':i, 'xor_mask':1}
        else:
            edited=b'\x01'
            mutation={'operation':'append_to_empty', 'offset':0, 'appended_hex':'01'}
        digest=hashlib.sha256(content).hexdigest()
        modified_digest=hashlib.sha256(edited).hexdigest()
        digest_path=f'digests/{sid}.sha256'
        untrusted_path=f'digests/{sid}.tampered.sha256'
        files[source]=content;files[changed]=edited
        files[aad]=canonical_json(meta);files[bad_aad]=canonical_json(bad_meta)
        files[digest_path]=(digest+'\n').encode('ascii')
        files[untrusted_path]=(modified_digest+'\n').encode('ascii')
        entries.append({'sample_id':sid, 'path':source, 'size_bytes':len(content),
            'sha256':digest, 'sha3_256':hashlib.sha3_256(content).hexdigest(),
            'metadata_path':aad, 'metadata_sha256':hashlib.sha256(files[aad]).hexdigest(),
            'tampered_path':changed, 'tampered_sha256':modified_digest,
            'tampered_metadata_path':bad_aad,
            'tampered_metadata_sha256':hashlib.sha256(files[bad_aad]).hexdigest(),
            'reference_digest_path':digest_path, 'attacker_digest_path':untrusted_path,
            'mutation':mutation})
    sizes=[1024,16384,65536,262144,1048576]
    benchmarks=[]
    for size in sizes:
        path=f'benchmark/{size:08d}_bytes.bin'
        content=deterministic_bytes(f'benchmark:{size}',size)
        files[path]=content
        benchmarks.append({'path':path,'size_bytes':size,
            'sha256':hashlib.sha256(content).hexdigest(),
            'sha3_256':hashlib.sha3_256(content).hexdigest()})
    manifest={'dataset_version':VERSION,'seed':SEED,'encoding':'Read ALL payloads as raw bytes',
        'manifest_role':'Trusted dataset inventory; keep separate from attacker-supplied digest in TC03',
        'samples':entries,'benchmarks':benchmarks}
    files['manifest.json']=pretty_json(manifest)
    files['test_cases.json']=pretty_json({'dataset_version':VERSION,'kind':'expected outcomes only',
        'profile':{'hash':'SHA-256(file_bytes)','hmac':'HMAC-SHA-256(file_bytes)',
                   'aead':'AEAD(plaintext=file_bytes, associated_data=metadata_file_bytes)'},
        'cases':test_cases()})
    files['lab_parameters.json']=pretty_json({'dataset_version':VERSION,
        'public_test_keys_not_secrets':True,
        'hmac_key_hex':bytes(range(32)).hex(),
        'hmac_wrong_key_hex':(b'\x01'+bytes(range(1,32))).hex(),
        'aead_key_hex':bytes(range(32,64)).hex(),
        'aead_wrong_key_hex':(b'\x21'+bytes(range(33,64))).hex(),
        'aead_example_profile':'AES-256-GCM', 'nonce_size_bytes':12,'tag_size_bytes':16,
        'nonce_policy':'Do not store a fixed nonce here. Generate a fresh nonce for every encryption; save it with that packet. Mutated verification cases reuse the original packet, not re-encryption.',
        'key_policy':'These public keys are fixture inputs only, never secrets. For each independent encryption run, prefer a fresh generated key.'})
    files['test_matrix.csv']=csv_bytes([
        ['case_id','name','hash_expected','hmac_expected','aead_expected','notes'],
        *[[c['case_id'],c['name'],c['expected']['hash'],c['expected']['hmac'],c['expected']['aead'],c['notes']] for c in test_cases()]])
    files['results_template.csv']=csv_bytes([['run_id','case_id','sample_id','mechanism',
        'expected_status','actual_status','applicable_to_detection','detected','elapsed_ns','evidence_path','tool_versions']])
    files['benchmark_results_template.csv']=csv_bytes([['run_id','algorithm','input_path','size_bytes',
        'repeat_index','elapsed_ns','io_included','python_version','platform','library_versions']])
    return files


def verify(root: Path) -> list[str]:
    expected=build_files()
    errors=[]
    for rel, content in expected.items():
        path=root/rel
        if not path.is_file():
            errors.append(f'missing: {rel}')
        elif path.read_bytes()!=content:
            errors.append(f'byte mismatch: {rel}')
    # Avoid silently accepting unlisted stale fixtures in the generated subdirectories.
    for dirname in ['samples','tampered','metadata','digests','benchmark']:
        if (root/dirname).exists():
            for path in (root/dirname).rglob('*'):
                if path.is_file() and path.relative_to(root).as_posix() not in expected:
                    errors.append(f'unlisted fixture: {path.relative_to(root).as_posix()}')
    return errors


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'data')
    parser.add_argument('--check',action='store_true',help='Read-only byte-for-byte validation')
    parser.add_argument('--extended',action='store_true',help='Also generate ignored 4 MiB and 16 MiB benchmark files')
    args=parser.parse_args()
    if args.check and args.extended:
        parser.error('--check and --extended cannot be combined')
    if args.check:
        errors=verify(args.output)
        if errors:
            print('FAIL: '+ '; '.join(errors[:10]))
            return 1
        print('OK: 18 samples; 18 payload mutations; 5 benchmark files; 9 test cases; deterministic bytes verified')
        return 0
    written=0
    for rel,content in build_files().items():
        path=args.output/rel
        if path.exists() and path.read_bytes()==content:
            continue
        if path.exists():
            print(f'FAIL: existing fixture differs: {path}. Preserve it before regenerating.',file=sys.stderr)
            return 1
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content);written+=1
    if args.extended:
        for size in [4*1024*1024,16*1024*1024]:
            path=args.output/'benchmark_extended'/f'{size:08d}_bytes.bin'
            content=deterministic_bytes(f'benchmark:{size}',size)
            if path.exists() and path.read_bytes()!=content:
                print(f'FAIL: existing extended fixture differs: {path}',file=sys.stderr);return 1
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content)
    print(f'GENERATED: {len(build_files())} dataset files; {written} new files')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
