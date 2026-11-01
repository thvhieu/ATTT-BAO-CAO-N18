import csv
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import unicodedata
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('generator',ROOT/'tools/generate_dataset.py')
generator=importlib.util.module_from_spec(spec);spec.loader.exec_module(generator)
spec2=importlib.util.spec_from_file_location('dataset_io',ROOT/'tools/dataset_io.py')
loader=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(loader)


class DatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=ROOT/'data'
        cls.manifest=json.loads((cls.data/'manifest.json').read_text(encoding='utf-8'))

    def test_01_complete_and_reproducible(self):
        self.assertEqual(generator.verify(self.data),[])
        self.assertEqual(generator.build_files(),generator.build_files())

    def test_02_payload_size_and_hashes(self):
        self.assertEqual(len(self.manifest['samples']),18)
        for r in self.manifest['samples']:
            b=(self.data/r['path']).read_bytes()
            self.assertEqual(len(b),r['size_bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),r['sha256'])
            self.assertEqual(hashlib.sha3_256(b).hexdigest(),r['sha3_256'])

    def test_03_payload_mutations(self):
        for r in self.manifest['samples']:
            a=(self.data/r['path']).read_bytes();b=(self.data/r['tampered_path']).read_bytes()
            self.assertNotEqual(a,b)
            self.assertEqual(hashlib.sha256(b).hexdigest(),r['tampered_sha256'])
            if a:
                self.assertEqual(len(a),len(b))
                self.assertEqual(sum((x^y).bit_count() for x,y in zip(a,b)),1)
            else:
                self.assertEqual(b,b'\x01')

    def test_04_metadata_is_canonical_and_mutated(self):
        for r in self.manifest['samples']:
            b=(self.data/r['metadata_path']).read_bytes();m=json.loads(b)
            bad=(self.data/r['tampered_metadata_path']).read_bytes();bm=json.loads(bad)
            self.assertEqual(b,generator.canonical_json(m))
            self.assertEqual(bad,generator.canonical_json(bm))
            self.assertEqual(m['sample_id'],r['sample_id'])
            self.assertEqual(bm,{**m,'version':2})
            self.assertEqual(hashlib.sha256(b).hexdigest(),r['metadata_sha256'])
            self.assertEqual(hashlib.sha256(bad).hexdigest(),r['tampered_metadata_sha256'])

    def test_05_untrusted_hash_is_not_a_collision(self):
        for r in self.manifest['samples']:
            self.assertNotEqual(r['sha256'],r['tampered_sha256'])
            self.assertEqual((self.data/r['reference_digest_path']).read_text().strip(),r['sha256'])
            self.assertEqual((self.data/r['attacker_digest_path']).read_text().strip(),r['tampered_sha256'])

    def test_06_benchmark_sizes_and_hashes(self):
        self.assertEqual([x['size_bytes'] for x in self.manifest['benchmarks']],[1024,16384,65536,262144,1048576])
        for r in self.manifest['benchmarks']:
            b=(self.data/r['path']).read_bytes()
            self.assertEqual(len(b),r['size_bytes'])
            self.assertEqual(hashlib.sha256(b).hexdigest(),r['sha256'])
            self.assertEqual(hashlib.sha3_256(b).hexdigest(),r['sha3_256'])

    def test_07_newlines_and_unicode_are_distinct_bytes(self):
        lf=loader.load_sample('S06')['data'];crlf=loader.load_sample('S07')['data']
        self.assertNotEqual(lf,crlf);self.assertEqual(lf,crlf.replace(b'\r\n',b'\n'))
        nfc=loader.load_sample('S17')['data'];nfd=loader.load_sample('S18')['data']
        self.assertNotEqual(nfc,nfd)
        self.assertEqual(unicodedata.normalize('NFC',nfd.decode('utf-8')),nfc.decode('utf-8'))

    def test_08_binary_boundaries_and_loader(self):
        self.assertEqual(loader.load_sample('S01')['data'],b'')
        self.assertEqual(set(loader.load_sample('S10')['data']),set(range(256)))
        self.assertEqual([len(loader.load_sample(x)['data']) for x in ['S14','S15','S16']],[15,16,17])
        with self.assertRaises(KeyError):loader.load_sample('UNKNOWN')

    def test_09_test_matrix_and_scopes(self):
        doc=json.loads((self.data/'test_cases.json').read_text(encoding='utf-8'))
        cases={x['case_id']:x for x in doc['cases']}
        self.assertEqual(len(cases),9)
        self.assertTrue(cases['TC01']['is_control'])
        self.assertEqual(cases['TC03']['expected']['hash'],'ACCEPT_UNTRUSTED')
        self.assertEqual(cases['TC07']['expected']['hmac'],'ACCEPT_METADATA_OUTSIDE_SCOPE')
        self.assertEqual(cases['TC07']['expected']['aead'],'REJECT')
        rows=list(csv.DictReader(io.StringIO((self.data/'test_matrix.csv').read_text(encoding='utf-8'))))
        self.assertEqual([x['case_id'] for x in rows],list(cases))

    def test_10_public_keys_and_no_static_nonce(self):
        p=json.loads((self.data/'lab_parameters.json').read_text(encoding='utf-8'))
        self.assertTrue(p['public_test_keys_not_secrets'])
        for mechanism in ['hmac','aead']:
            a=bytes.fromhex(p[f'{mechanism}_key_hex']);b=bytes.fromhex(p[f'{mechanism}_wrong_key_hex'])
            self.assertEqual(len(a),32);self.assertEqual(len(b),32);self.assertNotEqual(a,b)
        self.assertEqual(p['nonce_size_bytes'],12)
        self.assertNotIn('nonce_hex',p)

    def test_11_results_templates_have_no_fabricated_rows(self):
        for file in ['results_template.csv','benchmark_results_template.csv']:
            rows=list(csv.reader(io.StringIO((self.data/file).read_text(encoding='utf-8'))))
            self.assertEqual(len(rows),1)
            self.assertIn('elapsed_ns',rows[0])

    def test_12_tamper_detection_and_restore(self):
        # Modify a disposable copy, confirm rejection, restore the byte and confirm acceptance.
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for rel,b in generator.build_files().items():
                path=root/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b)
            path=root/'samples/S03_ascii.txt';original=path.read_bytes()
            path.write_bytes(original+b'changed')
            self.assertIn('byte mismatch: samples/S03_ascii.txt',generator.verify(root))
            path.write_bytes(original)
            self.assertEqual(generator.verify(root),[])


if __name__=='__main__':unittest.main()
