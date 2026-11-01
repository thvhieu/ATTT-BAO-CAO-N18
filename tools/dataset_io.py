"""Read the same bytes for A/B/C. No hash/HMAC/AEAD implementation is included."""
from __future__ import annotations
import json
from pathlib import Path

DATA_ROOT=Path(__file__).resolve().parents[1]/'data'


def load_manifest(data_root: Path=DATA_ROOT) -> dict:
    return json.loads((data_root/'manifest.json').read_text(encoding='utf-8'))


def load_sample(sample_id: str, data_root: Path=DATA_ROOT) -> dict:
    record=next((x for x in load_manifest(data_root)['samples'] if x['sample_id']==sample_id),None)
    if record is None:
        raise KeyError(f'Unknown sample_id: {sample_id}')
    return {'record':record, 'data':(data_root/record['path']).read_bytes(),
        'aad':(data_root/record['metadata_path']).read_bytes(),
        'tampered_data':(data_root/record['tampered_path']).read_bytes(),
        'tampered_aad':(data_root/record['tampered_metadata_path']).read_bytes()}
