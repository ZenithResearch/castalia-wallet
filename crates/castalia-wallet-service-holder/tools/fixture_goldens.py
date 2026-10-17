"""Recompute public fixture metadata only; never generate keys, signatures or custody."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[1]
VENDOR = PACKAGE / 'vendor/secS-service-b'
FIXTURES = PACKAGE / 'tests/fixtures'

def field(name, value):
    name = name.encode()
    return struct.pack('>H', len(name)) + name + struct.pack('>I', len(value)) + value

def generated():
    delegation = json.loads((FIXTURES / 'delegation-goldens.json').read_text())
    # Descriptor framing is frozen input; native Rust tests independently compare its fingerprint.
    preimage = bytes.fromhex(delegation['descriptor_preimage_hex'])
    if hashlib.sha256(preimage).hexdigest() != delegation['descriptor_sha256']:
        raise ValueError('descriptor oracle preimage mismatch; review against native fingerprint before replacing')
    for vector in delegation['vectors']:
        raw = json.dumps(vector['policy'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        vector.update(canonical_utf8=raw.decode(), preimage_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
    bundle = json.loads((FIXTURES / 'bundle-oracle.json').read_text())
    reader = hashlib.sha256((VENDOR / 'crates/secs-service-call-contract/src/lib.rs').read_bytes()).digest()
    for vector in bundle['vectors']:
        raw = b'secs-service-public-contract-bundle-v1\0' + field('application', vector['application'].encode())
        for item in sorted(vector['schemas'], key=lambda item: item['filename']):
            digest = hashlib.sha256((VENDOR / 'crates/secs-service-call-contract/schemas' / item['filename']).read_bytes()).digest()
            item['sha256'] = digest.hex()
            raw += field(item['filename'], digest)
        raw += field('reader_profile', b'secs-service-call-contract/v1') + field('reader_source_sha256', reader)
        vector.update(reader_source_sha256=reader.hex(), preimage_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
    return {'delegation-goldens.json': delegation, 'bundle-oracle.json': bundle}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='write reviewed public metadata; SOURCE.json and verifier pins then need explicit review')
    args = parser.parse_args()
    changed = []
    for name, value in generated().items():
        path = FIXTURES / name
        if json.loads(path.read_text()) != value:
            changed.append(name)
        if args.write:
            path.write_text(json.dumps(value, indent=2) + '\n')
    print(json.dumps({'matches': not changed, 'different_files': changed, 'signing_performed': False}, indent=2))
    return 0 if args.write or not changed else 1

if __name__ == '__main__':
    sys.exit(main())
