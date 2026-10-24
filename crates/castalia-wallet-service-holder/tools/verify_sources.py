"""Read-only source-package integrity checks; never authority or custody admission."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tomllib

COMMIT = '7e32f132549236ec78ebd9ec8bf364ec66b33721'
NATIVE_MANIFEST_SHA256 = 'c482dd23a4b32f1b6515cddcdc478985a0341a4263120befb0f95d60963b9456'
FIXTURE_MANIFEST_SHA256 = 'd729333cd6fe026ff2b79b7edeeee29faaa8e74a828b260807828456740edf5c'
CUSTODY_MANIFEST_SHA256 = 'f3a5d9aed996cad7dc5c810869803e8a8b1d17c0edfd92557678ee0e56088cd5'
PRIVATE_FILES_SHA256 = {
    'src/lib.rs': '56a29e496705bab57cbaafa03df727c11be417f8a34763faae8e5011ee53f968',
    'src/service_store.rs': '55a89a0642024b50bd021d5e4602f6cd2d4bc10f69e51f2ff3397dd7fc5edb4e',
    # Root fixture only: bounded WouldBlock wait after concurrent fork. Production pins above are unchanged.
    'src/service_store_tests.rs': '8ab5e28d8497f73a02e7303b7bb832d2b22c3285c7e105d1db82789a8f10bab0',
}
# Reviewed shared Web/native core closure and core0.3.0 version stamp.
# Portable source gates and cross-client fixtures pass; standalone holder/native exports are unchanged.
# Historical reviewed closure: fa716bd58592f85f8847337926be14d0eae4fbdd9437cd7dca6139dd7c4eecc5.
GENERIC_LOCK_SHA256 = '566f5c755c2ad42b97a7dfa3a361a12ca646ad16fa399e1ba1efc5db5dd7ee32'
GENERIC_GUARD_SHA256 = '1bbbb3fad42cf2b8e5bc237ca2a4b02131208cccfa17e81cd34645ff28abbc4b'
PACKAGE = 'crates/castalia-wallet-service-holder'
VENDOR = 'vendor/secS-magik-7e32f13'
GENERIC_MEMBERS = ['crates/castalia-wallet-cli', 'crates/castalia-wallet-private-files', 'crates/castalia-wallet-presentation', 'crates/castalia-wallet-core', 'crates/castalia-wallet-native']
EXCLUSIONS = [PACKAGE, VENDOR, VENDOR + '/core', VENDOR + '/server', VENDOR + '/permissions', VENDOR + '/crates/secs-service-call-contract']

# Replaced only after reviewed Native Stage B is committed and exported by actual git archive.
STAGE_B_COMMIT = '3484dc40b86f0497ca5d34d2545a5f1b652fb660'
STAGE_B_MANIFEST_SHA256 = '34fb72ed625b735721bc4386cfda66658f98b92fdca549bd4be835303207af13'
STAGE_B_VENDOR = PACKAGE + '/vendor/secS-service-b'
STAGE_B_FS = STAGE_B_VENDOR + '/vendor/castalia-wallet-private-files-9cc8140'
STAGE_B_FS_SOURCE_SHA256 = '0f6f7fa87424c99dbca1718d5d391563d5958f812a232e7449d61f77508c4434'
HOLDER_REGISTRY_SHA256 = '214e310642b7c3f0dc641f57a62a85eee5ab499a15d576fdb322131ddddfc4f0'
GENERIC_MANIFEST_SHA256 = 'e23c951b6847201e9d7fabf60f363d88630f313cd010e3f307258dbf56cc9110'

# All five historical exports remain immutable and independently checked.
BOOTSTRAP_COMMIT = 'afeb6e60f5e3b062e503e545c8d6417c0c3ca9e7'
BOOTSTRAP_MANIFEST_SHA256 = '507d67078952d1c98ac55ba945592e93ca2e0f10e8cbcfa61a62e56ae0d0b2de'
BOOTSTRAP_VENDOR = PACKAGE + '/vendor/secS-service-authority-afeb6e6'
BOOTSTRAP_FS = BOOTSTRAP_VENDOR + '/vendor/castalia-wallet-private-files-9cc8140'

RESUME_COMMIT = '20d064ddbcb9b021a46fdccf00b1d5e6be236025'
RESUME_MANIFEST_SHA256 = '56fea6fa4e483d4d3672767a14dface47918928ceb374609f1f06a4b05b02b66'
RESUME_VENDOR = PACKAGE + '/vendor/secS-service-authority-20d064d'
RESUME_FS = RESUME_VENDOR + '/vendor/castalia-wallet-private-files-9cc8140'

CAPACITY_COMMIT = 'a7100a770b60417e9e2b17655ab6e75f46b0be6e'
CAPACITY_MANIFEST_SHA256 = 'ec6f091795a61351a8197c263280fb8dc766c5feb1276a335d2f8e0347792c71'
CAPACITY_VENDOR = PACKAGE + '/vendor/secS-service-authority-a7100a7'
CAPACITY_FS = CAPACITY_VENDOR + '/vendor/castalia-wallet-private-files-9cc8140'

CURRENT_COMMIT = 'd1ff595c214f68a6b1c8b763708d82d6c1eff620'
CURRENT_MANIFEST_SHA256 = '5e61cdf4933f5c4b2e59e8f657a915f33b7668b71e1a26cdae110b76a83c54f9'
CURRENT_RELATIVE = 'vendor/secS-service-authority-d1ff595'
CURRENT_VENDOR = PACKAGE + '/' + CURRENT_RELATIVE
CURRENT_FS = CURRENT_VENDOR + '/vendor/castalia-wallet-private-files-9cc8140'

QUERY_COMMIT = 'eb8d839a805f64d9d1d0e280896d03f9b95239bc'
QUERY_MANIFEST_SHA256 = '00ad08bd4222adfc677f9f17142c36c10a362ab3fd60637d9f7c1a28b4ac5766'
QUERY_VENDOR = PACKAGE + '/vendor/secS-service-authority-eb8d839'
QUERY_FS = QUERY_VENDOR + '/vendor/castalia-wallet-private-files-9cc8140'
CURRENT_SOURCE_FILES = 342


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify(root):
    errors = []
    def check_hash(path, expected, label):
        if not path.is_file() or path.is_symlink() or sha(path) != expected:
            errors.append(label + ': ' + str(path.relative_to(root)))
            return False
        return True
    def inventory(base, entries, label, excluded=()):
        paths = []
        for entry in entries:
            rel = PurePosixPath(entry['path'])
            if rel.is_absolute() or '..' in rel.parts or str(rel) in paths:
                errors.append(label + ' inventory: invalid or duplicate path')
                continue
            paths.append(str(rel))
            check_hash(base / str(rel), entry['sha256'], label + ' sha256')
            if 'mode' in entry and not (base / str(rel)).is_symlink() and (base / str(rel)).is_file() and (base / str(rel)).stat().st_mode & 0o7777 != entry['mode']:
                errors.append(label + ' mode: ' + str(rel))
        actual = []
        for path in base.rglob('*'):
            if path.is_symlink():
                errors.append(label + ' inventory: symlink ' + str(path.relative_to(base)))
            elif path.is_file() and str(path.relative_to(base)) not in excluded:
                actual.append(str(path.relative_to(base)))
        if set(paths) != set(actual):
            errors.append(label + ' inventory: missing or extra files')
    native_path = root / (VENDOR + '.source.json')
    if check_hash(native_path, NATIVE_MANIFEST_SHA256, 'native manifest'):
        native = json.loads(native_path.read_text())
        if native['commit'] != COMMIT or len(native['source_files']) != 302:
            errors.append('native inventory: wrong commit or count')
        inventory(root / VENDOR, native['source_files'], 'native')
    # Historical exports remain immutable; actual dependency selection is checked separately.
    selected_path = root / (STAGE_B_VENDOR + '.source.json')
    if check_hash(selected_path, STAGE_B_MANIFEST_SHA256, 'native service-b manifest'):
        selected = json.loads(selected_path.read_text())
        if STAGE_B_COMMIT is None or selected.get('commit') != STAGE_B_COMMIT:
            errors.append('native service-b manifest: uncommitted or wrong actual revision')
        inventory(root / STAGE_B_VENDOR, selected['source_files'], 'native service-b')
    bootstrap_path = root / (BOOTSTRAP_VENDOR + '.source.json')
    if check_hash(bootstrap_path, BOOTSTRAP_MANIFEST_SHA256, 'native bootstrap manifest'):
        bootstrap = json.loads(bootstrap_path.read_text())
        if bootstrap.get('commit') != BOOTSTRAP_COMMIT or len(bootstrap.get('source_files', [])) != 331:
            errors.append('native bootstrap manifest: wrong committed revision or inventory count')
        inventory(root / BOOTSTRAP_VENDOR, bootstrap['source_files'], 'native bootstrap')
    resume_path = root / (RESUME_VENDOR + '.source.json')
    if check_hash(resume_path, RESUME_MANIFEST_SHA256, 'native resume manifest'):
        resume = json.loads(resume_path.read_text())
        if resume.get('commit') != RESUME_COMMIT or len(resume.get('source_files', [])) != 332:
            errors.append('native resume manifest: wrong committed revision or inventory count')
        inventory(root / RESUME_VENDOR, resume['source_files'], 'native resume')
    query_path = root / (QUERY_VENDOR + '.source.json')
    if check_hash(query_path, QUERY_MANIFEST_SHA256, 'native query manifest'):
        query = json.loads(query_path.read_text())
        if query.get('commit') != QUERY_COMMIT or len(query.get('source_files', [])) != 333:
            errors.append('native query manifest: wrong committed revision or inventory count')
        inventory(root / QUERY_VENDOR, query['source_files'], 'native query')
    capacity_path = root / (CAPACITY_VENDOR + '.source.json')
    if check_hash(capacity_path, CAPACITY_MANIFEST_SHA256, 'native capacity manifest'):
        capacity = json.loads(capacity_path.read_text())
        if capacity.get('commit') != CAPACITY_COMMIT or len(capacity.get('source_files', [])) != 342:
            errors.append('native capacity manifest: wrong committed revision or inventory count')
        inventory(root / CAPACITY_VENDOR, capacity['source_files'], 'native capacity')
    current_path = root / (CURRENT_VENDOR + '.source.json')
    if check_hash(current_path, CURRENT_MANIFEST_SHA256, 'native current manifest'):
        current = json.loads(current_path.read_text())
        if current.get('commit') != CURRENT_COMMIT or len(current.get('source_files', [])) != CURRENT_SOURCE_FILES:
            errors.append('native current manifest: wrong committed revision or inventory count')
        inventory(root / CURRENT_VENDOR, current['source_files'], 'native current')
    for shared_path in [STAGE_B_FS, BOOTSTRAP_FS, RESUME_FS, QUERY_FS, CAPACITY_FS, CURRENT_FS]:
        fs_path = root / (shared_path + '.source.json')
        if check_hash(fs_path, STAGE_B_FS_SOURCE_SHA256, 'shared FS manifest'):
            shared = json.loads(fs_path.read_text())
            if shared['commit'] != '9cc814075704f1ae4a55b0f0ac17ecb2449c578f' or len(shared['source_files']) != 4 or shared['license_origin'] is not None:
                errors.append('shared FS manifest: origin/count/license drift')
            inventory(root / shared_path, shared['source_files'], 'shared FS')
    for relative in [VENDOR, STAGE_B_VENDOR, STAGE_B_FS, BOOTSTRAP_VENDOR, BOOTSTRAP_FS, RESUME_VENDOR, RESUME_FS, QUERY_VENDOR, QUERY_FS, CAPACITY_VENDOR, CAPACITY_FS, CURRENT_VENDOR, CURRENT_FS]:
        path = root / relative
        if any(item.is_symlink() for item in [path, *path.parents] if item != root and item.is_relative_to(root)):
            errors.append('native inventory: symlink in source root ' + relative)
    check_hash(root / 'Cargo.toml', GENERIC_MANIFEST_SHA256, 'generic manifest baseline')
    fixture_dir = root / PACKAGE / 'tests/fixtures'
    fixture_manifest = fixture_dir / 'SOURCE.json'
    if check_hash(fixture_manifest, FIXTURE_MANIFEST_SHA256, 'fixture manifest'):
        fixture = json.loads(fixture_manifest.read_text())
        inventory(fixture_dir, fixture['files'], 'fixture', ['SOURCE.json'])
    custody_dir = root / PACKAGE / 'tests/custody-vectors'
    if check_hash(custody_dir / 'SOURCE.json', CUSTODY_MANIFEST_SHA256, 'custody manifest'):
        custody = json.loads((custody_dir / 'SOURCE.json').read_text())
        inventory(custody_dir, custody['files'], 'custody vector', ['SOURCE.json'])
    for rel, digest in PRIVATE_FILES_SHA256.items():
        check_hash(root / 'crates/castalia-wallet-private-files' / rel, digest, 'private-files source')
    check_hash(root / 'Cargo.lock', GENERIC_LOCK_SHA256, 'generic lock')
    check_hash(root / 'scripts/presentation-boundary.test.mjs', GENERIC_GUARD_SHA256, 'generic guard')
    main = tomllib.loads((root / 'Cargo.toml').read_text())['workspace']
    if main['members'] != GENERIC_MEMBERS or not set(EXCLUSIONS).issubset(main.get('exclude', [])):
        errors.append('generic workspace: member/exclusion drift')
    package = root / PACKAGE
    native_lock = tomllib.loads((root / CURRENT_VENDOR / 'Cargo.lock').read_text())['package']
    registry = {(p['name'], p['version'], p['source']): p.get('checksum')
                for p in native_lock if p.get('source', '').startswith('registry+')}
    holder_lock = tomllib.loads((package / 'Cargo.lock').read_text())['package']
    rows = [{key: item[key] for key in ['name', 'version', 'source', 'checksum']} for item in holder_lock if item.get('source', '').startswith('registry+')]
    if len(rows) != 186 or hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest() != HOLDER_REGISTRY_SHA256:
        errors.append('holder registry: bounded baseline row drift')
    seen = set()
    for item in holder_lock:
        key = (item['name'], item['version'], item.get('source'))
        if key in seen:
            errors.append('holder registry: duplicate lock entry ' + item['name'])
        seen.add(key)
        source = item.get('source')
        if source is not None and (not source.startswith('registry+')
                                   or key not in registry
                                   or registry[key] != item.get('checksum')):
            errors.append('holder registry: source/version/checksum drift ' + item['name'])
    manifest = tomllib.loads((package / 'Cargo.toml').read_text())
    if 'workspace' not in manifest or manifest['package'].get('publish') is not False:
        errors.append('holder workspace: missing independent root or publish=false')
    def check_unconditional(owner, name, expected_path, label):
        declarations = []
        def collect(container, target):
            for kind in ['dependencies', 'dev-dependencies', 'build-dependencies']:
                for key, value in container.get(kind, {}).items():
                    if key == name or isinstance(value, dict) and value.get('package') == name:
                        declarations.append((kind, target, key, value))
        collect(owner, None)
        for target, container in owner.get('target', {}).items():
            collect(container, target)
        valid = len(declarations) == 1
        if valid:
            kind, target, key, value = declarations[0]
            valid = (kind == 'dependencies' and target is None and key == name and isinstance(value, dict)
                     and value.get('path') == expected_path and value.get('optional', False) is False
                     and value.get('package', name) == name and 'git' not in value and 'registry' not in value)
        if not valid:
            errors.append('unconditional declaration: ' + label)
    check_unconditional(manifest, 'server', 'vendor/secS-service-authority-d1ff595/server', 'holder -> server')
    dependencies = manifest['dependencies']
    expected = {'castalia-wallet-private-files': 'vendor/secS-service-authority-d1ff595/vendor/castalia-wallet-private-files-9cc8140', 'server': 'vendor/secS-service-authority-d1ff595/server', 'libsec-core': 'vendor/secS-service-authority-d1ff595/core', 'secs-service-call-contract': 'vendor/secS-service-authority-d1ff595/crates/secs-service-call-contract'}
    for name, path in expected.items():
        if dependencies.get(name, {}).get('path') != path:
            errors.append('holder dependency: wrong immutable path for ' + name)
    if manifest.get('dev-dependencies', {}).get('secs-permissions', {}).get('path') != 'vendor/secS-service-authority-d1ff595/permissions':
        errors.append('holder dependency: wrong immutable path for secs-permissions')
    foreign = ['vendor/secS-service-authority-d1ff595'] + ['vendor/secS-service-authority-d1ff595/' + item for item in ['core', 'client', 'server', 'permissions', 'panel', 'crates/secs-service-call-contract', 'vendor/castalia-wallet-private-files-9cc8140']]
    if not set(foreign).issubset(manifest['workspace'].get('exclude', [])):
        errors.append('holder workspace: missing new foreign exclusions')
    server_manifest = tomllib.loads((root / CURRENT_VENDOR / 'server/Cargo.toml').read_text())
    check_unconditional(server_manifest, 'castalia-wallet-private-files', '../vendor/castalia-wallet-private-files-9cc8140', 'server -> shared FS')
    server_fs = server_manifest['dependencies']['castalia-wallet-private-files']['path']
    holder_fs = dependencies.get('castalia-wallet-private-files', {}).get('path', '')
    if (root / CURRENT_VENDOR / 'server' / server_fs).resolve() != (package / holder_fs).resolve():
        errors.append('shared FS identity: server and holder manifest paths differ')
    setup = tomllib.loads((root / 'crates/castalia-wallet-local-review-setup/Cargo.toml').read_text())
    for name, suffix in [('server','server'), ('libsec-core','core'), ('castalia-wallet-private-files','vendor/castalia-wallet-private-files-9cc8140')]:
        check_unconditional(setup, name, '../castalia-wallet-service-holder/' + CURRENT_RELATIVE + '/' + suffix, 'setup -> ' + name)
    workspace_setup = tomllib.loads((root / 'crates/castalia-wallet-workspace-setup/Cargo.toml').read_text())
    for name, suffix in [('server','server'), ('libsec-core','core'), ('castalia-wallet-private-files','vendor/castalia-wallet-private-files-9cc8140')]:
        check_unconditional(workspace_setup, name, '../castalia-wallet-service-holder/' + CURRENT_RELATIVE + '/' + suffix, 'workspace setup -> ' + name)
    for table in ['dependencies', 'dev-dependencies', 'build-dependencies']:
        for name, value in manifest.get(table, {}).items():
            if isinstance(value, dict):
                if 'git' in value or 'registry' in value:
                    errors.append('holder dependency: unexpected remote source ' + name)
                if 'path' in value:
                    path = Path(value['path'])
                    target = (package / path).resolve()
                    if path.is_absolute() or not target.is_relative_to(root.resolve()):
                        errors.append('holder dependency: operator path ' + name)
    for source in (package / 'src').rglob('*.rs'):
        text = source.read_text()
        if re.search(r'include_(?:bytes|str)!\s*\(\s*"(?:/|[A-Za-z]:)', text) or re.search(r'#\[path\s*=\s*"(?:/|[A-Za-z]:)', text):
            errors.append('absolute include: ' + str(source.relative_to(root)))
    return errors

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[3])
    args = parser.parse_args()
    try:
        errors = verify(args.repo_root.resolve())
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors = ['source package unreadable: ' + str(error)]
    print(json.dumps({'source_integrity': not errors, 'native_commit': COMMIT, 'native_files': 302, 'selected_native_stage_b_commit': STAGE_B_COMMIT, 'legacy_selection_fields_historical': True, 'retained_query_native_commit': QUERY_COMMIT, 'retained_query_native_export': QUERY_VENDOR, 'selected_native_commit': CURRENT_COMMIT, 'selected_native_export': CURRENT_VENDOR, 'source_pin_committed': STAGE_B_COMMIT is not None, 'production_qualified': False, 'errors': errors}, indent=2))
    return 1 if errors else 0

if __name__ == '__main__':
    sys.exit(main())
