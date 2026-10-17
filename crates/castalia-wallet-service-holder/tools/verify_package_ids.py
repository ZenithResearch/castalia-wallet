"""Verify actual locked/offline holder package identities; never authority admission."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

PACKAGE = Path('crates/castalia-wallet-service-holder')
NATIVE = PACKAGE / 'vendor/secS-service-b'
FS = NATIVE / 'vendor/castalia-wallet-private-files-9cc8140'

def run_metadata(root, features=None):
    command = ['cargo', '+1.96', 'metadata', '--format-version', '1', '--locked', '--offline', '--manifest-path', str(root / PACKAGE / 'Cargo.toml')]
    if features:
        command += ['--features', features]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise ValueError('locked offline Cargo metadata failed: ' + result.stderr)
    return json.loads(result.stdout)

def check_metadata(root, metadata):
    errors = []
    expected = {'castalia-wallet-service-holder': PACKAGE, 'server': NATIVE / 'server', 'libsec-core': NATIVE / 'core', 'secs-permissions': NATIVE / 'permissions', 'secs-service-call-contract': NATIVE / 'crates/secs-service-call-contract', 'castalia-wallet-private-files': FS}
    packages = metadata.get('packages', [])
    ids = [p['id'] for p in packages]
    if len(ids) != len(set(ids)):
        errors.append('package identity: duplicate package ID')
    selected = {}
    for name, relative in expected.items():
        matches = [p for p in packages if p['name'] == name]
        if len(matches) != 1:
            errors.append('package identity: expected exactly one ' + name)
            continue
        package = matches[0]
        selected[name] = package['id']
        if Path(package['manifest_path']).resolve() != (root / relative / 'Cargo.toml').resolve() or package.get('source') is not None or not Path(package['manifest_path']).resolve().is_relative_to(root.resolve()):
            errors.append('package identity: wrong canonical manifest/source for ' + name)
    def unconditional(owner_name, dependency_name, relative):
        owners = [p for p in packages if p['id'] == selected.get(owner_name)]
        declarations = [d for p in owners for d in p.get('dependencies', []) if d.get('name') == dependency_name or d.get('rename') == dependency_name]
        valid = len(declarations) == 1
        if valid:
            declaration = declarations[0]
            path = declaration.get('path')
            valid = (declaration.get('name') == dependency_name and declaration.get('rename') is None
                     and declaration.get('kind') is None and declaration.get('target') is None
                     and declaration.get('optional') is False and declaration.get('source') is None
                     and isinstance(path, str) and Path(path).resolve() == (root / relative).resolve())
        if not valid:
            errors.append('package identity: expected one unconditional declaration ' + owner_name + ' -> ' + dependency_name)
    unconditional('castalia-wallet-service-holder', 'server', NATIVE / 'server')
    unconditional('server', 'castalia-wallet-private-files', FS)
    for package in packages:
        if package.get('source') is None and package['id'] not in selected.values():
            errors.append('package identity: unexpected local package ' + package['name'])
    resolution = metadata.get('resolve') or {}
    nodes = resolution.get('nodes', [])
    graph = {node['id']: set(node.get('dependencies', [])) for node in nodes}
    if len(graph) != len(nodes):
        errors.append('package identity: duplicate resolve node')
    for source, targets in graph.items():
        if source not in ids or any(target not in ids for target in targets):
            errors.append('package identity: unknown resolve package ID')
    holder = selected.get('castalia-wallet-service-holder')
    server = selected.get('server')
    fs = selected.get('castalia-wallet-private-files')
    if resolution.get('root') != holder or metadata.get('workspace_members') != [holder]:
        errors.append('package identity: holder must be the sole selected workspace root')
    if holder not in graph or any(value not in graph.get(holder, set()) for key, value in selected.items() if key != 'castalia-wallet-service-holder'):
        errors.append('package identity: holder does not select the exact native dependency set')
    if server not in graph or fs not in graph.get(server, set()):
        errors.append('package identity: server and holder do not share the exact FS package ID')
    visiting, complete = set(), set()
    def visit(node):
        if node in visiting:
            errors.append('package identity: dependency cycle')
            return
        if node in complete:
            return
        visiting.add(node)
        for child in graph.get(node, set()):
            visit(child)
        visiting.remove(node)
        complete.add(node)
    if holder:
        visit(holder)
    if server and holder:
        pending, seen = [server], set()
        while pending:
            node = pending.pop()
            if node in seen:
                continue
            seen.add(node)
            pending.extend(graph.get(node, set()) - seen)
        if holder in seen:
            errors.append('package identity: server reaches holder')
    return errors

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--metadata-json', type=Path)
    parser.add_argument('--features')
    args = parser.parse_args()
    try:
        metadata = json.loads(args.metadata_json.read_text()) if args.metadata_json else run_metadata(args.repo_root.resolve(), args.features)
        errors = check_metadata(args.repo_root.resolve(), metadata)
    except (OSError, ValueError, KeyError, TypeError) as error:
        errors = ['package identity unreadable: ' + str(error)]
    print(json.dumps({'package_identity': not errors, 'metadata_origin': 'supplied_record' if args.metadata_json else 'actual_locked_offline_Cargo', 'production_qualified': False, 'errors': errors}, indent=2))
    return 1 if errors else 0

if __name__ == '__main__':
    sys.exit(main())
