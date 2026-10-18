"""Packaging immutability regressions; operates on disposable source copies only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = Path('crates/castalia-wallet-service-holder')
SCRIPT = ROOT / PACKAGE / 'tools/verify_sources.py'

class PackagingIntegrityTests(unittest.TestCase):
    def run_check(self, root):
        return subprocess.run(['python3', str(SCRIPT), '--repo-root', str(root)], capture_output=True, text=True)

    def fixture(self):
        tmp = tempfile.TemporaryDirectory(prefix='wallet-source-', dir=os.environ.get('WALLET_SOURCE_TEST_TMPDIR'))
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name in ['Cargo.toml', 'Cargo.lock', 'scripts/presentation-boundary.test.mjs']:
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, dest)
        shutil.copytree(ROOT / 'vendor', root / 'vendor', ignore=shutil.ignore_patterns('target', '__pycache__'))
        shutil.copytree(ROOT / PACKAGE, root / PACKAGE, ignore=shutil.ignore_patterns('target', '__pycache__'))
        shutil.copytree(ROOT / 'crates/castalia-wallet-private-files', root / 'crates/castalia-wallet-private-files', ignore=shutil.ignore_patterns('target', '__pycache__'))
        shutil.copytree(ROOT / 'crates/castalia-wallet-local-review-setup', root / 'crates/castalia-wallet-local-review-setup', ignore=shutil.ignore_patterns('target', '__pycache__'))
        shutil.copytree(ROOT / 'crates/castalia-wallet-workspace-setup', root / 'crates/castalia-wallet-workspace-setup', ignore=shutil.ignore_patterns('target', '__pycache__'))
        return root

    def test_actual_packaged_source_passes(self):
        result = self.run_check(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_native_byte_tamper_denies(self):
        root = self.fixture()
        path = root / 'vendor/secS-magik-7e32f13/core/src/lib.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native sha256', result.stdout + result.stderr)

    def test_extra_native_file_denies(self):
        root = self.fixture()
        (root / 'vendor/secS-magik-7e32f13/unreviewed.rs').write_text('// extra\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native inventory', result.stdout + result.stderr)

    def test_fixture_tamper_denies(self):
        root = self.fixture()
        (root / PACKAGE / 'tests/fixtures/wallet-owner-input.fixture.json').write_text('{}')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('fixture sha256', result.stdout + result.stderr)

    def test_absolute_temporary_include_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'src/tests.rs'
        path.write_text(path.read_text() + '\nconst BAD: &str = include_str!("/private/tmp/unowned.json");\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('absolute include', result.stdout + result.stderr)

    def test_standalone_registry_lock_tamper_denies(self):
        import re
        root = self.fixture()
        path = root / PACKAGE / 'Cargo.lock'
        text = path.read_text()
        pattern = r'(name = "serde_json"\n.*?checksum = ")([a-f0-9]{64})(")'
        match = re.search(pattern, text, re.S)
        self.assertIsNotNone(match)
        checksum = match.group(2)
        changed = ('0' if checksum[0] != '0' else '1') + checksum[1:]
        path.write_text(text[:match.start(2)] + changed + text[match.end(2):])
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('holder registry', result.stdout + result.stderr)

    def test_generic_lock_change_denies(self):
        root = self.fixture()
        path = root / 'Cargo.lock'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('generic lock', result.stdout + result.stderr)

    def test_existing_private_files_implementation_tamper_denies(self):
        root = self.fixture()
        path = root / 'crates/castalia-wallet-private-files/src/lib.rs'
        path.write_text(path.read_text().replace('use ', '// changed\nuse ', 1))
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('private-files', result.stdout + result.stderr)

    def test_accepted_service_store_tamper_denies(self):
        root = self.fixture()
        path = root / 'crates/castalia-wallet-private-files/src/service_store.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('private-files', result.stdout + result.stderr)

    def test_custody_vector_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'tests/custody-vectors/state-1.json'
        path.write_text('{}')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('custody', result.stdout + result.stderr)

    def test_optional_holder_server_declaration_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'Cargo.toml'
        text = path.read_text()
        before = 'server = { path = "vendor/secS-service-authority-d1ff595/server" }'
        self.assertIn(before, text)
        path.write_text(text.replace(before, before[:-2] + ', optional = true }'))
        result = self.run_check(root)
        self.assertIn('unconditional declaration: holder -> server', result.stdout + result.stderr)

    def test_optional_server_FS_declaration_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-authority-d1ff595/server/Cargo.toml'
        text = path.read_text()
        before = 'castalia-wallet-private-files = { path = "../vendor/castalia-wallet-private-files-9cc8140" }'
        self.assertIn(before, text)
        path.write_text(text.replace(before, before[:-2] + ', optional = true }'))
        result = self.run_check(root)
        self.assertIn('unconditional declaration: server -> shared FS', result.stdout + result.stderr)

    def test_selected_native_byte_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-b/core/src/lib.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native service-b sha256', result.stdout + result.stderr)

    def test_selected_native_extra_file_denies(self):
        root = self.fixture()
        (root / PACKAGE / 'vendor/secS-service-b/unreviewed.rs').write_text('// extra\n')
        result = self.run_check(root)
        self.assertIn('native service-b inventory', result.stdout + result.stderr)

    def test_shared_FS_byte_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-b/vendor/castalia-wallet-private-files-9cc8140/src/service_store.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertIn('shared FS sha256', result.stdout + result.stderr)

    def test_shared_FS_manifest_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-b/vendor/castalia-wallet-private-files-9cc8140.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertIn('shared FS manifest', result.stdout + result.stderr)

    def test_generic_FS_redirect_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'Cargo.toml'
        text = path.read_text()
        before = 'path = "vendor/secS-service-authority-d1ff595/vendor/castalia-wallet-private-files-9cc8140"'
        self.assertIn(before, text)
        path.write_text(text.replace(before, 'path = "../castalia-wallet-private-files"'))
        result = self.run_check(root)
        self.assertIn('holder dependency: wrong immutable path for castalia-wallet-private-files', result.stdout + result.stderr)
        self.assertIn('shared FS identity', result.stdout + result.stderr)

    def test_new_export_manifest_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-b.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertIn('native service-b manifest', result.stdout + result.stderr)


    def test_bootstrap_native_byte_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-authority-afeb6e6/server/src/service_authority_startup.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native bootstrap sha256', result.stdout + result.stderr)

    def test_bootstrap_native_extra_file_denies(self):
        root = self.fixture()
        (root / PACKAGE / 'vendor/secS-service-authority-afeb6e6/unreviewed.rs').write_text('// extra\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native bootstrap inventory', result.stdout + result.stderr)

    def test_bootstrap_native_manifest_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-authority-afeb6e6.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native bootstrap manifest', result.stdout + result.stderr)


    def test_selected_native_dependency_rollback_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'Cargo.toml'
        text = path.read_text()
        before = 'path = "vendor/secS-service-authority-d1ff595/server"'
        self.assertIn(before, text)
        path.write_text(text.replace(before, 'path = "vendor/secS-service-b/server"'))
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unconditional declaration: holder -> server', result.stdout + result.stderr)

    def test_binary_absolute_include_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'src/bin/unowned.rs'
        path.parent.mkdir(exist_ok=True)
        path.write_text('const BAD: &str = include_str!("/private/tmp/unowned.json");\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('absolute include', result.stdout + result.stderr)

    def test_resume_native_byte_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-authority-20d064d/server/src/service_authority_startup.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native resume sha256', result.stdout + result.stderr)

    def test_resume_native_extra_tamper_denies(self):
        root = self.fixture()
        (root / PACKAGE / 'vendor/secS-service-authority-20d064d/unreviewed.rs').write_text('// extra\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native resume inventory', result.stdout + result.stderr)

    def test_resume_native_manifest_tamper_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'vendor/secS-service-authority-20d064d.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native resume manifest', result.stdout + result.stderr)

    def test_bootstrap_dependency_rollback_denies(self):
        root = self.fixture()
        path = root / PACKAGE / 'Cargo.toml'
        text = path.read_text()
        before = 'path = "vendor/secS-service-authority-d1ff595/server"'
        self.assertIn(before, text)
        path.write_text(text.replace(before, 'path = "vendor/secS-service-authority-afeb6e6/server"'))
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unconditional declaration: holder -> server', result.stdout + result.stderr)


    def test_query_native_selection_reports_exact_committed_epoch(self):
        result = self.run_check(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['retained_query_native_commit'], 'eb8d839a805f64d9d1d0e280896d03f9b95239bc')
        self.assertEqual(report['retained_query_native_export'], str(PACKAGE / 'vendor/secS-service-authority-eb8d839'))
        self.assertFalse(report['production_qualified'])

    def test_query_native_byte_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-eb8d839/server/src/service_authority_startup.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native query sha256', result.stdout + result.stderr)

    def test_query_native_extra_file_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        (root / PACKAGE / 'vendor/secS-service-authority-eb8d839/unreviewed.rs').write_text('// extra\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native query inventory', result.stdout + result.stderr)

    def test_query_native_manifest_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-eb8d839.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native query manifest', result.stdout + result.stderr)

    def test_query_dependency_downgrade_to_resume20d_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'Cargo.toml'
        text = path.read_text()
        selected = 'path = "vendor/secS-service-authority-d1ff595/server"'
        self.assertIn(selected, text)
        path.write_text(text.replace(selected, 'path = "vendor/secS-service-authority-20d064d/server"'))
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unconditional declaration: holder -> server', result.stdout + result.stderr)


    def test_capacity_export_byte_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-a7100a7/server/src/service_challenge_store.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native capacity sha256', result.stdout + result.stderr)

    def test_capacity_export_extra_file_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        (root / PACKAGE / 'vendor/secS-service-authority-a7100a7/unreviewed.rs').write_text('// extra\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native capacity inventory', result.stdout + result.stderr)

    def test_capacity_export_sidecar_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-a7100a7.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native capacity manifest', result.stdout + result.stderr)

    def test_workspace_selection_reports_exact_qualified_commit(self):
        result = self.run_check(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['selected_native_commit'], 'd1ff595c214f68a6b1c8b763708d82d6c1eff620')
        self.assertEqual(report['selected_native_export'], str(PACKAGE / 'vendor/secS-service-authority-d1ff595'))
        self.assertFalse(report['production_qualified'])

    def test_setup_mixed_native_export_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / 'crates/castalia-wallet-local-review-setup/Cargo.toml'
        text = path.read_text()
        selected = '../castalia-wallet-service-holder/vendor/secS-service-authority-d1ff595/server'
        # This old selection is still correct in RED; GREEN selects the new one.
        if selected not in text:
            selected = '../castalia-wallet-service-holder/vendor/secS-service-authority-eb8d839/server'
        self.assertIn(selected, text)
        path.write_text(text.replace(selected, '../castalia-wallet-service-holder/vendor/secS-service-b/server'))
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unconditional declaration: setup -> server', result.stdout + result.stderr)

    def test_workspace_native_export_byte_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-d1ff595/server/src/service_authority.rs'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native current sha256', result.stdout + result.stderr)

    def test_workspace_native_export_mode_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-d1ff595/server/src/service_authority.rs'
        self.assertEqual(path.stat().st_mode & 0o7777, 0o644)
        path.chmod(0o755)
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native current mode', result.stdout + result.stderr)

    def test_workspace_native_export_sidecar_tamper_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / PACKAGE / 'vendor/secS-service-authority-d1ff595.source.json'
        path.write_bytes(path.read_bytes() + b'\n')
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('native current manifest', result.stdout + result.stderr)

    def test_workspace_setup_mixed_native_export_denies(self):
        root = self.fixture()
        self.assertEqual(self.run_check(root).returncode, 0)
        path = root / 'crates/castalia-wallet-workspace-setup/Cargo.toml'
        original = path.read_text()
        selected = '../castalia-wallet-service-holder/vendor/secS-service-authority-d1ff595/server'
        self.assertIn(selected, original)
        path.write_text(original.replace(selected, '../castalia-wallet-service-holder/vendor/secS-service-authority-a7100a7/server'))
        result = self.run_check(root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unconditional declaration: workspace setup -> server', result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main()
