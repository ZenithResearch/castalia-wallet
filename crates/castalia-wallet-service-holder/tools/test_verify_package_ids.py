"""Adversarial checks mutate actual locked Cargo metadata, never invent a passing graph."""
import copy
from pathlib import Path
import unittest
import verify_package_ids as verifier

ROOT = Path(__file__).resolve().parents[3]

class PackageIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = verifier.run_metadata(ROOT)

    def check_mutation(self, mutate, phrase):
        metadata = copy.deepcopy(self.actual)
        mutate(metadata)
        self.assertTrue(any(phrase in error for error in verifier.check_metadata(ROOT, metadata)))

    def test_actual_locked_offline_graph_passes(self):
        self.assertEqual(verifier.check_metadata(ROOT, self.actual), [])

    def test_optional_default_enabled_holder_server_denies(self):
        def mutate(data):
            holder = next(p for p in data['packages'] if p['name'] == 'castalia-wallet-service-holder')
            next(d for d in holder['dependencies'] if d['name'] == 'server')['optional'] = True
            holder['features']['default'] = ['dep:server']
        self.check_mutation(mutate, 'unconditional declaration')

    def test_optional_default_enabled_server_FS_denies(self):
        def mutate(data):
            server = next(p for p in data['packages'] if p['name'] == 'server')
            next(d for d in server['dependencies'] if d['name'] == 'castalia-wallet-private-files')['optional'] = True
            server['features']['default'] = ['dep:castalia-wallet-private-files']
        self.check_mutation(mutate, 'unconditional declaration')

    def test_targeted_server_FS_denies(self):
        def mutate(data):
            server = next(p for p in data['packages'] if p['name'] == 'server')
            next(d for d in server['dependencies'] if d['name'] == 'castalia-wallet-private-files')['target'] = 'cfg(unix)'
        self.check_mutation(mutate, 'unconditional declaration')

    def test_aliased_holder_server_denies(self):
        def mutate(data):
            holder = next(p for p in data['packages'] if p['name'] == 'castalia-wallet-service-holder')
            next(d for d in holder['dependencies'] if d['name'] == 'server')['rename'] = 'other_server'
        self.check_mutation(mutate, 'unconditional declaration')

    def test_extra_server_declaration_denies(self):
        def mutate(data):
            holder = next(p for p in data['packages'] if p['name'] == 'castalia-wallet-service-holder')
            duplicate = copy.deepcopy(next(d for d in holder['dependencies'] if d['name'] == 'server'))
            duplicate['kind'] = 'dev'
            holder['dependencies'].append(duplicate)
        self.check_mutation(mutate, 'unconditional declaration')

    def test_generic_FS_manifest_denies(self):
        def mutate(data):
            next(p for p in data['packages'] if p['name'] == 'castalia-wallet-private-files')['manifest_path'] = str(ROOT / 'crates/castalia-wallet-private-files/Cargo.toml')
        self.check_mutation(mutate, 'wrong canonical manifest')

    def test_second_FS_package_ID_denies(self):
        def mutate(data):
            package = copy.deepcopy(next(p for p in data['packages'] if p['name'] == 'castalia-wallet-private-files'))
            package['id'] += '-second-source'
            data['packages'].append(package)
        self.check_mutation(mutate, 'expected exactly one castalia-wallet-private-files')

    def test_missing_server_FS_edge_denies(self):
        def mutate(data):
            server = next(p['id'] for p in data['packages'] if p['name'] == 'server')
            fs = next(p['id'] for p in data['packages'] if p['name'] == 'castalia-wallet-private-files')
            next(p for p in data['resolve']['nodes'] if p['id'] == server)['dependencies'].remove(fs)
        self.check_mutation(mutate, 'do not share the exact FS package ID')

    def test_server_to_holder_cycle_denies(self):
        def mutate(data):
            server = next(p['id'] for p in data['packages'] if p['name'] == 'server')
            holder = next(p['id'] for p in data['packages'] if p['name'] == 'castalia-wallet-service-holder')
            next(p for p in data['resolve']['nodes'] if p['id'] == server)['dependencies'].append(holder)
        self.check_mutation(mutate, 'server reaches holder')

    def test_extra_generic_local_package_denies(self):
        def mutate(data):
            data['packages'].append({'name':'castalia-wallet-core', 'id':'unexpected-local-wallet-core', 'source':None, 'manifest_path':str(ROOT / 'crates/castalia-wallet-core/Cargo.toml')})
        self.check_mutation(mutate, 'unexpected local package')

    def test_duplicate_package_ID_denies(self):
        self.check_mutation(lambda data: data['packages'].append(copy.deepcopy(data['packages'][0])), 'duplicate package ID')

if __name__ == '__main__':
    unittest.main()
