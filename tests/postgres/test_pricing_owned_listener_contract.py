import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LISTENER_SPEC = importlib.util.spec_from_file_location(
    'pricing_listener', ROOT / 'tests/postgres/pricing_owned_listener.py'
)
listener_module = importlib.util.module_from_spec(LISTENER_SPEC)
LISTENER_SPEC.loader.exec_module(listener_module)


class PricingListenerPublication(unittest.TestCase):
    def make_listener(self, evidence, qualification_mode):
        listener = listener_module.PricingOwnedListener.__new__(listener_module.PricingOwnedListener)
        listener.qualification_mode = qualification_mode
        listener.evidence = Path(evidence)
        listener.state = {}
        listener.save = lambda: None
        return listener

    def workspace_id(self):
        return subprocess.run(
            [
                'node', '-e',
                "process.stdout.write(require('./scripts/application-data-root').workspaceId(process.cwd()))",
            ], cwd=ROOT, check=True, capture_output=True, text=True
        ).stdout

    def valid_managed_record(self):
        workspace_id = self.workspace_id()
        return {
            'version': 1,
            'enabled': True,
            'workspaceId': workspace_id,
            'ownerId': '10000000-0000-4000-8000-000000000001',
            'dockerAuthoritySha256': 'a' * 64,
            'containerName': 'dvaia-pricing-' + workspace_id,
            'containerId': 'b' * 64,
            'imageId': 'sha256:' + 'c' * 64,
            'packageSha256': 'd' * 64,
            'profile': 'dvaia-owned-pricing-http-' + workspace_id,
            'port': 18093,
            'token': 'e' * 43,
        }

    def validate_managed_record(self, record):
        result = subprocess.run(
            [
                'node', '-e',
                "const c=require('./server/services/secureshopPricingManagedConfiguration');"
                "const value=JSON.parse(process.argv[1]);"
                "process.stdout.write(JSON.stringify(c.validate(value,{root:process.cwd()})));",
                json.dumps(record),
            ], cwd=ROOT, check=True, capture_output=True, text=True
        )
        return json.loads(result.stdout)

    def test_legacy_writes_loadable_managed_record_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            listener = self.make_listener(temporary, False)
            directory = Path(temporary) / 'private'
            directory.mkdir()
            record = self.valid_managed_record()
            published = listener.publish_config(directory, record, {})
            managed = directory / 'pricing-managed.json'
            self.assertEqual(published, {})
            self.assertEqual(json.loads(managed.read_text()), record)
            self.assertEqual(self.validate_managed_record(json.loads(managed.read_text())), record)
            self.assertFalse((Path(temporary) / 'pricing-listener-descriptor.json').exists())

    def test_nonce_writes_hashed_descriptor_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            listener = self.make_listener(temporary, True)
            directory = Path(temporary) / 'private'
            directory.mkdir()
            workspace_id = self.workspace_id()
            descriptor = {
                'version': 1,
                'ownerId': '10000000-0000-4000-8000-000000000001',
                'workspaceId': workspace_id,
                'qualificationNonce': 'b' * 12,
                'containerId': 'c' * 64,
                'imageId': 'sha256:' + 'd' * 64,
                'packageSha256': 'e' * 64,
                'profile': 'dvaia-owned-pricing-http-' + 'b' * 12,
                'origin': 'http://127.0.0.1:18093',
                'token': 'f' * 43,
            }
            published = listener.publish_config(directory, {}, descriptor)
            descriptor_path = Path(published['SECURESHOP_STANDALONE_PRICING_DESCRIPTOR'])
            self.assertTrue(descriptor_path.is_file())
            self.assertEqual(
                published['SECURESHOP_STANDALONE_PRICING_DESCRIPTOR_SHA256'],
                listener.state['descriptorSha256'],
            )
            self.assertEqual(json.loads(descriptor_path.read_text()), descriptor)
            self.assertFalse((directory / 'pricing-managed.json').exists())


if __name__ == '__main__':
    unittest.main()
