import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/postgres'))
RUNNER = ROOT / 'tests/postgres/run-secureshop-bound-review-composition-isolated.py'
VARIANT = 'manual-similarity-mismatch-v1'

class VariantContract(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('v26_mismatch_launcher', RUNNER)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.base = ['--docker-host','unix:///unused','--docker-cli','/unused/docker',
                     '--docker-cli-sha256','0'*64,'--node','/unused/node','--node-sha256','1'*64,
                     '--suite','manual-rag-paired-browser','--main-checkout','--current-host-profile','/owned/profile']

    def test_exact_paired_selection_and_default(self):
        self.assertIsNone(self.module.parse_args(self.base).manual_rag_payload_variant)
        args = self.module.parse_args(self.base + ['--manual-rag-payload-variant',VARIANT])
        self.module.validate_current_host_selection(args)
        self.assertEqual(self.module.variant_attempt_path(ROOT,VARIANT).name,'v26-'+VARIANT+'-attempt.json')
        for patch in ({'suite':'manual-rag-browser'},{'suite':'manual-rag-fixed-browser'},
                      {'main_checkout':False},{'current_host_profile':None},{'manual_rag_payload_variant':'unknown'}):
            bad=copy.copy(args)
            for key,value in patch.items(): setattr(bad,key,value)
            with self.assertRaisesRegex(RuntimeError,'Payload variant requires'):
                self.module.validate_current_host_selection(bad)
        with self.assertRaises(RuntimeError): self.module.variant_attempt_path(ROOT,'unknown')

    def test_both_fixture_pins_are_actual(self):
        actual=hashlib.sha256((ROOT/'tests/postgres/secureshopManualRagRendered.integration.test.js').read_bytes()).hexdigest()
        self.assertEqual(self.module.MANUAL_RAG_BROWSER_TEST_SHA256,actual)
        self.assertEqual(self.module.MANUAL_RAG_PAIRED_TEST_SHA256,actual)

if __name__ == '__main__': unittest.main()
