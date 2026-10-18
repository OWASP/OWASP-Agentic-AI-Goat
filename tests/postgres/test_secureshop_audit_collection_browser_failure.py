"""Controlled failure preservation checks; no native processes or model calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'v36_failure_adapter', Path(__file__).with_name('run-secureshop-audit-collection-browser.py'))
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class V36FailurePreservation(unittest.TestCase):
    def _main(self, directory, error):
        self.original_calls = []
        def popen(command, *args, **kwargs):
            self.original_calls.append((command, kwargs))
            return object()
        main = SimpleNamespace(
            subprocess=SimpleNamespace(Popen=popen),
            complete_tap_counts=lambda *args: None,
            admin_audit_jobs_receipt=lambda *args: None,
            ADMIN_AUDIT_JOBS_ASSERTION='original assertion')
        originals = (main.subprocess.Popen, main.complete_tap_counts, main.admin_audit_jobs_receipt)
        def execute(argv):
            main.subprocess.Popen(['controlled-node', L.TEST], env={
                'SECURESHOP_ADMIN_AUDIT_JOBS_BROWSER_EVIDENCE_PATH':
                    str(directory / 'admin-audit-jobs-browser.json')})
            raise error
        main.main = execute
        return main, originals

    def test_receipt_file_path_preserves_original_failure_and_supplement(self):
        primary = RuntimeError('original qualification failure')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            result = directory / 'result.json'
            result.write_text(json.dumps({'passed': False, 'errors': ['original']}))
            result.chmod(0o600)
            receipt = directory / 'admin-audit-jobs-browser.json'
            receipt.write_text(json.dumps({'passed': False, 'errors': ['fixture']}))
            receipt.chmod(0o600)
            originals_bytes = {p: p.read_bytes() for p in (result, receipt)}
            main, hooks = self._main(directory, primary)
            before = {'fixture': 'a' * 64}
            after = {'fixture': 'b' * 64}
            with patch.object(L, 'frozen_source_digests', return_value=after):
                with self.assertRaises(RuntimeError) as raised:
                    L.run(main, [], before)
            self.assertIs(raised.exception, primary)
            for path, raw in originals_bytes.items():
                self.assertEqual(path.read_bytes(), raw)
            report_path = directory / 'v36-adapter-report.json'
            report = json.loads(report_path.read_text())
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(report['adapterPassed'])
            self.assertEqual(report['sourceBefore'], before)
            self.assertEqual(report['sourceAfter'], after)
            self.assertFalse(report['sourceUnchanged'])
            self.assertEqual(report['modelVerification']['status'], 'unverified')
            self.assertEqual(report['mainResultSha256'], hashlib.sha256(originals_bytes[result]).hexdigest())
            self.assertEqual((main.subprocess.Popen, main.complete_tap_counts,
                              main.admin_audit_jobs_receipt), hooks)
            env = self.original_calls[0][1]['env']
            self.assertEqual(env['SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE'], '1')
            self.assertEqual(env['OLLAMA_CONTEXT_WINDOW'], '32768')

    def test_supplement_failure_cannot_replace_original_exception(self):
        primary = RuntimeError('original qualification failure')
        with tempfile.TemporaryDirectory() as temporary:
            main, hooks = self._main(Path(temporary), primary)
            with patch.object(L, 'frozen_source_digests', side_effect=OSError('controlled aftercheck failure')):
                with self.assertRaises(RuntimeError) as raised:
                    L.run(main, [], {'fixture': 'a' * 64})
            self.assertIs(raised.exception, primary)
            self.assertEqual((main.subprocess.Popen, main.complete_tap_counts,
                              main.admin_audit_jobs_receipt), hooks)

    def test_outer_source_drift_cannot_replace_original_exception(self):
        primary = RuntimeError('original qualification failure')
        main = SimpleNamespace(parse=lambda argv: SimpleNamespace(plan=False))
        with patch.object(L, 'validate_frozen_sources'), \
                patch.object(L, 'load_main', return_value=main), \
                patch.object(L, 'frozen_source_digests', side_effect=[{'fixture': 'before'}, {'fixture': 'after'}]), \
                patch.object(L, 'run', side_effect=primary):
            with self.assertRaises(RuntimeError) as raised:
                L.main(['--cohort', L.COHORT])
        self.assertIs(raised.exception, primary)


if __name__ == '__main__':
    unittest.main()
