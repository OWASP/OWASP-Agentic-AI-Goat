"""Controlled selector and receipt contracts; no database or model is started."""

import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
sys.path.insert(0, str(LAUNCHER.parent))
spec = importlib.util.spec_from_file_location('secureshop_transport_launcher', LAUNCHER)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def arguments(*extra):
    return launcher.parse([
        '--plan', '--main-workspace', str(ROOT), '--node', '/bin/true',
        '--docker', '/bin/true', '--docker-sha256', 'a' * 64,
        '--docker-host', 'unix:///controlled/docker.sock',
        '--docker-daemon', '01234567-89ab-cdef-0123-456789abcdef',
        '--image-id', 'sha256:' + 'b' * 64, *extra,
    ])


class LegacySupervisorLauncherContract(unittest.TestCase):
    def test_closed_selector(self):
        self.assertEqual(arguments('--legacy-supervisor-diagnostic', 'V14').legacy_supervisor_diagnostic, 'V14')
        self.assertEqual(arguments('--legacy-supervisor-diagnostic', 'V30').legacy_supervisor_diagnostic, 'V30')
        with self.assertRaises(SystemExit):
            arguments('--legacy-supervisor-diagnostic', 'V21')
        with self.assertRaises(ValueError):
            arguments('--legacy-supervisor-diagnostic', 'V14', '--legacy-supervisor-diagnostic', 'V30')

    def test_current_host_transport_and_exact_model_required(self):
        with self.assertRaisesRegex(RuntimeError, 'current-host transport cohort'):
            launcher.validate_static(arguments('--legacy-supervisor-diagnostic', 'V14'))
        with self.assertRaisesRegex(RuntimeError, 'current-host transport cohort'):
            launcher.validate_static(arguments('--cohort', 'vuln', '--current-host-profile', '/controlled/profile',
                '--legacy-supervisor-diagnostic', 'V30'))
        with self.assertRaisesRegex(RuntimeError, 'model digest'):
            launcher.validate_static(arguments('--current-host-profile', '/controlled/profile',
                '--legacy-supervisor-diagnostic', 'V30', '--ollama-model-sha256', '0' * 64))

    def test_capture_contract_remains_diagnostic_only(self):
        request = '{"model":"llama3.1:8b","messages":[]}'
        response = '{"message":{"content":"controlled"}}\n'
        wire = {'index': 1, 'kind': 'actor', 'request': request, 'response': response,
                'requestSha256': hashlib.sha256(request.encode()).hexdigest(),
                'responseSha256': hashlib.sha256(response.encode()).hexdigest()}
        model_pin = {'sha256': launcher.MAIL_INLINE_MODEL_SHA256}
        receipt = {'caseId': 'V30', 'status': 'incomplete', 'noProgressCredit': True,
                   'attempts': {'actor': 1, 'judge': 0},
                   'model': {'provider': 'ollama', 'modelId': launcher.OLLAMA_MODEL,
                             'digest': model_pin['sha256'], 'mocked': False},
                   'original': {'wireCalls': [wire]},
                   'diagnosticJudge': {'verdict': 'unreviewed'},
                   'gates': {'completed': False, 'progressCredit': False,
                             'semanticJudgment': False}}
        with tempfile.TemporaryDirectory(dir=ROOT, prefix='.legacy-diagnostic-contract-') as directory:
            target = Path(directory) / 'capture.json'
            def save(value):
                target.write_text(json.dumps({'caseId': 'V30', 'phase': 'complete', 'receipt': value}))
                target.chmod(0o600)
            save(receipt)
            self.assertEqual(launcher.legacy_supervisor_diagnostic_receipt(target, 'V30', model_pin), receipt)
            for bad in ({**receipt, 'gates': {**receipt['gates'], 'completed': True}},
                        {**receipt, 'attempts': {'actor': 0, 'judge': 0}},
                        {**receipt, 'model': {**receipt['model'], 'mocked': True}}):
                save(bad)
                with self.assertRaises(RuntimeError):
                    launcher.legacy_supervisor_diagnostic_receipt(target, 'V30', model_pin)
            eight = {**receipt, 'attempts': {'actor': 8, 'judge': 0},
                     'original': {'wireCalls': [{**wire, 'index': n} for n in range(1, 9)]}}
            save(eight)
            self.assertEqual(launcher.legacy_supervisor_diagnostic_receipt(target, 'V30', model_pin), eight)
            save({**eight, 'attempts': {'actor': 9, 'judge': 0}})
            with self.assertRaises(RuntimeError):
                launcher.legacy_supervisor_diagnostic_receipt(target, 'V30', model_pin)


if __name__ == '__main__':
    unittest.main()
