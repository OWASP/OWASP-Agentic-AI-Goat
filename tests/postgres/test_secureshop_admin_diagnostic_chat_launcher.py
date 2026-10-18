"""Resource-free admission checks for the owned System diagnostic chat cohort."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
sys.path.insert(0, str(LAUNCHER.parent))
SPEC = importlib.util.spec_from_file_location('admin_diagnostic_launcher', LAUNCHER)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def private_json(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


class AdminDiagnosticChatLauncherTest(unittest.TestCase):
    def test_frozen_fixture_and_current_main_admission(self):
        self.assertEqual(launcher.digest(ROOT / launcher.ADMIN_DIAGNOSTIC_CHAT_TEST),
                         launcher.ADMIN_DIAGNOSTIC_CHAT_TEST_SHA256)
        self.assertEqual(launcher.digest(ROOT / launcher.ADMIN_DIAGNOSTIC_CHAT_CONTRACT),
                         launcher.ADMIN_DIAGNOSTIC_CHAT_CONTRACT_SHA256)
        source = LAUNCHER.read_text()
        self.assertIn("ADMIN_DIAGNOSTIC_CHAT_TEST if cohort == 'admin-system-diagnostic-chat-browser'", source)
        self.assertIn("files.update((ADMIN_DIAGNOSTIC_CHAT_CONTRACT,", source)
        self.assertIn("'admin-system-diagnostic-chat-browser-process.json'", source)
        self.assertIn("'admin-system-diagnostic-chat-browser.json'", source)
        self.assertIn("'admin_system_diagnostic_chat_browser'", source)

    def test_closed_receipt_and_boolean_count_rejection(self):
        value = {flag: True for flag in launcher.ADMIN_DIAGNOSTIC_CHAT_FLAGS}
        value.update(scope=launcher.ADMIN_DIAGNOSTIC_CHAT_SCOPE, actorCalls=4,
                     roleTurns=2, judgeCalls=0, executorCalls=1, errors=[])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'receipt.json'
            private_json(target, value)
            self.assertEqual(launcher.admin_diagnostic_chat_receipt(target), value)
            for field, invalid in [('actorCalls', 15), ('judgeCalls', False),
                                   ('executorCalls', 0), ('roleTurns', True), ('errors', ['x'])]:
                altered = {**value, field: invalid}
                private_json(target, altered)
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    launcher.admin_diagnostic_chat_receipt(target)

    def test_original_wire_and_narrow_completed_sse_cancellation(self):
        calls = []
        for ordinal in range(1, 5):
            request = json.dumps({'model': launcher.OLLAMA_MODEL, 'messages': []})
            response = json.dumps({'message': {'content': 'observed'}})
            calls.append(dict(ordinal=ordinal, requestSha256=sha(request), requestBody=request,
                              responseSha256=sha(response), responseBody=response))
        request = '{}'
        response = '{"status":"completed"}'
        session = '5503f11e-e102-4763-bab0-37a526c0a241'
        first = f'/agents/admin/assistant/operations/{session}/445a6f90-a2fb-40a2-b710-10ec3ae62e1c'
        fixed = f'/agents/admin/assistant/operations/{session}/e4a7c1fc-047a-445c-a1a4-d462acc5426b'
        wire = dict(version=1, model=launcher.OLLAMA_MODEL, modelDigest='a' * 64,
                    calls=calls, executor=[dict(method='POST', path='/secureshop/system/diagnostic',
                    status=200, requestBody=request, responseBody=response,
                    bytes=len(response.encode()), responseSha256=sha(response))],
                    requests=[dict(method='POST', path='/agents/admin/assistant/chat', status=200),
                              dict(method='GET', path=first, status=200),
                              dict(method='POST', path='/agents/admin/assistant/chat', status=200)] + [
                              dict(method='GET', path=fixed, status=200) for _ in range(3)] + [
                              dict(method='POST', path='/agents/admin/assistant/system/diagnostic/confirm', status=status)
                              for status in (503, 403)], pageErrors=[],
                    requestFailures=[dict(method='POST', path='/api/secureshop/agents/admin/assistant/chat',
                                          error='net::ERR_ABORTED')] + [
                        dict(method='GET', path='/api/secureshop/products', error='net::ERR_ABORTED')
                        for _ in range(3)] + [
                        dict(method='GET', path='/api/secureshop/admin/system/restart', error='net::ERR_ABORTED'),
                        dict(method='GET', path='/api/secureshop/admin/db-sizes', error='net::ERR_ABORTED'),
                        dict(method='GET', path='/api/secureshop' + fixed, error='net::ERR_ABORTED')])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'wire.json'
            private_json(target, wire)
            launcher.admin_diagnostic_chat_wire(target, {'actorCalls': 4, 'roleTurns': 2,
                'executorCalls': 1}, 'a' * 64)
            def excess_product_cancellations(value):
                value['requestFailures'].extend([
                    dict(method='GET', path='/api/secureshop/products', error='net::ERR_ABORTED')
                    for _ in range(2)])
            def lose_fixed_source_proof(value):
                value['requests'][3]['status'] = 503
                value['requests'][4]['status'] = 503
            for mutation in (lambda w: w['calls'][0].update(requestSha256='0' * 64),
                             lambda w: w['executor'][0].update(responseSha256='0' * 64),
                             lambda w: w['requestFailures'][0].update(error='net::ERR_FAILED'),
                             lambda w: w['requestFailures'][-1].update(path='/api/secureshop' + first),
                             lambda w: w['requestFailures'][-1].update(path='/api/secureshop/agents/admin/assistant/system/diagnostic/confirm/' + session + '/e4a7c1fc-047a-445c-a1a4-d462acc5426b/ce774de0-568e-5f6b-81ef-bbefe5697ea4'),
                             lose_fixed_source_proof,
                             lambda w: w['requestFailures'][-2].update(path='/api/secureshop/admin/overview/kpis'),
                             excess_product_cancellations,
                             lambda w: w['requests'][-1].update(status=200)):
                altered = json.loads(json.dumps(wire))
                mutation(altered)
                private_json(target, altered)
                with self.assertRaises(RuntimeError):
                    launcher.admin_diagnostic_chat_wire(target, {'actorCalls': 4,
                        'roleTurns': 2, 'executorCalls': 1}, 'a' * 64)

    def test_partial_start_identity_capture_rejects_replacement(self):
        owner = 'test-owner'
        class FakeExecutor:
            name = 'owned-container'
            network = 'owned-network'
            tag = 'owned-image'
            def inspect(self, kind, name):
                identity = 'a' * 64
                if kind == 'container':
                    return {'Id': identity, 'Name': '/' + name,
                            'Config': {'Labels': {'dvaia.test.owner': owner}}}
                if kind == 'network':
                    return {'Id': identity, 'Name': name,
                            'Labels': {'dvaia.test.owner': owner}}
                return {'Id': 'sha256:' + identity,
                        'Config': {'Labels': {'dvaia.test.owner': owner}}}
        with tempfile.TemporaryDirectory() as directory:
            executor = FakeExecutor()
            ids = launcher.capture_owned_diagnostic_ids(executor, owner, Path(directory))
            executor.inspect('container', executor.name)
            executor.inspect('network', executor.network)
            executor.inspect('image', executor.tag)
            self.assertEqual(set(ids), {'container', 'network', 'image'})
            self.assertEqual(json.loads((Path(directory) / 'owned-diagnostic-executor-ids.json').read_text()), ids)
            def replaced(kind, name):
                if kind == 'container':
                    return {'Id': 'b' * 64, 'Name': '/' + name,
                            'Config': {'Labels': {'dvaia.test.owner': owner}}}
                return FakeExecutor.inspect(executor, kind, name)
            executor.inspect = replaced
            successor = launcher.capture_owned_diagnostic_ids(executor, owner, Path(directory))
            successor['container'] = 'a' * 64
            with self.assertRaises(RuntimeError):
                executor.inspect('container', executor.name)


if __name__ == '__main__':
    unittest.main()
