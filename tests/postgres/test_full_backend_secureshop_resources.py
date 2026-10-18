"""Offline tests for SecureShop read-only qualification resources."""
import errno
import hashlib
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import full_backend_secureshop_resources as resources


MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'


class Response:
    def __init__(self, payload, status=200):
        self.payload, self.status = payload, status

    def read(self, maximum):
        return self.payload[:maximum]


class Connection:
    def __init__(self, payload, status=200):
        self.response = Response(payload, status)
        self.requested = None
        self.closed = False

    def request(self, method, path):
        self.requested = (method, path)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class RejectedReservation:
    def __init__(self):
        self.closed = False

    def bind(self, endpoint):
        self.endpoint = endpoint

    def getsockname(self):
        return ('127.0.0.1', 8082)

    def close(self):
        self.closed = True


def model_payload(digest=MODEL_DIGEST):
    return json.dumps({'models': [{'name': 'llama3.1:8b', 'digest': digest}]}).encode()


class RendererFixture:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / 'source'
        self.evidence = self.root / 'evidence'
        self.renderer = self.root / 'renderer'
        source_file = self.source / resources.RENDERER_SOURCE
        source_file.parent.mkdir(parents=True)
        source_file.write_bytes(b'export default function ReviewCard() {}\n')
        self.evidence.mkdir(mode=0o700)
        self.renderer.mkdir()
        artifact = self.renderer / 'renderer.cjs'
        artifact.write_bytes(b"'use strict';module.exports={};\n")
        manifest = {
            'version': 1, 'component': 'SecureShop.ReviewCard',
            'source': resources.RENDERER_SOURCE,
            'sourceSha256': hashlib.sha256(source_file.read_bytes()).hexdigest(),
            'artifact': artifact.name,
            'artifactSha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }
        (self.renderer / 'manifest.json').write_text(json.dumps(manifest) + '\n')
        self.manifest_sha256 = hashlib.sha256(
            (self.renderer / 'manifest.json').read_bytes()).hexdigest()
        for path in self.source.rglob('*'):
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
        os.chmod(self.source, 0o555)
        for path in self.renderer.iterdir():
            os.chmod(path, 0o444)
        os.chmod(self.renderer, 0o555)

    def close(self):
        for base in (self.source, self.renderer):
            if base.exists():
                os.chmod(base, 0o755)
                for path in base.rglob('*'):
                    try:
                        os.chmod(path, 0o755 if path.is_dir() else 0o644)
                    except FileNotFoundError:
                        pass
        self.temporary.cleanup()


class RendererValidationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RendererFixture()

    def tearDown(self):
        self.fixture.close()

    def validate(self):
        return resources.validate_renderer_bundle(
            source=self.fixture.source, evidence=self.fixture.evidence,
            renderer_root=self.fixture.renderer,
            manifest_sha256=self.fixture.manifest_sha256)

    def test_exact_readonly_renderer_bundle_is_bound_to_frozen_source(self):
        result = self.validate()
        self.assertEqual(result['artifact'], 'renderer.cjs')
        self.assertEqual(result['manifestSha256'], self.fixture.manifest_sha256)

    def test_writable_extra_and_corrupted_renderer_material_fail_closed(self):
        artifact = self.fixture.renderer / 'renderer.cjs'
        os.chmod(artifact, 0o644)
        with self.assertRaises(RuntimeError):
            self.validate()
        os.chmod(artifact, 0o444)
        os.chmod(self.fixture.renderer, 0o755)
        extra = self.fixture.renderer / 'extra.js'
        extra.write_text('extra')
        os.chmod(extra, 0o444)
        os.chmod(self.fixture.renderer, 0o555)
        with self.assertRaises(RuntimeError):
            self.validate()
        os.chmod(self.fixture.renderer, 0o755)
        extra.unlink()
        os.chmod(artifact, 0o644)
        artifact.write_text('corrupted')
        os.chmod(artifact, 0o444)
        os.chmod(self.fixture.renderer, 0o555)
        with self.assertRaises(RuntimeError):
            self.validate()


class ModelInventoryTests(unittest.TestCase):
    def test_bounded_inventory_requires_one_exact_model_and_closes_connection(self):
        created = []
        def factory(host, port, timeout):
            self.assertEqual((host, port, timeout), ('127.0.0.1', 11434, 10))
            value = Connection(model_payload())
            created.append(value)
            return value
        self.assertEqual(resources.inventory_model(
            MODEL_DIGEST, connection_factory=factory)['digest'], MODEL_DIGEST)
        self.assertEqual(created[0].requested, ('GET', '/api/tags'))
        self.assertTrue(created[0].closed)
        for payload, status in [
            (model_payload('a' * 64), 200),
            (json.dumps({'models': [
                {'name': 'llama3.1:8b', 'digest': MODEL_DIGEST},
                {'name': 'llama3.1:8b', 'digest': MODEL_DIGEST},
            ]}).encode(), 200),
            (b'{}', 200),
            (b'x' * (resources.MODEL_RESPONSE_LIMIT + 1), 200),
            (model_payload(), 503),
        ]:
            connection = Connection(payload, status)
            with self.subTest(status=status, size=len(payload)), self.assertRaises(RuntimeError):
                resources.inventory_model(
                    MODEL_DIGEST,
                    connection_factory=lambda *_args, value=connection, **_kwargs: value)
            self.assertTrue(connection.closed)


class ResourceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = RendererFixture()

    def tearDown(self):
        self.fixture.close()

    def make_resources(self, records, payloads=None):
        queue = list(payloads or [model_payload(), model_payload()])
        def factory(*_args, **_kwargs):
            return Connection(queue.pop(0))
        return resources.FullBackendSecureShopResources(
            record=lambda name, value: records.append((name, value)),
            source=self.fixture.source, evidence=self.fixture.evidence,
            renderer_root=self.fixture.renderer,
            renderer_manifest_sha256=self.fixture.manifest_sha256,
            model_digest=MODEL_DIGEST, connection_factory=factory,
            assert_processes_absent=lambda: None)

    def test_port_is_reserved_then_released_and_cleanup_is_receipted(self):
        records = []
        owned = self.make_resources(records)
        manifest = owned.prepare(34101)
        port = manifest['agentHost']['port']
        self.assertEqual(manifest['fixtures'], [])
        self.assertNotIn(port, {34101, 5432, 8081, 8082, 11434})
        contender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(OSError):
                contender.bind(('127.0.0.1', port))
        finally:
            contender.close()
        self.assertEqual(owned.release_for_launch(), port)
        available = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        available.bind(('127.0.0.1', port))
        available.close()
        receipt = owned.cleanup()
        self.assertEqual(receipt['status'], 'verified')
        self.assertTrue(receipt['portAbsenceVerified'])
        self.assertTrue(receipt['modelPostflight'])
        self.assertTrue(receipt['rendererPostflight'])
        self.assertEqual([name for name, _value in records], [
            'secureshop-resources.json', 'secureshop-agent-port.json',
            'secureshop-resources-cleanup.json'])

    def test_cleanup_reports_postflight_model_failure_after_releasing_port(self):
        records = []
        owned = self.make_resources(records, [model_payload(), model_payload('a' * 64)])
        owned.prepare(34101)
        owned.release_for_launch()
        with self.assertRaises(RuntimeError):
            owned.cleanup()
        name, receipt = records[-1]
        self.assertEqual(name, 'secureshop-resources-cleanup.json')
        self.assertEqual(receipt['status'], 'cleanup_unverified')
        self.assertIn('model_postflight', receipt['failures'])
        self.assertTrue(receipt['portAbsenceVerified'])

    def test_port_reservation_attempts_are_bounded_and_every_rejection_is_closed(self):
        records, reservations = [], []
        def socket_factory(*_args):
            value = RejectedReservation()
            reservations.append(value)
            return value
        owned = resources.FullBackendSecureShopResources(
            record=lambda name, value: records.append((name, value)),
            source=self.fixture.source, evidence=self.fixture.evidence,
            renderer_root=self.fixture.renderer,
            renderer_manifest_sha256=self.fixture.manifest_sha256,
            model_digest=MODEL_DIGEST,
            connection_factory=lambda *_args, **_kwargs: Connection(model_payload()),
            socket_factory=socket_factory)
        with self.assertRaisesRegex(RuntimeError, 'reservation exhausted'):
            owned.prepare(34101)
        self.assertEqual(len(reservations), resources.PORT_RESERVATION_ATTEMPTS)
        self.assertTrue(all(value.closed for value in reservations))
        self.assertFalse(owned.prepared)
        with self.assertRaises(RuntimeError):
            owned.cleanup()
        receipt = records[-1][1]
        self.assertIn('prepare_incomplete', receipt['failures'])
        self.assertFalse(receipt['qualificationPrepared'])

    def test_failed_initial_model_check_cannot_emit_verified_cleanup(self):
        records = []
        owned = self.make_resources(records, [model_payload('a' * 64)])
        with self.assertRaises(RuntimeError):
            owned.prepare(34101)
        with self.assertRaises(RuntimeError):
            owned.cleanup()
        receipt = records[-1][1]
        self.assertEqual(receipt['status'], 'cleanup_unverified')
        self.assertIn('prepare_incomplete', receipt['failures'])
        self.assertIn('model_not_checked', receipt['failures'])
        self.assertFalse(receipt['modelPostflight'])
        self.assertFalse(receipt['qualificationPrepared'])

    def test_port_bind_errors_retain_errno_and_type_without_messages(self):
        for error in [OSError(errno.EADDRINUSE, 'private controlled detail'),
                      PermissionError(errno.EACCES, 'private controlled detail'),
                      RuntimeError('private controlled detail')]:
            with self.subTest(error=type(error).__name__):
                records = []
                owned = self.make_resources(records)
                owned.prepared = True
                owned.model_checked = True
                owned.renderer = owned._validate_renderer()
                owned.agent_port = 34102
                class Probe:
                    closed = False
                    def bind(self, endpoint):
                        self.endpoint = endpoint
                        raise error
                    def close(self): self.closed = True
                probe = Probe()
                owned.socket_factory = lambda *_args: probe
                now=[0.0]
                owned.monotonic=lambda:now[0]
                owned.sleep=lambda seconds:now.__setitem__(0,now[0]+seconds)
                with self.assertRaisesRegex(RuntimeError, 'agent_port_postflight'):
                    owned.cleanup()
                receipt = records[-1][1]
                self.assertEqual(receipt['status'], 'cleanup_unverified')
                self.assertFalse(receipt['portAbsenceVerified'])
                self.assertEqual(receipt['failures'], ['agent_port_postflight'])
                self.assertEqual(receipt['agentPortError'], {
                    'errorType': type(error).__name__,
                    'errno': error.errno if isinstance(error, OSError) else None})
                self.assertNotIn('private controlled detail', json.dumps(receipt))
                self.assertTrue(probe.closed)
                self.assertEqual(probe.endpoint, ('127.0.0.1', 34102))

    def test_module_import_performs_no_http_or_socket_action(self):
        path = Path(resources.__file__)
        import importlib.util
        spec = importlib.util.spec_from_file_location('inert_secureshop_resources', path)
        module = importlib.util.module_from_spec(spec)
        with patch('http.client.HTTPConnection') as http_connection, \
             patch('socket.socket') as socket_factory:
            spec.loader.exec_module(module)
        http_connection.assert_not_called()
        socket_factory.assert_not_called()




class ReleaseWait(unittest.TestCase):
    def run_wait(self, errors, absent_error=None, close_error=False):
        now=[0.0];probes=[];checks=[];sleeps=[]
        class Probe:
            def __init__(self,index):self.index=index;self.closed=False
            def bind(self,endpoint):
                self.endpoint=endpoint
                error=errors[min(self.index,len(errors)-1)]
                if error:raise error
            def getsockname(self):return self.endpoint
            def close(self):
                self.closed=True
                if close_error:raise RuntimeError('close failure')
            def setsockopt(self,*args):raise AssertionError('Reuse options forbidden')
        def factory(*args):
            p=Probe(len(probes));probes.append(p);return p
        def absent():
            checks.append(True)
            if absent_error:raise absent_error
        def sleep(seconds):sleeps.append(seconds);now[0]+=seconds
        result=resources.wait_for_agent_port_release(34102,assert_processes_absent=absent,
            socket_factory=factory,monotonic=lambda:now[0],sleep=sleep)
        self.assertTrue(all(p.closed for p in probes))
        return result,probes,checks,sleeps
    def test_address_in_use_then_success_preserves_initial_error(self):
        result,probes,checks,sleeps=self.run_wait([OSError(errno.EADDRINUSE,'occupied'),None])
        self.assertTrue(result['portAbsenceVerified']);self.assertEqual(result['failures'],[])
        self.assertEqual(result['agentPortInitialError']['errno'],errno.EADDRINUSE)
        self.assertEqual(result['agentPortError']['errno'],errno.EADDRINUSE)
        self.assertEqual(len(probes),2);self.assertEqual(len(checks),2);self.assertEqual(sleeps,[.5])
    def test_persistent_occupant_is_bounded_and_never_accepted(self):
        result,probes,checks,sleeps=self.run_wait([OSError(errno.EADDRINUSE,'occupied')])
        self.assertFalse(result['portAbsenceVerified']);self.assertEqual(sum(sleeps),60)
        self.assertLessEqual(len(probes),121);self.assertEqual(len(checks),len(probes))
        self.assertEqual(result['agentPortElapsedMs'],60000)
    def test_other_errors_and_close_failure_abort_without_retry(self):
        for error in [PermissionError(errno.EACCES,'denied'),RuntimeError('bad')]:
            result,probes,checks,sleeps=self.run_wait([error]);self.assertEqual(len(probes),1);self.assertEqual(sleeps,[]);self.assertFalse(result['portAbsenceVerified'])
        result,probes,checks,sleeps=self.run_wait([None],close_error=True)
        self.assertIn('agent_port_probe_close',result['failures']);self.assertFalse(result['portAbsenceVerified']);self.assertEqual(sleeps,[])
    def test_ownership_failure_prevents_socket_creation(self):
        result,probes,checks,sleeps=self.run_wait([None],absent_error=RuntimeError('present'))
        self.assertEqual(probes,[]);self.assertEqual(sleeps,[]);self.assertIn('agent_process_absence',result['failures'])

class SlowAbsenceDeadline(unittest.TestCase):
    def test_slow_absence_check_cannot_open_socket_after_deadline(self):
        now=[0.0]
        def absence():now[0]=60.1
        with patch('socket.socket') as factory:
            result=resources.wait_for_agent_port_release(34102,
                assert_processes_absent=absence,socket_factory=factory,
                monotonic=lambda:now[0],sleep=lambda _:self.fail('No sleep after deadline'))
        factory.assert_not_called()
        self.assertFalse(result['portAbsenceVerified'])
        self.assertIn('agent_port_deadline',result['failures'])
        self.assertEqual(result['agentPortAttemptCount'],1)

if __name__ == '__main__':
    unittest.main()
