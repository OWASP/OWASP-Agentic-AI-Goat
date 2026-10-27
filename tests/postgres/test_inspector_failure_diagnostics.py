"""Controlled inspector diagnostics; no process roster, Docker or model calls."""
import os
import socket
import threading
import unittest
from unittest import mock

import trusted_process_inspector as inspector
from run_bound_review_with_inspector import inspection_failure_diagnostic


class InspectorDiagnosticTests(unittest.TestCase):
    def test_fixed_categories_never_include_messages(self):
        for error, category in ((RuntimeError('/secret'), 'validation'),
                                (PermissionError('/private'), 'permission'),
                                (TimeoutError('credential'), 'timeout')):
            self.assertEqual(inspection_failure_diagnostic('scope', error),
                             'INSPECTOR_FAILURE:scope:' + category)

    def test_hostile_exception_callbacks_never_called(self):
        class Hostile(RuntimeError):
            def __getattribute__(self, key): raise AssertionError('attribute callback')
            def __str__(self): raise AssertionError('render callback')
            def __repr__(self): raise AssertionError('repr callback')
        self.assertEqual(inspection_failure_diagnostic('process-inventory', Hostile()),
                         'INSPECTOR_FAILURE:process-inventory:other')

    def test_untrusted_stage_denied_without_callback(self):
        class Hostile(str):
            def __eq__(self, other): raise AssertionError('comparison callback')
        for stage in ('/secret/path', Hostile('scope'), None):
            self.assertEqual(inspection_failure_diagnostic(stage, RuntimeError()),
                             'INSPECTOR_FAILURE:unknown:validation')

    def test_invalid_request_records_schema_stage_without_inspection(self):
        subject = object.__new__(inspector.Inspector)
        subject.inspect = mock.Mock(side_effect=AssertionError('must not inspect'))
        with self.assertRaises(RuntimeError):
            subject.handle({})
        self.assertEqual(subject.failure_stage, 'request-schema')
        subject.inspect.assert_not_called()

    def roundtrip(self, error):
        left, right = socket.socketpair()
        failures = []
        def peer():
            try:
                request = inspector.receive(right)
                inspector.send(right, dict(request=request, absent=False, error=error))
            except BaseException as exc:
                failures.append(type(exc))
            finally:
                right.close()
        with mock.patch.object(inspector, 'peer_identity', return_value=(os.getppid(), os.getuid())):
            client = inspector.Client(left)
        worker = threading.Thread(target=peer)
        worker.start()
        try:
            if error is None:
                self.assertFalse(client.absent('/controlled', 'temporary-profiles'))
                self.assertGreaterEqual(left.fileno(), 0)
            else:
                with self.assertRaisesRegex(RuntimeError, 'inspection failed'):
                    client.absent('/controlled', 'temporary-profiles')
                self.assertEqual(left.fileno(), -1)
                sequence = client.sequence
                with self.assertRaisesRegex(RuntimeError, 'prior failure'):
                    client.absent('/controlled', 'temporary-profiles')
                self.assertEqual(client.sequence, sequence)
        finally:
            left.close()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])

    def test_failed_response_poison_remains_fail_closed(self):
        self.roundtrip('inspection-failed')

    def test_live_negative_absence_remains_false(self):
        self.roundtrip(None)

    def test_closed_socket_denied_without_attempting_send(self):
        left, right = socket.socketpair()
        try:
            with mock.patch.object(inspector, 'peer_identity', return_value=(os.getppid(), os.getuid())):
                client = inspector.Client(left)
            left.close()
            with mock.patch.object(inspector, 'send', side_effect=AssertionError('must not send')) as send:
                with self.assertRaisesRegex(RuntimeError, 'prior failure'):
                    client.absent('/controlled', 'temporary-profiles')
                send.assert_not_called()
            self.assertEqual(client.sequence, 0)
        finally:
            left.close()
            right.close()


if __name__ == '__main__':
    unittest.main()
