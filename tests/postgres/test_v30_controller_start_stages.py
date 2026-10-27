"""Maintained actual-source stage publication controls; no native execution."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/postgres'))
import v30_agent_host_controller as module

class Archive:
    def __init__(self, _run):
        self.events = []

    def write(self, name, raw, append=False):
        if name.endswith('.jsonl'):
            self.events.append(json.loads(raw)['event'])
        return hashlib.sha256(raw).hexdigest()


class Driver:
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []

    def launcher(self): self.calls.append('launcher')
    def bind_worker(self, _pid, _grant): self.calls.append('bind')
    def worker(self): self.calls.append('worker')

    def verify_pg(self, _grant):
        self.calls.append('pg')
        if self.fail == 'pg': raise RuntimeError('private controlled failure text')

    def probe(self, _grant, _profile):
        self.calls.append('probe')
        if self.fail == 'probe': raise RuntimeError('private controlled failure text')
        return {'controlled': True}

    def start(self, _grant, _profile, _instance):
        self.calls.append('host-spawn')
        return 123, [1, 2]

    def terminal(self): return None


class InertPath:
    def __init__(self, value): self.value = str(value)
    def __truediv__(self, part): return InertPath(self.value + '/' + part)
    def __str__(self): return self.value
    def mkdir(self, **_): pass


class StageTests(unittest.TestCase):
    def run_case(self, fail):
        driver = Driver(fail)
        validation = []
        def validate(_repo, _grant):
            validation.append(True)
            if fail == 'source' and len(validation) == 2:
                raise RuntimeError('private controlled failure text')
        module.combined_policy = lambda *_: 'controlled-policy'
        expected = hashlib.sha256(b'controlled-policy').hexdigest()
        module.sha = lambda _path: '0' * 64 if fail == 'policy' else expected
        module.Path = InertPath
        module.private = lambda *_args, **_kwargs: None
        controller = module.Controller(Path('/controlled'), 101, 'a' * 64, driver,
                                       validator=validate, archive_factory=Archive)
        grant = {'run': '/controlled/tasks/qualification/run-controlled',
                 'pgPort': 40101, 'hostPort': 40102}
        def frame(side, sequence, op, payload):
            return {'version': 1, 'sequence': sequence, 'nonce': 'a' * 64,
                    'pid': 101 if side == 'launcher' else 102,
                    'op': op, 'payload': payload}
        controller.handle('launcher', frame('launcher', 1, 'grant', grant))
        controller.handle('launcher', frame('launcher', 2, 'bind-worker', {'pid': 102}))
        request = frame('worker', 1, 'start', {'instanceId': '11111111-2222-4333-8444-555555555555'})
        if fail:
            with self.assertRaises(RuntimeError): controller.handle('worker', request)
        else:
            controller.handle('worker', request)
        return controller.archive.events, driver.calls, len(validation), controller

    def test_fixed_stage_boundary_and_no_host_effect_on_each_failure(self):
        cases = {
            'source': 'start-attempted',
            'pg': 'start-source-verified',
            'policy': 'start-pg-verified',
            'probe': 'start-policy-verified',
        }
        for fail, last in cases.items():
            with self.subTest(fail=fail):
                events, calls, checks, controller = self.run_case(fail)
                self.assertEqual(events[-1], last)
                self.assertNotIn('network-probed', events)
                self.assertNotIn('host-spawned', events)
                self.assertNotIn('host-spawn', calls)
                self.assertTrue(controller.started)  # One-shot consumed before checks.
                self.assertEqual(checks, 2)
                self.assertNotIn('private controlled failure text', repr(events))

    def test_success_keeps_original_probe_then_host_order(self):
        events, calls, checks, _ = self.run_case(None)
        self.assertEqual(checks, 2)
        self.assertEqual(events[-6:], [
            'start-attempted', 'start-source-verified', 'start-pg-verified',
            'start-policy-verified', 'network-probed', 'host-spawned'])
        self.assertLess(calls.index('probe'), calls.index('host-spawn'))


if __name__ == '__main__':
    unittest.main()
