"""Execute only the launcher's finally AST with in-memory resource stubs."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'scripts/qualify-secureshop-system-config-enabled-index.py'

class ArtifactCleanup(unittest.TestCase):
    def test_retention_failures_do_not_skip_owned_cleanup(self):
        tree = ast.parse(SOURCE.read_text())
        final = next(n.finalbody for n in tree.body if isinstance(n, ast.Try) and n.finalbody)
        code = compile(ast.Module(body=final, type_ignores=[]), str(SOURCE), 'exec')
        for phase in ('read', 'write', 'chmod', 'pg-capture', 'pg-write', 'pg-chmod', 'foreign'):
            with self.subTest(phase=phase):
                calls = []
                class FakePath:
                    def __init__(self, name): self.name = name
                    def __truediv__(self, name): return FakePath(self.name + '/' + name)
                    def is_file(self): return True
                    def read_bytes(self):
                        if phase == 'read': raise OSError('retention read denied')
                        return b'evidence'
                    def write_bytes(self, data):
                        if phase == 'write': raise OSError('retention write denied')
                    def write_text(self, data):
                        if phase == 'pg-write': raise OSError('postgres write denied')
                def chmod(path, mode):
                    if phase == 'pg-chmod' and path.name.endswith('postgres.log'):
                        raise OSError('postgres chmod denied')
                    if phase == 'chmod' and not path.name.endswith('postgres.log'):
                        raise OSError('retention chmod denied')
                def docker(args, **kwargs):
                    calls.append(args[0])
                    return json.dumps([{'Config': {'Labels': {'dvaia.test.owner': 'foreign' if phase == 'foreign' else 'owned'}}}])
                def logs(*args, **kwargs):
                    if phase == 'pg-capture': raise OSError('postgres capture denied')
                    return SimpleNamespace(stdout='', stderr='')
                child = SimpleNamespace(pid=123, poll=lambda: 0)
                executor = SimpleNamespace(state={'cleanup': True}, close=lambda: calls.append('executor') or True)
                result = {'status': 'passed', 'error': {'message': 'original failure'}}
                env = dict(signal=SimpleNamespace(alarm=lambda _: None),
                    gate=SimpleNamespace(protect_cleanup=lambda: None, received=[]),
                    runtime=FakePath('runtime'), evidence=FakePath('evidence'),
                    os=SimpleNamespace(chmod=chmod), children=[child],
                    owned_group_members=lambda pid: calls.append('process') or [],
                    pg_created=True, pg_name='owned-pg', owner='owned', DOCKER=[], env={},
                    subprocess=SimpleNamespace(run=logs),
                    docker=docker, executor=executor, pg_absent=lambda: True,
                    result=result, time=SimpleNamespace(strftime=lambda *a: 'time', gmtime=lambda: None),
                    write=lambda path, value: calls.append('receipt'), task_result=FakePath('task'),
                    json=json, print=lambda *a: None, exit_code=0)
                exec(code, env)
                self.assertIn('process', calls)
                self.assertIn('inspect', calls)
                if phase == 'foreign': self.assertNotIn('rm', calls)
                else: self.assertIn('rm', calls)
                self.assertIn('executor', calls)
                self.assertEqual(calls.count('receipt'), 2)
                self.assertEqual(result['error']['message'], 'original failure')
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(env['exit_code'], 1)
                errors = result['cleanup']['errors']
                if phase in ('read', 'write', 'chmod'):
                    self.assertEqual(len(errors), 8)
                    self.assertTrue(all('retention ' + phase + ' denied' in e for e in errors))
                else:
                    self.assertEqual(len(errors), 1)
                    self.assertTrue(errors[0].startswith('postgres:' if phase == 'foreign' else 'postgres-diagnostics:'))

if __name__ == '__main__':
    unittest.main()
