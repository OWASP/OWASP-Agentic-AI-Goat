"""Run only actual finally ASTs with in-memory resources; never import launchers."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

class PolicyCleanup(unittest.TestCase):
    def test_diagnostics_and_foreign_container_do_not_skip_other_cleanup(self):
        root = Path(__file__).resolve().parents[2]
        for filename in ('qualify-secureshop-prompt-policy-enabled-index.py',
                         'qualify-secureshop-prompt-policy-task-enabled-index.py'):
            source = root / 'scripts' / filename
            tree = ast.parse(source.read_text())
            final = next(n.finalbody for n in tree.body if isinstance(n, ast.Try) and n.finalbody)
            code = compile(ast.Module(body=final, type_ignores=[]), str(source), 'exec')
            for phase in ('capture', 'write', 'chmod', 'foreign', 'inspect'):
                with self.subTest(filename=filename, phase=phase):
                    calls = []
                    class Output:
                        def __truediv__(self, name): return self
                        def write_text(self, text):
                            if phase == 'write': raise OSError('diagnostic write failed')
                    def logs(*args, **kwargs):
                        if phase == 'capture': raise OSError('diagnostic capture failed')
                        return SimpleNamespace(stdout='', stderr='')
                    def chmod(*args):
                        if phase == 'chmod': raise OSError('diagnostic chmod failed')
                    def docker(args, **kwargs):
                        calls.append(args)
                        if args[0] == 'inspect':
                            if phase == 'inspect' and args[1] == 'renderer': raise OSError('inspect failed')
                            owner = 'foreign' if phase == 'foreign' and args[1] == 'renderer' else 'owned'
                            return json.dumps([{'Config': {'Labels': {'dvaia.qualification': owner}}}])
                        return ''
                    result = {'status': 'passed', 'error': {'message': 'original failure'}}
                    namespace = dict(signal=SimpleNamespace(alarm=lambda _: None),
                        gate=SimpleNamespace(protect_cleanup=lambda: None, received=[]), children=[],
                        created={('container','renderer'),('container','pg'),('image','image'),('network','network')},
                        renderer_name='renderer',pg_name='pg',renderer_image='image',renderer_network='network',
                        suffix='owned',DOCKER=[],env={},subprocess=SimpleNamespace(run=logs),
                        evidence=Output(),os=SimpleNamespace(chmod=chmod),docker=docker,
                        absent=lambda kind,name: not (phase in ('foreign','inspect') and name=='renderer'),
                        result=result,time=SimpleNamespace(strftime=lambda *a:'time',gmtime=lambda:None),
                        write=lambda *args:calls.append(['receipt']),task_result=Output(),json=json,
                        print=lambda *args:None,exit_code=0)
                    exec(code, namespace)
                    self.assertIn(['inspect','renderer'], calls)
                    self.assertIn(['inspect','pg'], calls)
                    self.assertIn(['rm','--force','--volumes','pg'], calls)
                    renderer_rm = ['rm','--force','--volumes','renderer']
                    if phase in ('foreign','inspect'): self.assertNotIn(renderer_rm,calls)
                    else: self.assertIn(renderer_rm,calls)
                    self.assertIn(['image','rm','--force','image'],calls)
                    self.assertIn(['network','rm','network'],calls)
                    self.assertEqual(calls.count(['receipt']),2)
                    self.assertEqual(result['error']['message'],'original failure')
                    self.assertEqual(result['status'],'failed')
                    self.assertEqual(namespace['exit_code'],1)
                    self.assertEqual(len(result['cleanup']['errors']),2 if phase in ('capture','write','chmod') else 1)

if __name__ == '__main__': unittest.main()
