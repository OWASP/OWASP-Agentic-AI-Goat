"""Execute the launcher's actual cleanup AST with inert resource adapters only."""
import ast
import json
import pathlib
import subprocess
import types
import unittest

SOURCE = pathlib.Path(__file__).with_name('run-pricing-provision-isolated.py')

class CleanupTests(unittest.TestCase):
    def test_diagnostic_failures_still_retire_original_resources(self):
        tree = ast.parse(SOURCE.read_text())
        main = next(n for n in tree.body if isinstance(n, ast.Try))
        owned = next(n for n in main.finalbody if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == 'wid')
        code = compile(ast.Module(body=[owned], type_ignores=[]), str(SOURCE), 'exec')
        for failure in (None, subprocess.TimeoutExpired('controlled', 30), subprocess.CalledProcessError(1, 'controlled')):
            with self.subTest(failure=type(failure).__name__):
                calls = []
                labels = {'owasp-ai-goat.pricing.owner':'owner', 'owasp-ai-goat.pricing.workspace':'workspace', 'owasp-ai-goat.pricing.package':'package'}
                staged = {'ownerId':'owner', 'packageSha256':'package'}
                class File:
                    def exists(self): return True
                    def read_text(self): return json.dumps(staged)
                class Directory:
                    def __truediv__(self, name): return File()
                    def exists(self): return False
                original_removed = False
                network_removed = False
                def docker(args):
                    nonlocal original_removed, network_removed
                    calls.append(args)
                    value = ''
                    if args[0] == 'ps' and args[-1] == 'name=^/owned$': value = '' if original_removed else 'container-id'
                    elif args == ['inspect', 'container-id']:
                        value = json.dumps([{'Id':'container-id','Image':'image-id','Config':{'Labels':labels},'State':{'Running':False,'ExitCode':1}}])
                    elif args == ['rm','-f','container-id']: original_removed = True
                    elif args[:2] == ['network','ls']: value = '' if network_removed else 'network-id'
                    elif args[:2] == ['network','inspect']: value = json.dumps([{'Id':'network-id','Labels':labels}])
                    elif args[:2] == ['network','rm']: network_removed = True
                    return types.SimpleNamespace(stdout=value)
                def run(*args, **kwargs):
                    if failure: raise failure
                    return types.SimpleNamespace(stdout='controlled diagnostic')
                errors = []
                scope = dict(wid='workspace',directory=Directory(),name='owned',network='network',tag='tag',profile='profile',state={},errors=errors,
                    docker=docker,run=run,save=lambda:None,json=json,DOCKER='inert',HOST='inert',ssh=[],env={},
                    shlex=types.SimpleNamespace(join=lambda args:'inert'),subprocess=types.SimpleNamespace(run=lambda *a,**k:types.SimpleNamespace(returncode=1)))
                exec(code, scope)
                self.assertTrue(original_removed)
                self.assertTrue(network_removed)
                self.assertIn(['images','-q','tag'], calls)
                self.assertEqual(errors, [] if failure is None else ['ReadinessDiagnostic:'+type(failure).__name__])

if __name__ == '__main__': unittest.main()
