"""Maintained executed actual MAIN OTHER/current branch controls, no native calls."""
import ast
import types
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
TEXT=(ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py').read_text()
TREE=ast.parse(TEXT)
class FakePath:
    def __init__(self,value): self.value=value
    def __truediv__(self,name): return FakePath(self.value+'/'+name)
    def __str__(self): return self.value
    def exists(self): return False
    def is_symlink(self): return False
    def read_text(self): return 'controlled tap'

def branch(cohort):
    for node in ast.walk(TREE):
        if isinstance(node,ast.If) and ast.unparse(node.test)==f'args.cohort == {cohort}' and any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='browser_path' for t in x.targets) for x in node.body):
            return ast.If(test=node.test,body=node.body,orelse=[])
    raise AssertionError(cohort)

class MainSeam(unittest.TestCase):
    def execute(self,other,cleanup=True):
        constants={}
        for node in TREE.body:
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name):
                try: constants[node.targets[0].id]=ast.literal_eval(node.value)
                except (ValueError,TypeError): pass
        chosen='SESSION_REVOKE_OTHER_BROWSER' if other else 'SESSION_REVOKE_BROWSER'
        calls=[]; receipts=[]
        args=types.SimpleNamespace(cohort=constants[chosen],node='node',browser='browser',browser_sha256='pin')
        namespace={**constants,'args':args,'source':FakePath('source'),'evidence':FakePath('evidence'),'env':{},'admitted_node_sha256':'nodepin','runtime':object(),'effect_counts':{},'tap_paths':{args.cohort:FakePath('tap')},
            'digest':lambda path: constants['SESSION_REVOKE_TEST_SHA256'] if str(path).startswith('source/') else 'pin',
            'node_pin_matches':lambda *args:True,'run_node':lambda *args:calls.append(args),
            'complete_tap_counts':lambda *args:{'tests':1},'standalone_browser_cleanup_state':lambda _: {'closed':cleanup},
            'session_revoke_receipt':lambda path:receipts.append(('v1',str(path))) or {'controlled':'other'},
            'session_current_revoke_receipt':lambda path:receipts.append(('v2',str(path))) or {'controlled':'current'}}
        node=ast.fix_missing_locations(ast.Module(body=[branch(chosen)],type_ignores=[]))
        exec(compile(node,'<actual-native-branch>','exec'),namespace)
        return namespace,calls,receipts
    def test_other_exact_v1_receipt_and_original_timeout(self):
        ns,calls,receipts=self.execute(True)
        self.assertEqual(receipts,[('v1','evidence/account-other-session-revoke-browser-v1.json')])
        self.assertEqual(len(calls),1); self.assertEqual(calls[0][-1],180)
        self.assertEqual(ns['env'],{'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH':'evidence/account-other-session-revoke-browser-v1.json'})
    def test_current_keeps_v2_receipt(self):
        ns,calls,receipts=self.execute(False)
        self.assertEqual(receipts,[('v2','evidence/account-current-session-revoke-browser-v2.json')])
        self.assertEqual(calls[0][-1],180)
        self.assertNotIn('SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH',ns['env'])
    def test_cleanup_denial_preserved(self):
        with self.assertRaisesRegex(RuntimeError,'retirement required'): self.execute(True,False)

if __name__=='__main__': unittest.main()
