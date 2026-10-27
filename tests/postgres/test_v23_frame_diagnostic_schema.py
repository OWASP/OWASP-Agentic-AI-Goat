import ast
import copy
import unittest
from pathlib import Path

SOURCE = globals().get('SOURCE') or (Path(__file__).resolve().parent / 'run-secureshop-agent-host-transport-main.py').read_text()
tree = ast.parse(SOURCE)
names = {'v23_public_frame_diagnostic', 'v23_public_receipt_core'}
namespace = {'V23_PUBLIC_GATES': ('hostStopped', 'browserClosed', 'httpClosed'),
             'V23_REQUEST_VARIANTS': ('original-v1',), 'V23_BOUNDARY_CONTRACTS': ('hard-fail-v1',)}
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[]), '<actual-core>', 'exec'), namespace)

class DiagnosticSchema(unittest.TestCase):
    def valid(self):
        return {'version': 1, 'stage': 'turn-frame-composer', 'signals': [{'kind': 'response', 'path': 'other', 'status': 200}], 'pageErrors': []}
    def core(self):
        return dict(version=1, scope='original-v23-public-admin-rendered-v1', passed=False,
            canonicalCredit=False, qualificationComplete=False, actorCalls=0, judgeCalls=0,
            registrationEffects=0, gates={k: True for k in namespace['V23_PUBLIC_GATES']},
            resources=dict(hostPid=1, privateProducer={}, browserProfile='private'), errors=['turn-frame-composer:Error:unknown'],
            cohort=None, caseEvidence=[], requestVariant='original-v1', boundaryContract='hard-fail-v1')
    def test_optional_and_failed_core(self):
        row=self.core(); namespace['v23_public_receipt_core'](row, passed=False)
        row['frameDiagnostic']=self.valid(); namespace['v23_public_receipt_core'](row, passed=False)
    def test_diagnostic_bounds_and_types(self):
        for key,value in [('version',True),('version',2),('stage','secret'),('signals',[{}]*25),('pageErrors',['Error']*5),('pageErrors',['secret']),('signals',None),('pageErrors',None)]:
            with self.subTest(key=key,value=value):
                row=self.valid();row[key]=value
                with self.assertRaises(RuntimeError): namespace['v23_public_frame_diagnostic'](row)
        for value in [None,[],{**self.valid(),'raw':'secret'}]:
            with self.assertRaises(RuntimeError): namespace['v23_public_frame_diagnostic'](value)
    def test_signal_denials(self):
        for signal in [None,{}, {'kind':'response','path':'other','status':True}, {'kind':'response','path':'other','status':600}, {'kind':'response','path':'other','status':99}, {'kind':'requestfailed','path':'other','status':200}, {'kind':'response','path':'https://secret'}, {'kind':'response','path':'other','raw':'secret'}, {'kind':'secret','path':'other'}]:
            row=self.valid();row['signals']=[signal]
            with self.assertRaises(RuntimeError): namespace['v23_public_frame_diagnostic'](row)
    def test_valid_emitted_shapes(self):
        row=self.valid();row['signals']=[{'kind':'requestfailed','path':'other'},{'kind':'response','path':'/secureshop-frame.html'}]*12
        row['pageErrors']=['Error','unknown','SyntaxError','ReferenceError']
        namespace['v23_public_frame_diagnostic'](row)
    def test_core_not_weakened(self):
        for change in [{'extra':True},{'canonicalCredit':True},{'qualificationComplete':True},{'passed':True},{'errors':[]}]:
            row=self.core();row.update(change);row['frameDiagnostic']=self.valid()
            with self.assertRaises(RuntimeError): namespace['v23_public_receipt_core'](row,passed=False)
        row=self.core();row['gates']['hostStopped']=False
        with self.assertRaises(RuntimeError): namespace['v23_public_receipt_core'](row,passed=False)
        row=self.core();row['passed']=True;row['frameDiagnostic']=self.valid()
        with self.assertRaises(RuntimeError): namespace['v23_public_receipt_core'](row,passed=True)

if __name__ == '__main__': unittest.main()
