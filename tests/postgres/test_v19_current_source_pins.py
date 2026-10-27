"""Actual active V19 source map and per-adoption drift rejection, no native calls."""
import ast
import hashlib
from pathlib import Path
import re
import unittest
ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
TREE=ast.parse(SOURCE.read_text())
ASSIGNMENT=next(n for n in TREE.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='V19_SUMMARY_PINS')
PINS=ast.literal_eval(ASSIGNMENT.value)
FUNCTION=next(n for n in TREE.body if isinstance(n,ast.FunctionDef) and n.name=='validate_v19_summary_pins')
NS={'re':re,'V19_SUMMARY_PINS':PINS}
exec(compile(ast.Module(body=[FUNCTION],type_ignores=[]),str(SOURCE),'exec'),NS)
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
CHANGED=('tests/postgres/secureshopCustomerCheckoutRendered.integration.test.js',
 'tests/fixtures/secureshopV19RenderedCohort.js','tests/fixtures/secureshopFileSummaryRenderedQualification.js',
 'tests/secureshopFileSummaryRenderedQualification.test.js','tests/postgres/secureshopMailActualTransport.js',
 'tests/secureshopMailActualTransportV19Budget.test.js','tests/postgres/test_secureshop_v19_file_summary_browser_launcher.py')
class ActivePins(unittest.TestCase):
    def test_all_twenty_actual_files(self):
        self.assertEqual(len(PINS),20)
        self.assertEqual(set(NS['validate_v19_summary_pins'](ROOT,digest)),set(PINS))
    def test_each_of_seven_changed_files_rejects_single_drift(self):
        for name in CHANGED:
            with self.subTest(path=name),self.assertRaisesRegex(RuntimeError,'Pinned V19 source changed'):
                NS['validate_v19_summary_pins'](ROOT,lambda path:'0'*64 if path==ROOT/name else digest(path))
if __name__=='__main__': unittest.main()
