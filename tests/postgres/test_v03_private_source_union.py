"""Offline controls over the actual MAIN source-union statements; no plans run."""
import ast
import json
from pathlib import Path
import re
import types
import unittest
from secureshop_current_host_admission import evidence_parent

SOURCE=Path(__file__).with_name('run-secureshop-agent-host-transport-main.py')
FUNCTION=next(node for node in ast.parse(SOURCE.read_text()).body if isinstance(node,ast.FunctionDef) and node.name=='source_snapshot')
BLOCK=next(node for node in FUNCTION.body if isinstance(node,ast.If) and ast.unparse(node.test)=='v03_private_run_id is not None')

def capture(packet,run='a'*32,cohort='v03'):
    calls=[]
    def command(argv,**kwargs):
        calls.append((argv,kwargs))
        return types.SimpleNamespace(stdout=json.dumps(packet))
    namespace=dict(files=set(),v03_producer_sources=None,v03_private_run_id=run,cohort=cohort,V03_OPTIMIZE_BROWSER='v03',
        source=Path('/synthetic/repo'),node='/synthetic/node',re=re,json=json,Path=Path,subprocess=types.SimpleNamespace(run=command))
    exec(compile(ast.Module(body=[BLOCK],type_ignores=[]),str(SOURCE),'exec'),namespace)
    return namespace,calls

def packet():
    return dict(target='original-v03-producer-source-union-v1',parentRunId='a'*32,executionApproved=False,
        qualificationComplete=False,sourcePins={'tests/postgres/example.js':'b'*64})

class ProducerSourceUnionControls(unittest.TestCase):
    def test_actual_main_evidence_selector_accepts_only_original_parent(self):
        tree=ast.parse(SOURCE.read_text())
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='select_evidence_parent')
        namespace=dict(current_host_evidence_parent=evidence_parent)
        exec(compile(ast.Module(body=[function],type_ignores=[]),str(SOURCE),'exec'),namespace)
        root=SOURCE.resolve().parents[2];parent=root/'tasks/qualification'
        args=types.SimpleNamespace(current_host_profile='goat-q',evidence_parent=str(parent))
        self.assertEqual(namespace['select_evidence_parent'](args,root,'unused'),parent)
        args.evidence_parent=str(parent/'v03-nested')
        with self.assertRaisesRegex(RuntimeError,'Current-host evidence must use repository tasks/qualification'):
            namespace['select_evidence_parent'](args,root,'unused')
    def test_actual_capture_uses_fixed_source_only_factory_and_original_run(self):
        namespace,calls=capture(packet())
        self.assertEqual(namespace['files'],{'tests/postgres/example.js'})
        self.assertEqual(len(calls),1)
        self.assertIn('captureProducerSources(process.cwd(),"'+'a'*32+'")',calls[0][0][2])
        self.assertEqual(calls[0][1]['timeout'],120)
        self.assertNotIn('--run',calls[0][0])

    def test_wrong_cohort_or_run_is_denied_before_source_plan(self):
        for run,cohort in [('bad','v03'),('a'*32,'other')]:
            with self.assertRaisesRegex(RuntimeError,'binding invalid'):capture(packet(),run,cohort)

    def test_qualification_claim_and_escaping_or_bad_pin_are_denied(self):
        value=packet();value['qualificationComplete']=True
        with self.assertRaisesRegex(RuntimeError,'result invalid'):capture(value)
        for name,digest in [('../outside','b'*64),('/outside','b'*64),('x//y','b'*64),('file','bad')]:
            value=packet();value['sourcePins']={name:digest}
            with self.assertRaisesRegex(RuntimeError,'pins invalid'):capture(value)

    def test_all_native_snapshot_calls_bind_same_private_run(self):
        tree=ast.parse(SOURCE.read_text())
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='source_snapshot']
        self.assertEqual(len(calls),3)
        for call in calls:
            value=next(item.value for item in call.keywords if item.arg=='v03_private_run_id')
            self.assertEqual(ast.unparse(value),'args.v03_private_run_id')

if __name__=='__main__':unittest.main()
