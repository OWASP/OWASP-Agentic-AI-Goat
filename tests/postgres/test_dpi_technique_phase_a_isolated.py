"""Pure launcher controls; real process/network/copy operations forbidden."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

FILE=Path(__file__).with_name('run-dpi-technique-phase-a-isolated.py')
spec=importlib.util.spec_from_file_location('phase_a_launcher',FILE)
m=importlib.util.module_from_spec(spec)
with patch('subprocess.Popen',side_effect=AssertionError('resource denied')):
    spec.loader.exec_module(m)

class Launcher(unittest.TestCase):
    def setUp(self):
        self.guards=contextlib.ExitStack()
        for name in ('subprocess.Popen','subprocess.run','shutil.copytree','os.killpg'):
            self.guards.enter_context(patch(name,side_effect=AssertionError('resource denied')))
        self.addCleanup(self.guards.close)

    def test_help_no_allocation(self):
        with patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:m.arguments(['--help'])
        self.assertEqual(caught.exception.code,0)

    def test_duplicates_unknown_and_no_abbreviation(self):
        with self.assertRaisesRegex(ValueError,'Duplicate'):m.arguments(['--phase-a','--phase-a'])
        for args in (['--unknown'],['--phase']):
            with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):m.arguments(args)

    def test_environment_has_no_inherited_authority(self):
        with patch.dict(os.environ,{'DATABASE_URL':'forbidden','NODE_OPTIONS':'forbidden','OPENAI_API_KEY':'forbidden'}):
            env=m.environment(Path('/owned'),Path('/runtime/node'),Path('/sealed/input'),Path('/owned/evidence'))
        self.assertNotIn('DATABASE_URL',env);self.assertNotIn('NODE_OPTIONS',env);self.assertNotIn('OPENAI_API_KEY',env)
        self.assertEqual(env['DPI_TECHNIQUE_PHASE_A_ACTUAL'],'1')

    def test_exact_session_and_uid(self):
        child=types.SimpleNamespace(pid=50)
        self.assertEqual(m.group_members(child,f'51 50 {os.getuid()}\n',lambda pid:50),[51])
        for text,sid in ((f'51 50 {os.getuid()}\n',60),('51 50 999999\n',50),('unknown',50)):
            with self.assertRaises(ValueError):m.group_members(child,text,lambda pid:sid)
        with self.assertRaises(ProcessLookupError):m.group_members(child,f'51 50 {os.getuid()}',lambda pid:(_ for _ in ()).throw(ProcessLookupError()))

    def test_exited_leader_does_not_imply_absence(self):
        self.assertEqual(m.group_members(types.SimpleNamespace(pid=50,returncode=0),f'51 50 {os.getuid()}',lambda pid:50),[51])
        self.assertEqual(m.group_members(types.SimpleNamespace(pid=50),'',lambda pid:50),[])

    def test_final_aggregate_fast_exit_log_limit(self):
        fake=lambda size:types.SimpleNamespace(exists=lambda:True,stat=lambda:types.SimpleNamespace(st_size=size))
        with self.assertRaisesRegex(ValueError,'Aggregate'):m.log_budget([fake(40*m.MIB),fake(40*m.MIB)])
        m.log_budget([fake(32*m.MIB),fake(32*m.MIB)])

    def test_disk_failure_before_allocation(self):
        with patch.object(m.shutil,'disk_usage',return_value=types.SimpleNamespace(free=9)),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')):
            with self.assertRaisesRegex(ValueError,'reserve'):m.check_space(Path('/'),10)

    def test_bounded_read(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x';p.write_bytes(b'12345')
            with self.assertRaises(ValueError):m.bounded(p,4)
            self.assertEqual(m.bounded(p,5),b'12345')

    def test_artifact_containment_modes_and_bounded_lines(self):
        with tempfile.TemporaryDirectory() as d:
            evidence=Path(d).resolve();child=evidence/'child';child.mkdir(mode=0o700)
            result=child/'result.json';result.write_text('{}');result.chmod(0o600)
            row={'type':'artifact','artifactDirectory':str(child),'resultPath':str(result)}
            self.assertEqual(m.artifact_from_stdout(json.dumps(row).encode(),evidence)[0],result)
            with self.assertRaises(ValueError):m.artifact_from_stdout(json.dumps(row).encode(),evidence/'other')
            result.chmod(0o644)
            with self.assertRaises(ValueError):m.artifact_from_stdout(json.dumps(row).encode(),evidence)
            with self.assertRaises(ValueError):m.artifact_from_stdout(b'x'*8193,evidence)

    def test_plan_never_launches_or_allocates(self):
        class Budget:
            def __init__(self,*a):pass
            def run(self,f):return f()
        modules={'mail_disclosure_cleanup_budget':types.SimpleNamespace(CleanupBudget=Budget),
                 'full_backend_auth_contract':types.SimpleNamespace(validate_package=lambda *a,**kw:None)}
        args=types.SimpleNamespace(manifest='m',manifest_sha256='h',node_sha256='n',plan=True)
        with patch.object(m,'bootstrap',return_value=(Path('/s'),Path('/n'),Path('/i'),Path('/p'),modules)),patch.object(m,'disk_requirement',return_value=123),patch.object(m,'check_space'),patch.object(m.tempfile,'mkdtemp',side_effect=AssertionError('allocation')),contextlib.redirect_stdout(io.StringIO()) as out:
            m.run(args)
        self.assertEqual(json.loads(out.getvalue())['status'],'plan-only')

    def test_child_timeout_and_fast_exit_cap(self):
        budget=types.SimpleNamespace(remaining=lambda:10)
        ticks=iter([0,2])
        with self.assertRaises(TimeoutError):m.wait_child(types.SimpleNamespace(poll=lambda:None),[],1,budget,clock=lambda:next(ticks),sleep=lambda _:None)
        fake=types.SimpleNamespace(exists=lambda:True,stat=lambda:types.SimpleNamespace(st_size=m.LOG_LIMIT+1))
        with self.assertRaises(ValueError):m.wait_child(types.SimpleNamespace(poll=lambda:0,returncode=0),[fake],1,budget)

    def test_independent_failure_retention(self):
        state={'primaryError':'Original','cleanupErrors':[],'integrityErrors':[]};seen=[]
        def physical():raise TimeoutError('spent physical budget')
        def integrity():seen.append('integrity');raise ValueError('changed bytes')
        m.finish_phases(physical,integrity,state)
        self.assertEqual(seen,['integrity']);self.assertEqual(state,{'primaryError':'Original','cleanupErrors':['TimeoutError'],'integrityErrors':['ValueError']})

    def test_descendant_growth_after_finish_and_final_cleanup(self):
        sizes=[20*m.MIB,20*m.MIB]
        logs=[types.SimpleNamespace(exists=lambda:True,stat=lambda i=i:types.SimpleNamespace(st_size=sizes[i])) for i in range(2)]
        def drain():sizes[:]=[40*m.MIB,40*m.MIB]
        m.log_budget(logs)
        with self.assertRaisesRegex(ValueError,'Aggregate'):m.finish_child(drain,logs)
        sizes[:]=[20*m.MIB,20*m.MIB]
        state={'primaryError':'Original','cleanupErrors':[],'integrityErrors':[]};seen=[]
        def failed_drain():drain();raise TimeoutError('physical unknown')
        m.finish_phases(failed_drain,lambda:seen.append('integrity'),state,logs)
        self.assertEqual(state['primaryError'],'Original')
        self.assertEqual(state['cleanupErrors'],['TimeoutError','ValueError'])
        self.assertEqual(seen,['integrity'])

    def test_bootstrap_hash_failure_before_import(self):
        args=types.SimpleNamespace(source='/s',python_binary='/p',python_sha256='bad')
        with patch.object(m,'canonical',side_effect=lambda x,*a:Path(x)),patch.object(m.importlib,'import_module',side_effect=AssertionError('must not import')):
            with self.assertRaisesRegex(ValueError,'Python'):m.bootstrap(args)

if __name__=='__main__':unittest.main()
