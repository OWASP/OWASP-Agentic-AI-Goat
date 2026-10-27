"""Controlled admission/cleanup checks; never starts Docker, PostgreSQL or probe."""
from contextlib import ExitStack
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import run_v30_boundary_probe_current_host as launcher
from sql_nosql_docker_ownership import validate_container_layout


class NoResourceContracts(unittest.TestCase):
    def execute_fixture(self, parent, *, create_failure=False, missing_birth=False,
                        publication_failure=False, failed_probe=False):
        admitted={'docker':'/none/docker','dockerHost':'unix:///none/docker.sock',
            'node':'/none/node'}
        snapshot={'cohort':launcher.host.COHORT,'sourcePins':{},'dependencyInventory':{}}
        class FakeDocker:
            def __init__(self, _admitted, _runtime, deadline): self.deadline=deadline
            def __call__(self, _parts, *, cap=8):
                return SimpleNamespace(returncode=0,stdout='',stderr='')
        class FakeProcess:
            pid=4321
            def poll(self): return None
        def required(_docker, parts, *, cap=8):
            if parts[0]=='run':
                if create_failure: raise RuntimeError('injected unknown create outcome')
                return 'a'*64
            if parts[0]=='exec' and 'SELECT count(*)' in parts[-1]: return '0'
            return ''
        with ExitStack() as stack:
            for target, value in (('current_host',admitted),('evidence_parent',parent),
                                  ('source_snapshot',snapshot),('Docker',FakeDocker)):
                stack.enter_context(mock.patch.object(launcher,target,return_value=value)
                    if target!='Docker' else mock.patch.object(launcher,target,value))
            stack.enter_context(mock.patch.object(launcher,'verify_daemon'))
            stack.enter_context(mock.patch.object(launcher,'verify_image'))
            stack.enter_context(mock.patch.object(launcher,'required',side_effect=required))
            stack.enter_context(mock.patch.object(launcher,'choose_host_port',return_value=49163))
            stack.enter_context(mock.patch.object(launcher,'validate_owner_write_paths'))
            stack.enter_context(mock.patch.object(launcher,'validate_container_layout',return_value=49162))
            stack.enter_context(mock.patch.object(launcher,'prepare_stores',return_value={
                'secureshop':'postgresql://owned-commerce',
                'secureshop_agents':'postgresql://owned-agents'}))
            stack.enter_context(mock.patch.object(launcher.host,'validate_grant'))
            stack.enter_context(mock.patch.object(launcher,'inspect_owned',side_effect=
                [None,{'Id':'a'*64}] if not create_failure else [None]))
            cleanup=stack.enter_context(mock.patch.object(launcher,'cleanup_owned',return_value={
                'status':'absent' if create_failure else 'removed_absence_verified',
                'containerId':None if create_failure else 'a'*64}))
            if missing_birth:
                stack.enter_context(mock.patch.object(launcher.subprocess,'Popen',return_value=FakeProcess()))
                stack.enter_context(mock.patch.object(launcher,'LibProc',return_value=
                    SimpleNamespace(identity=lambda _pid:None)))
                stack.enter_context(mock.patch.object(launcher,'retire_probe_process',return_value=False))
            if failed_probe:
                class FailedProcess:
                    pid=4321
                    def poll(self): return 1
                    def wait(self, timeout):
                        runs=list(parent.glob('run-v30-boundary-*'))
                        self_owner.assertEqual(len(runs),1)
                        entry=json.loads((runs[0]/'outer-probe-birth.json').read_text())
                        self_owner.assertEqual(entry['pid'],self.pid)
                        self_owner.assertEqual(entry['birth'],[200,3])
                        return 1
                self_owner=self
                captured=[]
                def spawned(argv, **_kwargs):
                    captured.append(argv)
                    return FailedProcess()
                stack.enter_context(mock.patch.object(launcher.subprocess,'Popen',side_effect=spawned))
                identity=SimpleNamespace(uid=os.getuid(),ruid=os.getuid(),ppid=os.getpid(),
                    pgid=4321,start_sec=200,start_usec=3)
                stack.enter_context(mock.patch.object(launcher,'LibProc',return_value=
                    SimpleNamespace(identity=lambda _pid:identity,
                        arguments=lambda _pid:captured[0])))
                stack.enter_context(mock.patch.object(launcher.os,'getsid',return_value=4321))
                stack.enter_context(mock.patch.object(launcher,'inspect_probe_retirement',
                    return_value=(True,True,True,False)))
            if publication_failure:
                stack.enter_context(mock.patch.object(launcher.os,'replace',side_effect=OSError('injected replace')))
            stack.enter_context(mock.patch.object(launcher,'LIVE_ENABLED',True))
            stack.enter_context(mock.patch.object(launcher.sys,'platform','darwin'))
            with self.assertRaises(OSError if publication_failure else RuntimeError):
                launcher.execute()
        runs=list(parent.glob('run-v30-boundary-*'))
        self.assertEqual(len(runs),1)
        return runs[0], cleanup

    def test_run_gate_precedes_any_host_admission_or_resource_creation(self):
        with mock.patch.object(launcher, 'LIVE_ENABLED', False), \
             mock.patch.object(launcher, 'current_host', side_effect=AssertionError('host inspected')):
            with self.assertRaisesRegex(RuntimeError, 'V30_PROBE_PROVISION_UNQUALIFIED'):
                launcher.execute()
        self.assertFalse(launcher.host.LIVE_ENABLED)
        self.assertTrue(launcher.boundary_probe.PROBE_LIVE_ENABLED)

    def test_plan_reports_actual_two_probe_gates_without_allocating(self):
        output=io.StringIO()
        with mock.patch.object(launcher,'current_host',return_value={'postgresImageId':launcher.host.IMAGE}), \
             redirect_stdout(output):
            self.assertEqual(launcher.main(['--plan']),0)
        plan=json.loads(output.getvalue())
        self.assertIs(plan['liveEnabled'],launcher.LIVE_ENABLED)
        self.assertIs(plan['probeLiveEnabled'],launcher.boundary_probe.PROBE_LIVE_ENABLED)
        self.assertIs(plan['originalV30Qualified'],False)

    def test_only_two_fixed_roles_and_databases_can_be_provisioned(self):
        seen = []
        def command(parts, *, cap=8):
            self.assertEqual(cap, 8)
            seen.append(parts)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        nonce = 'a1b2c3d4e5f6'
        urls = launcher.prepare_stores(command, 'b' * 64, 49162, nonce)
        self.assertEqual(urls, {
            'secureshop': 'postgresql://dvaia_secureshop_runtime@127.0.0.1:49162/dvaia_test_agent_host_a1b2c3d4e5f6_secureshop',
            'secureshop_agents': 'postgresql://dvaia_secureshop_agents_runtime@127.0.0.1:49162/dvaia_test_agent_host_a1b2c3d4e5f6_secureshop_agents',
        })
        self.assertEqual(len(seen), 10)
        for parts in seen:
            self.assertEqual(parts[:11], ['exec', 'b' * 64, 'psql', '-h', '127.0.0.1',
                '-p', '5432', '-U', 'postgres', '-d', 'postgres'])
            self.assertEqual(parts[11:14], ['-v', 'ON_ERROR_STOP=1', '-c'])
        self.assertEqual([row[-1].split()[0] for row in seen],
            ['CREATE','CREATE','CREATE','REVOKE','GRANT'] * 2)
        for value in ('identity', 'secureshop_review', '../secureshop'):
            with self.assertRaisesRegex(RuntimeError, 'V30_PROBE_STORE'):
                launcher.provision_statements(nonce, value)
        with self.assertRaisesRegex(RuntimeError, 'V30_PROBE_STORE'):
            launcher.provision_statements('wrong', 'secureshop')

    def test_docker_commands_have_bounded_total_and_no_ambient_context(self):
        admitted = {'docker':'/repository/tasks/runtime/container/bin/docker',
            'dockerHost':'unix:///repository/.qualification/goat-q/docker.sock'}
        real_popen=launcher.subprocess.Popen
        seen=[]
        def harmless(argv, **kwargs):
            seen.append((argv,kwargs))
            return real_popen(['/bin/echo','owned'],**kwargs)
        with mock.patch.object(launcher.subprocess, 'Popen', side_effect=harmless):
            docker = launcher.Docker(admitted, Path('/repository/private'), launcher.time.monotonic()+10)
            self.assertEqual(docker(['info','--format','{{.ID}}']).stdout,'owned\n')
            argv, kwargs = seen[0]
            self.assertEqual(argv[:3], [admitted['docker'],'--host',admitted['dockerHost']])
            self.assertEqual(kwargs['env'], {'PATH':'/usr/bin:/bin',
                'HOME':'/repository/private', 'TMPDIR':'/repository/private/tmp',
                'XDG_CACHE_HOME':'/repository/private/tmp',
                'DOCKER_CONFIG':'/repository/private'})
            self.assertTrue(kwargs['start_new_session'])
            docker.deadline = launcher.time.monotonic()-1
            with self.assertRaises(TimeoutError): docker(['info'])
            self.assertEqual(len(seen),1)

    def test_docker_streaming_output_bound_reaps_child(self):
        admitted={'docker':'/repository/tasks/runtime/container/bin/docker',
            'dockerHost':'unix:///repository/.qualification/goat-q/docker.sock'}
        real_popen=launcher.subprocess.Popen
        children=[]
        def flood(_argv, **kwargs):
            child=real_popen(['/usr/bin/yes'],**kwargs)
            children.append(child)
            return child
        with mock.patch.object(launcher.subprocess,'Popen',side_effect=flood):
            docker=launcher.Docker(admitted,Path('/repository/private'),launcher.time.monotonic()+5)
            with self.assertRaisesRegex(RuntimeError,'DOCKER_OUTPUT_BOUND'):
                docker(['info'])
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)

    def test_selector_construction_failure_after_docker_spawn_reaps_child(self):
        admitted={'docker':'/repository/tasks/runtime/container/bin/docker',
            'dockerHost':'unix:///repository/.qualification/goat-q/docker.sock'}
        real_popen=launcher.subprocess.Popen
        children=[]
        def flood(_argv, **kwargs):
            child=real_popen(['/usr/bin/yes'],**kwargs)
            children.append(child)
            return child
        with mock.patch.object(launcher.subprocess,'Popen',side_effect=flood), \
             mock.patch.object(launcher.selectors,'DefaultSelector',side_effect=OSError('injected selector')):
            docker=launcher.Docker(admitted,Path('/repository/private'),launcher.time.monotonic()+5)
            with self.assertRaisesRegex(OSError,'injected selector'):
                docker(['info'])
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].poll())
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)

    def test_postgres_run_flags_match_unchanged_ownership_layout(self):
        labels={'dvaia.owner':'11111111-2222-4333-8444-555555555555',
            'dvaia.cohort':launcher.host.COHORT}
        args=launcher.postgres_run_args('dvaia-v30-original-disclosure-a1b2c3d4e5f6',labels)
        self.assertEqual(args[:6],['run','--detach','--pull','never','--name',
            'dvaia-v30-original-disclosure-a1b2c3d4e5f6'])
        self.assertEqual(args[-4:],['127.0.0.1::5432',launcher.host.IMAGE,
            '-c','max_connections=64'])
        self.assertEqual(args.count('--label'),2)
        self.assertIn('--memory',args)
        self.assertEqual(args[args.index('--memory')+1],'512m')
        self.assertEqual(args[args.index('--cpus')+1],'2')
        self.assertEqual(args[args.index('--pids-limit')+1],'256')
        self.assertEqual(args[args.index('--tmpfs')+1],'/var/lib/postgresql:rw,size=268435456')
        row={'HostConfig':{'Tmpfs':{'/var/lib/postgresql':'rw,size=268435456'},
            'Memory':536870912,'NanoCpus':2000000000,'PidsLimit':256},
            'Mounts':[],'NetworkSettings':{'Ports':{'5432/tcp':[{'HostIp':'127.0.0.1',
                'HostPort':'49162'}]}}}
        self.assertEqual(validate_container_layout(row),49162)

    def test_owner_write_scope_rejects_foreign_or_nonprivate_paths(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-scope-') as raw:
            repo=Path(raw)
            parent=repo/'tasks/qualification'; parent.mkdir(parents=True,mode=0o700)
            run=parent/'run-v30-boundary-a1b2c3d4e5f6'; run.mkdir(mode=0o700)
            runtime=run/'runtime'; runtime.mkdir(mode=0o700)
            (runtime/'tmp').mkdir(mode=0o700)
            launcher.validate_owner_write_paths(repo,parent,run,runtime)
            with self.assertRaisesRegex(RuntimeError,'WRITE_SCOPE'):
                launcher.validate_owner_write_paths(repo,temporary,run,runtime)
            runtime.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError,'PRIVATE_PATH'):
                launcher.validate_owner_write_paths(repo,parent,run,runtime)

    def test_failed_create_by_name_cleans_only_exact_owned_identity(self):
        labels={'dvaia.owner':'11111111-2222-4333-8444-555555555555',
            'dvaia.cohort':launcher.host.COHORT}
        expected={'status':'removed_absence_verified','containerId':'a'*64}
        with mock.patch.object(launcher,'cleanup_owned',return_value=expected) as cleanup:
            self.assertEqual(launcher.retire_container_if_safe(object(),
                creation_attempted=True,probe_attempted=False,probe_terminal=False,
                probe_report=False,probe_group_absent=False,sandbox_group_absent=False,
                name='dvaia-v30-original-disclosure-a1b2c3d4e5f6',labels=labels,
                captured_id=None),expected)
            self.assertEqual(cleanup.call_args.kwargs['name'],
                'dvaia-v30-original-disclosure-a1b2c3d4e5f6')
            self.assertIsNone(cleanup.call_args.kwargs['captured_id'])
            cleanup.reset_mock()
            with self.assertRaisesRegex(RuntimeError,'RETAINED_UNCERTAIN'):
                launcher.retire_container_if_safe(object(),creation_attempted=True,
                    probe_attempted=True,probe_terminal=True,probe_report=False,
                    probe_group_absent=True,sandbox_group_absent=True,
                    name='dvaia-v30-original-disclosure-a1b2c3d4e5f6',labels=labels,
                    captured_id='a'*64)
            cleanup.assert_not_called()

    def test_execute_unknown_creation_preserves_intent_then_exact_name_cleanup(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-exec-') as raw:
            run,cleanup=self.execute_fixture(Path(raw),create_failure=True)
            intent=json.loads((run/'pg-create-intent.json').read_text())
            self.assertEqual(intent['imageId'],launcher.host.IMAGE)
            self.assertEqual(intent['daemonId'],launcher.host.DAEMON)
            self.assertEqual(intent['name'],'dvaia-v30-original-disclosure-'+run.name[-12:])
            self.assertIsNone(cleanup.call_args.kwargs['captured_id'])
            result=json.loads((run/'v30-boundary-probe-owner-result.json').read_text())
            self.assertIs(result['passed'],False)
            self.assertEqual(result['containerCleanup']['status'],'absent')

    def test_execute_unverified_child_retains_owned_postgres(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-exec-') as raw:
            run,cleanup=self.execute_fixture(Path(raw),missing_birth=True)
            cleanup.assert_not_called()
            result=json.loads((run/'v30-boundary-probe-owner-result.json').read_text())
            self.assertIs(result['passed'],False)
            self.assertIsNone(result['containerCleanup'])
            self.assertIs(result['probeAttempted'],True)

    def test_failed_probe_birth_is_durable_before_wait_and_pg_can_retire(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-exec-') as raw:
            run,cleanup=self.execute_fixture(Path(raw),failed_probe=True)
            entry=json.loads((run/'outer-probe-birth.json').read_text())
            self.assertEqual(entry['pid'],4321)
            self.assertEqual(entry['birth'],[200,3])
            self.assertEqual(entry['argv'][2],str(launcher.PROBE))
            cleanup.assert_called_once()
            result=json.loads((run/'v30-boundary-probe-owner-result.json').read_text())
            self.assertIs(result['passed'],False)
            self.assertEqual(result['containerCleanup']['status'],'removed_absence_verified')

    def test_final_publication_failure_keeps_incomplete_placeholder(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-exec-') as raw:
            run,_=self.execute_fixture(Path(raw),create_failure=True,publication_failure=True)
            result=json.loads((run/'v30-boundary-probe-owner-result.json').read_text())
            self.assertIs(result['passed'],False)
            self.assertEqual(result['status'],'incomplete')

    def test_candidate_file_and_directory_sync_failures_never_replace_placeholder(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-publication-') as raw:
            path=Path(raw)/'result.json'
            launcher.private_json(path,{'passed':False})
            with mock.patch.object(launcher.os,'fsync',side_effect=OSError('injected fsync')):
                with mock.patch.object(launcher.os,'replace') as replace:
                    with self.assertRaises(OSError):
                        launcher.publish_final(path,{'passed':True})
                    replace.assert_not_called()
            self.assertEqual(json.loads(path.read_text()),{'passed':False})
            self.assertTrue((Path(raw)/'result.json.candidate').exists())

    def test_changed_placeholder_inode_refuses_success_replacement(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-publication-') as raw:
            path=Path(raw)/'result.json'
            launcher.private_json(path,{'passed':False})
            actual=launcher.private_json
            def displaced(candidate, value):
                created=actual(candidate,value)
                displaced_path=path.with_name('displaced.json')
                path.rename(displaced_path)
                actual(path,{'passed':False,'replacement':True})
                return created
            with mock.patch.object(launcher,'private_json',side_effect=displaced):
                with mock.patch.object(launcher.os,'replace') as replace:
                    with self.assertRaisesRegex(RuntimeError,'PUBLICATION_IDENTITY'):
                        launcher.publish_final(path,{'passed':True})
                    replace.assert_not_called()
            self.assertIs(json.loads(path.read_text())['passed'],False)

    def test_changed_candidate_inode_refuses_success_replacement(self):
        temporary=Path(os.environ['TMPDIR']).resolve()
        with tempfile.TemporaryDirectory(dir=temporary,prefix='v30-owner-publication-') as raw:
            path=Path(raw)/'result.json'
            launcher.private_json(path,{'passed':False})
            actual=launcher.private_json
            def displaced(candidate, value):
                created=actual(candidate,value)
                candidate.rename(candidate.with_name('displaced-candidate.json'))
                actual(candidate,{'passed':True,'replacement':True})
                return created
            with mock.patch.object(launcher,'private_json',side_effect=displaced):
                with mock.patch.object(launcher.os,'replace') as replace:
                    with self.assertRaisesRegex(RuntimeError,'PUBLICATION_IDENTITY'):
                        launcher.publish_final(path,{'passed':True})
                    replace.assert_not_called()
            self.assertIs(json.loads(path.read_text())['passed'],False)

    def test_pg_retirement_requires_physical_probe_and_sandbox_absence(self):
        self.assertTrue(launcher.may_retire_container(probe_attempted=False,
            probe_terminal=False,probe_report=False,probe_group_absent=False,sandbox_group_absent=False))
        for missing in ('probe_terminal','probe_report','probe_group_absent','sandbox_group_absent'):
            facts = dict(probe_attempted=True,probe_terminal=True,probe_report=True,
                probe_group_absent=True,sandbox_group_absent=True)
            facts[missing] = False
            self.assertFalse(launcher.may_retire_container(**facts),missing)
        self.assertTrue(launcher.may_retire_container(probe_attempted=True,
            probe_terminal=True,probe_report=True,probe_group_absent=True,sandbox_group_absent=True))

    def test_probe_result_and_both_group_absences_are_independently_joined(self):
        repository=Path(__file__).resolve().parents[2]
        temporary=Path(os.environ['TMPDIR']).resolve()
        self.assertTrue(temporary.is_relative_to(repository))
        with tempfile.TemporaryDirectory(dir=temporary, prefix='v30-probe-owner-') as raw:
            run=Path(raw)
            report={'kind':'v30-combined-boundary-probe-v1','cleanupVerified':True,
                'sourceUnchanged':True,'originalV30Qualified':False,'modelCalls':0,
                'databaseMutation':False,'terminal':{'exitCode':0,'signalCode':None},
                'pid':1234,'birth':[100,2],'passed':True}
            journal=[{'version':1,'event':'spawned','pid':1234},
                     {'version':1,'event':'birth','pid':1234,'birth':[100,2]},
                     {'version':1,'event':'retired','processQuiescent':True}]
            report_file=run/'v30-boundary-probe.json'
            journal_file=run/'v30-boundary-probe.jsonl'
            launcher.private_json(run/'v30-boundary-probe-grant.json',{'version':1})
            launcher.private_json(run/'source-before.json',{'version':1})
            report['grantSha256']=launcher.host.sha(run/'v30-boundary-probe-grant.json')
            report['sourceManifestSha256']=launcher.host.sha(run/'source-before.json')
            launcher.private_json(report_file,report)
            journal_file.write_bytes(b''.join(launcher.host.encoded(row)+b'\n' for row in journal))
            journal_file.chmod(0o600)
            process=SimpleNamespace(pid=4321,poll=lambda:0)
            api=SimpleNamespace(group_pids=lambda _: [], identity=lambda _: None)
            self.assertEqual(launcher.inspect_probe_retirement(run,process,(200,3),api),
                (True,True,True,True))
            launcher.private_json(run/'controlled-denial.json',{'present':True})
            report['passed']=False
            report_file.write_bytes(launcher.host.encoded(report));report_file.chmod(0o600)
            self.assertEqual(launcher.inspect_probe_retirement(run,process,(200,3),api),
                (True,True,True,False))
            report['terminal']={'exitCode':65,'signalCode':None}
            report_file.write_bytes(launcher.host.encoded(report));report_file.chmod(0o600)
            self.assertEqual(launcher.inspect_probe_retirement(run,process,(200,3),api),
                (True,True,True,False))  # Failed probe still permits verified retirement.
            report['grantSha256']='0'*64
            report_file.write_bytes(launcher.host.encoded(report));report_file.chmod(0o600)
            self.assertEqual(launcher.inspect_probe_retirement(run,process,(200,3),api),
                (False,True,True,False))
            journal_file.write_bytes(launcher.host.encoded({'version':1,'event':'spawned','pid':1234})+b'\n')
            self.assertEqual(launcher.inspect_probe_retirement(run,process,(200,3),api),
                (False,True,False,False))


if __name__ == '__main__':
    unittest.main()
