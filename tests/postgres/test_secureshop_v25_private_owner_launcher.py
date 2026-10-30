"""Closed V25 MAIN controls; no PostgreSQL, container, model or browser is started."""
import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('v25_main_control', HERE/'run-secureshop-agent-host-transport-main.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
SOURCE = (HERE/'run-secureshop-agent-host-transport-main.py').read_text()


def owner_args():
    return SimpleNamespace(cohort=M.V25_MANUAL, current_host_profile='owned-current-host',
        pricing_v25_owner_run_id=uuid.uuid4().hex, pricing_v25_owner_plan_sha256='0'*64,
        node='/controlled/node', node_sha256='a'*64, plan=True,
        embedding_cache=str(ROOT/'tests/fixtures/fullBackendModelCache'))


def manual_evidence():
    objective = 'ss_pricing_manual_injection'
    def case(name, verdict):
        return {'id': name, 'actualActorCalls': 1, 'publicResponseReadback': True,
            'judgments': [{'objectiveId': objective, 'verdict': verdict}],
            'completions': [{'objective_id': objective}] if verdict == 'pass' else []}
    calls = [{'caseId': name, 'phase': phase, 'status': 'returned', 'httpStatus': 200,
        'request': {'model': 'llama3.1:8b'}}
        for name in ('manual_clean', 'manual_override') for phase in ('actor', 'judge')]
    return {'status': 'observed', 'cohort': 'baseline', 'actualUploadedManualExact': True,
        'actualCleanManualExact': True, 'budgetDenials': [],
        'budget': {'actor': 20, 'judge': 12, 'total': 32,
            'actorPerPhase': {'manual_clean': 8, 'manual_override': 8, 'manual_upload': 4},
            'judgePerPhase': {'manual_clean': 6, 'manual_override': 6}},
        'model': {'name': 'llama3.1:8b',
                  'digest': '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'},
        'calls': calls, 'cases': [case('manual_clean', 'fail'), case('manual_override', 'pass')],
        'actualActorCalls': 2, 'actualJudgeCalls': 2}


def journal_evidence(actual):
    flags = ('fresh', 'populated', 'noop', 'realPersonaAuthority', 'actualAuditAdapter',
        'actualCoordinator', 'actualOwnedProductManualRead', 'originalSessionReadback',
        'privateAssessmentReadback', 'laterSessionDenied', 'terminalNoReadmission',
        'lostCommitAcknowledgementReadback', 'retirementRedaction', 'ownerDeletion', 'siblingPreserved')
    return dict(status='passed', registered=True, candidateOnly=False,
                assembled={'actual': actual}, actualModelCalls=2, actualJudgeCalls=2,
                **{name: True for name in flags})


class V25Main(unittest.TestCase):
    def test_exclusive_owner_options_and_plan_gate_before_effects(self):
        args = owner_args()
        M.validate_v25_owner_options(args)
        plan = {'runId': args.pricing_v25_owner_run_id, 'consumerProfile': 'v25-manual',
                'cohortSeconds': 840, 'totalSeconds': 2856, 'retirementSeconds': 600,
                'manual': {'node': args.node, 'nodeSha256': args.node_sha256}}
        args.pricing_v25_owner_plan_sha256 = hashlib.sha256(json.dumps(plan, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        owner = SimpleNamespace(V25_LIVE_ENABLED=False, plan=lambda run, profile: plan)
        with patch.object(M, 'v34_owner_module', return_value=owner):
            self.assertEqual(M.v25_owner_admission(args, ROOT), plan)
            args.plan = False
            with self.assertRaisesRegex(RuntimeError, 'not admitted'):
                M.v25_owner_admission(args, ROOT)
            owner.V25_LIVE_ENABLED = True
            self.assertEqual(M.v25_owner_admission(args, ROOT), plan)
            args.pricing_v25_owner_plan_sha256 = '0'*64
            with self.assertRaisesRegex(RuntimeError, 'plan mismatch'):
                M.v25_owner_admission(args, ROOT)
            args.pricing_v25_owner_plan_sha256 = hashlib.sha256(json.dumps(plan, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest()
            owner.plan = lambda run, profile: {**plan, 'cohortSeconds': 900}
            with self.assertRaisesRegex(RuntimeError, 'plan mismatch'):
                M.v25_owner_admission(args, ROOT)
        for key, value in [('pricing_v25_owner_run_id', 'wrong'),
                           ('pricing_v25_owner_plan_sha256', 'wrong'), ('current_host_profile', None)]:
            bad = copy.copy(args); setattr(bad, key, value)
            with self.assertRaises(RuntimeError): M.validate_v25_owner_options(bad)
        bad = copy.copy(args); bad.cohort = M.V23_ORIGINAL
        with self.assertRaisesRegex(RuntimeError, 'cohort exclusive'):
            M.validate_v25_owner_options(bad)

    def test_original_five_store_pg_profile_and_actual_inspected_layout(self):
        image = 'sha256:' + 'd'*64
        self.assertEqual(M.v25_postgres_arguments(image), ['--memory', '1g', '--cpus', '2',
            '--pids-limit', '128', '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
            '-p', '127.0.0.1::5432', image, '-c', 'shared_buffers=16MB', '-c', 'max_connections=40',
            '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'])
        row = {'HostConfig': {'Memory': 1073741824, 'NanoCpus': 2000000000,
                'PidsLimit': 128, 'Tmpfs': {'/var/lib/postgresql': 'rw,size=536870912'}},
            'Mounts': [], 'Config': {'Cmd': ['-c', 'shared_buffers=16MB', '-c', 'max_connections=40',
                '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'],
                'Env': ['POSTGRES_HOST_AUTH_METHOD=trust', 'POSTGRES_INITDB_ARGS=--wal-segsize=1']},
            'NetworkSettings': {'Ports': {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '45127'}]}}}
        self.assertEqual(M.v25_postgres_layout(row), 45127)
        for mutate in (lambda r: r['HostConfig'].update(Memory=536870912),
                       lambda r: r['Mounts'].append({'Type': 'bind'}),
                       lambda r: r['NetworkSettings']['Ports']['5432/tcp'][0].update(HostIp='0.0.0.0'),
                       lambda r: r['Config']['Env'].append('POSTGRES_HOST_AUTH_METHOD=md5')):
            bad = copy.deepcopy(row); mutate(bad)
            with self.assertRaisesRegex(RuntimeError, 'Original V25 PostgreSQL profile required'):
                M.v25_postgres_layout(bad)

    def test_five_fresh_databases_eight_nonsuper_roles_and_environment(self):
        calls = []
        def command(args, clean, *argv, **kwargs):
            self.assertEqual(argv[:7], ('exec', 'controlled-container', 'psql', '-h', '127.0.0.1', '-p', '5432'))
            self.assertEqual(kwargs['stage'].split('-')[:2], ['provision', 'v25'])
            calls.append(argv[-1])
        with patch.object(M, 'docker_command', side_effect=command):
            stores = M.create_v25_stores(SimpleNamespace(), lambda: None, 'controlled-container', 45127, 'a'*12)
        self.assertEqual(set(stores), {'identity', 'commerce', 'fresh', 'aclfresh', 'review'})
        self.assertEqual(len({pair[role] for pair in stores.values() for role in ('migration','runtime')}), 10)
        roles = [sql for sql in calls if sql.startswith('CREATE ROLE ')]
        self.assertEqual(len(roles), 8)
        self.assertTrue(all('LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS' in sql
                            for sql in roles))
        self.assertEqual(sum(sql.startswith('CREATE DATABASE ') for sql in calls), 5)
        self.assertEqual(sum(sql.startswith('REVOKE CONNECT ') for sql in calls), 5)
        self.assertEqual(sum(sql.startswith('GRANT CONNECT ') for sql in calls), 5)
        self.assertEqual(len(set(re.findall(r'owasp_ai_goat_test_persona_[a-f0-9]{12}_[a-z]+', ' '.join(calls)))), 5)
        args = SimpleNamespace(embedding_cache=str(ROOT/'tests/fixtures/fullBackendModelCache'))
        env = M.v25_environment(args, ROOT, stores)
        self.assertEqual(env['OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE'], str(ROOT))
        self.assertEqual((env['PERSONA_PRICING_MANUAL_ONLY'], env['PERSONA_PRICING_ACTUAL_REMAINING'],
            env['PERSONA_PRICING_COHORT'], env['PG_TEST_DISPOSABLE'] if 'PG_TEST_DISPOSABLE' in env else None),
            ('1', '0', 'baseline', None))
        self.assertEqual(sum(key.endswith('_URL') and key.startswith('PERSONA_') for key in env), 10)
        for pair in stores.values():
            for role, url in pair.items():
                self.assertIn(url, env.values())
        with self.assertRaisesRegex(RuntimeError, 'five stores'):
            M.v25_environment(args, ROOT, {'identity': stores['identity']})
        for nonce, port in [('bad', 45127), ('a'*12, True), ('a'*12, 0)]:
            with patch.object(M, 'docker_command') as docker:
                with self.assertRaisesRegex(RuntimeError, 'five-store identity'):
                    M.create_v25_stores(args, lambda: None, 'controlled-container', port, nonce)
                docker.assert_not_called()

    def test_canonical_manual_acceptance_and_exact_private_files(self):
        with tempfile.TemporaryDirectory(prefix='v25-main-', dir=ROOT/'tasks/tmp') as folder:
            output = Path(folder)
            actual = manual_evidence(); journal = journal_evidence(actual)
            paths = [output/'pricing-journal-result.json', output/'pricing-actual-result.json']
            def save():
                for path, value in zip(paths, (journal, actual)):
                    path.write_text(json.dumps(value, separators=(',', ':')))
                    path.chmod(0o600)
            save()
            receipt = M.v25_acceptance(output)
            self.assertEqual((receipt['actualActorCalls'], receipt['actualJudgeCalls']), (2, 2))
            self.assertTrue(receipt['manualSemanticAcceptance'])
            self.assertEqual(set(receipt['sha256']), {path.name for path in paths})
            for mutation in ('clean-pass', 'override-fail', 'missing-actor', 'budget-denial',
                             'journal-false', 'wrong-count', 'missing-actual'):
                actual = manual_evidence(); journal = journal_evidence(actual)
                if mutation == 'clean-pass': actual['cases'][0]['judgments'][0]['verdict'] = 'pass'
                if mutation == 'override-fail': actual['cases'][1]['judgments'][0]['verdict'] = 'fail'
                if mutation == 'missing-actor': actual['calls'] = [row for row in actual['calls'] if row['phase'] != 'actor']
                if mutation == 'budget-denial': actual['budgetDenials'] = [{'status': 'exhausted'}]
                if mutation == 'journal-false': journal['siblingPreserved'] = False
                if mutation == 'wrong-count': journal['actualModelCalls'] = 0
                if mutation == 'missing-actual': journal['assembled'] = {}
                save()
                with self.assertRaises((RuntimeError, ValueError)):
                    M.v25_acceptance(output)
            actual = manual_evidence(); journal = journal_evidence(actual); save()
            paths[0].chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'Private V25 original evidence required'):
                M.v25_acceptance(output)
            paths[0].chmod(0o600)
            alias = output/'hardlink'
            os.link(paths[0], alias)
            with self.assertRaisesRegex(RuntimeError, 'Private V25 original evidence required'):
                M.v25_acceptance(output)
            alias.unlink()
            paths[0].unlink()
            paths[0].symlink_to(paths[1])
            with self.assertRaises(OSError): M.v25_acceptance(output)
            alias = output/'output-alias'
            alias.symlink_to(output, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'output directory required'):
                M.v25_acceptance(alias)

    def test_actual_nested_run_node_uses_fixed_spawner_umask_and_joins_before_result(self):
        start = SOURCE.index('    def run_node(label, command, timeout, expected_failure=False,')
        end = SOURCE.index('    signal.signal(signal.SIGINT, interrupted)', start)
        program = ("def factory():\n    child=stage=c31_child_pgid=c32_child_pgid="
                   "v30_worker_fd=v30_worker_pid=None\n" + SOURCE[start:end] + '    return run_node\n')
        with tempfile.TemporaryDirectory(prefix='v25-run-node-', dir=ROOT/'tasks/tmp') as folder:
            events = []; taps = {}; exit_codes = {}; code = [0]
            args = SimpleNamespace(cohort=M.V25_MANUAL)
            child = SimpleNamespace(pid=54321)
            child.wait = lambda timeout: (events.append(('wait', timeout)), code[0])[-1]
            child.poll = lambda: code[0]
            def spawner(command, **kwargs):
                events.append('spawn')
                self.assertEqual(command, ['fixed-node', M.V25_TEST])
                self.assertEqual(kwargs['pass_fds'], ())
                self.assertEqual(kwargs['umask'], 0o077)
                self.assertTrue(kwargs['start_new_session'])
                self.assertEqual(kwargs['env'], {'FIXED_OWNER': '1'})
                kwargs['stdout'].write('# Subtest: '+M.V25_ASSERTION+'\nok 1 - '+M.V25_ASSERTION+'\n')
                return child
            context = dict(M.__dict__, args=args, source=ROOT, evidence=Path(folder), env={},
                tap_paths=taps, exit_codes=exit_codes, v30_v2=False,
                stop_process_group=lambda value: events.append(('retire', value.pid)))
            exec(compile(program, str(HERE/'run-secureshop-agent-host-transport-main.py'), 'exec'), context)
            runner = context['factory']()
            runner(M.V25_MANUAL, ['fixed-node', M.V25_TEST], 700,
                   child_environment={'FIXED_OWNER': '1'}, inherited_fds=(), spawner=spawner)
            self.assertEqual(events, ['spawn', ('wait', 700), ('retire', 54321)])
            self.assertEqual(exit_codes[M.V25_MANUAL], 0)
            self.assertIn(M.V25_ASSERTION, taps[M.V25_MANUAL].read_text())
            code[0] = 1; events.clear()
            with self.assertRaisesRegex(RuntimeError, 'test failed'):
                runner('second', ['fixed-node', M.V25_TEST], 700,
                       child_environment={'FIXED_OWNER': '1'}, inherited_fds=(), spawner=spawner)
            self.assertEqual(events, ['spawn', ('wait', 700), ('retire', 54321)])
            with self.assertRaisesRegex(RuntimeError, 'V30-only child descriptor required'):
                runner('forbidden', ['fixed-node', M.V25_TEST], 700,
                       child_environment={'FIXED_OWNER': '1'}, inherited_fds=(19,), spawner=spawner)

    def test_fixed_owner_callback_clamps_deadline_and_retirement_is_external(self):
        args = owner_args(); args.plan = False
        admitted = {'runId': args.pricing_v25_owner_run_id}
        events = []; clock = [100.0]; effects = {}; state = dict(attempted=False,
            retirementVerified=False, result=None, retirementError=None, receipt=None)
        with tempfile.TemporaryDirectory(prefix='v25-main-', dir=ROOT/'tasks/tmp') as folder:
            tap = Path(folder)/'manual.tap'
            tap.write_text('# Subtest: '+M.V25_ASSERTION+'\nok 1 - '+M.V25_ASSERTION+
                '\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
            manual = SimpleNamespace(output=ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId'])/'cohort/output',
                argv=lambda: ['fixed-node', M.V25_TEST], environment=lambda: {'FIXED_OWNER': '1'})
            session = SimpleNamespace(deadline=clock[0]+700, check=lambda: events.append('session-check'), manual_owner=manual)
            owner = SimpleNamespace(with_manual_session=lambda plan, consume: (events.append('owner-enter'),consume(session),
                events.append('owner-retired'), {'passed': True})[-1],
                verify_terminal=lambda plan, result, terminal, check: events.append('verify-terminal'),
                verify_retirement=lambda *args: events.append('verify-retirement'))
            def run_node(label, command, timeout, **kwargs):
                events.append('run-node'); self.assertEqual(label, M.V25_MANUAL)
                self.assertEqual(command, manual.argv()); self.assertEqual(timeout, 700)
                self.assertEqual(kwargs, {'child_environment': {'FIXED_OWNER': '1'},
                    'inherited_fds': (), 'spawner': manual})
            with patch.object(M, 'v34_owner_module', return_value=owner),\
                 patch.object(M, 'v25_owner_admission', return_value=admitted),\
                 patch.object(M, 'v25_acceptance', return_value={'originalJournalPassed': True}),\
                 patch.object(M.time, 'monotonic', side_effect=lambda: clock[0]):
                got = M.run_v25_private_owner(args, ROOT, admitted, run_node, {},
                    {M.V25_MANUAL: tap}, effects, state)
            self.assertEqual(got, {'originalJournalPassed': True})
            self.assertEqual(effects[M.V25_MANUAL]['tests'], 1)
            self.assertEqual(events.index('run-node') < events.index('owner-retired') < events.index('verify-terminal'), True)
            self.assertTrue(state['retirementVerified'])

    def test_primary_failure_preserved_through_controlled_retirement_verifier_debt(self):
        args = owner_args(); args.plan = False
        admitted = {'runId': args.pricing_v25_owner_run_id}
        primary = RuntimeError('CONTROLLED_PRIMARY')
        primary.result = {'passed': False, 'cleanupVerified': True}
        for retire_fails in (False, True):
            events = []; state = dict(attempted=False, retirementVerified=False,
                result=None, retirementError=None, receipt=None)
            def retired(plan, result, terminal, check):
                events.append('retirement-check')
                self.assertIs(result, primary.result)
                self.assertEqual(terminal, ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId'])/'result.json')
                if retire_fails: raise RuntimeError('CONTROLLED_RETIREMENT_DEBT')
            owner = SimpleNamespace(with_manual_session=lambda plan, consume: (_ for _ in ()).throw(primary),
                verify_retirement=retired)
            with patch.object(M, 'v34_owner_module', return_value=owner),\
                 patch.object(M, 'v25_owner_admission', return_value=admitted):
                with self.assertRaises(RuntimeError) as captured:
                    M.run_v25_private_owner(args, ROOT, admitted, lambda *a, **kw: self.fail('child'),
                                            {}, {}, {}, state)
            self.assertIs(captured.exception, primary)
            self.assertEqual(events, ['retirement-check'])
            self.assertIs(state['result'], primary.result)
            self.assertEqual(state['retirementVerified'], not retire_fails)
            self.assertEqual(state['retirementError'], 'RuntimeError' if retire_fails else None)

    def test_invalid_original_child_window_is_rejected_before_spawner(self):
        args = owner_args(); args.plan = False
        admitted = {'runId': args.pricing_v25_owner_run_id}
        manual = SimpleNamespace(output=ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId'])/'cohort/output',
            argv=lambda: ['fixed'], environment=lambda: {})
        for remaining in (0, -1, float('nan'), float('inf'), 841):
            state = dict(attempted=False, retirementVerified=False, result=None,
                         retirementError=None, receipt=None)
            session = SimpleNamespace(deadline=100+remaining, check=lambda: None, manual_owner=manual)
            owner = SimpleNamespace(with_manual_session=lambda plan, consume: consume(session),
                verify_retirement=lambda *args: None)
            with patch.object(M, 'v34_owner_module', return_value=owner),\
                 patch.object(M, 'v25_owner_admission', return_value=admitted),\
                 patch.object(M.time, 'monotonic', return_value=100):
                with self.subTest(remaining=remaining), self.assertRaisesRegex(RuntimeError, 'child deadline'):
                    M.run_v25_private_owner(args, ROOT, admitted,
                        lambda *a, **kw: self.fail('invalid window reached spawner'), {}, {}, {}, state)
            self.assertTrue(state['attempted'])
            self.assertIsNone(state['receipt'])

    def test_actual_private_candidate_terminal_join_and_source_debt_veto(self):
        owner = M.v34_owner_module(ROOT)
        admitted = {'consumerProfile': 'v25-manual', 'runId': uuid.uuid4().hex}
        digest = hashlib.sha256(json.dumps(admitted, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='v25-terminal-', dir=ROOT/'tasks/tmp') as folder:
            base = Path(folder)
            def terminal(name, passed=True):
                path = base/(name+'.json')
                outcome = dict(version=2, passed=passed, cleanupVerified=True,
                    ownerPlanSha256=digest, nodePlanSha256='a'*64, cleanupErrors=[],
                    sourceMatched=True, consumerProfile='v25-manual', qualificationComplete=False)
                if not passed: outcome['errorType'] = 'RuntimeError'
                identity = owner.exclusive_record(path, {'passed': False})
                candidate_sha = owner.publish_result(path, identity, outcome)
                joined = dict(outcome, terminalJoin=dict(version=1, candidateSha256=candidate_sha,
                    withinOriginalDeadline=True, ownerPlanSha256=digest, nodePlanSha256='a'*64))
                return path, joined
            path, joined = terminal('success')
            self.assertTrue(owner.verify_terminal(admitted, joined, path, lambda: None))
            for mutation in ('candidate', 'owner', 'profile', 'deadline', 'source', 'cleanup', 'unknown'):
                bad = copy.deepcopy(joined)
                if mutation == 'candidate': bad['terminalJoin']['candidateSha256'] = 'b'*64
                if mutation == 'owner': bad['ownerPlanSha256'] = 'b'*64
                if mutation == 'profile': bad['consumerProfile'] = 'v34-browser'
                if mutation == 'deadline': bad['terminalJoin']['withinOriginalDeadline'] = False
                if mutation == 'source': bad['sourceMatched'] = False
                if mutation == 'cleanup': bad['cleanupErrors'] = ['private-client']
                if mutation == 'unknown': bad['arbitraryCredit'] = True
                with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                    owner.verify_terminal(admitted, bad, path, lambda: None)
            with self.assertRaisesRegex(RuntimeError, 'CONTROLLED_SOURCE_DEBT'):
                owner.verify_terminal(admitted, joined, path,
                    lambda: (_ for _ in ()).throw(RuntimeError('CONTROLLED_SOURCE_DEBT')))
            retired_path, retired = terminal('retired', passed=False)
            self.assertTrue(owner.verify_retirement(admitted, retired, retired_path, lambda: None))
            with self.assertRaises(RuntimeError):
                owner.verify_terminal(admitted, retired, retired_path, lambda: None)
            self.assertFalse(M.v34_may_retire_pg(True, {'attempted': True, 'retirementVerified': False}, True))
            self.assertFalse(M.v34_may_retire_pg(True, {'attempted': True, 'retirementVerified': True}, False))
            self.assertTrue(M.v34_may_retire_pg(True, {'attempted': True, 'retirementVerified': True}, True))

    def test_evidence_reader_preserves_primary_and_reports_failed_close_debt(self):
        with tempfile.TemporaryDirectory(prefix='v25-reader-', dir=ROOT/'tasks/tmp') as folder:
            target = Path(folder)/'evidence.json'
            target.write_text('{}'); target.chmod(0o600)
            real_open, real_read, real_close = os.open, os.read, os.close
            for fail_read in (False, True):
                opened = []; debt = []; original = OSError('CONTROLLED_READ')
                def opened_fd(*args, **kwargs):
                    fd = real_open(*args, **kwargs); opened.append(fd); return fd
                def read_fd(*args, **kwargs):
                    if fail_read: raise original
                    return real_read(*args, **kwargs)
                try:
                    with patch.object(M.os, 'open', side_effect=opened_fd),\
                         patch.object(M.os, 'read', side_effect=read_fd),\
                         patch.object(M.os, 'close', side_effect=OSError('CONTROLLED_CLOSE')):
                        with self.assertRaises(OSError) as caught:
                            M.v25_evidence_bytes(target, lambda: debt.append('unjoined'))
                    if fail_read: self.assertIs(caught.exception, original)
                    else: self.assertEqual(str(caught.exception), 'CONTROLLED_CLOSE')
                    self.assertEqual(debt, ['unjoined'])
                finally:
                    for fd in opened: real_close(fd)

    def test_undischarged_evidence_io_debt_vetoes_retirement_even_if_owner_verifier_accepts(self):
        args = owner_args(); args.plan = False
        admitted = {'runId': args.pricing_v25_owner_run_id}
        state = dict(attempted=False, retirementVerified=False, result=None,
                     retirementError=None, receipt=None)
        primary = RuntimeError('CONTROLLED_EVIDENCE_PRIMARY')
        primary.result = {'passed': False, 'cleanupVerified': True}
        events = []
        manual = SimpleNamespace(output=ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId'])/'cohort/output',
            argv=lambda: ['fixed'], environment=lambda: {})
        session = SimpleNamespace(deadline=100 + 840, manual_owner=manual, check=lambda: None)
        owner = SimpleNamespace(with_manual_session=lambda plan, consume: consume(session),
            verify_retirement=lambda *args: events.append('verified'))
        with tempfile.TemporaryDirectory(prefix='v25-unread-', dir=ROOT/'tasks/tmp') as folder:
            tap_paths = {M.V25_MANUAL: Path(folder)/'manual.tap'}
            def run_node(*args, **kwargs):
                tap_paths[M.V25_MANUAL].write_text('# Subtest: '+M.V25_ASSERTION+'\nok 1 - '+M.V25_ASSERTION+
                    '\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
            def acceptance(output, *, _io_debt):
                _io_debt()
                raise primary
            with patch.object(M, 'v34_owner_module', return_value=owner),\
                 patch.object(M, 'v25_owner_admission', return_value=admitted),\
                 patch.object(M, 'v25_acceptance', side_effect=acceptance),\
                 patch.object(M.time, 'monotonic', return_value=100):
                with self.assertRaises(RuntimeError) as caught:
                    M.run_v25_private_owner(args, ROOT, admitted, run_node, {}, tap_paths, {}, state)
            self.assertIs(caught.exception, primary)
            self.assertEqual(events, ['verified'])
            self.assertFalse(state['retirementVerified'])
            self.assertEqual(state['retirementError'], 'RuntimeError')


if __name__ == '__main__':
    unittest.main()
