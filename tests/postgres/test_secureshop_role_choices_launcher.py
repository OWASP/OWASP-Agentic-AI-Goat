#!/usr/bin/env python3
"""Closed receipt and admission checks for the role choices browser cohort."""

import importlib.util
import hashlib
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class MerchantMailLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_MAIL_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_MAIL_SCOPE, actorCalls=12,
                     roleTurns=6, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_exact_fixture_contract_and_closed_model_bounds(self):
        self.assertIn('merchant-mail-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-mail-browser', LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.MERCHANT_MAIL_TEST, LAUNCHER.ROLE_CHOICES_TEST)
        fixture = (HERE.parent.parent / LAUNCHER.MERCHANT_MAIL_TEST).read_text()
        self.assertIn("const MERCHANT_MAIL_ASSERTION = '" + LAUNCHER.MERCHANT_MAIL_ASSERTION + "';", fixture)
        self.assertIn("const MERCHANT_MAIL_SCOPE = '" + LAUNCHER.MERCHANT_MAIL_SCOPE + "';", fixture)
        flags = fixture.split('const MERCHANT_MAIL_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        import ast
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), LAUNCHER.MERCHANT_MAIL_FLAGS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for count in (6, 12, 30):
                expected = self.receipt(path, actorCalls=count)
                self.assertEqual(LAUNCHER.merchant_mail_receipt(path), expected)

    def test_rejects_incomplete_false_extra_or_unbounded_receipts(self):
        variants = [{flag: False} for flag in LAUNCHER.MERCHANT_MAIL_FLAGS] + [
            {'actorCalls': 5}, {'actorCalls': 31}, {'actorCalls': True},
            {'roleTurns': 5}, {'roleTurns': 7}, {'roleTurns': True},
            {'judgeCalls': 1}, {'judgeCalls': False}, {'scope': 'other'},
            {'errors': ['failure']}, {'extra': True}, {'retainedGetNoProvision': 1},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_mail_receipt(path)
            partial = self.receipt(path)
            del partial['oneDisclosureNoReplay']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_mail_receipt(path)

    def test_private_receipt_and_owned_mail_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_mail_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_mail_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp' / 'dvaia-role-mail-unit').mkdir(parents=True)
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])

    def test_plan_stays_before_allocation_and_unrelated_authorities(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'merchant-mail-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(LAUNCHER, 'validate_ssh', side_effect=AssertionError('SSH')), \
                patch.object(LAUNCHER, 'embedding_inventory', side_effect=AssertionError('embedding')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.MERCHANT_MAIL_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)
        self.assertIs(plan['actualJudgeRequired'], False)


class MerchantMailActionsLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_MAIL_ACTIONS_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_MAIL_ACTIONS_SCOPE, actorCalls=12,
                     roleTurns=5, replyAgentCalls=3, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_exact_fixture_contract_and_closed_model_bounds(self):
        self.assertIn('merchant-mail-actions-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-mail-actions-browser', LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.MERCHANT_MAIL_ACTIONS_TEST, LAUNCHER.ROLE_CHOICES_TEST)
        fixture = (HERE.parent.parent / LAUNCHER.MERCHANT_MAIL_ACTIONS_TEST).read_text()
        self.assertIn("const MERCHANT_MAIL_ACTIONS_ASSERTION = '" + LAUNCHER.MERCHANT_MAIL_ACTIONS_ASSERTION + "';", fixture)
        self.assertIn("const MERCHANT_MAIL_ACTIONS_SCOPE = '" + LAUNCHER.MERCHANT_MAIL_ACTIONS_SCOPE + "';", fixture)
        flags = fixture.split('const MERCHANT_MAIL_ACTIONS_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        import ast
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), LAUNCHER.MERCHANT_MAIL_ACTIONS_FLAGS)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for count in (8, 13, 30):
                expected = self.receipt(path, actorCalls=count)
                self.assertEqual(LAUNCHER.merchant_mail_actions_receipt(path), expected)

    def test_rejects_incomplete_false_extra_or_unbounded_receipts(self):
        variants = [{flag: False} for flag in LAUNCHER.MERCHANT_MAIL_ACTIONS_FLAGS] + [
            {'actorCalls': 7}, {'actorCalls': 31}, {'actorCalls': True},
            {'roleTurns': 4}, {'roleTurns': 6}, {'roleTurns': True},
            {'replyAgentCalls': 0}, {'replyAgentCalls': 2}, {'replyAgentCalls': True},
            {'replyAgentCalls': 8}, {'judgeCalls': 1}, {'judgeCalls': False}, {'scope': 'other'},
            {'errors': ['failure']}, {'extra': True}, {'replyAgentSavedReply': 1},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_mail_actions_receipt(path)
            partial = self.receipt(path)
            del partial['physicalSendConfirmed']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_mail_actions_receipt(path)

    def test_private_receipt_and_owned_mail_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_mail_actions_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_mail_actions_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp' / 'dvaia-role-mail-actions-unit').mkdir(parents=True)
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])

    def test_plan_stays_before_allocation_and_unrelated_authorities(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'merchant-mail-actions-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(LAUNCHER, 'validate_ssh', side_effect=AssertionError('SSH')), \
                patch.object(LAUNCHER, 'embedding_inventory', side_effect=AssertionError('embedding')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.MERCHANT_MAIL_ACTIONS_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)
        self.assertIs(plan['actualJudgeRequired'], False)


class RoleChoicesLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ROLE_CHOICES_FLAGS}
        value.update(scope=LAUNCHER.ROLE_CHOICES_SCOPE, actorCalls=8,
                     chatTurns=4, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_real_model_call_bounds(self):
        self.assertIn('standalone-role-choices-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('standalone-role-choices-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.standalone_role_choices_receipt(path), expected)
            self.receipt(path, actorCalls=4)
            LAUNCHER.standalone_role_choices_receipt(path)
            self.receipt(path, actorCalls=20)
            LAUNCHER.standalone_role_choices_receipt(path)

    def test_rejects_false_partial_extra_and_mock_call_counts(self):
        variants = [
            {'merchantRenderedSearch': False}, {'adminSelectedCardReadback': None},
            {'noMutation': 1}, {'zeroJudge': False}, {'siblingChoiceDenied': False},
            {'actorCalls': 0}, {'actorCalls': 3}, {'actorCalls': 21}, {'actorCalls': True},
            {'chatTurns': 3}, {'chatTurns': True}, {'judgeCalls': 1},
            {'judgeCalls': False}, {'errors': ['browser-remains']},
            {'scope': 'other'}, {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.standalone_role_choices_receipt(path)
            partial = self.receipt(path)
            del partial['choiceProvenanceBound']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.standalone_role_choices_receipt(path)

    def test_rejects_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.standalone_role_choices_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.standalone_role_choices_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.standalone_role_choices_receipt(path)

    def test_owned_role_profile_is_in_cleanup_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            temporary = runtime / 'tmp'
            temporary.mkdir()
            profile = temporary / 'dvaia-role-choices-unit'
            profile.mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class AdminReadLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_READ_CHAT_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_READ_CHAT_SCOPE, actorCalls=9,
                     roleTurns=3, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_selector_and_three_actual_turns(self):
        self.assertIn('admin-read-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('admin-read-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.admin_read_chat_receipt(path), expected)
            for count in (3, 15):
                self.receipt(path, actorCalls=count)
                LAUNCHER.admin_read_chat_receipt(path)

    def test_rejects_partial_inflated_and_nonprivate_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in ({'sqlExactResultRendered': False}, {'configExactGetRecovery': None},
                            {'ownedSystemExecutorReady': 1}, {'actorCalls': 2},
                            {'actorCalls': 16}, {'actorCalls': True}, {'roleTurns': 2},
                            {'judgeCalls': 1}, {'errors': ['sidecar-remains']},
                            {'scope': 'other'}, {'extra': True}):
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.admin_read_chat_receipt(path)
            partial = self.receipt(path)
            del partial['healthModelSelectedFresh']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_read_chat_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_read_chat_receipt(path)

    def test_owned_read_browser_profile_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            temporary = runtime / 'tmp'
            temporary.mkdir()
            (temporary / 'dvaia-role-admin-read-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class SystemConfigTraversalLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_FLAGS}
        value.update(scope=LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_SCOPE, actorCalls=9,
                     roleTurns=3, judgeCalls=1, readEffects=2,
                     fixedClientCalls=0, genuineCredit=1, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_selector_fixture_and_strict_receipt(self):
        self.assertIn('system-config-traversal-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('system-config-traversal-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        fixture = (HERE.parent.parent / LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_TEST).read_text()
        self.assertIn("const SYSTEM_CONFIG_ASSERTION = '" + LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_ASSERTION + "';", fixture)
        self.assertIn("const SYSTEM_CONFIG_SCOPE = '" + LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_SCOPE + "';", fixture)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.system_config_traversal_receipt(path), expected)
            boundary = self.receipt(path, actorCalls=13, judgeCalls=1)
            self.assertEqual(LAUNCHER.system_config_traversal_receipt(path), boundary)

    def test_rejects_incomplete_counts_extra_and_nonprivate_receipts(self):
        variants = [
            {'physicalTraversalSelected': False}, {'canonicalTenantCredit': None},
            {'roleTurns': 2}, {'actorCalls': 2}, {'actorCalls': 16},
            {'actorCalls': 13, 'judgeCalls': 2},
            {'judgeCalls': 0}, {'judgeCalls': 5}, {'readEffects': 1},
            {'fixedClientCalls': 1}, {'genuineCredit': 0},
            {'errors': ['sidecar-remains']}, {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.system_config_traversal_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.system_config_traversal_receipt(path)

    def test_plan_is_nonallocating_and_requires_real_judge(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'system-config-traversal-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64,
                '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['actualJudgeRequired'], True)


class SystemCredentialLauncherContract(unittest.TestCase):
    def credential_receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.SYSTEM_CREDENTIAL_FLAGS}
        value.update(scope=LAUNCHER.SYSTEM_CREDENTIAL_SCOPE, actorCalls=6, roleTurns=3,
                     judgeCalls=2, readEffects=2, fixedClientCalls=0, genuineCredit=1, errors=[],
                     catalogAdmission={'objectiveId':'ss_system_credential_disclosure',
                        'fixtureLocalCandidateAdmission':True,'productionQualification':'pending',
                        'productionDefaultEnabled':False})
        value.update(changes)
        path.write_text(json.dumps(value)); os.chmod(path, 0o600)
        return value

    def test_credential_selector_closed_receipt_and_independent_criteria(self):
        fixture = (HERE.parent.parent / LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_TEST).read_text()
        for name in ('ASSERTION', 'SCOPE'):
            self.assertIn("const SYSTEM_CREDENTIAL_" + name + " = '" + getattr(LAUNCHER, 'SYSTEM_CREDENTIAL_' + name) + "';", fixture)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            value = self.credential_receipt(path)
            self.assertEqual(LAUNCHER.system_config_traversal_receipt(path, True), value)
            qualified = self.credential_receipt(path, catalogAdmission={**value['catalogAdmission'],
                'fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge'})
            self.assertEqual(LAUNCHER.system_config_traversal_receipt(path, True),qualified)
            self.credential_receipt(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.system_config_traversal_receipt(path)
            for change in ({'judgeCalls':1}, {'judgeCalls':3}, {'scope':LAUNCHER.SYSTEM_CONFIG_TRAVERSAL_SCOPE},
                           {'bothCredentialsDisclosed':False}, {'independentResponseJudgeCriteria':False},
                           {'catalogAdmission':None}, {'extra':True}):
                self.credential_receipt(path, **change)
                with self.assertRaises(RuntimeError):
                    LAUNCHER.system_config_traversal_receipt(path, True)
            for change in ({'fixtureLocalCandidateAdmission':False}, {'productionDefaultEnabled':True},
                           {'productionDefaultEnabled':0}, {'productionQualification':'native-browser-judge'},
                           {'objectiveId':'ss_system_config_traversal'}, {'extra':True}):
                admission = {**value['catalogAdmission'], **change}
                self.credential_receipt(path, catalogAdmission=admission)
                with self.assertRaises(RuntimeError):
                    LAUNCHER.system_config_traversal_receipt(path, True)

    def test_credential_flag_is_cohort_exclusive_and_plan_starts_nothing(self):
        source = HERE.parent.parent
        argv = ['--cohort','system-config-traversal-browser','--system-credential-disclosure',
                '--main-workspace',str(source),'--node','/pinned/node','--docker','/pinned/docker',
                '--docker-sha256','a'*64,'--docker-host',LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon','unit-owned-daemon','--ollama-model-sha256','b'*64,'--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER,'validate_static',return_value=source), \
                patch.object(LAUNCHER,'policy_renderer_admission',return_value=None), \
                patch.object(LAUNCHER.tempfile,'mkdtemp',side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess,'run',side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv),0)
            invalid = argv.copy(); invalid[1] = 'admin-read-browser'
            with self.assertRaises(ValueError): LAUNCHER.main(invalid)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'],LAUNCHER.SYSTEM_CREDENTIAL_COHORT)
        self.assertEqual(plan['stores'],['identity','secureshop_agents','secureshop','secureshop_review'])
        self.assertIs(plan['actualJudgeRequired'],True)
        self.assertIs(plan['nativeStarted'],False)

    def test_native_receipt_requires_closed_noncredit_credential_lifecycle_and_preserves_historical_v46(self):
        import copy
        value = {flag:True for flag in LAUNCHER.STANDALONE_ASSESSMENT_RECEIPT_FLAGS}
        value.update(scope=LAUNCHER.STANDALONE_ASSESSMENT_RECEIPT_SCOPE,
            v46CatalogAdmission={'objectiveId':'ss_upload_path_traversal_write',
                'fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge','productionDefaultEnabled':False})
        proof = dict(controlled=True,actualModel=False,genuineCredit=False,
            candidateAdmission={'objectiveId':'ss_system_credential_disclosure','fixtureLocalCandidateAdmission':True,
                'productionQualification':'pending','productionDefaultEnabled':False},
            ownedReadReceipts=3,assessmentCalls=4,controlledJudgeTransportCalls=4,controlledSceneResolver=True,
            retainedSceneFeatureResetFenced=True,siblingAndImmutableHistoryPreserved=True,pendingFreshPopulatedNoop=True,
            judgments=[{'evaluationId':f'11111111-1111-4111-8111-{index:012d}',
                'evidenceDigest':'a'*64,'verdict':'pass' if index<2 else 'unavailable',
                'disposition':'grading_unqualified' if index<2 else 'not_pass'} for index in range(4)])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'receipt.json'
            def validate(candidate, current=True, qualification='pending'):
                path.write_text(json.dumps(candidate));os.chmod(path,0o600)
                return LAUNCHER.standalone_assessment_receipt(path,require_credential=current,
                    credential_qualification=qualification)
            self.assertEqual(validate(value,False),value)
            with self.assertRaises(RuntimeError):validate(value)
            current={**value,'v41CredentialAssessment':proof}
            self.assertEqual(validate(current),current)
            qualified=copy.deepcopy(current)
            qualified['v41CredentialAssessment']['candidateAdmission'].update(
                fixtureLocalCandidateAdmission=False,productionQualification='native-browser-judge')
            self.assertEqual(validate(qualified,qualification='native-browser-judge'),qualified)
            with self.assertRaises(RuntimeError):validate(current,qualification='native-browser-judge')
            with self.assertRaises(RuntimeError):validate(qualified)
            for fields in ({'actualModel':True},{'genuineCredit':True},{'ownedReadReceipts':2},
                           {'assessmentCalls':3},{'controlledJudgeTransportCalls':5},
                           {'retainedSceneFeatureResetFenced':False},{'pendingFreshPopulatedNoop':False},
                           {'judgments':proof['judgments'][:3]},{'extra':True}):
                with self.assertRaises(RuntimeError):validate({**current,'v41CredentialAssessment':{**proof,**fields}})
            for mutate in (lambda p:p['candidateAdmission'].update(productionDefaultEnabled=True),
                           lambda p:p['candidateAdmission'].update(fixtureLocalCandidateAdmission=False),
                           lambda p:p['judgments'][0].update(disposition='awarded'),
                           lambda p:p['judgments'][0].update(evidenceDigest='forged'),
                           lambda p:p['judgments'][1].update(evaluationId=p['judgments'][0]['evaluationId'])):
                changed=copy.deepcopy(proof);mutate(changed)
                with self.assertRaises(RuntimeError):validate({**current,'v41CredentialAssessment':changed})


class MerchantOrderLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_ORDER_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_ORDER_SCOPE, actorCalls=6,
                     roleTurns=2, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_real_model_call_bounds(self):
        self.assertIn('merchant-order-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-order-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.merchant_order_receipt(path), expected)
            for count in (2, 10):
                self.receipt(path, actorCalls=count)
                LAUNCHER.merchant_order_receipt(path)

    def test_rejects_false_partial_extra_and_inflated_calls(self):
        variants = [
            {'mixedOrderSeeded': False}, {'merchantOnlyDetail': None},
            {'controlledStaleDenied': 1}, {'controlledPagination': False},
            {'noMutation': False}, {'zeroJudge': False},
            {'actorCalls': 0}, {'actorCalls': 1}, {'actorCalls': 11},
            {'actorCalls': True}, {'roleTurns': 1}, {'roleTurns': True},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'errors': ['cleanup-remains']}, {'scope': 'other'},
            {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_order_receipt(path)
            partial = self.receipt(path)
            del partial['choiceProvenanceBound']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_order_receipt(path)

    def test_rejects_nonprivate_or_replaced_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_order_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_order_receipt(link)
            path.write_text('x' * 4097)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_order_receipt(path)

    def test_owned_profile_is_in_cleanup_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            temporary = runtime / 'tmp'
            temporary.mkdir()
            (temporary / 'dvaia-role-order-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class MerchantReviewLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.MERCHANT_REVIEW_FLAGS}
        value.update(scope=LAUNCHER.MERCHANT_REVIEW_SCOPE, actorCalls=24,
                     roleTurns=8, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_closed_actual_model_receipt(self):
        self.assertIn('merchant-review-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('merchant-review-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.merchant_review_receipt(path), expected)
            for count in (8, 40):
                self.receipt(path, actorCalls=count)
                LAUNCHER.merchant_review_receipt(path)

    def test_rejects_partial_false_extra_and_unbounded_claim(self):
        variants = [
            {'firstUsePreparedByRoleRun': False}, {'approveProposalNoEffect': None},
            {'rejectReasonBound': 1}, {'exactGetRecoveryNoReplay': False},
            {'modeAndSnapshotFenced': False}, {'zeroJudge': False},
            {'namedProductSearch': False}, {'productFilteredPending': False},
            {'otherOwnedProductExcluded': False}, {'approvedSameProductReadback': False},
            {'rejectedSameProductReadback': False},
            {'actorCalls': 0}, {'actorCalls': 7}, {'actorCalls': 41},
            {'actorCalls': True}, {'roleTurns': 7}, {'roleTurns': 9}, {'roleTurns': True},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'errors': ['failure']}, {'scope': 'other'}, {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.merchant_review_receipt(path)
            partial = self.receipt(path)
            del partial['siblingReviewDenied']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_review_receipt(path)

    def test_private_receipt_and_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_review_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.merchant_review_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp').mkdir(parents=True)
            (runtime / 'tmp' / 'dvaia-role-review-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class AdminAuditChatLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_AUDIT_CHAT_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_AUDIT_CHAT_SCOPE, actorCalls=2,
                     roleTurns=1, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_closed_actual_model_receipt(self):
        self.assertIn('admin-audit-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('admin-audit-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.ADMIN_AUDIT_CHAT_TEST, LAUNCHER.ADMIN_USER_CHAT_TEST)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.admin_audit_chat_receipt(path), expected)
            for count in range(2, 6):
                self.receipt(path, actorCalls=count)
                LAUNCHER.admin_audit_chat_receipt(path)

    def test_rejects_partial_false_extra_and_unbounded_claim(self):
        variants = [
            {'ownedAuditSeeded': False}, {'filteredAuditRead': None},
            {'structuredAuditRendered': 1}, {'exactGetRecoveryNoReplay': False},
            {'foreignAuditExcluded': False}, {'noMutation': False}, {'zeroJudge': False},
            {'actorCalls': 0}, {'actorCalls': 1}, {'actorCalls': 6}, {'actorCalls': True},
            {'roleTurns': 2}, {'roleTurns': True}, {'judgeCalls': 1}, {'judgeCalls': False},
            {'errors': ['failure']}, {'scope': 'other'}, {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.admin_audit_chat_receipt(path)
            partial = self.receipt(path)
            del partial['foreignAuditExcluded']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_audit_chat_receipt(path)

    def test_private_receipt_and_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_audit_chat_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_audit_chat_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp').mkdir(parents=True)
            (runtime / 'tmp' / 'dvaia-role-admin-audit-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class AdminUserChatLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_USER_CHAT_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_USER_CHAT_SCOPE, actorCalls=12,
                     roleTurns=4, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_closed_actual_model_receipt(self):
        self.assertIn('admin-user-chat-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('admin-user-chat-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.admin_user_chat_receipt(path), expected)
            for count in (4, 20):
                self.receipt(path, actorCalls=count)
                LAUNCHER.admin_user_chat_receipt(path)

    def test_rejects_partial_false_extra_and_unbounded_claim(self):
        variants = [
            {'registeredTargetSelected': False}, {'roleProposalNoEffect': None},
            {'roleReceiptRecoveredOnce': 1}, {'targetSessionRevokedOnRole': False},
            {'banProposalNoEffect': False}, {'controlledAuthorityFences': False},
            {'zeroJudge': False}, {'actorCalls': 3}, {'actorCalls': 21},
            {'actorCalls': True}, {'roleTurns': 3}, {'roleTurns': True},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'errors': ['failure']}, {'scope': 'other'}, {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.admin_user_chat_receipt(path)
            partial = self.receipt(path)
            del partial['physicalBanConfirmed']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_user_chat_receipt(path)

    def test_private_receipt_and_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_user_chat_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_user_chat_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp').mkdir(parents=True)
            (runtime / 'tmp' / 'dvaia-role-admin-user-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class AdminPasswordResetChatLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_PASSWORD_RESET_CHAT_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_PASSWORD_RESET_CHAT_SCOPE, actorCalls=12,
                     roleTurns=4, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_closed_actual_model_receipt(self):
        self.assertIn('admin-password-reset-chat-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('admin-password-reset-chat-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.ADMIN_PASSWORD_RESET_CHAT_TEST, LAUNCHER.ADMIN_USER_CHAT_TEST)
        self.assertNotEqual(LAUNCHER.ADMIN_PASSWORD_RESET_CHAT_ASSERTION, LAUNCHER.ADMIN_USER_CHAT_ASSERTION)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.admin_password_reset_chat_receipt(path), expected)
            for count in (4, 20):
                self.receipt(path, actorCalls=count)
                LAUNCHER.admin_password_reset_chat_receipt(path)

    def test_rejects_partial_false_extra_and_unbounded_claim(self):
        variants = [
            {'registeredSelectedSetup': False}, {'teachingSelectedSetup': None},
            {'noEffectBeforeConfirmation': 1}, {'physicalTeachingResetLostAck': False},
            {'privateParentRevealAcknowledge': False},
            {'secretExcludedFromChildModelStorage': False}, {'zeroJudge': False},
            {'actorCalls': 3}, {'actorCalls': 21}, {'actorCalls': True},
            {'roleTurns': 3}, {'roleTurns': True}, {'judgeCalls': 1},
            {'judgeCalls': False}, {'errors': ['failure']}, {'scope': 'other'},
            {'unexpected': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.admin_password_reset_chat_receipt(path)
            partial = self.receipt(path)
            del partial['registeredExactGetNoReplay']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_password_reset_chat_receipt(path)

    def test_private_receipt_and_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_password_reset_chat_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_password_reset_chat_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp').mkdir(parents=True)
            (runtime / 'tmp' / 'dvaia-role-admin-reset-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class AdminPolicyChatLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.ADMIN_POLICY_CHAT_FLAGS}
        value.update(scope=LAUNCHER.ADMIN_POLICY_CHAT_SCOPE, actorCalls=24,
                     roleTurns=8, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_closed_actual_renderer_receipt(self):
        self.assertIn('admin-policy-chat-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('admin-policy-chat-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.admin_policy_chat_receipt(path), expected)
            for count in (8, 40):
                self.receipt(path, actorCalls=count)
                LAUNCHER.admin_policy_chat_receipt(path)

    def test_rejects_false_partial_extra_and_wrong_model_bounds(self):
        variants = [
            {'realRendererPreview': False}, {'previewHeadUnchanged': None},
            {'physicalDeleteLostAck': 1}, {'versionConflictControlled': False},
            {'siblingDenied': False}, {'zeroJudge': False},
            {'actorCalls': 7}, {'actorCalls': 41}, {'actorCalls': True},
            {'roleTurns': 7}, {'roleTurns': 9}, {'roleTurns': True},
            {'judgeCalls': 1}, {'judgeCalls': False},
            {'errors': ['failure']}, {'scope': 'other'}, {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.admin_policy_chat_receipt(path)
            partial = self.receipt(path)
            del partial['fullCandidateVisible']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_policy_chat_receipt(path)

    def test_private_receipt_owned_profile_and_source_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_policy_chat_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.admin_policy_chat_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp').mkdir(parents=True)
            (runtime / 'tmp' / 'dvaia-role-admin-policy-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])
        source = (HERE / '../fixtures/secureshopOwnedPolicyRendererAdmission.js').resolve()
        self.assertTrue(source.is_file())
        self.assertIn('tests/fixtures/secureshopOwnedPolicyRendererAdmission.js',
                      (HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        for relative in ('tests/fixtures/secureshopDisposablePolicyRenderer.js',
                         'tests/secureshopDisposablePolicyRenderer.test.js',
                         'tests/fixtures/secureshopPolicyTemplateActualQualification.js',
                         'tests/secureshopPolicyTemplateActualQualification.test.js'):
            self.assertTrue((HERE.parent.parent / relative).is_file())
            self.assertIn(relative, (HERE / 'run-secureshop-agent-host-transport-main.py').read_text())


class PolicyTemplateLauncherContract(unittest.TestCase):
    def test_separate_cohort_and_exact_child_contract(self):
        self.assertIn(LAUNCHER.POLICY_TEMPLATE_BROWSER, LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn(LAUNCHER.POLICY_TEMPLATE_BROWSER,
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        fixture = (HERE.parent.parent / LAUNCHER.POLICY_TEMPLATE_TEST).read_text()
        self.assertIn("const POLICY_TEMPLATE_ASSERTION = '" + LAUNCHER.POLICY_TEMPLATE_ASSERTION + "'", fixture)
        self.assertIn("const POLICY_TEMPLATE_SCOPE = '" + LAUNCHER.POLICY_TEMPLATE_SCOPE + "'", fixture)
        flags = fixture.split('const POLICY_TEMPLATE_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        import ast
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), LAUNCHER.POLICY_TEMPLATE_FLAGS)

    def test_closed_positive_and_negative_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy-template.json'
            value = {flag: True for flag in LAUNCHER.POLICY_TEMPLATE_FLAGS}
            value.update(scope=LAUNCHER.POLICY_TEMPLATE_SCOPE, roleTurns=2,
                         actorCalls=4, judgeCalls=1, errors=[])
            path.write_text(json.dumps(value)); path.chmod(0o600)
            self.assertEqual(LAUNCHER.policy_template_receipt(path), value)
            for change in ({'canonicalJudgment': False}, {'judgeCalls': 0}, {'judgeCalls': True},
                           {'actorCalls': 1}, {'actorCalls': 11}, {'roleTurns': 8},
                           {'extra': True}, {'scope': LAUNCHER.ADMIN_POLICY_CHAT_SCOPE}):
                changed = dict(value, **change)
                path.write_text(json.dumps(changed))
                with self.assertRaises(RuntimeError):
                    LAUNCHER.policy_template_receipt(path)


class ChatPresentationLauncherContract(unittest.TestCase):
    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CHAT_PRESENTATION_FLAGS}
        value.update(scope=LAUNCHER.CHAT_PRESENTATION_SCOPE, actorCalls=0,
                     controlledCalls=18, chatTurns=9, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_selector_and_controlled_receipt(self):
        self.assertIn('chat-presentation-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('chat-presentation-browser',
                      LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            expected = self.receipt(path)
            self.assertEqual(LAUNCHER.chat_presentation_receipt(path), expected)
            for count in (9, 27):
                self.receipt(path, controlledCalls=count)
                LAUNCHER.chat_presentation_receipt(path)

    def test_rejects_partial_typed_or_actual_model_claim(self):
        variants = [
            {'mobileHitTargets': False}, {'pendingRecoveryReachable': None},
            {'manualScrollPreserved': 1}, {'zeroActualModel': False},
            {'actorCalls': 1}, {'actorCalls': True}, {'controlledCalls': 8},
            {'controlledCalls': 28}, {'controlledCalls': True},
            {'chatTurns': 8}, {'judgeCalls': 1}, {'errors': ['failure']},
            {'scope': 'other'}, {'extra': True},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for variant in variants:
                with self.subTest(variant=variant):
                    self.receipt(path, **variant)
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.chat_presentation_receipt(path)
            partial = self.receipt(path)
            del partial['threeRoleComposers']
            path.write_text(json.dumps(partial))
            with self.assertRaises(RuntimeError):
                LAUNCHER.chat_presentation_receipt(path)

    def test_private_receipt_and_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.chat_presentation_receipt(path)
            os.chmod(path, 0o600)
            link = Path(directory) / 'alias.json'
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.chat_presentation_receipt(link)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp').mkdir(parents=True)
            (runtime / 'tmp' / 'dvaia-chat-presentation-unit').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])


class CatalogPageLauncherContract(unittest.TestCase):
    @staticmethod
    def original_wire():
        def uid(number):
            return f'70000000-0000-4000-8000-{number:012d}'
        def raw(index, envelope, decision):
            request = json.dumps({'model': LAUNCHER.OLLAMA_MODEL,
                'messages': [{'role': 'user', 'content': envelope}]})
            response = json.dumps({'model': LAUNCHER.OLLAMA_MODEL,
                'message': {'content': json.dumps(decision)}, 'done': True})
            return {'index': index, 'model': LAUNCHER.OLLAMA_MODEL, 'status': 200,
                    'request': request, 'requestBytes': len(request.encode()),
                    'requestSha256': hashlib.sha256(request.encode()).hexdigest(),
                    'response': response, 'responseBytes': len(response.encode()),
                    'responseObservedBytes': len(response.encode()),
                    'responseSha256': hashlib.sha256(response.encode()).hexdigest(),
                    'responseComplete': True, 'responseCaptureTruncated': False,
                    'terminalReason': 'end'}
        calls, turns = [], []
        for position in range(8):
            role = 'customer' if position < 3 else 'merchant'
            offset = position % 3 if position < 6 else position - 6
            request_id = uid(position + 1)
            session_id = uid(21 if role == 'customer' else 22)
            tool = ('catalog.search' if role == 'customer' else 'merchant.catalog_search')
            if role == 'customer' and offset == 2:
                tool = 'catalog.details'
            agent, name = tool.split('.')
            search = 'Owned inactive products' if position >= 6 else 'Owned products'
            params = ({'search': search} if offset == 0 else {}
                      if offset == 1 else {'choiceId': turns[-1]['receipt']['cards'][0]['choiceId']})
            if offset == 2 and role == 'merchant':
                params = {'choiceId': turns[-1]['receipt']['cards'][0]['choiceId']}
            if position == 6:
                params = {'search': search, 'status': 'inactive'}
            if position == 7:
                params = {'choiceId': turns[-1]['receipt']['cards'][0]['choiceId']}
            text = f'Saved response {position}'
            total, page_size = (15, 12) if role == 'customer' else (1, 5) if position >= 6 else (7, 5)
            count = page_size if offset == 0 else total - page_size if offset == 1 else 1
            if position >= 6:
                count = 1
            cards = [{'kind': 'product' if role == 'customer' else 'merchant_product',
                'choiceId': uid(100 + position * 20 + number), 'title': f'Product {number}',
                **({'readOnly': True} if position >= 6 else {})}
                for number in range(count)]
            observation = {'total': total if offset < 2 else 1,
                'products': [{'id': 1 if position >= 6 else number + 1,
                              **({'status': 'inactive'} if position >= 6 else {})}
                             for number in range(count)]}
            if role == 'customer':
                observation['cards'] = cards
            hop = {'tool': tool, 'params': params,
                'result': {'content': [{'type': 'text', 'text': json.dumps(observation)}]}}
            saved = {'stopReason': 'end_turn', 'text': text, 'hops': [hop],
                'modeCapability': {'feature': 'customer_chat' if role == 'customer' else 'merchant_assistant'},
                'taskMetadata': {'customerChat' if role == 'customer' else 'roleChat': {
                    'envelopeSha256': 'b' * 64, 'targetId': uid(50),
                    'sceneId': uid(51), 'sceneGeneration': 1}}}
            receipt = {'status': 'completed', 'replayed': True, 'sessionId': session_id,
                'requestId': request_id, 'hops': [hop], 'cards': cards, 'catalogPage': None,
                'modeCapability': saved['modeCapability']}
            request = {'sessionId': session_id, 'requestId': request_id,
                'message': 'Find products' if offset == 0 else 'Show more products'}
            if position in (0, 1, 3, 4, 6):
                previous = turns[-1] if offset == 1 else None
                next_cursor = cards[-1]['choiceId'] if position == 0 else 5 if position == 3 else None
                page = {'version': 1, 'search': search,
                    'status': 'inactive' if position == 6 else 'active',
                    'afterCursor': previous['saved']['taskMetadata'][
                        'customerChat' if role == 'customer' else 'roleChat']['catalogPageSource']['nextCursor']
                        if previous else None,
                    'nextCursor': next_cursor, 'sourceRequestId': previous['requestId'] if previous else None,
                    'total': total, 'returnedCount': count}
                saved['taskMetadata']['customerChat' if role == 'customer' else 'roleChat']['catalogPageSource'] = page
                if role == 'merchant':
                    saved['taskMetadata']['roleChat']['choices'] = [
                        {'sourceId': observation['products'][index]['id'], 'card': card}
                        for index, card in enumerate(cards)]
                receipt['catalogPage'] = {'version': 1, 'total': total, 'pageSize': page_size,
                    'returnedCount': count, 'hasMore': position in (0, 3)}
                if previous:
                    request['catalogContinuation'] = {'intent': 'catalog_next',
                        'sourceRequestId': previous['requestId']}
            else:
                request['selection'] = {'choiceId': params['choiceId'],
                    'intent': 'details' if role == 'customer' else 'product_details'}
            envelope = {'version': 1}
            if role == 'merchant':
                envelope['role'] = role
            envelope.update(sceneId=uid(51), sceneGeneration=1, targetId=uid(50))
            if role == 'customer':
                envelope['requestId'] = request_id
            envelope['message'] = request['message']
            if role == 'merchant' and 'catalogContinuation' in request:
                envelope['catalogContinuation'] = request['catalogContinuation']
            if 'selection' in request:
                envelope['selection'] = ({'kind': turns[-1]['receipt']['cards'][0]['kind'],
                    **request['selection']} if role == 'customer' else request['selection'])
            if role == 'customer' and 'catalogContinuation' in request:
                envelope['catalogContinuation'] = request['catalogContinuation']
            source_envelope = json.dumps(envelope, separators=(',', ':'), ensure_ascii=False)
            selected = {'tool_calls': [{'agent': agent, 'tool': name, 'args': params}]}
            start = len(calls) + 1
            calls.extend((raw(start, source_envelope, selected),
                          raw(start + 1, source_envelope, {'answer': text})))
            logical = [{'method': 'chat', 'provider': 'ollama', 'model': LAUNCHER.OLLAMA_MODEL,
                'tools': [tool], 'stopReason': 'tool_use'},
                {'method': 'finalResponse', 'provider': 'ollama', 'model': LAUNCHER.OLLAMA_MODEL,
                 'tools': [], 'stopReason': 'end_turn'}]
            turns.append({'role': role, 'sessionId': session_id, 'requestId': request_id,
                'request': request, 'sourceEnvelope': source_envelope,
                'binding': {'request_hash': 'a' * 64,
                    'journal_hash': 'a' * 64, 'request_version': 1,
                    'envelope_sha256': 'b' * 64, 'target_id': uid(50), 'persona_id': 6},
                'saved': saved, 'receipt': receipt, 'logicalCalls': logical,
                'wireStart': start, 'wireEnd': len(calls)})
        return {'version': 1, 'scope': LAUNCHER.CATALOG_PAGE_SCOPE,
                'model': LAUNCHER.OLLAMA_MODEL, 'modelDigest': 'c' * 64,
                'calls': calls, 'turns': turns}

    def test_private_catalog_wire_joins_original_bytes_saved_pages_and_actor_spans(self):
        import copy
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'catalog-page-original-wire.json'
            receipt = {'actorCalls': 16, 'roleTurns': 8, 'judgeCalls': 0}
            value = self.original_wire()
            def check(candidate, accepted=False):
                path.write_text(json.dumps(candidate))
                os.chmod(path, 0o600)
                if accepted:
                    self.assertEqual(LAUNCHER.catalog_page_wire(path, receipt, 'c' * 64), candidate)
                else:
                    with self.assertRaises(RuntimeError):
                        LAUNCHER.catalog_page_wire(path, receipt, 'c' * 64)
            check(value, True)
            explicit_all = copy.deepcopy(value)
            merchant_first = explicit_all['turns'][3]
            merchant_first['saved']['taskMetadata']['roleChat']['catalogPageSource']['status'] = 'all'
            merchant_first['saved']['hops'][0]['params']['status'] = 'all'
            merchant_first['receipt']['hops'] = copy.deepcopy(merchant_first['saved']['hops'])
            explicit_all['turns'][4]['saved']['taskMetadata']['roleChat']['catalogPageSource']['status'] = 'all'
            raw_choice = explicit_all['calls'][merchant_first['wireStart'] - 1]
            selected = json.loads(json.loads(raw_choice['response'])['message']['content'])
            selected['tool_calls'][0]['args']['status'] = 'all'
            response = json.loads(raw_choice['response'])
            response['message']['content'] = json.dumps(selected)
            raw_choice['response'] = json.dumps(response)
            raw_choice['responseBytes'] = len(raw_choice['response'].encode())
            raw_choice['responseObservedBytes'] = raw_choice['responseBytes']
            raw_choice['responseSha256'] = hashlib.sha256(raw_choice['response'].encode()).hexdigest()
            check(explicit_all, True)
            def replace_raw_body(value, index, part, change):
                call = value['calls'][index]
                parsed = json.loads(call[part])
                change(parsed)
                call[part] = json.dumps(parsed)
                call[part + 'Bytes'] = len(call[part].encode())
                call[part + 'Sha256'] = hashlib.sha256(call[part].encode()).hexdigest()
                if part == 'response':
                    call['responseObservedBytes'] = call['responseBytes']
            def change_merchant_prompt(value):
                replace_raw_body(value, 6, 'request', lambda row:
                    row['messages'][-1].update(content='{"version":1,"role":"merchant"}'))
            def change_selected_args(value):
                def altered(row):
                    decision = json.loads(row['message']['content'])
                    decision['tool_calls'][0]['args']['search'] = 'unowned search'
                    row['message']['content'] = json.dumps(decision)
                replace_raw_body(value, 6, 'response', altered)
            def change_final_answer(value):
                def altered(row):
                    decision = json.loads(row['message']['content'])
                    decision['answer'] = 'forged answer'
                    row['message']['content'] = json.dumps(decision)
                replace_raw_body(value, 7, 'response', altered)
            def change_inactive_observation(value, change):
                turn = value['turns'][6]
                observation = json.loads(turn['saved']['hops'][0]['result']['content'][0]['text'])
                change(observation['products'][0])
                turn['saved']['hops'][0]['result']['content'][0]['text'] = json.dumps(observation)
                turn['receipt']['hops'] = copy.deepcopy(turn['saved']['hops'])
            mutations = [
                lambda v: v['calls'][0].update(requestSha256='0' * 64),
                lambda v: v['calls'][0].update(responseComplete=False),
                lambda v: v['calls'][0].update(status=503),
                lambda v: v['calls'][0].update(responseCaptureTruncated=True),
                lambda v: v['calls'][0].update(model='mock'),
                lambda v: v['turns'][1].update(wireStart=1),
                lambda v: v['turns'][1]['binding'].update(journal_hash='0' * 64),
                lambda v: v['turns'][1]['saved']['taskMetadata']['customerChat']['catalogPageSource'].update(afterCursor=None),
                lambda v: v['turns'][1]['request']['catalogContinuation'].update(sourceRequestId=v['turns'][2]['requestId']),
                lambda v: v['turns'][3].update(sourceEnvelope='{}'),
                lambda v: v['turns'][4]['saved']['taskMetadata']['roleChat']['catalogPageSource'].update(status='all'),
                change_merchant_prompt,
                change_selected_args,
                change_final_answer,
                lambda v: v['turns'][4]['saved']['hops'][0].update(params={'search': 'invented'}),
                lambda v: v['turns'][6]['binding'].update(target_id='70000000-0000-4000-8000-000000009999'),
                lambda v: v['turns'][6]['saved']['taskMetadata']['roleChat']['choices'][0].update(sourceId=999),
                lambda v: change_inactive_observation(v, lambda product: product.update(status='active')),
                lambda v: v['turns'][6]['receipt']['cards'][0].update(readOnly=False),
                lambda v: v['turns'][2]['request']['selection'].update(choiceId=uid_bad),
                lambda v: v['calls'][1].update(response=v['calls'][1]['response'].replace('Saved response 0', 'Forged response')),
                lambda v: v['calls'].append(copy.deepcopy(v['calls'][-1])),
            ]
            uid_bad = '70000000-0000-4000-8000-000000009999'
            for index, mutate in enumerate(mutations):
                with self.subTest(mutation=index):
                    altered = copy.deepcopy(value)
                    mutate(altered)
                    check(altered)
            check(value, True)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.catalog_page_wire(path, receipt, 'c' * 64)
            os.chmod(path, 0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.catalog_page_wire(alias, receipt, 'c' * 64)

    def receipt(self, path, **changes):
        value = {flag: True for flag in LAUNCHER.CATALOG_PAGE_FLAGS}
        value.update(scope=LAUNCHER.CATALOG_PAGE_SCOPE, actorCalls=16,
                     roleTurns=8, judgeCalls=0, errors=[])
        value.update(changes)
        path.write_text(json.dumps(value))
        os.chmod(path, 0o600)
        return value

    def test_closed_fixture_contract_and_captured_source(self):
        self.assertIn('catalog-page-browser', LAUNCHER.LIVE_BROWSER_COHORTS)
        self.assertIn('catalog-page-browser', LAUNCHER.parser()._option_string_actions['--cohort'].choices)
        self.assertEqual(LAUNCHER.CATALOG_PAGE_TEST, LAUNCHER.NAMED_ORDER_FILTER_TEST)
        fixture = (HERE.parent.parent / LAUNCHER.CATALOG_PAGE_TEST).read_text()
        self.assertIn("const CATALOG_PAGE_ASSERTION = '" + LAUNCHER.CATALOG_PAGE_ASSERTION + "';", fixture)
        self.assertIn("const CATALOG_PAGE_SCOPE = '" + LAUNCHER.CATALOG_PAGE_SCOPE + "';", fixture)
        self.assertIn("const CATALOG_PAGE_BROWSER = process.env.SECURESHOP_CATALOG_PAGE_BROWSER_NATIVE === '1'", fixture)
        self.assertIn('async function seedCatalogPageProducts(', fixture)
        self.assertIn('async function qualifyCatalogPages(', fixture)
        self.assertIn("await chatReplayOrStale('customer', customerSecond, customerFirst,", fixture)
        self.assertIn("await chatReplayOrStale('merchant', merchantSecond, merchantFirst,", fixture)
        import ast
        flags = fixture.split('const CATALOG_PAGE_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), LAUNCHER.CATALOG_PAGE_FLAGS)

    def test_closed_receipt_bounds_and_private_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'receipt.json'
            for count in (16, 37):
                expected = self.receipt(path, actorCalls=count)
                self.assertEqual(LAUNCHER.catalog_page_receipt(path), expected)
            for change in ({'actorCalls': 15}, {'actorCalls': 38}, {'actorCalls': True},
                           {'roleTurns': 7}, {'roleTurns': True}, {'judgeCalls': 1},
                           {'judgeCalls': False}, {'customerTwelveThenThree': False},
                           {'merchantFiveThenTwo': False}, {'savedSourceBound': False},
                           {'fixtureCleaned': False}, {'errors': ['failed']}, {'extra': True}):
                self.receipt(path, **change)
                with self.assertRaises(RuntimeError):
                    LAUNCHER.catalog_page_receipt(path)
            self.receipt(path)
            os.chmod(path, 0o644)
            with self.assertRaises(RuntimeError):
                LAUNCHER.catalog_page_receipt(path)
            os.chmod(path, 0o600)
            alias = Path(directory) / 'alias.json'
            alias.symlink_to(path)
            with self.assertRaises(RuntimeError):
                LAUNCHER.catalog_page_receipt(alias)
            runtime = Path(directory) / 'runtime'
            (runtime / 'tmp' / 'dvaia-role-catalog-page-owned').mkdir(parents=True)
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])

    def test_plan_has_four_disposable_stores_without_allocating(self):
        source = HERE.parent.parent
        argv = ['--cohort', 'catalog-page-browser', '--main-workspace', str(source),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--ollama-model-sha256', 'b' * 64, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=source), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                patch.object(LAUNCHER.tempfile, 'mkdtemp', side_effect=AssertionError('allocation')), \
                patch.object(LAUNCHER.subprocess, 'run', side_effect=AssertionError('process')), \
                patch.object(LAUNCHER, 'validate_ssh', side_effect=AssertionError('SSH')), \
                patch.object(LAUNCHER, 'embedding_inventory', side_effect=AssertionError('embedding')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.CATALOG_PAGE_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertIs(plan['browser'], True)
        self.assertIs(plan['nativeStarted'], False)
        self.assertIs(plan['sourceCopy'], False)
        self.assertIs(plan['actualJudgeRequired'], False)



class UserLookupDisclosureLauncherContract(unittest.TestCase):
    def receipt(self,path,**changes):
        value={flag:True for flag in LAUNCHER.USER_LOOKUP_FLAGS}
        value.update(scope=LAUNCHER.USER_LOOKUP_SCOPE,actorCalls=4,roleTurns=2,judgeCalls=4,genuineCredit=1,errors=[],catalogAdmission={'objectiveId':'ss_user_lookup_sensitive_disclosure','fixtureLocalCandidateAdmission':True,'productionQualification':'pending','productionDefaultEnabled':False})
        value.update(changes);path.write_text(json.dumps(value));os.chmod(path,0o600);return value

    def test_exact_lookup_counts_admission_and_default_receipts(self):
        fixture=(HERE.parent.parent/LAUNCHER.ADMIN_USER_CHAT_TEST).read_text()
        for name in ('ASSERTION','SCOPE'):
            self.assertIn("const USER_LOOKUP_"+name+" = '"+getattr(LAUNCHER,'USER_LOOKUP_'+name)+"';",fixture)
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'receipt.json';value=self.receipt(path)
            self.assertEqual(LAUNCHER.user_lookup_receipt(path),value)
            qualified={**value['catalogAdmission'],'fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge'}
            self.receipt(path,catalogAdmission=qualified)
            self.assertEqual(LAUNCHER.user_lookup_receipt(path)['catalogAdmission'],qualified)
            for variant in ([{flag:False} for flag in LAUNCHER.USER_LOOKUP_FLAGS]+[{'actorCalls':5},{'actorCalls':True},{'judgeCalls':3},{'judgeCalls':5},{'roleTurns':3},{'genuineCredit':True},{'extra':True},{'scope':'other'}]):
                self.receipt(path,**variant)
                with self.assertRaises(RuntimeError):LAUNCHER.user_lookup_receipt(path)
            for variant in ({'fixtureLocalCandidateAdmission':1},{'productionDefaultEnabled':0},{'productionQualification':'native-browser-judge'},{'productionDefaultEnabled':True}):
                self.receipt(path,catalogAdmission={**value['catalogAdmission'],**variant})
                with self.assertRaises(RuntimeError):LAUNCHER.user_lookup_receipt(path)
            self.receipt(path)
            with self.assertRaises(RuntimeError):LAUNCHER.admin_user_chat_receipt(path)
            os.chmod(path,0o644)
            with self.assertRaises(RuntimeError):LAUNCHER.user_lookup_receipt(path)

    def test_closed_lookup_plan_starts_nothing_preserves_default(self):
        source=HERE.parent.parent
        argv=['--cohort','admin-user-chat-browser','--main-workspace',str(source),'--node','/pinned/node','--docker','/pinned/docker','--docker-sha256','a'*64,'--docker-host',LAUNCHER.EXPECTED_DOCKER_HOST,'--docker-daemon','unit-owned-daemon','--ollama-model-sha256','b'*64,'--plan']
        with patch.object(LAUNCHER,'validate_static',return_value=source),patch.object(LAUNCHER,'policy_renderer_admission',return_value=None),patch.object(LAUNCHER.tempfile,'mkdtemp',side_effect=AssertionError('allocation')),patch.object(LAUNCHER.subprocess,'run',side_effect=AssertionError('process')):
            output=io.StringIO()
            with contextlib.redirect_stdout(output):self.assertEqual(LAUNCHER.main(argv+['--user-lookup-disclosure']),0)
            plan=json.loads(output.getvalue());self.assertEqual(plan['cohort'],LAUNCHER.USER_LOOKUP_COHORT)
            self.assertEqual([plan[key] for key in ('maximumActorCalls','maximumJudgeCalls','maximumModelCalls','roleTurns','genuineCredit')],[4,4,8,2,1])
            self.assertIs(plan['actualJudgeRequired'],True);self.assertIs(plan['nativeStarted'],False);self.assertIs(plan['sourceCopy'],False)
            self.assertEqual(plan['stores'],['identity','secureshop_agents','secureshop','secureshop_review'])
            default=io.StringIO()
            with contextlib.redirect_stdout(default):self.assertEqual(LAUNCHER.main(argv),0)
            original=json.loads(default.getvalue());self.assertEqual(original['cohort'],LAUNCHER.ADMIN_USER_CHAT_COHORT);self.assertIs(original['actualJudgeRequired'],False)
            invalid=argv.copy();invalid[1]='admin-read-browser'
            with self.assertRaises(RuntimeError):LAUNCHER.main(invalid+['--user-lookup-disclosure'])

    def test_raw_capture_requires_model_cleanup_then_actual_node_validator(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'capture.json';value={'version':1,'modelIdentity':{'model':LAUNCHER.OLLAMA_MODEL,'digest':'a'*64,'maximumPhysicalCalls':8},'cleanup':{'fixtureCleaned':True,'errors':[]}}
            path.write_text(json.dumps(value));os.chmod(path,0o600)
            with patch.object(LAUNCHER.subprocess,'run') as run:
                LAUNCHER.user_lookup_capture(path,'/pinned/node',HERE.parent.parent,'a'*64)
                run.assert_called_once();self.assertIn('assertUserLookupOriginalCapture',run.call_args.args[0][2])
            value['modelIdentity']['maximumPhysicalCalls']=9;path.write_text(json.dumps(value))
            with patch.object(LAUNCHER.subprocess,'run',side_effect=AssertionError('must reject before validator')):
                with self.assertRaises(RuntimeError):LAUNCHER.user_lookup_capture(path,'/pinned/node',HERE.parent.parent,'a'*64)


if __name__ == '__main__':
    unittest.main()
