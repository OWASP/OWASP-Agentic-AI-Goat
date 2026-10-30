#!/usr/bin/env python3
"""Inert admission checks for the current-main ACL foundation qualification."""
import ast
from types import SimpleNamespace
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
PATH = HERE / 'run-persona-transition-main-isolated.py'
SPEC = importlib.util.spec_from_file_location('persona_acl_foundation_launcher', PATH)
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class AclFoundationLauncherContract(unittest.TestCase):
    def test_product_summary_uses_existing_four_store_owner_without_allocation(self):
        fixture, prefix, stores, count = LAUNCHER.SUITES['persona-product-canonical']
        self.assertEqual(fixture, 'tests/postgres/secureshopPersonaProductCanonical.integration.test.js')
        self.assertEqual(prefix, 'PERSONA_')
        self.assertEqual(stores, (('IDENTITY', 'identity'), ('FRESH', 'secureshop_agents'),
                                  ('COMMERCE', 'secureshop'), ('REVIEW', 'secureshop_review')))
        self.assertEqual(count, 1)
        result = subprocess.run([sys.executable, '-B', str(PATH), '--suite',
                                 'persona-product-canonical', '--plan'], capture_output=True,
                                text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['fixture'], fixture)
        self.assertEqual(plan['expectedTests'], 1)
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualModel'])
        self.assertNotIn('postgresql://', result.stdout)

    def test_product_summary_actual_environment_uses_main_cwd(self):
        tree = ast.parse(PATH.read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        assignment = next(node for node in main.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                    and target.slice.value == 'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE' for target in node.targets))
        code = compile(ast.fix_missing_locations(ast.Module(body=[assignment], type_ignores=[])), str(PATH), 'exec')
        workspace = Path('/private/owned/evidence/runtime/workspace')
        for suite in ('persona-product-canonical', 'conversation-purpose'):
            namespace = {'env': {}, 'args': SimpleNamespace(suite=suite), 'ROOT': LAUNCHER.ROOT, 'workspace': workspace}
            exec(code, namespace)
            self.assertEqual(namespace['env']['OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE'],
                             str(LAUNCHER.ROOT if suite == 'persona-product-canonical' else workspace))

    def test_product_summary_pin_rejects_drift_before_resources(self):
        with patch.object(LAUNCHER, 'PRODUCT_CANONICAL_FIXTURE_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), '--suite', 'persona-product-canonical', '--plan']):
            with self.assertRaisesRegex(RuntimeError, 'Product canonical fixture pin mismatch'):
                LAUNCHER.main()

    def test_frozen_fixture_and_owned_store_plan(self):
        fixture, prefix, stores, count = LAUNCHER.SUITES['acl-foundation']
        self.assertEqual(fixture, 'tests/postgres/secureshopBoundAclFoundation.integration.test.js')
        self.assertEqual(prefix, 'PERSONA_')
        self.assertEqual(stores, (('IDENTITY', 'identity'), ('FRESH', 'secureshop_agents'),
                                  ('COMMERCE', 'secureshop'), ('ACLFRESH', 'secureshop_agents')))
        self.assertEqual(count, 2)
        self.assertEqual(LAUNCHER.sha(LAUNCHER.ROOT / fixture),
                         LAUNCHER.ACL_FOUNDATION_FIXTURE_SHA256)

    def test_plan_is_current_v30_and_does_not_allocate(self):
        result = subprocess.run([sys.executable, '-B', str(PATH), '--suite',
                                 'acl-foundation', '--plan'], capture_output=True,
                                text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['expectedTests'], 2)
        self.assertEqual(plan['fixtureSha256'], LAUNCHER.ACL_FOUNDATION_FIXTURE_SHA256)
        self.assertIn('0100', plan['qualificationScope'])
        self.assertIn('current v30 fresh/populated/noop', plan['qualificationScope'])
        self.assertIn('all29 direct predecessor', plan['qualificationScope'])
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualModel'])
        self.assertNotIn('postgresql://', result.stdout)

    def test_pin_drift_fails_before_resource_setup(self):
        with patch.object(LAUNCHER, 'ACL_FOUNDATION_FIXTURE_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), '--suite', 'acl-foundation', '--plan']):
            with self.assertRaisesRegex(RuntimeError, 'fixture pin mismatch'):
                LAUNCHER.main()

    def test_current_migration_is_in_source_inventory(self):
        fixture = LAUNCHER.ROOT / LAUNCHER.SUITES['acl-foundation'][0]
        inventory = LAUNCHER.source_inventory([fixture])
        self.assertEqual(inventory[str(fixture.relative_to(LAUNCHER.ROOT))],
                         LAUNCHER.ACL_FOUNDATION_FIXTURE_SHA256)
        migration = 'db/postgres/workshop-migrations/secureshop_agents/' \
                    '0100_coupon_probe_guided_v2_registry_successor.sql'
        self.assertIn(migration, inventory)
        self.assertEqual(inventory[migration], LAUNCHER.sha(LAUNCHER.ROOT / migration))


class AclV38CurrentHostLauncherContract(unittest.TestCase):
    ARGS = ['--suite', 'acl-foundation-v38', '--acl-foundation-current-host', '--plan']

    def test_exact_v38_fixture_store_plan_and_current_host_admission(self):
        fixture, prefix, stores, count = LAUNCHER.SUITES['acl-foundation-v38']
        self.assertEqual(fixture, 'tests/postgres/secureshopMcpDescribeRegistryFoundation.integration.test.js')
        self.assertEqual(prefix, 'PERSONA_')
        self.assertEqual(stores, LAUNCHER.SUITES['acl-foundation'][2])
        self.assertEqual(count, 1)
        self.assertEqual(LAUNCHER.sha(LAUNCHER.ROOT / fixture), LAUNCHER.ACL_V38_FIXTURE_SHA256)
        result = subprocess.run([sys.executable, '-B', str(PATH), *self.ARGS],
            capture_output=True, text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertTrue(plan['repositoryOnly'])
        self.assertTrue(plan['currentHost'])
        self.assertEqual(plan['fixtureSha256'], LAUNCHER.ACL_V38_FIXTURE_SHA256)
        self.assertEqual(plan['expectedTests'], 1)
        self.assertIn('0117', plan['qualificationScope'])
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualModel'])
        self.assertNotIn('postgresql://', result.stdout)

    def test_current_host_selector_never_falls_through_to_legacy(self):
        for argv in (['--suite', 'acl-foundation-v38', '--plan'],
                     ['--suite', 'acl-foundation', '--acl-foundation-current-host', '--plan'],
                     ['--suite', 'conversation-purpose', '--acl-foundation-current-host', '--plan']):
            with self.assertRaises(SystemExit):
                LAUNCHER.arguments(argv)
        legacy = subprocess.run([sys.executable, '-B', str(PATH), '--suite', 'acl-foundation', '--plan'],
            capture_output=True, text=True, check=True)
        self.assertNotIn('currentHost', json.loads(legacy.stdout))
        self.assertNotIn('repositoryOnly', json.loads(legacy.stdout))

    def test_v38_fixture_and_admission_pin_drift_fail_before_allocation(self):
        with patch.object(LAUNCHER, 'ACL_V38_FIXTURE_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            with self.assertRaisesRegex(RuntimeError, 'ACL v38 fixture pin mismatch'):
                LAUNCHER.main()
        with patch.object(LAUNCHER, 'ACL_CURRENT_HOST_ADMISSION_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            with self.assertRaisesRegex(RuntimeError, 'Current-host runtime/helper pin mismatch'):
                LAUNCHER.main()
        with patch.object(LAUNCHER, 'ACL_PROCESS_INVENTORY_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            with self.assertRaisesRegex(RuntimeError, 'Current-host runtime/helper pin mismatch'):
                LAUNCHER.main()

    def test_v38_actor_and_cleanup_dependencies_are_source_bound(self):
        source = PATH.read_text()
        for item in ('secureshopMcpDescribeFoundationActor.js',
                     'admin_browser_current_main_admission.py', 'darwin_process_inventory.py',
                     'secureshop_bound_browser_ownership.py', 'trusted_process_inspector.py'):
            self.assertIn("ROOT/'tests/" + ('helpers/' if item.endswith('.js') else 'postgres/') + item, source)
        self.assertEqual(LAUNCHER.sha(LAUNCHER.ROOT / 'tests/helpers/secureshopMcpDescribeFoundationActor.js'),
                         LAUNCHER.ACL_V38_ACTOR_SHA256)

    def test_current_host_uses_pinned_owned_runtime_and_docker_verifiers(self):
        source = PATH.read_text()
        self.assertIn("if current_host:docker_ownership.verify_image(docker_command,image)", source)
        self.assertIn('docker_ownership.verify_daemon(docker_command,daemon_id)', source)
        self.assertIn("'--pull','never'", source)
        self.assertIn("if args.suite=='acl-foundation-v38':env['PERSONA_ACL_V38_FOUNDATION_NATIVE']='1'", source)
        self.assertIn("if current_host:env.update(DOCKER_HOST=", source)

    def test_cleanup_never_removes_an_unverified_or_already_absent_container(self):
        main = next(node for node in ast.parse(PATH.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        final = next(node for node in main.body if isinstance(node, ast.Try)).finalbody
        branch = next(node for node in final if isinstance(node, ast.If)
                      and ast.unparse(node.test) == 'attempted and (not child_retirement_unproven)')
        code = compile(ast.fix_missing_locations(ast.Module(body=[branch], type_ignores=[])), str(PATH), 'exec')
        for captured, verified, expected_removals in ((None, None, 0), ('captured-id', None, 0),
                                                       (None, 'verified-id', 1)):
            commands = []
            def fake_run(argv):
                commands.append(argv)
                return SimpleNamespace(stdout='')
            namespace = {'attempted': True, 'daemon': lambda: None,
                'inspect_owned': lambda: verified, 'container_id': captured,
                'run': fake_run, 'docker': ['docker'], 'name': 'owned-name',
                'result': {}, 'errors': [], 'child_retirement_unproven': False,
                'RuntimeError': RuntimeError, 'BaseException': BaseException}
            exec(code, namespace)
            removals = [argv for argv in commands if 'rm' in argv]
            self.assertEqual(len(removals), expected_removals)
            self.assertFalse(namespace['errors'])
            self.assertTrue(namespace['result']['containerAbsent'])

    def test_failed_child_stop_withholds_current_host_container_and_postflight(self):
        main = next(node for node in ast.parse(PATH.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        final = next(node for node in main.body if isinstance(node, ast.Try)).finalbody
        code = compile(ast.fix_missing_locations(ast.Module(body=final[:10], type_ignores=[])), str(PATH), 'exec')
        called = []
        def failed_stop(_child):
            called.append('stop')
            raise RuntimeError('owned child identity uncertain')
        def forbidden(*_args, **_kwargs):
            called.append('forbidden')
            raise AssertionError('No retirement or postflight after uncertain child stop')
        namespace = {'children': [object()], 'current_host': {'repositoryOnly': True},
            'attempted': True, 'lifecycle': SimpleNamespace(helpers=SimpleNamespace(stop_group=failed_stop),
                cleanup_owned=forbidden), 'daemon': forbidden, 'inspect_owned': forbidden,
            'run': forbidden, 'source_inventory': forbidden,
            'inventories': SimpleNamespace(inventory=forbidden), 'result': {'passed': True},
            'container_id': 'captured-id', 'docker': ['docker'], 'evidence': Path('/private/owned'),
            'name': 'owned-name'}
        exec(code, namespace)
        self.assertEqual(called, ['stop'])
        self.assertFalse(namespace['result']['passed'])
        self.assertFalse(namespace['result']['childGroupsAbsent'])
        self.assertFalse(namespace['result']['sourceUnchanged'])
        self.assertFalse(namespace['result']['dependenciesUnchanged'])
        self.assertNotIn('containerAbsent', namespace['result'])
        self.assertTrue(any('retirement withheld' in error for error in namespace['result']['cleanupErrors']))


class AclV39CurrentHostLauncherContract(unittest.TestCase):
    ARGS = ['--suite', 'acl-foundation-v39', '--acl-foundation-current-host', '--plan']

    def test_distinct_v39_fixture_plan_and_unchanged_v38(self):
        fixture, prefix, stores, count = LAUNCHER.SUITES['acl-foundation-v39']
        self.assertEqual(fixture, 'tests/postgres/secureshopMcpListRegistryFoundation.integration.test.js')
        self.assertEqual(prefix, 'PERSONA_')
        self.assertEqual(stores, LAUNCHER.SUITES['acl-foundation-v38'][2])
        self.assertEqual(count, 1)
        self.assertEqual(LAUNCHER.sha(LAUNCHER.ROOT / fixture), LAUNCHER.ACL_V39_FIXTURE_SHA256)
        result = subprocess.run([sys.executable, '-B', str(PATH), *self.ARGS],
            capture_output=True, text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['fixtureSha256'], LAUNCHER.ACL_V39_FIXTURE_SHA256)
        self.assertIn('0118', plan['qualificationScope'])
        self.assertEqual(plan['expectedTests'], 1)
        self.assertTrue(plan['repositoryOnly'])
        self.assertTrue(plan['currentHost'])
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualModel'])
        self.assertNotIn('postgresql://', result.stdout)
        older = subprocess.run([sys.executable, '-B', str(PATH), '--suite',
            'acl-foundation-v38', '--acl-foundation-current-host', '--plan'],
            capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(older.stdout)['fixtureSha256'], LAUNCHER.ACL_V38_FIXTURE_SHA256)

    def test_v39_requires_closed_selector_and_exact_fixture_pin(self):
        with self.assertRaises(SystemExit):
            LAUNCHER.arguments(['--suite', 'acl-foundation-v39', '--plan'])
        with patch.object(LAUNCHER, 'ACL_V39_FIXTURE_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            with self.assertRaisesRegex(RuntimeError, 'ACL v39 fixture pin mismatch'):
                LAUNCHER.main()
        with patch.object(LAUNCHER, 'ACL_PROCESS_INVENTORY_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            with self.assertRaisesRegex(RuntimeError, 'Current-host runtime/helper pin mismatch'):
                LAUNCHER.main()
        with patch.object(LAUNCHER, 'ACL_V39_HISTORY_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            with self.assertRaisesRegex(RuntimeError, 'Current-host runtime/helper pin mismatch'):
                LAUNCHER.main()

    def test_v39_closure_contains_exact_0118_and_shared_actor(self):
        fixture = LAUNCHER.ROOT / LAUNCHER.SUITES['acl-foundation-v39'][0]
        actor = LAUNCHER.ROOT / 'tests/helpers/secureshopMcpDescribeFoundationActor.js'
        history = LAUNCHER.ROOT / 'tests/helpers/secureshopHistoricalRegistry.js'
        inventory = LAUNCHER.source_inventory([fixture, actor, history])
        self.assertEqual(inventory[str(fixture.relative_to(LAUNCHER.ROOT))],
                         LAUNCHER.ACL_V39_FIXTURE_SHA256)
        self.assertEqual(inventory[str(actor.relative_to(LAUNCHER.ROOT))],
                         LAUNCHER.ACL_V38_ACTOR_SHA256)
        self.assertEqual(inventory[str(history.relative_to(LAUNCHER.ROOT))],
                         LAUNCHER.ACL_V39_HISTORY_SHA256)
        self.assertIn("if args.suite=='acl-foundation-v39':extra.append(ROOT/'tests/helpers/secureshopHistoricalRegistry.js')",
                      PATH.read_text())
        migration = 'db/postgres/workshop-migrations/secureshop_agents/' \
                    '0118_mcp_list_servers_registry_successor.sql'
        self.assertIn(migration, inventory)


class Identity0154CurrentHostLauncherContract(unittest.TestCase):
    ARGS = ['--suite', 'ctf-reset-memory-0154', '--ctf-reset-memory-current-host', '--plan']
    MIGRATION = 'db/postgres/identity-migrations/0154_ctf_global_reset_adaptive_memory.sql'

    def test_two_owned_identity_databases_and_truthful_sql_only_plan(self):
        fixture, prefix, stores, count = LAUNCHER.SUITES['ctf-reset-memory-0154']
        self.assertEqual(fixture, 'tests/postgres/ctfGlobalResetAdaptiveMemory.integration.test.js')
        self.assertEqual(prefix, 'PG_CTF_RESET_MEMORY_')
        self.assertEqual(stores, (('FRESH', 'identity'), ('POPULATED', 'identity')))
        self.assertEqual(count, 1)
        self.assertEqual(LAUNCHER.sha(LAUNCHER.ROOT / fixture), LAUNCHER.CTF_RESET_MEMORY_FIXTURE_SHA256)
        result = subprocess.run([sys.executable, '-B', str(PATH), *self.ARGS],
            capture_output=True, text=True, check=True)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['fixtureSha256'], LAUNCHER.CTF_RESET_MEMORY_FIXTURE_SHA256)
        self.assertEqual(plan['migrationSha256'], LAUNCHER.CTF_RESET_MEMORY_MIGRATION_SHA256)
        self.assertEqual(plan['expectedTests'], 1)
        self.assertTrue(plan['repositoryOnly'])
        self.assertTrue(plan['currentHost'])
        self.assertIn('0154', plan['qualificationScope'])
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualModel'])
        self.assertNotIn('postgresql://', result.stdout)

    def test_identity_selector_is_exclusive_and_pins_fixture_migration_and_runtime(self):
        for argv in (['--suite', 'ctf-reset-memory-0154', '--plan'],
                     ['--suite', 'acl-foundation-v38', '--ctf-reset-memory-current-host', '--plan'],
                     ['--suite', 'ctf-reset-memory-0154', '--acl-foundation-current-host', '--plan']):
            with self.assertRaises(SystemExit):
                LAUNCHER.arguments(argv)
        for name, replacement, message in (
            ('CTF_RESET_MEMORY_FIXTURE_SHA256', '0' * 64, 'Identity 0154 fixture pin mismatch'),
            ('CTF_RESET_MEMORY_MIGRATION_SHA256', '0' * 64, 'Identity 0154 migration pin mismatch'),
            ('ACL_PROCESS_INVENTORY_SHA256', '0' * 64, 'Current-host runtime/helper pin mismatch')):
            with self.subTest(name=name), patch.object(LAUNCHER, name, replacement), \
                 patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
                with self.assertRaisesRegex(RuntimeError, message):
                    LAUNCHER.main()
        with patch.object(LAUNCHER, 'ACL_V38_ACTOR_SHA256', '0' * 64), \
             patch.object(LAUNCHER, 'ACL_V39_HISTORY_SHA256', '0' * 64), \
             patch.object(sys, 'argv', [str(PATH), *self.ARGS]):
            self.assertEqual(LAUNCHER.main(), 0)

    def test_selected_0154_closure_and_actual_env_database_shape(self):
        fixture = LAUNCHER.ROOT / LAUNCHER.SUITES['ctf-reset-memory-0154'][0]
        migration = LAUNCHER.ROOT / self.MIGRATION
        inventory = LAUNCHER.source_inventory([fixture, migration])
        self.assertEqual(inventory[str(fixture.relative_to(LAUNCHER.ROOT))],
                         LAUNCHER.CTF_RESET_MEMORY_FIXTURE_SHA256)
        self.assertEqual(inventory[self.MIGRATION], LAUNCHER.CTF_RESET_MEMORY_MIGRATION_SHA256)
        source = PATH.read_text()
        self.assertIn("if args.suite=='ctf-reset-memory-0154':env['CTF_GLOBAL_RESET_MEMORY_NATIVE']='1'", source)
        self.assertIn("database='owasp_ai_goat_test_ctf_reset_memory_'+nonce[:12]+'_'+store.lower()", source)
        self.assertIn("extra.append(ROOT/'db/postgres/identity-migrations/0154_ctf_global_reset_adaptive_memory.sql')", source)
        self.assertEqual(LAUNCHER.CTF_RESET_MEMORY_TAP_TITLE,
                         'identity 0154 Full Reset ACK clears adaptive memory only on ordered first application')


if __name__ == '__main__':
    unittest.main()


class PricingCanonicalLauncherContract(unittest.TestCase):
    def test_closed_selector_and_default_plan_allocate_nothing(self):
        for extra,cohort in [([], 'blocked-denial'),(['--pricing-cohort','canonical-current'],'canonical-current')]:
            run=subprocess.run([sys.executable,'-B',str(PATH),'--suite','pricing-journal','--plan',*extra],capture_output=True,text=True,check=True)
            plan=json.loads(run.stdout)
            self.assertEqual(plan['pricingCohort'],cohort);self.assertFalse(plan['allocationStarted']);self.assertFalse(plan['sourceCopies']);self.assertFalse(plan['actualModel']);self.assertEqual(plan['expectedTests'],1);self.assertEqual(len(plan['stores']),5)
            self.assertEqual(plan['fixtureSha256'],LAUNCHER.PRICING_JOURNAL_FIXTURE_SHA256)
            if extra:self.assertEqual(plan['qualificationScope'],LAUNCHER.PRICING_CANONICAL_SCOPE);self.assertEqual(plan['expectedArtifact'],'pricing-journal-result.json')
        for argv in [['--suite','conversation-purpose','--pricing-cohort','canonical-current'],['--suite','pricing-journal','--pricing-cohort','unknown']]:
            with self.assertRaises(SystemExit):LAUNCHER.arguments(argv)

    def test_actual_environment_preserves_blocked_default_and_selects_canonical_only(self):
        tree=ast.parse(PATH.read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        branch=next(n for n in main.body if isinstance(n,ast.If) and ast.unparse(n.test)=="args.suite == 'pricing-journal'" and any(isinstance(x,ast.Assign) and any(isinstance(t,ast.Subscript) and isinstance(t.slice,ast.Constant) and t.slice.value=='PERSONA_PRICING_NATIVE' for t in x.targets) for x in n.body))
        code=compile(ast.Module(body=branch.body,type_ignores=[]),str(PATH),'exec')
        for selected in [None,'blocked-denial','canonical-current']:
            env={'PERSONA_PRICING_BLOCKED_NATIVE':'1'};ns={'env':env,'args':SimpleNamespace(pricing_cohort=selected),'ROOT':LAUNCHER.ROOT,'workspace':Path('/owned/output')};exec(code,ns)
            self.assertEqual(env['PERSONA_PRICING_NATIVE'],'1');self.assertEqual(env['PERSONA_PRICING_CANONICAL'],'1');self.assertEqual(env['OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE'],str(LAUNCHER.ROOT));self.assertEqual(env['OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT'],'/owned/output')
            if selected=='canonical-current':self.assertNotIn('PERSONA_PRICING_BLOCKED_NATIVE',env)
            else:self.assertEqual(env['PERSONA_PRICING_BLOCKED_NATIVE'],'1')
            self.assertNotIn('PERSONA_PRICING_ACTUAL',env);self.assertNotIn('PERSONA_PRICING_HTTP_NATIVE',env)

    def test_fixture_drift_stops_before_resources(self):
        with patch.object(LAUNCHER,'PRICING_JOURNAL_FIXTURE_SHA256','0'*64),patch.object(sys,'argv',[str(PATH),'--suite','pricing-journal','--pricing-cohort','canonical-current','--plan']):
            with self.assertRaisesRegex(RuntimeError,'Pricing journal fixture pin mismatch'):LAUNCHER.main()
