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
                    and target.slice.value == 'DVAIA_ISOLATED_TEST_WORKSPACE' for target in node.targets))
        code = compile(ast.fix_missing_locations(ast.Module(body=[assignment], type_ignores=[])), str(PATH), 'exec')
        workspace = Path('/private/owned/evidence/runtime/workspace')
        for suite in ('persona-product-canonical', 'conversation-purpose'):
            namespace = {'env': {}, 'args': SimpleNamespace(suite=suite), 'ROOT': LAUNCHER.ROOT, 'workspace': workspace}
            exec(code, namespace)
            self.assertEqual(namespace['env']['DVAIA_ISOLATED_TEST_WORKSPACE'],
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
            self.assertEqual(env['PERSONA_PRICING_NATIVE'],'1');self.assertEqual(env['PERSONA_PRICING_CANONICAL'],'1');self.assertEqual(env['DVAIA_ISOLATED_TEST_WORKSPACE'],str(LAUNCHER.ROOT));self.assertEqual(env['DVAIA_PRICING_OWNED_OUTPUT_ROOT'],'/owned/output')
            if selected=='canonical-current':self.assertNotIn('PERSONA_PRICING_BLOCKED_NATIVE',env)
            else:self.assertEqual(env['PERSONA_PRICING_BLOCKED_NATIVE'],'1')
            self.assertNotIn('PERSONA_PRICING_ACTUAL',env);self.assertNotIn('PERSONA_PRICING_HTTP_NATIVE',env)

    def test_fixture_drift_stops_before_resources(self):
        with patch.object(LAUNCHER,'PRICING_JOURNAL_FIXTURE_SHA256','0'*64),patch.object(sys,'argv',[str(PATH),'--suite','pricing-journal','--pricing-cohort','canonical-current','--plan']):
            with self.assertRaisesRegex(RuntimeError,'Pricing journal fixture pin mismatch'):LAUNCHER.main()
