import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).with_name('run-admin-auth-browser-cohort-isolated.py')
spec = importlib.util.spec_from_file_location('dpi_selector', path)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class ContainmentSelector(unittest.TestCase):
    def tearDown(self):
        launcher.configure_cohort('full')

    def test_closed_two_store_cohort_without_browser(self):
        launcher.configure_cohort('dpi-containment')
        self.assertEqual(launcher.SCOPE, 'dpi_semantic_containment_pg18')
        self.assertEqual(launcher.NODE_VERSION, 'v26.10.0')
        self.assertEqual(len(launcher.SUITES), 1)
        suite = launcher.SUITES[0]
        self.assertEqual(suite['test'], 'tests/postgres/dpiSemanticCreditContainment.integration.test.js')
        self.assertEqual(suite['timeoutSeconds'], 300)
        plan = launcher.database_plan('abcdef123456')
        self.assertEqual(len(set(plan.values())), 2)
        env = launcher.suite_environment({'PG_TEST_DISPOSABLE': 'yes'}, suite, plan, 12345)
        self.assertEqual(env['DPI_CONTAINMENT_ISOLATED'], '1')
        self.assertNotIn('RUN_ADMIN_PRODUCTION_BROWSER', env)
        for label, key in [('FRESH', 'dpiSemanticContainment'), ('POPULATED', 'dpiSemanticContainmentPopulated')]:
            self.assertEqual(env[f'PG_DPI_CONTAINMENT_{label}_RUNTIME_URL'],
                f'postgresql://dvaia_identity_runtime@127.0.0.1:12345/{plan[key]}')
            self.assertEqual(env[f'PG_DPI_CONTAINMENT_{label}_MIGRATION_URL'],
                f'postgresql://dvaia_identity_migration@127.0.0.1:12345/{plan[key]}')
        self.assertEqual(launcher.cohort_resource_args('dpi-containment'),
            ['--memory', '1g', '--cpus', '1', '--pids-limit', '128'])

    def test_missing_secondary_store_fails_closed(self):
        launcher.configure_cohort('dpi-containment')
        plan = launcher.database_plan('abcdef123456')
        del plan['dpiSemanticContainmentPopulated']
        with self.assertRaises(KeyError):
            launcher.suite_environment({}, launcher.SUITES[0], plan, 12345)
        with self.assertRaises(ValueError):
            launcher.database_plan('app_database')

    def test_existing_selectors_restore_exact_original_suites(self):
        launcher.configure_cohort('dpi-containment')
        launcher.configure_cohort('full')
        self.assertEqual(launcher.SUITES, launcher.FULL_SUITES)
        self.assertEqual(len(launcher.database_plan('abcdef123456')), 4)
        self.assertEqual(launcher.cohort_resource_args('full'), [])
        launcher.configure_cohort('analytics-only')
        self.assertEqual([s['name'] for s in launcher.SUITES], ['adminProgressAnalytics'])
        self.assertEqual(len(launcher.database_plan('abcdef123456')), 1)
        self.assertEqual(launcher.cohort_resource_args('analytics-only'), [])
        with self.assertRaises(ValueError):
            launcher.configure_cohort('dpi-arbitrary')
