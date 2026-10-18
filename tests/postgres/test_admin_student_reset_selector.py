import importlib.util, pathlib, tempfile, types, unittest
p = pathlib.Path(__file__).with_name('run-admin-auth-browser-cohort-isolated.py')
s = importlib.util.spec_from_file_location('student_reset_selector', p)
m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
class Selector(unittest.TestCase):
    def tearDown(self): m.configure_cohort('full')
    def test_closed_selection_distinct_stores_and_minimum_roles(self):
        m.configure_cohort('student-reset-only')
        plan = m.database_plan('abcdef123456')
        self.assertEqual(len(plan), 2); self.assertEqual(len(set(plan.values())), 2)
        self.assertEqual(m.SCOPE, 'admin_student_reset_pg18')
        self.assertEqual(m.NODE_VERSION, 'v26.10.0')
        self.assertEqual(m.SUITES[0]['timeoutSeconds'], 480)
        env = m.suite_environment({}, m.SUITES[0], plan, 1234)
        self.assertIn('dvaia_identity_runtime@', env['PG_ADMIN_BROWSER_TEST_RUNTIME_URL'])
        self.assertIn('dvaia_finflow_runtime@', env['FINFLOW_WORKSHOP_DATABASE_URL'])
        self.assertIn('dvaia_finflow_migration@', env['FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL'])
        self.assertEqual(env['ADMIN_STUDENT_RESET_ONLY'], '1')
        self.assertEqual(env['RUN_ADMIN_PRODUCTION_BROWSER'], '1')
        self.assertEqual(m.cohort_resource_args('student-reset-only'), ['--memory','1g','--cpus','1','--pids-limit','128'])
    def test_exact_grant_names_both_databases_and_role_bindings(self):
        m.configure_cohort('student-reset-only')
        with tempfile.TemporaryDirectory() as directory:
            handle = pathlib.Path(directory) / 'owner'; handle.write_text('123')
            args = types.SimpleNamespace(package_root=directory, owner_handle_file=str(handle), container_nonce='abcdef123456',
                grant_id='test', canonical_workspace=directory, managed_node='/node', chromium='/chromium', evidence_root=directory,
                cohort='student-reset-only')
            manifest = dict(sourceFilesSha256='s', dependencyFilesSha256='d', dependencySymlinksSha256='l')
            grant = m.expected_grant(args, manifest, 123, 'n', 'c', 'm')
            self.assertEqual(grant['databasePlan'], m.database_plan('abcdef123456'))
            self.assertEqual(grant['databaseRoles'], m.database_roles())
            self.assertEqual(set(grant['databasePlan']), set(grant['databaseRoles']))
    def test_full_unchanged_and_unknown_mode_rejected(self):
        m.configure_cohort('full'); self.assertEqual(len(m.SUITES), 4)
        self.assertEqual(len(m.database_plan('abcdef123456')), 4)
        self.assertEqual(m.NODE_VERSION, 'v26.9.0')
        self.assertRaises(ValueError, m.configure_cohort, 'student-reset-any-store')

    def test_real_cli_closed_mode_flags(self):
        fields = ('package-root','manifest','managed-node','chromium','docker-host','postgres-image-id',
                  'container-nonce','evidence-root','grant-file','grant-id','owner','owner-handle-file',
                  'canonical-workspace','scope')
        argv = [item for name in fields for item in ('--'+name, 'fixture')]
        self.assertEqual(m.parse_args(argv + ['--cohort','student-reset-only']).cohort, 'student-reset-only')
        import contextlib, io
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            m.parse_args(argv + ['--cohort','student-reset-unbounded'])
