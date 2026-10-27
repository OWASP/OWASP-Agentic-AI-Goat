"""V27 scoped controls without native processes, browser or model."""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


L = load('run-secureshop-policy-output-browser.py')
C = load('run_policy_output_with_inspector.py')


class Admission(unittest.TestCase):
    def test_closed_selection(self):
        args = ['--cohort', L.COHORT, '--policy-output-browser', '--policy-output-test-no-sandbox']
        self.assertEqual(L.arguments(args), args[:-1])
        for bad in (args[:-1], args + [args[-1]], ['--cohort', 'foreign', *args[2:]], args[:2] + args[3:]):
            with self.assertRaises(RuntimeError):
                L.arguments(bad)
        outer = []
        for key in C.REQUIRED:
            outer += [key, str(C.ROOT) if key == '--main-workspace' else C.COHORT if key == '--cohort' else 'controlled']
        outer += ['--run', *args[2:]]
        command = C.child_command(outer)
        self.assertEqual(command[:2], ['/bin/bash', str(C.ROOT / 'tasks/run-in-repository.sh')])
        self.assertNotIn('--run', command)
        with self.assertRaises(RuntimeError):
            C.child_command(outer + ['--shell', 'arbitrary'])

    def test_original_environment_and_nested_profile(self):
        evidence = L.ROOT / 'tasks/qualification/run-1234abcd/standalone-ssrf-rendered'
        env = {'SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE': '1', 'SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE': '1',
               'SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE': '1',
               'SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH': str(evidence / 'result.json'),
               'OLLAMA_CONTEXT_WINDOW': 'original', 'RUNTIME_URL': 'runtime', 'MIGRATION_URL': 'migration'}
        actual, root = L.owned_environment(env, NS(browser_sha256='a' * 64))
        self.assertEqual(root, evidence)
        for key, value in env.items():
            self.assertEqual(actual[key], value)
        with self.assertRaises(RuntimeError):
            L.owned_environment({**env, 'SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE': '0'}, NS())

    def test_independent_direct_node(self):
        watcher, ownership = L.lifecycle()
        original = L.load(L.LIFECYCLE, 'unchanged_v12')
        self.assertEqual(original.KIND, 'idor_lesson_browser')
        self.assertEqual(watcher.KIND, 'policy_output_browser')
        parsed = NS(node='node')
        self.assertEqual(watcher.direct_command(['node', '--test', '--test-reporter=tap',
            '--test-concurrency=1', L.TEST], parsed), ['node', '--test-reporter=tap', L.TEST])

    def capture(self, change=None):
        # This helper isolates the original low-level birth/no-signal API.
        # The complete singleton-aware lifecycle is exercised separately.
        ownership = L.load(L.OWNERSHIP, 'policy_low_level_capture_ownership')
        uid = os.getuid()
        parent = NS(pid=100, ppid=99, uid=uid, ruid=uid, pgid=100, start_sec=1, start_usec=2, status=1)
        browser = NS(pid=101, ppid=100, uid=uid, ruid=uid, pgid=100, start_sec=3, start_usec=4, status=1)
        record = {'pid':101, 'parentPid':100, 'pgid':100, 'sessionId':100, 'uid':uid,
                  'birth':[3,4], 'executablePath':'/chrome'}
        runtime = L.ROOT / 'tasks/qualification/run-1234abcd/standalone-ssrf-rendered/runtime'
        argv = ['/chrome', '--user-data-dir=' + str(runtime / 'browser-profile')]
        if change:
            change(record, parent, browser, argv)
        api = NS(identity=lambda pid: parent if pid == 100 else browser, arguments=lambda pid: argv)
        with patch.object(ownership, '_browser_modules', return_value=(None, 99, None, None, Mock())):
            captured = L.capture_live_policy(record, (1,2), runtime, api=api, ownership=ownership, getsid=lambda pid:100)
        return captured, ownership, api

    def test_same_group_capture_and_no_signal_authority(self):
        captured, ownership, api = self.capture()
        absent = Mock(return_value=[{'absent':True}])
        signal = Mock(side_effect=AssertionError('must not signal Node group'))
        with patch.object(ownership, '_browser_modules', return_value=(None, None, None, None, absent)):
            ownership.retire_live_v36(captured, api=api, killpg=signal)
        signal.assert_not_called()
        absent.assert_called_once_with([captured.record], api=api)
        with self.assertRaises(RuntimeError):
            ownership.retire_live_v36(captured.record, api=api, killpg=signal)

    def test_reject_foreign_birth_parent_group_profile(self):
        changes = [
            lambda r,p,b,a: r.update(pgid=101, sessionId=101),
            lambda r,p,b,a: setattr(p,'start_sec',9),
            lambda r,p,b,a: setattr(b,'start_usec',9),
            lambda r,p,b,a: setattr(b,'ppid',999),
            lambda r,p,b,a: a.__setitem__(1,'--user-data-dir=/foreign'),
        ]
        for change in changes:
            with self.assertRaises(RuntimeError):
                self.capture(change)

    def test_failure_checks_profile_and_preserves_primary(self):
        primary = RuntimeError('original V27 failure')
        owner = NS(captured=object(), evidence=None, error=None, retired=None)
        shared = NS(subprocess=NS(Popen=object()), main=lambda args: (_ for _ in ()).throw(primary))
        for failure in (None, RuntimeError('profile remains')):
            with patch.object(L,'lifecycle',return_value=(NS(BrowserOwner=lambda *a:owner),object())), \
                    patch.object(L,'inventory',return_value={}), \
                    patch.object(L,'verify_retirement',side_effect=failure) as checked:
                with self.assertRaises(RuntimeError) as raised:
                    L.run(shared, [], NS(), {})
                self.assertIs(raised.exception,primary)
                checked.assert_called_once()

    def test_exact_profile_absence(self):
        root = L.ROOT / 'tasks/qualification/run-1234abcd/standalone-ssrf-rendered'
        owner = NS(evidence=root,captured=NS(profile=str(root/'runtime/browser-profile'),record={}))
        ownership = NS(_browser_modules=lambda:(None,None,None,None,Mock()))
        with patch.object(Path,'exists',return_value=False), patch.object(Path,'is_symlink',return_value=False):
            L.verify_retirement(owner,ownership)
        with patch.object(Path,'exists',return_value=True):
            with self.assertRaises(RuntimeError):
                L.verify_retirement(owner,ownership)
        owner.captured.profile='/foreign'
        with self.assertRaises(RuntimeError):
            L.verify_retirement(owner,ownership)

    def test_postspawn_capture_setup_failure_returns_owned_child(self):
        watcher, _ = L.lifecycle()
        primary = RuntimeError('capture setup failed')
        child = NS(pid=100, wait=lambda **kwargs:0)
        ownership = NS(_browser_modules=lambda:(_ for _ in ()).throw(primary))
        parsed = NS(node='node')
        owner = watcher.BrowserOwner(lambda *a,**kw:child,parsed,ownership)
        command = ['node','--test','--test-reporter=tap','--test-concurrency=1',L.TEST]
        with patch.object(watcher,'owned_environment',return_value=({},L.ROOT)):
            self.assertIs(owner(command,env={}),child)
        with self.assertRaises(RuntimeError) as raised:
            child.wait(timeout=1)
        self.assertIs(raised.exception,primary)
        self.assertEqual(child.wait(timeout=1),0)

    def test_late_descendants_preserve_timeout_and_shared_child_handle(self):
        watcher, _ = L.lifecycle()
        primary = TimeoutError('original Node timeout')
        parent = NS(ppid=os.getpid(),uid=os.getuid(),ruid=os.getuid(),pgid=100,status=1,start_sec=1,start_usec=2)
        child = NS(pid=100,wait=lambda **kw:(_ for _ in ()).throw(primary))
        retire = Mock(side_effect=RuntimeError('late descendant remains for shared cleanup'))
        ownership = NS(_browser_modules=lambda:(lambda:NS(identity=lambda pid:parent),99,None,None,None),
                       retire_live_v36=retire)
        thread = NS(start=lambda:None,join=lambda **kw:None,is_alive=lambda:False)
        owner = watcher.BrowserOwner(lambda *a,**kw:child,NS(node='node'),ownership)
        command = ['node','--test','--test-reporter=tap','--test-concurrency=1',L.TEST]
        with patch.object(watcher,'owned_environment',return_value=({},L.ROOT)), \
                patch.object(watcher.os,'getsid',return_value=100), \
                patch.object(watcher.threading,'Thread',return_value=thread):
            self.assertIs(owner(command,env={}),child)
        owner.captured=object()
        with self.assertRaises(TimeoutError) as raised:
            child.wait(timeout=1)
        self.assertIs(raised.exception,primary)
        retire.assert_called_once()
        self.assertIsNotNone(owner.error)

    def test_frozen_sources(self):
        L.validate_pins()
        self.assertTrue(set(L.PINS)<=L.inventory().keys())


if __name__ == '__main__':
    unittest.main()
