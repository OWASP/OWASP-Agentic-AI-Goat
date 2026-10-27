"""Real pinned Node preload controls with an inherited OS pipe; no VM/network."""
import fcntl
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
NODE = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
PRELOAD = ROOT / 'tests/postgres/v03_browser_start_barrier.js'
FIXTURE = ROOT / 'tests/postgres/v03_browser_start_barrier_fixture.js'
CLOSE_FAILURE = ROOT / 'tests/postgres/v03_browser_start_barrier_close_failure.js'


class BarrierControls(unittest.TestCase):
    def run_child(self, release, command=None, before=(), extra_env=None):
        owned = set()
        child = None
        try:
            read, write = os.pipe()
            owned.update((read, write))
            child_fd = fcntl.fcntl(read, fcntl.F_DUPFD, 5)
            owned.add(child_fd)
            os.close(read)
            owned.remove(read)
            child = subprocess.Popen([str(NODE), *sum((['--require', str(path)] for path in before), []),
                '--require', str(PRELOAD), *(command or
                ['-e', 'process.stdout.write("BARRIER_BODY_RAN")'])], cwd=ROOT,
                env={**os.environ, 'SECURESHOP_V03_PRIVATE_START_FD': str(child_fd),
                    **(extra_env or {})},
                pass_fds=(child_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(child_fd)
            owned.remove(child_fd)
            if release is not None:
                os.write(write, release)
            os.close(write)
            owned.remove(write)
            output, error = child.communicate(timeout=5)
            return child.returncode, output.decode(), error.decode()
        except BaseException:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
            raise
        finally:
            for descriptor in tuple(owned):
                try: os.close(descriptor)
                except OSError: pass

    def test_exact_release_precedes_body(self):
        code, output, error = self.run_child(b'G')
        self.assertEqual(code, 0, error)
        self.assertEqual(output, 'BARRIER_BODY_RAN')

    def test_eof_wrong_and_extra_bytes_deny(self):
        for release in (None, b'X', b'GG'):
            with self.subTest(release=release):
                code, output, error = self.run_child(release)
                self.assertNotEqual(code, 0)
                self.assertNotIn('BARRIER_BODY_RAN', output)
                self.assertIn('V03_PRIVATE_START_BARRIER_DENIED', error)

    def test_original_node_test_mode_is_released_once(self):
        code, output, error = self.run_child(b'G', ['--test', '--test-reporter=tap', str(FIXTURE)])
        self.assertEqual(code, 0, output + error)
        self.assertIn('# pass 1', output)

    def test_descriptor_close_failure_denies_even_after_correct_release(self):
        code, output, error = self.run_child(b'G', before=(CLOSE_FAILURE,))
        self.assertNotEqual(code, 0)
        self.assertNotIn('BARRIER_BODY_RAN', output)
        self.assertIn('V03_PRIVATE_START_BARRIER_DENIED', error)

    def test_forged_parent_marker_cannot_bypass_raw_pipe(self):
        marker = f'{os.getpid()}:' + 'a'*64
        code, output, error = self.run_child(b'G', extra_env={
            'SECURESHOP_V03_PRIVATE_START_GRANTED': marker,
            'NODE_TEST_CONTEXT': 'child-v8'})
        self.assertNotEqual(code, 0)
        self.assertNotIn('BARRIER_BODY_RAN', output)
        self.assertIn('V03_PRIVATE_START_BARRIER_DENIED', error)

    def test_worker_marker_requires_real_context_and_parent_pid(self):
        for context, parent in ((None, os.getpid()), ('child-v8', 1)):
            env = {**os.environ, 'SECURESHOP_V03_PRIVATE_START_GRANTED': f'{parent}:'+'a'*64}
            env.pop('SECURESHOP_V03_PRIVATE_START_FD', None)
            if context is None: env.pop('NODE_TEST_CONTEXT', None)
            else: env['NODE_TEST_CONTEXT'] = context
            process = subprocess.run([str(NODE), '--require', str(PRELOAD), '-e',
                'process.stdout.write("BARRIER_BODY_RAN")'], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assertNotIn('BARRIER_BODY_RAN', process.stdout)


if __name__ == '__main__':
    unittest.main()
