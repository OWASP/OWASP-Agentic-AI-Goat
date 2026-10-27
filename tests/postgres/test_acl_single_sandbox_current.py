"""Intended destination: tests/postgres/test_acl_single_sandbox_current.py.

Exercise the actual Inspector child command without a database or browser.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]  # destination tests/postgres/
sys.path.insert(0, str(ROOT / 'tests/postgres'))
import run_acl_permission_with_inspector as inspector


class SingleSandboxCurrent(unittest.TestCase):
    def test_exact_one_sandbox_and_strict_write_boundary(self):
        packet = json.loads((ROOT / 'tasks/qualification/acl-current-host-frozen-plan.json').read_text())
        argv = packet['argv'][:]
        argv[0] = '--run'
        argv += ['--snapshot-sha256', packet['plan']['snapshotSha256']]
        child = inspector.child_command(argv)
        self.assertEqual(child[:2], ['/usr/bin/sandbox-exec', '-p'])
        self.assertEqual(child.count('/usr/bin/sandbox-exec'), 1)
        self.assertNotIn('tasks/run-in-repository.sh', ' '.join(child))
        self.assertEqual(child[3:5], [sys.executable, '-B'])
        self.assertEqual(child[5], str(ROOT / 'tests/postgres/run-acl-permission-current-host.py'))
        self.assertEqual(child[6:], argv)
        self.assertIn('(deny file-write*)', child[2])
        self.assertIn('(subpath "' + str(ROOT / 'tasks/qualification') + '")', child[2])
        self.assertIn('(subpath "' + str(ROOT / 'tasks/tmp') + '")', child[2])

        # The same actual profile permits a fresh owned file but denies writes
        # to repository source and outside the repository; no network/DB used.
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp', prefix='acl-single-current-') as directory:
            nonce = Path(directory).name
            script = '''import errno,os,sys
allowed,source,outside=sys.argv[1:]
fd=os.open(allowed,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'owned');os.close(fd);os.unlink(allowed)
for target in (source,outside):
 try: fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 except OSError as e: assert e.errno in (errno.EPERM,errno.EACCES)
 else:
  os.close(fd);os.unlink(target);raise AssertionError('write containment absent')
print('owned write allowed; source and outside writes denied')
'''
            result = subprocess.run(child[:3] + [sys.executable, '-B', '-c', script,
                str(Path(directory) / 'owned'), str(ROOT / 'tests' / nonce),
                '/private/tmp/' + nonce], cwd=ROOT, capture_output=True, text=True,
                timeout=10, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TMPDIR=directory))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(),
                'owned write allowed; source and outside writes denied')


if __name__ == '__main__':
    unittest.main()
