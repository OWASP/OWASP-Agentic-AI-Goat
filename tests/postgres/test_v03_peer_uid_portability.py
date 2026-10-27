"""Offline real inherited-socket controls for the current V03 UID admission."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'tests/postgres'))
from darwin_process_inventory import LibProc
from trusted_process_inspector import peer_identity
import trusted_process_inspector

import v03_private_executors as actual
RUN_ID = 'a' * 32
PLAN_SHA256 = 'b' * 64


def child_main(packet):
    fd = packet['fd']
    mode = packet['mode']
    module = actual
    if mode == 'wrong-uid':
        trusted_process_inspector.peer_identity = lambda channel: (os.getppid(), os.getuid() + 1)
    elif mode == 'lookup-failure':
        def failed_lookup(channel):
            raise RuntimeError('Inspector peer credentials unavailable')
        trusted_process_inspector.peer_identity = failed_lookup
    identity = packet['parentIdentity']
    argv = packet['parentArgv']
    if mode == 'wrong-birth':
        identity = dict(identity, birth=[identity['birth'][0], identity['birth'][1] + 1])
    if mode == 'wrong-argv':
        argv = [*argv, '--untrusted']
    try:
        facade = module.V03PrivateExecutors.from_inherited_fd(fd, run_id=RUN_ID,
            plan_sha256=PLAN_SHA256, parent_identity=identity, parent_argv=argv)
    except BaseException as error:
        if mode in ('wrong-uid', 'lookup-failure'):
            try:
                os.fstat(fd)
            except OSError as closed:
                assert closed.errno == errno.EBADF
            else:
                raise AssertionError('Rejected inherited channel was left open')
        else:
            os.close(fd)
        return {'accepted': False, 'errorType': type(error).__name__, 'errorCode': str(error)}
    try:
        assert mode == 'valid'
        assert facade.parent_identity == packet['parentIdentity']
        assert facade.parent_argv == packet['parentArgv']
        facade._parent()
        return {'accepted': True, 'peerUid': os.getuid(), 'state': facade.state}
    finally:
        facade.channel.close()


class V03PeerUidPortability(unittest.TestCase):
    def test_current_admission_pins_imported_helper(self):
        source = (ROOT / 'tests/postgres/v03_private_executors.py').read_text()
        self.assertNotIn('channel.getpeereid()', source)
        self.assertEqual(source.count("'tests/postgres/trusted_process_inspector.py'"), 1)
        self.assertEqual(source.count('peer_identity(channel)[1] != os.getuid()'), 1)
        self.assertIn('_identity(api.identity(os.getppid())) != parent_identity', source)
        self.assertIn('list(api.arguments(os.getppid())) != parent_argv', source)

    def test_actual_inherited_parent_child_socket_and_fail_closed_variants(self):
        api = LibProc()
        parent_identity = actual._identity(api.identity(os.getpid()))
        self.assertIsNotNone(parent_identity)
        parent_argv = list(api.arguments(os.getpid()))
        for mode in ('valid', 'wrong-uid', 'lookup-failure', 'wrong-birth', 'wrong-argv'):
            with self.subTest(mode=mode):
                parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    self.assertEqual(peer_identity(child)[1], os.getuid())
                    packet = {'fd': child.fileno(), 'mode': mode,
                        'parentIdentity': parent_identity, 'parentArgv': parent_argv}
                    command = [sys.executable, '-B', str(Path(__file__).resolve()),
                        '--child', json.dumps(packet, separators=(',', ':'))]
                    result = subprocess.run(command, pass_fds=(child.fileno(),),
                        capture_output=True, text=True, timeout=15, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr[:500])
                    answer = json.loads(result.stdout)
                    if mode == 'valid':
                        self.assertEqual(answer, {'accepted': True, 'peerUid': os.getuid(), 'state': 'new'})
                    else:
                        self.assertFalse(answer['accepted'])
                        self.assertEqual(answer['errorCode'],
                            'V03_PARENT_CHANNEL' if mode == 'wrong-uid' else
                            'Inspector peer credentials unavailable' if mode == 'lookup-failure' else
                            'V03_PARENT_BIRTH')
                finally:
                    child.close()
                    parent.close()


if __name__ == '__main__':
    if sys.argv[1:2] == ['--child']:
        print(json.dumps(child_main(json.loads(sys.argv[2])), separators=(',', ':')))
    else:
        unittest.main()
