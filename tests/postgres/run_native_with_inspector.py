#!/usr/bin/env python3
"""Outside read-only process inspector around the unchanged repository sandbox.

Usage: python3 -B tests/postgres/run_native_with_inspector.py [native options]
Only the fixed local native wrapper is executed. No model or browser is started
by the inspector itself; native options retain the launcher's admission gates.
"""

import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys

from trusted_process_inspector import FD_ENV, Inspector, receive, send


def coordinate(repo, arguments):
    if sys.platform != 'darwin':
        raise RuntimeError('Outside inspector is Darwin-only')
    repo = Path(repo).resolve()
    wrapper = repo / 'tasks' / 'run-native-current.sh'
    if wrapper.is_symlink() or not wrapper.is_file():
        raise RuntimeError('Current-source native wrapper required')
    parent, worker = socket.socketpair()
    parent.settimeout(15)
    environment = dict(os.environ)
    if FD_ENV in environment:
        raise RuntimeError('Nested inspector is not supported')
    environment[FD_ENV] = str(worker.fileno())
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    child = None
    try:
        child = subprocess.Popen(['/bin/bash', str(wrapper), *arguments], cwd=repo,
                                 env=environment, close_fds=True,
                                 pass_fds=(worker.fileno(),))
        worker.close()
        inspector = Inspector(repo, child.pid)
        while child.poll() is None:
            ready, _, _ = select.select([parent], [], [], 0.25)
            if ready:
                if not parent.recv(1, socket.MSG_PEEK):
                    break
                request = receive(parent)
                try:
                    response = inspector.handle(request)
                except Exception:
                    # No host command lines or exception details cross the channel.
                    send(parent, {'request': request, 'absent': False, 'error': 'inspection-failed'})
                    # The launcher must execute its own resource-cleanup finally.
                    # Closing this capability denies subsequent checks; never kill
                    # the launcher merely because inspection failed.
                    parent.close()
                    return child.wait()
                send(parent, response)
        return child.wait()
    except KeyboardInterrupt:
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGINT)
        raise
    finally:
        parent.close()
        worker.close()
        if child is not None and child.poll() is None:
            # Channel closure makes inspection fail closed inside the worker;
            # let its existing finally clean owned browser/container resources.
            child.wait()


if __name__ == '__main__':
    raise SystemExit(coordinate(Path(__file__).resolve().parents[2], sys.argv[1:]))
