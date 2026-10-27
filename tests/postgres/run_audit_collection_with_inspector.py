#!/usr/bin/env python3
"""Fixed V36 adapter launcher with an outside, read-only process inspector."""
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys

try:
    from trusted_process_inspector import FD_ENV, Inspector, receive, send
except ModuleNotFoundError:
    from tests.postgres.trusted_process_inspector import FD_ENV, Inspector, receive, send

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'secureshop-admin-audit-collection-browser-current-main-v1'
REQUIRED_VALUES = frozenset(('--main-workspace', '--node', '--node-sha256', '--docker',
    '--docker-sha256', '--docker-host', '--docker-daemon', '--image-id',
    '--current-host-profile', '--cohort', '--browser', '--browser-sha256',
    '--browser-root', '--ollama-model-sha256', '--evidence-parent'))
OPTIONAL_VALUES = frozenset(('--embedding-cache',))


def validate_arguments(arguments):
    values, flags = {}, set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in ('--run', '--v36-test-no-sandbox'):
            if key in flags:
                raise RuntimeError('Duplicate V36 flag')
            flags.add(key)
            index += 1
        elif key in REQUIRED_VALUES | OPTIONAL_VALUES:
            if key in values or index + 1 >= len(arguments) \
                    or not arguments[index + 1] or arguments[index + 1].startswith('--'):
                raise RuntimeError('Duplicate or missing V36 argument')
            values[key] = arguments[index + 1]
            index += 2
        else:
            raise RuntimeError('Only closed V36 adapter arguments are permitted')
    if flags != {'--run', '--v36-test-no-sandbox'} or not REQUIRED_VALUES <= values.keys() \
            or values['--cohort'] != COHORT or values['--main-workspace'] != str(ROOT):
        raise RuntimeError('Explicit current-source V36 run and browser opt-in required')
    return [value for value in arguments if value != '--run']


def child_command(arguments):
    forwarded = validate_arguments(arguments)
    wrapper = ROOT / 'tasks/run-in-repository.sh'
    adapter = ROOT / 'tests/postgres/run-secureshop-audit-collection-browser.py'
    for path in (wrapper, adapter):
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Fixed V36 source entrypoint unavailable')
    return ['/bin/bash', str(wrapper), sys.executable, '-B', str(adapter), *forwarded]


def coordinate(arguments):
    if sys.platform != 'darwin':
        raise RuntimeError('V36 outside inspector is Darwin-only')
    command = child_command(arguments)
    if FD_ENV in os.environ:
        raise RuntimeError('Nested inspector is not supported')
    parent, worker = socket.socketpair()
    parent.settimeout(15)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    environment[FD_ENV] = str(worker.fileno())
    child = None
    try:
        child = subprocess.Popen(command, cwd=ROOT, env=environment,
                                 close_fds=True, pass_fds=(worker.fileno(),))
        worker.close()
        inspector = Inspector(ROOT, child.pid)
        while child.poll() is None:
            ready, _, _ = select.select([parent], [], [], 0.25)
            if ready:
                if not parent.recv(1, socket.MSG_PEEK):
                    break
                request = receive(parent)
                try:
                    response = inspector.handle(request)
                except Exception:
                    send(parent, {'request': request, 'absent': False, 'error': 'inspection-failed'})
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
            child.wait()


if __name__ == '__main__':
    raise SystemExit(coordinate(sys.argv[1:]))
