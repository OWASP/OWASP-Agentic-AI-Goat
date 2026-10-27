#!/usr/bin/env python3
"""Outside read-only inspector for the fixed current-source product/manual launcher.

This coordinator starts only the repository sandbox wrapper and its fixed
bound-review Python launcher. It grants no arbitrary shell or host command.
"""

import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys

try:
    from trusted_process_inspector import FD_ENV, Inspector, receive, send
except ModuleNotFoundError:  # Package import in focused unit tests.
    from tests.postgres.trusted_process_inspector import FD_ENV, Inspector, receive, send


def inspection_failure_diagnostic(stage, error):
    """Fixed enums only; never inspect exception attributes or render its text."""
    stages = ('request-schema', 'request-identity', 'child-before', 'scope',
              'run-binding', 'process-inventory', 'child-after')
    if type(stage) is not str or stage not in stages:
        stage = 'unknown'
    category = 'other'
    for kind, label in ((RuntimeError, 'validation'), (TimeoutError, 'timeout'),
                        (PermissionError, 'permission'), (FileNotFoundError, 'missing'),
                        (OSError, 'os-error'), (ValueError, 'value'),
                        (subprocess.CalledProcessError, 'subprocess')):
        if type(error) is kind:
            category = label
            break
    return 'INSPECTOR_FAILURE:' + stage + ':' + category


def validate_arguments(arguments):
    if '--run' not in arguments or '--main-checkout' not in arguments \
            or '--current-host-profile' not in arguments:
        raise RuntimeError('Fixed current-host direct-source run required')
    suites = [arguments[index + 1] for index, value in enumerate(arguments[:-1])
              if value == '--suite']
    if len(suites) != 1 or suites[0] not in (
            'persona-sessions', 'product-summary-browser', 'manual-rag-browser', 'manual-rag-fixed-browser', 'manual-rag-paired-browser', 'manual-rag-source', 'manual-private-model', 'manual-ranking-model', 'review-moderation-recovery', 'analytics-resource', 'tool-output-actual', 'direct-injection-actual'):
        raise RuntimeError('Unsupported bound-review inspector suite')
    if any(value in ('--', '--suite=') for value in arguments):
        raise RuntimeError('Ambiguous inspector arguments')


def coordinate(repo, arguments):
    if sys.platform != 'darwin':
        raise RuntimeError('Outside inspector is Darwin-only')
    validate_arguments(arguments)
    repo = Path(repo).resolve()
    wrapper = repo / 'tasks/run-in-repository.sh'
    launcher = repo / 'tests/postgres/run-secureshop-bound-review-composition-isolated.py'
    if any(path.is_symlink() or not path.is_file() for path in (wrapper, launcher)):
        raise RuntimeError('Fixed current-source launcher unavailable')
    parent, worker = socket.socketpair()
    parent.settimeout(15)
    environment = dict(os.environ)
    if FD_ENV in environment:
        raise RuntimeError('Nested inspector is not supported')
    environment[FD_ENV] = str(worker.fileno())
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    child = None
    try:
        child = subprocess.Popen(['/bin/bash', str(wrapper), sys.executable,
                                  str(launcher), *arguments], cwd=repo, env=environment,
                                 close_fds=True, pass_fds=(worker.fileno(),))
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
                except Exception as error:
                    print(inspection_failure_diagnostic(inspector.failure_stage, error),
                          file=sys.stderr, flush=True)
                    send(parent, {'request': request, 'absent': False,
                                  'error': 'inspection-failed'})
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
    raise SystemExit(coordinate(Path(__file__).resolve().parents[2], sys.argv[1:]))
