#!/usr/bin/env python3
"""Outside read-only Inspector for the fixed acl-permission worker only."""

import os
from pathlib import Path
import re
import select
import signal
import socket
import subprocess
import sys
import time

try:
    from trusted_process_inspector import FD_ENV, Inspector, receive, send
except ModuleNotFoundError:
    from tests.postgres.trusted_process_inspector import FD_ENV, Inspector, receive, send


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_VALUES = frozenset((
    '--nonce', '--node', '--node-sha256', '--docker', '--docker-sha256',
    '--docker-host', '--daemon-id', '--image-id', '--current-host-profile',
    '--chromium', '--chromium-sha256', '--browser-root', '--python-sha256',
    '--build-sha256', '--build-report', '--build-report-sha256',
    '--build-input-sha256', '--build-output-sha256', '--build-recorder-sha256',
    '--source-sha256', '--snapshot-sha256',
))
CLEANUP_SECONDS = 135  # Worker cleanup permits 120 seconds plus bounded exit allowance.
TERM_SECONDS = 5


def validate_arguments(arguments):
    """Reject alternate launches before the source plan's own run admission."""
    values = {}
    flags = set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in ('--run', '--acl-permission-recovery'):
            if key in flags:
                raise RuntimeError('Duplicate acl-permission run flag')
            flags.add(key)
            index += 1
        elif key in REQUIRED_VALUES:
            if key in values or index + 1 >= len(arguments) \
                    or not arguments[index + 1] or arguments[index + 1].startswith('--'):
                raise RuntimeError('Duplicate or missing acl-permission value')
            values[key] = arguments[index + 1]
            index += 2
        else:
            raise RuntimeError('Only the fixed acl-permission run arguments are admitted')
    if flags != {'--run', '--acl-permission-recovery'} or set(values) != REQUIRED_VALUES:
        raise RuntimeError('Complete acl-permission run selection required')
    if re.fullmatch(r'[a-f0-9]{12}', values['--nonce']) is None \
            or re.fullmatch(r'[a-f0-9]{64}', values['--snapshot-sha256']) is None:
        raise RuntimeError('Exact reviewed nonce and snapshot required')

    try:
        from acl_permission_current_host import parse
    except ModuleNotFoundError:
        from tests.postgres.acl_permission_current_host import parse
    parsed = parse(arguments)
    if parsed.run is not True or getattr(parsed, 'plan', False):
        raise RuntimeError('Source did not admit acl-permission execution')
    return parsed


def child_command(arguments):
    validate_arguments(arguments)
    wrapper = ROOT / 'tasks/run-in-repository.sh'
    launcher = ROOT / 'tests/postgres/run-acl-permission-current-host.py'
    for path in (wrapper, launcher):
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Fixed acl-permission source entrypoint unavailable')
    import json
    writable = ('tasks/qualification', 'tasks/tmp')
    profile = '(version 1)(allow default)(deny file-write*)' + ''.join('(allow file-write* (subpath ' + json.dumps(str(ROOT / part)) + '))' for part in writable) + '(allow file-write* (literal "/dev/null") (literal "/dev/tty"))'
    return ['/usr/bin/sandbox-exec', '-p', profile, sys.executable, '-B', str(launcher), *arguments]


def service_requests(parent, child, inspector, *, deadline=None):
    """Keep the private Inspector alive while the owned child is cleaning up."""
    while child.poll() is None:
        remaining = None if deadline is None else deadline - time.monotonic()
        if remaining is not None and remaining <= 0:
            return False
        ready, _, _ = select.select([parent], [], [],
                                    .25 if remaining is None else min(.25, remaining))
        if ready:
            if not parent.recv(1, socket.MSG_PEEK):
                # The worker can close its IPC endpoint just before the direct
                # wrapper process is reaped. Only its actual terminal status,
                # never EOF alone, resolves the transport obligation.
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired as error:
                    raise RuntimeError('Inspector channel closed before worker terminal') from error
                return True
            request = receive(parent)
            try:
                response = inspector.handle(request)
            except Exception:
                response = dict(request=request, absent=False,
                                error='inspection-failed')
            send(parent, response)
    return True


def finish_interrupted_child(parent, child, inspector):
    """Give cleanup bounded RPC service before escalating this owned child."""
    if child is None:
        return
    if child.poll() is None:
        child.send_signal(signal.SIGINT)
        try:
            service_requests(parent, child, inspector,
                             deadline=time.monotonic() + CLEANUP_SECONDS)
        except Exception:
            # A lost or malformed private transport cannot prove absence.
            pass
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
        try:
            child.wait(timeout=TERM_SECONDS)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=TERM_SECONDS)
    else:
        child.wait()


def coordinate(arguments):
    if sys.platform != 'darwin':
        raise RuntimeError('Student-deletion outside Inspector is Darwin-only')
    command = child_command(arguments)
    if FD_ENV in os.environ:
        raise RuntimeError('Nested Inspector forbidden')
    parent, worker = socket.socketpair()
    parent.settimeout(15)
    # Preserve the repository wrapper environment without applying a second sandbox.
    for relative in ('tasks/tmp', 'tasks/cache/xdg', 'tasks/cache/npm', 'tasks/cache/browser'):
        path = ROOT / relative
        if path.is_symlink() or path.resolve() != path or not path.is_dir():
            raise RuntimeError('Canonical repository runtime directory required')
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
        TMPDIR=str(ROOT / 'tasks/tmp'), XDG_CACHE_HOME=str(ROOT / 'tasks/cache/xdg'),
        npm_config_cache=str(ROOT / 'tasks/cache/npm'),
        PUPPETEER_CACHE_DIR=str(ROOT / 'tasks/cache/browser'),
        PLAYWRIGHT_BROWSERS_PATH=str(ROOT / 'tasks/cache/browser'),
        PATH=str(ROOT / 'tasks/runtime/node/node_modules/node/bin') + ':' + os.environ.get('PATH', '/usr/bin:/bin'))
    environment[FD_ENV] = str(worker.fileno())
    child = None
    inspector = None
    try:
        child = subprocess.Popen(command, cwd=ROOT, env=environment,
                                 close_fds=True, pass_fds=(worker.fileno(),))
        worker.close()
        inspector = Inspector(ROOT, child.pid)
        service_requests(parent, child, inspector)
        return child.wait()
    except KeyboardInterrupt:
        try:
            finish_interrupted_child(parent, child, inspector)
        except Exception:
            # Preserve the primary interruption after bounded cleanup attempts.
            pass
        raise
    except Exception:
        try:
            finish_interrupted_child(parent, child, inspector)
        except Exception:
            # Never turn a failed cleanup into a successful run or mask its cause.
            pass
        raise
    finally:
        primary_error = sys.exc_info()[0] is not None
        close_error = None
        for endpoint in (parent, worker):
            try:
                endpoint.close()
            except Exception as error:
                if close_error is None:
                    close_error = error
        if close_error is not None and not primary_error:
            raise RuntimeError('Inspector socket close failed') from close_error


if __name__ == '__main__':
    raise SystemExit(coordinate(sys.argv[1:]))
