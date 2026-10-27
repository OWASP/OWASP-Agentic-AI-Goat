#!/usr/bin/env python3
"""Outside read-only inspector for the fixed current-checkout MCP launcher."""

import importlib.util
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys

from mcp_process_inspector import McpInspector
from trusted_process_inspector import FD_ENV, receive, send


def select_launcher(repo, arguments):
    """Admit the existing assembly CLI or its one closed V39 MAIN alias."""
    launcher = repo / 'tests' / 'postgres' / 'run-owned-mcp-assembly-isolated.py'
    admitted = arguments
    if any(value == '--cohort' or value.startswith('--cohort=') for value in arguments):
        launcher = repo / 'tests' / 'postgres' / 'run-secureshop-agent-host-transport-main.py'
        if launcher.is_symlink() or not launcher.is_file():
            raise RuntimeError('Current-source V39 MAIN required')
        spec = importlib.util.spec_from_file_location('mcp_inspector_v39_main', launcher)
        main = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main)
        admitted = main.v39_atomic_owner_arguments(arguments)
        if admitted is None:
            raise RuntimeError('Outside MCP inspector admits only the exact V39 MAIN cohort')
    if not all(flag in admitted for flag in ('--run', '--registry-rendered',
              '--main-workspace', '--current-host-profile')):
        raise RuntimeError('Outside MCP inspector requires explicit rendered live mode')
    return launcher


def coordinate(repo, arguments):
    if sys.platform != 'darwin':
        raise RuntimeError('Outside MCP inspector is Darwin-only')
    repo = Path(repo).resolve()
    wrapper = repo / 'tasks' / 'run-in-repository.sh'
    environment = dict(os.environ)
    if FD_ENV in environment:
        raise RuntimeError('Nested MCP inspector is not supported')
    launcher = select_launcher(repo, arguments)
    if any(path.is_symlink() or not path.is_file() for path in (wrapper, launcher)):
        raise RuntimeError('Current-source MCP wrapper and launcher required')
    parent, worker = socket.socketpair()
    parent.settimeout(15)
    environment[FD_ENV] = str(worker.fileno())
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    child = None
    try:
        child = subprocess.Popen(['/bin/bash', str(wrapper), 'python3', '-B', str(launcher),
                                  *arguments], cwd=repo, env=environment, close_fds=True,
                                 pass_fds=(worker.fileno(),))
        worker.close()
        inspector = McpInspector(repo, child.pid)
        while child.poll() is None:
            ready, _, _ = select.select([parent], [], [], 0.25)
            if ready:
                if not parent.recv(1, socket.MSG_PEEK):
                    break
                request = receive(parent)
                try:
                    response = inspector.handle(request)
                except Exception:
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
