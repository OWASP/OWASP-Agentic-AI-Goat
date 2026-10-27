"""Fixed outside read-only inspector; all worker writes remain sandboxed."""
import os
from pathlib import Path
import select
import socket
import subprocess
import sys

from trusted_process_inspector import FD_ENV, Inspector, receive, send


def validate_arguments(arguments):
    from admin_q05_current_host import arguments as parse
    args = parse(arguments)
    if not args.run:
        raise RuntimeError('Coordinator admits execution only; plan directly in wrapper')
    return args


def coordinate(repo, arguments):
    if sys.platform != 'darwin':
        raise RuntimeError('Darwin fixed coordinator required')
    validate_arguments(arguments)
    repo = Path(repo).resolve()
    wrapper = repo / 'tasks/run-in-repository.sh'
    launcher = repo / 'tests/postgres/run-admin-auth-browser-cohort-isolated.py'
    if any(path.is_symlink() or not path.is_file() for path in (wrapper, launcher)):
        raise RuntimeError('Fixed source launcher unavailable')
    if FD_ENV in os.environ:
        raise RuntimeError('Nested inspector forbidden')
    parent, worker = socket.socketpair()
    parent.settimeout(15)
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    environment[FD_ENV] = str(worker.fileno())
    child = None
    try:
        child = subprocess.Popen(['/bin/bash', str(wrapper), sys.executable, '-B',
                                  str(launcher), *arguments], cwd=repo, env=environment,
                                 close_fds=True, pass_fds=(worker.fileno(),))
        worker.close()
        inspector = Inspector(repo, child.pid)
        while child.poll() is None:
            ready, _, _ = select.select([parent], [], [], .25)
            if ready:
                if not parent.recv(1, socket.MSG_PEEK):
                    break
                request = receive(parent)
                try:
                    response = inspector.handle(request)
                except Exception:
                    response = dict(request=request, absent=False, error='inspection-failed')
                send(parent, response)
        return child.wait()
    finally:
        parent.close()
        worker.close()
        if child is not None and child.poll() is None:
            child.wait()


if __name__ == '__main__':
    raise SystemExit(coordinate(Path(__file__).resolve().parents[2], sys.argv[1:]))
