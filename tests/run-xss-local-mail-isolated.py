#!/usr/bin/env python3
"""Run the XSS local-mail adapter against one owned disposable Mailpit container."""

import argparse
import os
import signal
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
args = parser.parse_args()

source = Path(__file__).resolve().parents[1]
root = Path(tempfile.mkdtemp(prefix='dvaia-xss-local-mail-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
docker = ['docker', '--host', args.docker_host]
container = 'dvaia-xss-local-mail-' + uuid.uuid4().hex[:12]
child = None
child_pgid = None
child_session_id = None


def run(command, **kwargs):
    kwargs.setdefault('timeout', 60)
    return subprocess.run(command, check=True, env=base_env, **kwargs)


def published_port(container_port):
    output = run(docker + ['port', container, str(container_port)], capture_output=True, text=True).stdout.strip()
    if not output:
        raise RuntimeError(f'Owned Mailpit did not publish port {container_port}')
    return int(output.splitlines()[-1].rsplit(':', 1)[1])


def interrupted(signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def owned_group_members(pgid, session_id):
    listing = subprocess.run(
        ['ps', '-axo', 'pid=,pgid=,uid='], env=base_env,
        capture_output=True, text=True, check=True, timeout=2,
    ).stdout
    members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) != 3 or int(fields[1]) != pgid:
            continue
        pid = int(fields[0])
        try:
            if os.getsid(pid) == session_id:
                members.append((pid, int(fields[2])))
        except ProcessLookupError:
            pass
    foreign = [pid for pid, uid in members if uid != os.getuid()]
    if foreign:
        raise RuntimeError(f'Refusing to signal process group {pgid}; it contains foreign processes')
    return [pid for pid, _uid in members]


def signal_owned_group(pgid, session_id, requested_signal):
    if not owned_group_members(pgid, session_id):
        return False
    os.killpg(pgid, requested_signal)
    return True


def stop_owned_group(process, pgid, session_id):
    signal_owned_group(pgid, session_id, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while owned_group_members(pgid, session_id) and time.monotonic() < deadline:
        process.poll()
        time.sleep(.05)
    if owned_group_members(pgid, session_id):
        signal_owned_group(pgid, session_id, signal.SIGKILL)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError('Owned Node process group did not terminate after SIGKILL') from error
    verify_deadline = time.monotonic() + 2
    while owned_group_members(pgid, session_id) and time.monotonic() < verify_deadline:
        time.sleep(.05)
    if owned_group_members(pgid, session_id):
        raise RuntimeError('Owned Node process group cleanup did not complete')


signal.signal(signal.SIGTERM, interrupted)


(workspace / 'server' / 'services').mkdir(parents=True)
(workspace / 'tests').mkdir()
for relative in [
    'server/services/xssLocalMail.js',
    'server/services/xssEmailCodec.js',
    'server/services/xssEmailDispatch.js',
    'tests/xssLocalMail.integration.test.js',
]:
    target = workspace / relative
    shutil.copy2(source / relative, target)
(workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

try:
    run(docker + [
        'run', '--detach', '--pull', 'never', '--name', container,
        '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16777216',
        '-p', '127.0.0.1::1025', '-p', '127.0.0.1::8025',
        'axllent/mailpit:latest',
    ], stdout=subprocess.DEVNULL)
    smtp_port = published_port('1025/tcp')
    api_port = published_port('8025/tcp')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        probe = subprocess.run(
            ['curl', '--fail', '--silent', '--show-error', '--max-time', '1',
             f'http://127.0.0.1:{api_port}/api/v1/info'],
            env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        )
        if probe.returncode == 0:
            break
        time.sleep(.2)
    else:
        raise RuntimeError('Owned Mailpit container did not become ready')

    env = dict(
        base_env,
        NODE_ENV='test',
        XSS_LOCAL_MAIL_TEST_DISPOSABLE='yes',
        XSS_LOCAL_MAIL_SMTP_HOST='127.0.0.1',
        XSS_LOCAL_MAIL_SMTP_PORT=str(smtp_port),
        XSS_LOCAL_MAIL_API_URL=f'http://127.0.0.1:{api_port}/',
    )
    result_log = root / 'result.log'
    timed_out = False
    returncode = None
    try:
        with result_log.open('w') as output:
            child = subprocess.Popen(
                ['node', '--test', '--test-reporter=tap', 'tests/xssLocalMail.integration.test.js'],
                cwd=workspace, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
            )
            child_pgid = os.getpgid(child.pid)
            child_session_id = os.getsid(child.pid)
            try:
                returncode = child.wait(timeout=40)
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        if child is not None and child_pgid is not None and child_session_id is not None:
            stop_owned_group(child, child_pgid, child_session_id)
    print(result_log.read_text(), end='')
    if timed_out:
        raise RuntimeError('XSS local-mail integration timed out after 40 seconds')
    if returncode:
        raise RuntimeError(f'XSS local-mail integration failed ({returncode})')
finally:
    subprocess.run(docker + ['rm', '--force', container], env=base_env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$', '--format', '{{.Names}}'],
                    capture_output=True, text=True).stdout.strip()
    if remaining:
        raise RuntimeError('Owned Mailpit container cleanup did not complete')
    print(f'Owned Mailpit cleanup complete; isolated evidence workspace: {root}')
