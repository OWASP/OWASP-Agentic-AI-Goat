"""Bounded private diagnostics for disposable native-service readiness failures."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

MAX_TEXT = 4096
HEALTH_FIELDS = (
    'ready', 'version', 'isolation', 'supervisorProfile',
    'protectedStateCapability', 'observedActionCapability',
)


def _bounded(value):
    return str(value or '')[:MAX_TEXT]


def probe(command, env, timeout, health=False):
    try:
        completed = subprocess.run(command, env=env, capture_output=True, text=True,
                                   timeout=timeout)
        result = {
            'status': 'ready' if completed.returncode == 0 else 'unavailable',
            'returnCode': completed.returncode,
            'errorClass': None,
            'stdout': _bounded(completed.stdout),
            'stderr': _bounded(completed.stderr),
        }
        if health and completed.returncode == 0:
            try:
                decoded = json.loads(completed.stdout)
                result['strictHealth'] = {key: decoded.get(key) for key in HEALTH_FIELDS}
            except (TypeError, ValueError) as error:
                result['status'] = 'invalid-response'
                result['errorClass'] = type(error).__name__
        return result
    except subprocess.TimeoutExpired as error:
        return {'status': 'timeout', 'returnCode': None,
                'errorClass': type(error).__name__, 'stdout': _bounded(error.stdout),
                'stderr': _bounded(error.stderr)}
    except Exception as error:
        return {'status': 'error', 'returnCode': None,
                'errorClass': type(error).__name__, 'stdout': '', 'stderr': ''}


def persist_private(path, value):
    path = Path(path)
    pending = path.with_suffix(path.suffix + '.pending')
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
    os.replace(pending, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_failure(root, services, containers, docker, env):
    root = Path(root)
    container_states = {}
    log_files = {}
    for name, container in containers.items():
        state = probe(docker + ['inspect', '--format', '{{json .State}}', container],
                      env, 20)
        if state['returnCode'] == 0:
            try:
                decoded = json.loads(state['stdout'])
                state['state'] = {key: decoded.get(key) for key in
                                  ('Status', 'Running', 'Paused', 'Restarting',
                                   'OOMKilled', 'Dead', 'ExitCode', 'Error')}
            except (TypeError, ValueError) as error:
                state['stateErrorClass'] = type(error).__name__
        container_states[name] = state
        log = probe(docker + ['logs', '--tail', '200', container], env, 20)
        log_path = root / f'readiness-{name}.log'
        log_hash = persist_private(log_path, {
            'status': log['status'], 'returnCode': log['returnCode'],
            'errorClass': log['errorClass'], 'stdout': log['stdout'],
            'stderr': log['stderr'],
        })
        log_files[name] = {'path': str(log_path), 'sha256': log_hash,
                           'mode': oct(log_path.stat().st_mode & 0o777)}
    snapshot = root / 'readiness-failure.json'
    snapshot_hash = persist_private(snapshot, {
        'version': 1, 'services': services, 'containers': container_states,
        'logs': log_files,
    })
    return {'path': str(snapshot), 'sha256': snapshot_hash,
            'mode': oct(snapshot.stat().st_mode & 0o777), 'logs': log_files,
            'services': services}
