"""Pure recovery, HTTP-session, and terminal-ledger rules for the rollout."""
import hashlib
import http.cookiejar
import json
import pathlib
import signal
import urllib.request


class RetryingPauseSet:
    def __init__(self):
        self.stopped = []

    def stop(self, pid, send):
        send(pid, signal.SIGSTOP)
        self.stopped.append(pid)

    def resume_all(self, send):
        errors, retry = [], []
        while self.stopped:
            pid = self.stopped.pop()
            try:
                send(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            except Exception as error:
                errors.append((pid, type(error).__name__))
                retry.append(pid)
        self.stopped.extend(reversed(retry))
        return errors

def attempt_all(steps):
    results, errors = {}, []
    for name, action in steps:
        try:
            results[name] = action()
        except BaseException as error:
            errors.append({'stage': name, 'type': type(error).__name__})
    return results, errors


def validate_terminal_grant(value, *, grant_id, owner, owner_handle, consumer_pid):
    if (not isinstance(value, dict) or value.get('grantId') != grant_id
            or value.get('status') != 'consumed' or value.get('owner') != owner
            or value.get('ownerHandle') != owner_handle
            or value.get('consumerPid') != consumer_pid):
        raise RuntimeError('terminal grant ownership changed')
    return value


def validate_owner_handle(value, *, consumer_pid):
    if not isinstance(value, str) or not value.isdecimal() or int(value) <= 0:
        raise RuntimeError('actual owner handle unavailable')
    handle = int(value)
    if handle == consumer_pid:
        raise RuntimeError('owner handle must be unified exec session, not consumer PID')
    return handle


def exact_image_absent(image_id):
    if image_id is not None:
        raise RuntimeError('rollback image tag remains')
    return True


def private_cookie_opener(redirect_handler):
    """Return a process-local HTTP client whose cookies are never serialized."""
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        redirect_handler,
    )


def validate_logout_result(status, value):
    if status != 200 or not isinstance(value, dict) or value.get('success') is not True:
        raise RuntimeError('temporary smoke session logout failed')
    return True


def validate_revoked_status(status, value):
    if not (status == 401 or (status == 200 and isinstance(value, dict)
                             and value.get('authenticated') is False)):
        raise RuntimeError('temporary smoke session remains valid')
    return True


def load_exact_source_manifest(root, relative_manifest):
    root = pathlib.Path(root).resolve()
    manifest_path = (root / relative_manifest).resolve()
    if root not in manifest_path.parents:
        raise RuntimeError('source manifest escaped workspace')
    value = json.loads(manifest_path.read_text())
    expected = value.get('sourceHashes') if isinstance(value, dict) else None
    if not isinstance(expected, dict) or not expected:
        raise RuntimeError('source manifest is incomplete')
    actual = {}
    for name, digest in expected.items():
        path = (root / name).resolve()
        if root not in path.parents or not isinstance(digest, str) or len(digest) != 64:
            raise RuntimeError('source manifest entry is invalid')
        actual[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError('observed-action rollout source changed')
    return actual


def rollback_retention_decision(cleanup, *, rollback_pinned, image_id):
    required = ('oldImageRestored', 'serviceRestored', 'mailpitPreserved',
                'targetVolumePreserved', 'privateConfigurationPreserved',
                'applicationHealthy')
    complete = all(cleanup.get(key) is True for key in required)
    if complete:
        return {'remove': True, 'retention': 'pending-removal'}
    present = image_id is not None
    if rollback_pinned and not present:
        raise RuntimeError('required rollback image tag missing')
    return {'remove': False,
            'retention': 'required-present' if present else 'required-missing'}
