"""Strict browser journal binding and absence-only outer profile cleanup."""
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

BASE_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
BROWSER_KEYS = {
    'pid', 'pgid', 'sessionId', 'uid', 'qualificationPid',
    'qualificationPgid', 'qualificationSessionId', 'profile',
    'executableSha256', 'workerPid',
}


def _browser_names(role):
    if role not in ('rendered', 'assessment'):
        raise RuntimeError('Unknown owned browser role')
    prefix = 'browser' if role == 'rendered' else 'assessment-browser'
    return prefix + '-process.json', prefix + '-profile', prefix + '-cleanup.json'


def _positive(value, label):
    if type(value) is not int or value <= 0:
        raise RuntimeError(f'Invalid {label}')
    return value


def read_private_json(path):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
            or info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise RuntimeError('Private owned browser journal required')
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise RuntimeError('Browser journal object required')
    return value


def process_rows():
    if sys.platform == 'darwin':
        from darwin_process_inventory import process_records
        return [(row['pid'], row['pgid'], row['sessionId'], row['uid'])
                for row in process_records()]
    result = subprocess.run(
        ['/bin/ps', '-axo', 'pid=,pgid=,uid='], env=BASE_ENV,
        capture_output=True, text=True, check=True, timeout=2)
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3 or any(not field.lstrip('-').isdecimal() for field in fields):
            raise RuntimeError('Process roster is malformed')
        pid, pgid, uid = map(int, fields)
        if min(pid, pgid) <= 0:
            raise RuntimeError('Process roster identity is invalid')
        try:
            session_id = os.getsid(pid)
        except ProcessLookupError:
            continue
        if session_id <= 0:
            raise RuntimeError('Process roster session is invalid')
        rows.append((pid, pgid, session_id, uid))
    return rows


def _bound_browser(runtime_root, qualification, browser, *, role='rendered'):
    _, profile_name, _ = _browser_names(role)
    runtime_root = Path(runtime_root)
    if (not runtime_root.is_absolute() or runtime_root.resolve() != runtime_root or runtime_root.is_symlink()
            or not runtime_root.is_dir() or runtime_root.stat().st_uid != os.getuid()
            or runtime_root.stat().st_mode & 0o077):
        raise RuntimeError('Private owned runtime root required')
    if type(qualification) is not dict or set(qualification) != {
            'name', 'pid', 'pgid', 'sessionId', 'status'}:
        raise RuntimeError('Exact qualification process journal required')
    if qualification['name'] != 'qualification' or qualification['status'] != 'cleanup_verified':
        raise RuntimeError('Qualification process cleanup is not verified')
    qpid = _positive(qualification['pid'], 'qualification PID')
    qpgid = _positive(qualification['pgid'], 'qualification process group')
    qsession = _positive(qualification['sessionId'], 'qualification session')
    if qpid != qpgid or qpid != qsession:
        raise RuntimeError('Qualification must own its process group and session')
    if type(browser) is not dict or set(browser) != BROWSER_KEYS:
        raise RuntimeError('Exact browser process journal required')
    pid = _positive(browser['pid'], 'browser PID')
    pgid = _positive(browser['pgid'], 'browser process group')
    session_id = _positive(browser['sessionId'], 'browser session')
    if type(browser['uid']) is not int or browser['uid'] != os.getuid():
        raise RuntimeError('Browser journal UID mismatch')
    if (browser['qualificationPid'], browser['qualificationPgid'], browser['qualificationSessionId']) != (qpid, qpgid, qsession):
        raise RuntimeError('Browser journal qualification identity mismatch')
    if pgid != qpgid or session_id != qsession:
        raise RuntimeError('Browser journal process group/session mismatch')
    worker_pid = _positive(browser['workerPid'], 'qualification worker PID')
    if worker_pid in (pid, qpid):
        raise RuntimeError('Qualification worker identity is invalid')
    profile = runtime_root / profile_name
    if type(browser['profile']) is not str or browser['profile'] != str(profile):
        raise RuntimeError('Browser profile is outside the exact runtime location')
    if (type(browser['executableSha256']) is not str or len(browser['executableSha256']) != 64
            or any(value not in '0123456789abcdef' for value in browser['executableSha256'])):
        raise RuntimeError('Browser executable digest is invalid')
    return dict(pid=pid, pgid=pgid, session_id=session_id, profile=profile)


def _assert_absent(bound, rows):
    for row in rows:
        if type(row) not in (tuple, list) or len(row) != 4 or any(type(value) is not int for value in row):
            raise RuntimeError('Process roster is malformed')
        pid, pgid, session_id, uid = row
        if pid == bound['pid'] or pgid == bound['pgid'] or session_id == bound['session_id']:
            if uid != os.getuid():
                raise RuntimeError('Browser identity now belongs to a foreign UID')
            raise RuntimeError('Browser PID, process group, or session remains')


def _inner_close(runtime_root, browser_pid, *, role='rendered'):
    _, profile_name, cleanup_name = _browser_names(role)
    path = Path(runtime_root) / cleanup_name
    if not path.exists() and not path.is_symlink():
        return False
    value = read_private_json(path)
    if set(value) != {'browserPid', 'pidAbsent', 'profileAbsent', 'closed'}:
        raise RuntimeError('Exact inner browser cleanup receipt required')
    if (value['browserPid'] != browser_pid or value['pidAbsent'] is not True
            or value['profileAbsent'] is not True or value['closed'] is not True):
        raise RuntimeError('Inner browser cleanup is not complete')
    profile = Path(runtime_root) / profile_name
    if profile.exists() or profile.is_symlink():
        raise RuntimeError('Inner browser profile absence claim is false')
    return True


def cleanup_browser_profile(runtime_root, qualification, *, rows=None, successful=False, role='rendered'):
    """Remove only the exact bound profile after process/session absence proof.

    This never signals a PID or group. A successful qualification still requires
    the inner graceful-close receipt; interruption cleanup proves absence only.
    """
    runtime_root = Path(runtime_root)
    journal_name, _, _ = _browser_names(role)
    browser = read_private_json(runtime_root / journal_name)
    bound = _bound_browser(runtime_root, qualification, browser, role=role)
    _assert_absent(bound, process_rows() if rows is None else rows)
    inner_close = _inner_close(runtime_root, bound['pid'], role=role)
    if successful and not inner_close:
        raise RuntimeError('Successful rendered qualification requires graceful browser close')
    profile = bound['profile']
    if profile.exists() or profile.is_symlink():
        info = profile.lstat()
        if (not stat.S_ISDIR(info.st_mode) or profile.is_symlink()
                or info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise RuntimeError('Exact private browser profile directory required')
        shutil.rmtree(profile)
        directory = os.open(runtime_root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    if profile.exists() or profile.is_symlink():
        raise RuntimeError('Browser profile cleanup is not verified')
    return {
        'browserPid': bound['pid'],
        'browserPgid': bound['pgid'],
        'browserSessionId': bound['session_id'],
        'pidGroupSessionAbsent': True,
        'profileAbsent': True,
        'innerCloseVerified': inner_close,
        'browserClosedClaimed': inner_close,
        'status': 'outer_absence_and_profile_cleanup_verified',
    }


def validate_browser_postflight(runtime_root, qualification, outer_receipt, *, successful, rows=None, role='rendered'):
    """Reusable future-control validation; it performs no cleanup or signalling."""
    runtime_root = Path(runtime_root)
    journal_name, _, _ = _browser_names(role)
    browser = read_private_json(runtime_root / journal_name)
    bound = _bound_browser(runtime_root, qualification, browser, role=role)
    _assert_absent(bound, process_rows() if rows is None else rows)
    if bound['profile'].exists() or bound['profile'].is_symlink():
        raise RuntimeError('Browser profile remains')
    inner_close = _inner_close(runtime_root, bound['pid'], role=role)
    if successful and not inner_close:
        raise RuntimeError('Successful rendered qualification requires graceful browser close')
    expected = {
        'browserPid': bound['pid'], 'browserPgid': bound['pgid'],
        'browserSessionId': bound['session_id'], 'pidGroupSessionAbsent': True,
        'profileAbsent': True, 'innerCloseVerified': inner_close,
        'browserClosedClaimed': inner_close,
        'status': 'outer_absence_and_profile_cleanup_verified',
    }
    if outer_receipt != expected:
        raise RuntimeError('Outer browser cleanup receipt mismatch')
    return True
