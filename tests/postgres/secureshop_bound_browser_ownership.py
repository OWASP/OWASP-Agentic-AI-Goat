"""Validate exact Darwin browser birth journals; never signal a PID from a receipt."""

import json
import os
from pathlib import Path
import stat
import signal
import time

_CAPTURE_KEY = object()


class CapturedBrowser:
    def __init__(self, record, key):
        if key is not _CAPTURE_KEY:
            raise RuntimeError('Live browser capture required')
        self.record = dict(record)

try:
    from darwin_process_inventory import LibProc, owned_group_members, SZOMB
except ModuleNotFoundError:  # Package import in focused unit tests.
    from tests.postgres.darwin_process_inventory import LibProc, owned_group_members, SZOMB


def capture_live(record, parent_birth, runtime, *, api=None, getsid=os.getsid,
                 profile_prefix="dvaia-similar-browser-"):
    """Only a live independently checked direct child grants signaling authority."""
    if profile_prefix not in ("dvaia-similar-browser-", "dvaia-manual-rag-browser-"):
        raise RuntimeError('Explicit supported browser profile prefix required')
    api = LibProc() if api is None else api
    def parent_current():
        parent = api.identity(record['parentPid'])
        if parent is None or (parent.start_sec, parent.start_usec) != tuple(parent_birth) \
                or parent.uid != os.getuid() or parent.ruid != os.getuid() \
                or getattr(parent, 'status', None) == SZOMB:
            raise RuntimeError('Owned browser parent birth unavailable')
    parent_current()
    first = api.identity(record['pid'])
    if first is None:
        return None
    expected = (record['pid'], record['parentPid'], record['uid'], record['uid'],
                record['pgid'], *record['birth'])
    fields = lambda p: (p.pid, p.ppid, p.uid, p.ruid, p.pgid, p.start_sec, p.start_usec)
    if fields(first) != expected or first.status == SZOMB or getsid(first.pid) != record['sessionId']:
        raise RuntimeError('Live browser identity mismatch')
    argv = api.arguments(first.pid)
    profiles = [v.split('=', 1)[1] for v in argv if v.startswith('--user-data-dir=')]
    if not argv or argv[0] != record['executablePath'] or len(profiles) != 1 \
            or Path(profiles[0]).parent != Path(runtime) / 'tmp' \
            or not Path(profiles[0]).name.startswith(profile_prefix):
        raise RuntimeError('Live browser executable/profile mismatch')
    second = api.identity(first.pid)
    parent_current()
    if second is None or fields(second) != expected or second.status == SZOMB:
        raise RuntimeError('Browser birth changed during capture')
    return CapturedBrowser(record, _CAPTURE_KEY)


def retire_captured(record, *, api=None, getsid=os.getsid, killpg=os.killpg,
                    monotonic=time.monotonic, sleep=time.sleep):
    """Bounded retirement of a live-captured session, never a journal-only PID."""
    if not isinstance(record, CapturedBrowser):
        raise RuntimeError('Independent live browser capture required')
    record = record.record
    api = LibProc() if api is None else api
    if record['pgid'] != record['pid'] or record['sessionId'] != record['pid']:
        raise RuntimeError('Detached browser session leader required')
    births = {record['pid']: tuple(record['birth'])}
    def members():
        return owned_group_members(record['pgid'], api=api, getsid=getsid, births=births)
    for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
        remaining = members()
        if not remaining:
            return
        leader = api.identity(record['pid'])
        if leader is None or (leader.start_sec, leader.start_usec) != tuple(record['birth']) \
                or leader.uid != record['uid'] or leader.ruid != record['uid'] \
                or leader.pgid != record['pgid'] or getsid(leader.pid) != record['sessionId']:
            raise RuntimeError('Detached browser cleanup lost its verified birth anchor')
        killpg(record['pgid'], sig)
        until = monotonic() + seconds
        while monotonic() < until:
            if not members():
                return
            sleep(0.1)
    if members():
        raise RuntimeError('Captured browser session remains')


def read_record(root, filename, kind, browser, browser_sha256, pgid, *,
                parent_pid, require_all, allow_browser_session=False):
    path = Path(root) / filename
    try:
        info = path.lstat()
    except FileNotFoundError:
        if require_all:
            raise RuntimeError('Owned browser birth record missing')
        return []
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
            or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096:
        raise RuntimeError('Private owned browser birth record required')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or set(value) != {'schemaVersion', 'processes'} \
            or value['schemaVersion'] != 2 or not isinstance(value['processes'], list) \
            or len(value['processes']) != 1:
        raise RuntimeError('Browser birth record schema invalid')
    row = value['processes'][0]
    expected = {'kind', 'pid', 'parentPid', 'uid', 'pgid', 'sessionId',
                'birth', 'executablePath', 'executableSha256'}
    if not isinstance(row, dict) or set(row) != expected or row['kind'] != kind \
            or row['executablePath'] != str(browser) \
            or row['executableSha256'] != browser_sha256 \
            or row['uid'] != os.getuid() or row['parentPid'] != parent_pid \
            or row['pgid'] not in ((pgid, row['pid']) if allow_browser_session else (pgid,)) \
            or row['sessionId'] != row['pgid'] \
            or any(type(row[key]) is not int or row[key] <= 1
                   for key in ('pid', 'parentPid', 'pgid', 'sessionId')) \
            or not isinstance(row['birth'], list) or len(row['birth']) != 2 \
            or any(type(item) is not int or item < 0 for item in row['birth']) \
            or row['birth'][0] <= 0 or row['birth'][1] >= 1000000:
        raise RuntimeError('Browser birth record identity mismatch')
    return [row]


def prove_record_absent(records, *, api=None):
    api = LibProc() if api is None else api
    results = []
    for row in records:
        identity = api.identity(row['pid'])
        if identity is not None and (identity.start_sec, identity.start_usec) == tuple(row['birth']):
            raise RuntimeError('Owned browser birth remains')
        results.append({'kind': row['kind'], 'pid': row['pid'],
                        'birth': row['birth'], 'absent': True})
    return results
