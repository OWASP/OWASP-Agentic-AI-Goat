"""Read-only, exact-PID Darwin browser birth proof for owned native fixtures.

This does not signal or clean processes. The launcher separately proves final
absence, including profile-using descendants, before accepting a receipt.
"""

import argparse
import json
import os
from pathlib import Path
import sys

try:
    from darwin_process_inventory import LibProc, SZOMB
except ModuleNotFoundError:  # Package import in focused unit tests.
    from tests.postgres.darwin_process_inventory import LibProc, SZOMB


def inspect_birth(pid, parent_pid, executable, *, api=None, getsid=os.getsid,
                  uid=None):
    if sys.platform != 'darwin' or type(pid) is not int or pid <= 1 \
            or type(parent_pid) is not int or parent_pid <= 1:
        raise RuntimeError('Owned Darwin browser PID required')
    expected = Path(executable)
    if not expected.is_absolute() or expected.is_symlink() or expected.resolve() != expected \
            or not expected.is_file():
        raise RuntimeError('Canonical owned browser executable required')
    api = LibProc() if api is None else api
    uid = os.getuid() if uid is None else uid
    first = api.identity(pid)
    if first is None or first.pid != pid or first.ppid != parent_pid \
            or first.uid != uid or first.ruid != uid or first.status == SZOMB \
            or first.start_sec <= 0 or not 0 <= first.start_usec < 1000000:
        raise RuntimeError('Owned browser birth unavailable')
    session = getsid(pid)
    arguments = api.arguments(pid)
    second = api.identity(pid)
    if second is None or (first.pid, first.ppid, first.uid, first.ruid, first.pgid,
            first.start_sec, first.start_usec) != (second.pid, second.ppid,
            second.uid, second.ruid, second.pgid, second.start_sec, second.start_usec) \
            or second.status == SZOMB or session != first.pgid or not arguments \
            or arguments[0] != str(expected):
        raise RuntimeError('Owned browser identity changed')
    return {'pid': pid, 'parentPid': parent_pid, 'uid': uid, 'pgid': first.pgid,
            'sessionId': session, 'birth': [first.start_sec, first.start_usec],
            'executablePath': str(expected)}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--parent', type=int, required=True)
    parser.add_argument('--executable', required=True)
    args = parser.parse_args(argv)
    print(json.dumps(inspect_birth(args.pid, args.parent, args.executable),
                     sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
