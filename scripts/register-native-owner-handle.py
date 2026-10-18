#!/usr/bin/env python3
"""Atomically bind a Codex exec session to one already-consumed native grant."""

import argparse
import json
import os
from pathlib import Path
import time


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('must be a positive integer')
    return parsed


parser = argparse.ArgumentParser()
parser.add_argument('--grant-file', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--owner', required=True)
parser.add_argument('--owner-handle', required=True, type=positive_int)
parser.add_argument('--wait-seconds', type=float, default=10)
args = parser.parse_args()
if not 0 <= args.wait_seconds <= 30:
    raise RuntimeError('wait-seconds must be between 0 and 30')

grant_path = Path(args.grant_file).resolve()
lock_path = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
deadline = time.monotonic() + args.wait_seconds

while True:
    grant = json.loads(grant_path.read_text())
    if grant.get('grantId') != args.grant_id or grant.get('owner') != args.owner:
        raise RuntimeError('Native verification grant identity mismatch')
    if grant.get('status') == 'consumed':
        break
    if grant.get('status') != 'granted' or time.monotonic() >= deadline:
        raise RuntimeError('Native verification grant is not consumed')
    time.sleep(.02)

while True:
    try:
        lock_path.mkdir(mode=0o700)
        break
    except FileExistsError:
        if time.monotonic() >= deadline:
            raise RuntimeError('Native verification grant registration lock is unavailable')
        time.sleep(.02)

try:
    grant = json.loads(grant_path.read_text())
    if grant.get('grantId') != args.grant_id or grant.get('owner') != args.owner \
            or grant.get('status') != 'consumed':
        raise RuntimeError('Consumed native verification grant changed during registration')
    consumer_pid = grant.get('consumerPid')
    if grant.get('allowedLaunches') != 1 or not isinstance(consumer_pid, int) or consumer_pid <= 0:
        raise RuntimeError('Consumed native verification grant has no valid launcher identity')
    existing = grant.get('ownerHandle')
    if existing not in (None, args.owner_handle):
        raise RuntimeError('Native verification grant already has another owner handle')
    grant['ownerHandle'] = args.owner_handle
    pending = grant_path.with_suffix(grant_path.suffix + f'.owner-handle-{os.getpid()}.pending')
    with pending.open('w') as output:
        output.write(json.dumps(grant, indent=2, sort_keys=True) + '\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(pending, grant_path)
    directory = os.open(grant_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({'grantId': args.grant_id, 'owner': args.owner,
        'consumerPid': consumer_pid, 'ownerHandle': args.owner_handle}, sort_keys=True))
finally:
    if lock_path.exists():
        lock_path.rmdir()
