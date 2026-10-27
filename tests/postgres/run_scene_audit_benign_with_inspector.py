#!/usr/bin/env python3
"""Closed V15 benign diagnostic under the existing outside read-only inspector."""
import hashlib
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'scene-audit-v15-browser'
BENIGN = '--v15-benign-diagnostic'
REQUIRED = frozenset(('--main-workspace', '--node', '--node-sha256', '--docker',
    '--docker-sha256', '--docker-host', '--docker-daemon', '--image-id',
    '--current-host-profile', '--cohort', '--browser', '--browser-sha256',
    '--browser-root', '--ollama-model-sha256', '--evidence-parent'))
OPTIONAL = frozenset(('--embedding-cache',))
WRAPPER = 'tasks/run-in-repository.sh'
ADAPTER = 'tests/postgres/run-secureshop-scene-audit-benign-browser.py'
COORDINATOR = 'tests/postgres/run_audit_collection_with_inspector.py'
INSPECTOR = 'tests/postgres/trusted_process_inspector.py'
PINS = {
    WRAPPER: '52f049a7debb82d58efd3fab0b7838cbdf2363ad2c624a83f31b1c4952c2c706',
    ADAPTER: 'a7d478893edf67af0e654c22a5645dbdbdb398d14c1d038b6144cafd2bbfe2ef',
    COORDINATOR: '74e6ec2394ee21212b3fcc5012cdabf288c0d9040328974e2847135937b5e67f',
    INSPECTOR: 'b4ea2dc0888f57129082c05ba02d70f2828a72f87a10597029ce7bd6d01a3866',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sources():
    for relative, expected in PINS.items():
        target = ROOT / relative
        if target.is_symlink() or not target.is_file() or target.resolve() != target \
                or digest(target) != expected:
            raise RuntimeError(f'V15 benign outside-inspector source mismatch: {relative}')


def child_command(arguments):
    values, flags = {}, set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in ('--run', '--v15-test-no-sandbox', BENIGN):
            if key in flags:
                raise RuntimeError('Duplicate V15 benign flag')
            flags.add(key)
            index += 1
        elif key in REQUIRED | OPTIONAL:
            if key in values or index + 1 >= len(arguments) \
                    or not arguments[index + 1] or arguments[index + 1].startswith('--'):
                raise RuntimeError('Duplicate or missing V15 benign argument')
            values[key] = arguments[index + 1]
            index += 2
        else:
            raise RuntimeError('Only closed V15 benign diagnostic arguments admitted')
    if flags != {'--run', '--v15-test-no-sandbox', BENIGN} \
            or not REQUIRED <= values.keys() or values['--cohort'] != COHORT \
            or values['--main-workspace'] != str(ROOT):
        raise RuntimeError('Explicit current-source V15 benign diagnostic run required')
    verify_sources()
    # --run belongs solely to the outside coordinator. The extra benign flag
    # belongs solely to this closed parent; the child adapter selects benign
    # evidence internally and still receives the original V15 browser opt-in.
    forwarded = [item for item in arguments if item not in ('--run', BENIGN)]
    return ['/bin/bash', str(ROOT / WRAPPER), sys.executable, '-B',
            str(ROOT / ADAPTER), *forwarded]


def coordinate(arguments):
    verify_sources()
    source = ROOT / COORDINATOR
    spec = importlib.util.spec_from_file_location('v15_benign_outside_inspector_loop', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.child_command = child_command
    return module.coordinate(arguments)


if __name__ == '__main__':
    raise SystemExit(coordinate(sys.argv[1:]))
