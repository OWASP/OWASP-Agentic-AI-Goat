#!/usr/bin/env python3
"""Closed V12 selection using the existing read-only outer inspector loop."""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'customer-idor-lesson-browser'
REQUIRED = frozenset(('--main-workspace', '--node', '--node-sha256', '--docker',
    '--docker-sha256', '--docker-host', '--docker-daemon', '--image-id',
    '--current-host-profile', '--cohort', '--browser', '--browser-sha256',
    '--browser-root', '--ollama-model-sha256', '--evidence-parent'))


def child_command(arguments):
    values, flags = {}, set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in ('--run', '--v12-test-no-sandbox'):
            if key in flags:
                raise RuntimeError('Duplicate V12 flag')
            flags.add(key)
            index += 1
        elif key in REQUIRED | {'--embedding-cache'}:
            if key in values or index + 1 >= len(arguments) \
                    or not arguments[index + 1] or arguments[index + 1].startswith('--'):
                raise RuntimeError('Duplicate or missing V12 argument')
            values[key] = arguments[index + 1]
            index += 2
        else:
            raise RuntimeError('Only closed V12 arguments are admitted')
    if flags != {'--run', '--v12-test-no-sandbox'} or not REQUIRED <= values.keys() \
            or values['--cohort'] != COHORT or values['--main-workspace'] != str(ROOT):
        raise RuntimeError('Explicit full current-source V12 run required')
    wrapper = ROOT / 'tasks/run-in-repository.sh'
    adapter = ROOT / 'tests/postgres/run-secureshop-idor-lesson-browser.py'
    for path in (wrapper, adapter):
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Fixed V12 entrypoint unavailable')
    return ['/bin/bash', str(wrapper), sys.executable, '-B', str(adapter),
            *(item for item in arguments if item != '--run')]


def coordinate(arguments):
    # Separate module instance: no V36 global or selector is modified.
    source = ROOT / 'tests/postgres/run_audit_collection_with_inspector.py'
    spec = importlib.util.spec_from_file_location('v12_outer_inspector_loop', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.child_command = child_command
    return module.coordinate(arguments)


if __name__ == '__main__':
    raise SystemExit(coordinate(sys.argv[1:]))
