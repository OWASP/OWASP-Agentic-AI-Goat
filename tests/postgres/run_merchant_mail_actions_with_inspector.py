#!/usr/bin/env python3
"""Fixed outside read-only inspector for the literal merchant mail-actions cohort."""
import importlib.util
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
COHORT = 'merchant-mail-actions-browser'
MODEL_SHA256 = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
ADAPTER = 'tests/postgres/run-secureshop-merchant-mail-actions-browser.py'
REQUIRED = frozenset(('--main-workspace', '--node', '--node-sha256', '--docker',
    '--docker-sha256', '--docker-host', '--docker-daemon', '--image-id',
    '--current-host-profile', '--cohort', '--browser', '--browser-sha256',
    '--browser-root', '--evidence-parent', '--ollama-model-sha256',
    '--build-report', '--build-report-sha256', '--build-input-sha256',
    '--build-output-sha256', '--build-recorder-sha256'))
OPT_IN = '--mail-actions-test-no-sandbox'


def validate_arguments(arguments, *, planning=False):
    values, flags = {}, set()
    index = 0
    while index < len(arguments):
        key = arguments[index]
        if key in ('--run', '--plan', OPT_IN):
            if key in flags:
                raise RuntimeError('Duplicate mail-actions flag')
            flags.add(key)
            index += 1
        elif key in REQUIRED | {'--expected-snapshot-sha256'}:
            if key in values or index + 1 >= len(arguments) \
                    or not arguments[index + 1] or arguments[index + 1].startswith('--'):
                raise RuntimeError('Duplicate or missing mail-actions argument')
            values[key] = arguments[index + 1]
            index += 2
        else:
            raise RuntimeError('Only closed merchant mail-actions arguments permitted')
    required = REQUIRED if planning else REQUIRED | {'--expected-snapshot-sha256'}
    if flags != {'--plan' if planning else '--run', OPT_IN} or set(values) != required \
            or values['--cohort'] != COHORT or values['--main-workspace'] != str(ROOT) \
            or values['--evidence-parent'] != str(ROOT / 'tasks/qualification') \
            or values['--ollama-model-sha256'] != MODEL_SHA256:
        raise RuntimeError('Exact current-source mail-actions and installed model required')
    if not planning and not re.fullmatch(r'[a-f0-9]{64}', values['--expected-snapshot-sha256']):
        raise RuntimeError('Reviewed mail-actions snapshot digest required')
    for key in ('--build-report-sha256', '--build-input-sha256',
                '--build-output-sha256', '--build-recorder-sha256'):
        if not re.fullmatch(r'[a-f0-9]{64}', values[key]):
            raise RuntimeError('Exact qualified mail-actions build provenance pins required')
    return [value for value in arguments if value != '--run']


def child_command(arguments):
    forwarded = validate_arguments(arguments)
    wrapper, adapter = ROOT / 'tasks/run-in-repository.sh', ROOT / ADAPTER
    for path in (wrapper, adapter):
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise RuntimeError('Fixed mail-actions entrypoint unavailable')
    return ['/bin/bash', str(wrapper), sys.executable, '-B', str(adapter), *forwarded]


def coordinate(arguments):
    path = ROOT / 'tests/postgres/run_audit_collection_with_inspector.py'
    spec = importlib.util.spec_from_file_location('mail_actions_fixed_inspector_loop', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.child_command = child_command
    return module.coordinate(arguments)


if __name__ == '__main__':
    raise SystemExit(coordinate(sys.argv[1:]))
