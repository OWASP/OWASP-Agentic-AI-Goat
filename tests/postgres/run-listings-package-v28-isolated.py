#!/usr/bin/env python3
"""Build one disposable qualified Listings image, then run V28 before retiring it.

This is intentionally a compound *qualification* driver.  It never reads or
writes the private installed Listings configuration and delegates package build
and cleanup to ``listings_package_candidate``.  The V28 browser launcher stays
unchanged and receives only the image ID whose package lifecycle remains live.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import listings_package_candidate as package

LAUNCHER = HERE / 'run-secureshop-agent-host-transport-main.py'
SELF = 'tests/postgres/run-listings-package-v28-isolated.py'
V28_COHORT = 'standalone-listing-generated-fixed-browser'
HEX = re.compile(r'[a-f0-9]{64}')
IMAGE_ID = re.compile(r'sha256:[a-f0-9]{64}')


def load_launcher():
    """Load the unchanged launcher as the package helper API, never by copy."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('secureshop_v28_current_main', LAUNCHER)
    if spec is None or spec.loader is None:
        raise RuntimeError('Current V28 launcher unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parser():
    value = argparse.ArgumentParser(allow_abbrev=False)
    value.add_argument('--main-workspace', required=True)
    value.add_argument('--node', required=True)
    value.add_argument('--docker', required=True)
    value.add_argument('--docker-sha256', required=True)
    value.add_argument('--docker-host', required=True)
    value.add_argument('--docker-daemon', required=True)
    value.add_argument('--image-id', required=True)
    value.add_argument('--browser', required=True)
    value.add_argument('--browser-sha256', required=True)
    value.add_argument('--browser-root', required=True)
    value.add_argument('--ollama-model-sha256', required=True)
    value.add_argument('--evidence-parent')
    value.add_argument('--plan', action='store_true')
    return value


def parse(argv):
    flags = [item.split('=', 1)[0] for item in argv if item.startswith('--')]
    if len(flags) != len(set(flags)):
        raise ValueError('Duplicate flags denied')
    return parser().parse_args(argv)


def qualified_package(node, source):
    program = (
        "const p=require('./scripts/install/secureshop-owned-listings-qualified-candidate');"
        "process.stdout.write(JSON.stringify(p.qualifiedPackage({root:process.cwd(),architecture:'arm64'})))"
    )
    result = subprocess.run([node, '-e', program], cwd=source, check=True,
        capture_output=True, text=True, timeout=20, env={'PATH': str(Path(node).parent)})
    value = json.loads(result.stdout)
    if (not isinstance(value, dict) or set(value) != {'architecture', 'runtimeDigest', 'qualifiedSourceSha256'}
            or value.get('architecture') != 'arm64'
            or not all(isinstance(value.get(name), str) and HEX.fullmatch(value[name])
                       for name in ('runtimeDigest', 'qualifiedSourceSha256'))):
        raise RuntimeError('Canonical Listings qualification required')
    return value


def package_argv(args):
    values = [
        '--main-workspace', args.main_workspace, '--node', args.node,
        '--docker', args.docker, '--docker-sha256', args.docker_sha256,
        '--docker-host', args.docker_host, '--docker-daemon', args.docker_daemon,
        '--cohort', 'listings-package',
    ]
    if args.evidence_parent:
        values += ['--evidence-parent', args.evidence_parent]
    return values


def v28_argv(args, listings_image_id, evidence_parent):
    if not IMAGE_ID.fullmatch(listings_image_id):
        raise RuntimeError('Exact disposable Listings image ID required')
    return [
        '--main-workspace', args.main_workspace, '--node', args.node,
        '--docker', args.docker, '--docker-sha256', args.docker_sha256,
        '--docker-host', args.docker_host, '--docker-daemon', args.docker_daemon,
        '--image-id', args.image_id, '--cohort', V28_COHORT,
        '--browser', args.browser, '--browser-sha256', args.browser_sha256,
        '--browser-root', args.browser_root,
        '--ollama-model-sha256', args.ollama_model_sha256,
        '--listings-image-id', listings_image_id,
        '--evidence-parent', str(evidence_parent),
    ]


def read_v28_result(evidence, image_id, source_sha256, runtime_digest):
    evidence = Path(evidence)
    path = evidence / 'result.json'
    status = path.lstat()
    if path.is_symlink() or not path.is_file() or status.st_size > 4 * 1024 * 1024:
        raise RuntimeError('V28 result artifact unavailable')
    value = json.loads(path.read_text())
    cleanup = value.get('cleanup')
    listings_cleanup = cleanup.get('listings') if isinstance(cleanup, dict) else None
    if (not isinstance(value, dict) or value.get('cohort') != 'secureshop-standalone-listing-generated-fixed-browser-current-main-v1'
            or value.get('passed') is not True or not isinstance(cleanup, dict)
            or cleanup.get('errors') != []
            or not all(cleanup.get(name) is True for name in ('containerNameAbsent', 'containerIdAbsent',
                                                              'browserProfilesAbsent', 'browserProcessesAbsent'))
            or listings_cleanup != dict.fromkeys(('containerAbsent', 'volumeAbsent', 'networkAbsent', 'profileAbsent'), True)
            or not isinstance(value.get('sourcePinsSha256'), str) or not HEX.fullmatch(value['sourcePinsSha256'])):
        raise RuntimeError('V28 result failed or cleanup unproven')
    resource_path = evidence / 'listings-resources.json'
    resource_status = resource_path.lstat()
    if resource_path.is_symlink() or not resource_path.is_file() or resource_status.st_size > 256 * 1024:
        raise RuntimeError('V28 Listings resource evidence unavailable')
    resource = json.loads(resource_path.read_text())
    labels = resource.get('labels') if isinstance(resource, dict) else None
    if (not isinstance(resource, dict) or resource.get('image') != image_id or not isinstance(labels, dict)
            or labels.get('owasp-ai-goat.listings.source') != source_sha256
            or labels.get('owasp-ai-goat.listings.runtime') != runtime_digest):
        raise RuntimeError('V28 result Listings identity mismatch')
    return value


def result_from_stdout(stdout, evidence_parent):
    result = None
    for line in reversed(stdout.decode('utf-8', 'strict').splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and set(value) == {'evidence', 'passed', 'cleanup'}:
            result = value
            break
    if result is None or result['passed'] is not True or not isinstance(result['evidence'], str):
        raise RuntimeError('V28 completion receipt unavailable')
    evidence = Path(result['evidence'])
    parent = Path(evidence_parent)
    if (not evidence.is_absolute() or evidence.is_symlink() or evidence.resolve() != evidence
            or not evidence.is_relative_to(parent) or evidence.parent != parent):
        raise RuntimeError('V28 evidence location invalid')
    return evidence


def stop_group(child):
    """Give the unchanged V28 launcher its signal-driven cleanup window first."""
    forced = False
    if child.poll() is None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            forced = True
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        probe = subprocess.run(['/bin/ps', '-axo', 'pgid='], check=True, capture_output=True,
            text=True, timeout=10, env={'PATH': '/usr/bin:/bin'})
        groups = probe.stdout.split()
        if any(not entry.isdigit() for entry in groups):
            raise RuntimeError('V28 process inventory invalid')
        if str(child.pid) not in groups:
            if forced:
                raise RuntimeError('V28 child required force termination; child cleanup unverified')
            return
        time.sleep(.05)
    raise RuntimeError('V28 child process group remains')


def run_v28(args, admission):
    expected = {'imageId', 'imageTag', 'sourceSha256', 'runtimeDigest', 'evidence'}
    if (not isinstance(admission, dict) or set(admission) != expected
            or not IMAGE_ID.fullmatch(admission['imageId'])
            or not all(isinstance(admission[name], str) and HEX.fullmatch(admission[name])
                       for name in ('sourceSha256', 'runtimeDigest'))):
        raise RuntimeError('Package callback admission invalid')
    package_evidence = Path(admission['evidence'])
    v28_parent = package_evidence / 'v28'
    v28_parent.mkdir(mode=0o700)
    v28_parent.chmod(0o700)
    if v28_parent.is_symlink() or v28_parent.resolve() != v28_parent:
        raise RuntimeError('Private V28 evidence parent required')
    output = package_evidence / 'v28.stdout'
    error = package_evidence / 'v28.stderr'
    command = [sys.executable, str(LAUNCHER), *v28_argv(args, admission['imageId'], v28_parent)]
    clean = {
        'PATH': f'{Path(args.node).parent}:{Path(args.docker).parent}:/usr/bin:/bin',
        'HOME': str(package_evidence / 'runtime' / 'home'),
        'TMPDIR': str(package_evidence / 'runtime' / 'tmp'),
        'LANG': 'C', 'DOCKER_HOST': args.docker_host,
    }
    child = None
    try:
        with output.open('xb') as out, error.open('xb') as err:
            os.chmod(output, 0o600); os.chmod(error, 0o600)
            child = subprocess.Popen(command, cwd=args.main_workspace, env=clean, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, start_new_session=True)
            child.wait(timeout=1200)
        if child.returncode != 0:
            raise RuntimeError('V28 child failed')
        raw = output.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError('V28 output exceeds bound')
        evidence = result_from_stdout(raw, v28_parent)
        result = read_v28_result(evidence, admission['imageId'], admission['sourceSha256'],
                                 admission['runtimeDigest'])
        return {'evidence': str(evidence), 'resultSha256': hashlib.sha256((evidence / 'result.json').read_bytes()).hexdigest(),
                'sourcePinsSha256': result['sourcePinsSha256']}
    finally:
        if child is not None:
            stop_group(child)


def main(argv=None):
    args = parse(sys.argv[1:] if argv is None else argv)
    launcher = load_launcher()
    package_args = launcher.parse(package_argv(args))
    source = launcher.validate_static(package_args)
    qualified = qualified_package(args.node, source)
    preflight = package.source_manifest(launcher, package_args, source, (SELF,))
    if preflight['package']['sha256'] != qualified['qualifiedSourceSha256']:
        raise RuntimeError('Current Listings source differs from canonical qualification')
    if args.plan:
        # Validate the unchanged V28 argument contract without allocating Docker,
        # profiles, browser, stores, or a candidate image.
        planned = launcher.parse(v28_argv(args, 'sha256:' + '0' * 64, Path('/private/v28')) + ['--plan'])
        launcher.validate_static(planned)
        print(json.dumps({'cohort': 'listings-package-v28', 'workspace': str(source),
            'packageCohort': 'listings-package', 'v28Cohort': V28_COHORT,
            'sourceCopy': False, 'nativeStarted': False, 'browserStarted': False,
            'runtimeDigest': qualified['runtimeDigest'], 'sourceSha256': qualified['qualifiedSourceSha256']}))
        return 0
    callback = lambda admission: run_v28(args, admission)
    code = package.qualify(launcher, package_args, source, after_package=callback,
        expected_runtime_digest=qualified['runtimeDigest'], expected_source_sha256=qualified['qualifiedSourceSha256'],
        additional_drivers=(SELF,))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
