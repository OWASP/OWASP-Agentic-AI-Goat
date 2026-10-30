#!/usr/bin/env python3
"""Closed repository-local admission and run route for rendered student deletion.

Plan eligibility means reviewed source and runtime inputs are admitted, not that
the native deletion has passed. Only the exact final receipt can prove that.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from full_backend_auth_contract import STORES, student_deletion_source_closure
from secureshop_current_host_admission import evidence_parent, validate_current_host
from admin_q05_current_host import (
    LibProc, encoded, files, inventory, physical_python, sandbox_write_denied,
    sha, source_files, validate_modern_build_receipt,
)


COHORT = 'admin-acl-permission-current-host'
ACL_SOURCE = ('tests/postgres/aclPermissionCurrentHostAdmission.js', 'tests/postgres/secureshopEnabledIndexStartup.integration.test.js', 'tests/fixtures/secureshopEnabledUsersBrowser.js', 'tests/postgres/acl_permission_execution.py', 'tests/postgres/acl_permission_current_host.py', 'tests/postgres/acl_permission_receipt.py', 'tests/postgres/run_acl_permission_with_inspector.py', 'tests/postgres/run-acl-permission-current-host.py', 'tests/fixtures/secureshopEnabledAclBrowser.js', 'tests/fixtures/secureshopAclPermissionRecoveryBrowser.js', 'tests/fixtures/inheritedFifoGrant.js', 'tests/fixtures/fullBackendBootControls.js', 'tests/fixtures/fullBackendRenderedSecureShop.js', 'tests/helpers/secureshopMcpToolsEnabledQualification.js')
AST_HELPER_SHA256 = 'b1d3daef8c0541c95b296b8fff1557a8d19d75d63896b0e7ad37a7f44565f7f2'
SUPPORT_SHA256 = '5044ea0823fc828a118db83e41d61e5ddc123f898bd2391aa82e367add1a0cab'
SEED_SUPPORT_SHA256 = 'd72fb00c55cec75a2e81e0ae37f26e2c29e429a53e9674d3cd73acbb6a688dcf'
ARTIFACT_SUPPORT_SHA256 = 'd0c1a6831c1308dbe13bb27916ec29270f0711b401ab36eb583bbabbbacc90fc'
NETWORK_GUARD_SHA256 = 'd712395abbdb875af25554154afad902c5ad4a4a3dde905622c4066b8375b539'
SECURESHOP_SUPPORT_SHA256 = '4b0315bc5de49f049eebc4a6aa1f49719e817b1003d1971c2fdee5bcc840c4e3'
RENDERED_TEST_SHA256 = '19915b9356999f802c4c30696224c08fecd1d0c040c9558676fe0c7ab9de08d4'
RENDERED_CONTRACT_SHA256 = '014589aae93f679c25ccbbe83ae10fc24fe5e1618e86ed952dfde893af409071'
INITIALIZER_SHA256 = 'd243ecca2194415c4173c54ad34113817b76fa1da81b62d17a6a8290e69d6801'
LIMITS = {
    'containers': 1, 'stores': 16, 'baseStoreRoles': 32,
    'dedicatedCtfDeliveryRoles': 1, 'totalLoginRoles': 33,
    'provisioningAdminExcludedFromRoleCount': True,
    'memoryBytes': 2 * 1024 ** 3,
    'memorySwapBytes': 2 * 1024 ** 3,
    'cpus': 2, 'pids': 256, 'postgresTmpfsBytes': 1024 ** 3,
    'maxConnections': 96, 'aggregatePoolBudget': 78,
    'migrationOrder': 'sequential', 'migrationPoolsDrainedBeforeRendered': True,
    'actualModelCalls': 0,
}
REQUIRED_FUTURE = (
    'tests/postgres/adminStudentDeletionInitialize.js',
    'tests/postgres/adminStudentDeletionRendered.integration.test.js',
    'tests/postgres/admin_student_deletion_receipt.py',
    'tests/postgres/run_acl_permission_with_inspector.py',
)


def database_plan(nonce):
    """Derive identifiers from the canonical sixteen-store manifest, never URLs."""
    if not isinstance(nonce, str) or re.fullmatch(r'[a-f0-9]{12}', nonce) is None:
        raise RuntimeError('Exact disposable database nonce required')
    rows = tuple({'schema': schema,
                  'database': f'owasp_ai_goat_test_student_deletion_{nonce}_{schema}',
                  'runtimeVariable': prefix + '_DATABASE_URL',
                  'migrationVariable': prefix + '_MIGRATION_DATABASE_URL'}
                 for schema, prefix in STORES)
    if len(rows) != 16 or len({row['database'] for row in rows}) != 16:
        raise RuntimeError('Sixteen distinct canonical stores required')
    if any(len(row['database'].encode('utf-8')) > 63 for row in rows):
        raise RuntimeError('PostgreSQL database identifier exceeds 63 bytes')
    return rows


def store_plan_sha256(nonce):
    """Bind only canonical database identities; pool reservations are separate."""
    rows = [{'database': row['database'], 'schema': row['schema']}
            for row in database_plan(nonce)]
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False).encode('utf-8')).hexdigest()


def admission_grant(repo, run_root, nonce, args, worker_pid, profile):
    """Construct a future one-worker FIFO grant without allocating a resource."""
    repo = Path(repo)
    parent = evidence_parent(repo)
    run_root = Path(run_root)
    expected = parent / ('run-admin-acl-permission-' + nonce)
    if run_root != expected or run_root.is_symlink() or not run_root.is_dir() \
            or run_root.stat().st_uid != os.getuid() or run_root.stat().st_mode & 0o077:
        raise RuntimeError('Exact private acl-permission run required')
    tmp = run_root / 'runtime/tmp'
    for directory in (run_root / 'runtime', tmp):
        if directory.is_symlink() or not directory.is_dir() \
                or directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            raise RuntimeError('Exact private acl-permission runtime required')
    expected_profile = tmp / ('owasp-ai-goat-acl-permission-browser-' + nonce)
    if Path(profile) != expected_profile or expected_profile.exists() or expected_profile.is_symlink():
        raise RuntimeError('Fresh exact acl-permission browser profile required')
    if type(worker_pid) is not int or worker_pid <= 0:
        raise RuntimeError('Owned worker PID required')
    for name in ('build_sha256', 'snapshot_sha256'):
        if not re.fullmatch(r'[a-f0-9]{64}', getattr(args, name, '') or ''):
            raise RuntimeError('Pinned build and source snapshot required')
    chromium = Path(args.chromium)
    if not chromium.is_absolute() or chromium.is_symlink() \
            or chromium.resolve() != chromium or not chromium.is_file():
        raise RuntimeError('Exact admitted Chromium executable required')
    return dict(version=1, cohort=COHORT, launcherPid=os.getpid(), workerPid=worker_pid,
                nonce=nonce, workspace=str(repo), buildSha256=args.build_sha256,
                snapshotSha256=args.snapshot_sha256, outerSandbox='repository-only',
                chromium=str(chromium), profile=str(expected_profile),
                storePlanSha256=store_plan_sha256(nonce))


def reviewed_file(repo, relative, expected):
    path = repo / relative
    if path.is_symlink() or path.resolve() != path or not path.is_file() \
            or not stat.S_ISREG(path.stat().st_mode) or sha(path) != expected:
        raise RuntimeError('Reviewed deletion support source pin mismatch')


def deletion_source_files(repo):
    """Authenticate the two transitive source trees omitted by Q05's scope."""
    result = source_files(repo)
    for relative in ACL_SOURCE:
        result[relative] = sha(repo / relative)
    for name in ('agent-host', 'sidecars'):
        root = repo / name
        if root.is_symlink() or root.resolve() != root or not root.is_dir():
            raise RuntimeError('Deletion transitive source tree unavailable')
        for directory, dirs, names in os.walk(root, followlinks=False):
            if any(Path(directory, item).is_symlink() for item in dirs + names):
                raise RuntimeError('Deletion transitive source link forbidden')
            dirs[:] = sorted(item for item in dirs if item not in ('node_modules', '__pycache__'))
            for item in sorted(names):
                path = Path(directory) / item
                if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
                    raise RuntimeError('Deletion transitive source must be regular')
                result[path.relative_to(repo).as_posix()] = sha(path)
    return dict(sorted(result.items()))


def blockers(repo, closure_error=None):
    result = [f'missing:{name}' for name in REQUIRED_FUTURE if not (repo / name).is_file()]
    if closure_error is not None:
        result.append('canonical-deletion-source-closure-unresolved')
    return tuple(result)


def parse(argv):
    flags = [item.split('=', 1)[0] for item in argv if item.startswith('--')]
    if len(flags) != len(set(flags)):
        raise RuntimeError('Duplicate options forbidden')
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--run', action='store_true')
    parser.add_argument('--acl-permission-recovery', action='store_true', required=True)
    parser.add_argument('--nonce', required=True)
    for name in ('node', 'node-sha256', 'docker', 'docker-sha256', 'docker-host',
                 'daemon-id', 'image-id', 'current-host-profile', 'chromium',
                 'chromium-sha256', 'browser-root', 'python-sha256', 'build-sha256',
                 'build-report', 'build-report-sha256', 'build-input-sha256',
                 'build-output-sha256', 'build-recorder-sha256', 'source-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--snapshot-sha256')
    args = parser.parse_args(argv)
    if args.run and re.fullmatch(r'[a-f0-9]{64}', args.snapshot_sha256 or '') is None:
        raise RuntimeError('Explicit reviewed deletion snapshot required')
    if args.plan and args.snapshot_sha256 is not None:
        raise RuntimeError('Plan cannot supply a future run snapshot')
    return args


def plan(args, *, repo=None, host_validator=validate_current_host,
         build_validator=validate_modern_build_receipt):
    repo = Path(repo) if repo is not None else Path(__file__).resolve().parents[2]
    if repo != Path(__file__).resolve().parents[2] or repo.is_symlink() \
            or repo.resolve() != repo or not repo.is_dir():
        raise RuntimeError('Only this existing checkout is admitted')
    rows = database_plan(args.nonce)
    for relative in ACL_SOURCE:
        if not (repo / relative).is_file(): raise RuntimeError("ACL source closure missing")
    source = deletion_source_files(repo)
    if not re.fullmatch(r'[a-f0-9]{64}', args.source_sha256 or '') \
            or encoded(source) != args.source_sha256:
        raise RuntimeError('Exact current-source snapshot pin required')
    host = host_validator(workspace=str(repo), profile=args.current_host_profile,
        docker_host=args.docker_host, node=args.node, node_sha256=args.node_sha256,
        docker=args.docker, docker_sha256=args.docker_sha256,
        daemon_id=args.daemon_id, image_id=args.image_id)
    build = files(repo / 'client/build')
    if 'index.html' not in build or encoded(build) != args.build_sha256:
        raise RuntimeError('Exact existing frontend build pin required')
    # This verifier checks the recorded installed dependency inventory against
    # client/node_modules before the source-owned AST helper loads Babel.
    provenance = build_validator(repo, args)
    closure_error = None
    closure = frozenset(ACL_SOURCE)
    if not closure <= set(source): raise RuntimeError("ACL source closure missing")
    browser = Path(args.chromium)
    browser_root = Path(args.browser_root)
    if browser.is_symlink() or browser.resolve() != browser or not browser.is_file() \
            or not browser.is_relative_to(browser_root) \
            or not re.fullmatch(r'[a-f0-9]{64}', args.chromium_sha256 or '') \
            or sha(browser) != args.chromium_sha256:
        raise RuntimeError('Exact existing Chromium pin required')
    browser_inventory = inventory(browser_root)
    python = Path(sys.executable).resolve()
    if not re.fullmatch(r'[a-f0-9]{64}', args.python_sha256 or '') \
            or sha(python) != args.python_sha256:
        raise RuntimeError('Exact Python pin required')
    remaining = blockers(repo, closure_error)
    return {
        'cohort': COHORT, 'eligible': not remaining, 'actualExecution': False,
        'sourceCopy': False, 'existingBuild': True,
        'limits': LIMITS, 'databases': rows, 'sourceSha256': args.source_sha256,
        'sourceClosureFiles': len(closure), 'buildSha256': args.build_sha256,
        'buildProvenance': provenance, 'browserInventorySha256': encoded(browser_inventory),
        'pythonSha256': args.python_sha256, 'currentHost': host,
        'blockers': remaining,
    }


def snapshot(repo, args, admitted):
    """Bind the actual input closure used by the direct-child rendered run."""
    repo = Path(repo)
    source = deletion_source_files(repo)
    if encoded(source) != args.source_sha256 or admitted['sourceSha256'] != args.source_sha256:
        raise RuntimeError('Deletion source changed after admission')
    build = files(repo / 'client/build')
    if encoded(build) != args.build_sha256:
        raise RuntimeError('Existing qualified build changed after admission')
    python = Path(sys.executable).resolve()
    physical = Path(physical_python())
    if sha(python) != args.python_sha256:
        raise RuntimeError('Pinned Python changed after admission')
    executables = {}
    for name in ('node', 'docker'):
        path = Path(getattr(args, name))
        expected = getattr(args, name + '_sha256')
        if path.is_symlink() or path.resolve() != path or not path.is_file() \
                or not path.is_relative_to(repo) or sha(path) != expected:
            raise RuntimeError('Pinned repository runtime changed after admission')
        executables[name] = {'path': str(path), 'sha256': expected}
    return dict(source=source, build=build,
        buildProvenance=admitted['buildProvenance'],
        dependencies={'root': inventory(repo / 'node_modules'),
                      'client': inventory(repo / 'client/node_modules')},
        browser=inventory(Path(args.browser_root)),
        python={'path': str(python), 'sha256': args.python_sha256,
                'physicalPath': str(physical), 'physicalSha256': sha(physical)},
        runtimes=executables,
        executionPins={'profile': args.current_host_profile,
            'dockerHost': args.docker_host, 'daemonId': args.daemon_id,
            'imageId': args.image_id, 'chromium': args.chromium,
            'chromiumSha256': args.chromium_sha256,
            'storePlanSha256': store_plan_sha256(args.nonce),
            'renderedFixtureSha256': RENDERED_TEST_SHA256,
            'initializerOwner': 'original-enabled-index-fixture'},
        limits=LIMITS, cohort=COHORT)


def verify_outer_boundary(repo, argv, inspector, *, api=None,
                          denied=sandbox_write_denied):
    """The fixed Inspector must be the live same-user direct parent."""
    api = api or LibProc()
    parent = os.getppid()
    if inspector.parent != parent:
        raise RuntimeError('Inspector is not current direct parent')
    row = api.identity(parent)
    if row is None or row.uid != os.getuid() or row.ruid != os.getuid():
        raise RuntimeError('Same-user Inspector parent required')
    birth = (row.start_sec, row.start_usec)
    actual = api.arguments(parent)
    fixed = str(repo / 'tests/postgres/run_acl_permission_with_inspector.py')
    if len(actual) != len(argv) + 3 or actual[0] != str(physical_python(api)) \
            or list(actual[1:]) != ['-B', fixed, *argv]:
        raise RuntimeError('Exact reviewed outside Inspector invocation required')
    after = api.identity(parent)
    if after is None or (after.start_sec, after.start_usec) != birth \
            or after.uid != os.getuid() or after.ruid != os.getuid():
        raise RuntimeError('Inspector parent birth changed')
    if not denied('/private/tmp') or denied(repo / 'tasks/qualification') or any(not denied(repo / part) for part in ('tests', 'server', 'client', 'db', 'scripts', 'agent-host', 'shared', 'sidecars')):
        raise RuntimeError('Repository-only write sandbox required')


def main(argv=None):
    raw = sys.argv[1:] if argv is None else argv
    args = parse(raw)
    repo = Path(__file__).resolve().parents[2]
    admitted = plan(args, repo=repo)
    before = snapshot(repo, args, admitted)
    digest = encoded(before)
    if args.plan:
        print(json.dumps({**admitted, 'snapshotSha256': digest},
                         sort_keys=True, separators=(',', ':')))
        return 0
    if admitted['blockers']:
        raise RuntimeError('Reviewed deletion run proofs remain incomplete')
    if sys.platform != 'darwin' or digest != args.snapshot_sha256:
        raise RuntimeError('Darwin reviewed deletion snapshot mismatch')
    from trusted_process_inspector import consume_environment
    from acl_permission_execution import execute
    from acl_permission_receipt import verify_deletion_tap, verify_final_evidence
    inspector = consume_environment()
    if inspector is None:
        raise RuntimeError('Fixed outside acl-permission Inspector required')
    verify_outer_boundary(repo, raw, inspector)
    run_root = evidence_parent(repo) / ('run-admin-acl-permission-' + args.nonce)
    result = execute(args, repo=repo, inspector=inspector, before=before,
        verify_tap=verify_deletion_tap,
        verify_fixture=lambda evidence, journal, browser: verify_final_evidence(
            evidence, journal, browser, repo=repo, run_root=run_root,
            nonce=args.nonce, chromium=args.chromium),
        snapshot_after=lambda: snapshot(repo, args, plan(args, repo=repo)))
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
