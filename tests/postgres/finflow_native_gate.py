"""Pure checks used by the owned FinFlow native launcher."""
import json
import re
import subprocess
from finflow_candidate_source import APPROVED_SOURCE_FIXTURES, validate_staged_path, verified_source_file
import os
import hashlib
import shutil
import secrets
from pathlib import Path


def _validate_cohort_path(relative, approved_fixtures):
    validate_staged_path(relative)
    if relative in APPROVED_SOURCE_FIXTURES and relative not in approved_fixtures:
        raise RuntimeError(f'source fixture is outside the selected FinFlow cohort: {relative}')


def stage_source_copy(source, copied, tracked, *, dependency_root, cohort):
    """Copy exactly the manifest-bound closure and attach the canonical dependencies."""
    source = Path(source).resolve()
    copied = Path(copied)
    dependency_root = Path(dependency_root).resolve()
    if copied.exists():
        raise RuntimeError('staged source destination must be absent')
    if not dependency_root.is_dir() or dependency_root.is_symlink():
        raise RuntimeError('canonical node_modules dependency root is required')
    approved_fixtures = cohort_contract(cohort)['fixtures']
    for relative in tracked:
        _validate_cohort_path(relative, approved_fixtures)
    copied.mkdir(parents=True, mode=0o700)
    for relative in tracked:
        validate_staged_path(relative)
        original = verified_source_file(source, relative)
        target = copied / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, target)
    (copied / 'node_modules').symlink_to(dependency_root, target_is_directory=True)
    copied_files = sorted(
        str(path.relative_to(copied))
        for path in copied.rglob('*')
        if path.is_file() and not path.is_symlink()
    )
    if copied_files != sorted(tracked):
        raise RuntimeError('staged source contains files outside the executable closure')

def private_jwt_secret():
    """Create an unlogged signing secret that meets the platform minimum."""
    value = secrets.token_urlsafe(48)
    if len(value.encode()) < 32:
        raise RuntimeError('generated JWT secret is shorter than 32 bytes')
    return value


def fixture_override_hashes(approved_baselines, fixtures):
    """Allow overlays only after all approved baseline fixture hashes are bound."""
    required = {
        'server/sensitive_files/logs/access.log',
        'server/sensitive_files/logs/error.log',
        'server/sensitive_files/logs/audit.log',
        'server/sensitive_files/logs/llm_requests.log',
    }
    if not required.issubset(approved_baselines):
        raise RuntimeError('approved log fixture baselines must be bound before overlays')
    allowed = {'server/sensitive_files/config/secrets.env', 'server/sensitive_files/config/llm_config.yml',
               'server/sensitive_files/etc/passwd', 'server/sensitive_files/logs/access.log', 'server/config/secrets.env'}
    if set(fixtures) != allowed:
        raise RuntimeError('exact synthetic FinFlow fixture overlay set is required')
    if 'server/sensitive_files/logs/llm_requests.log' in fixtures:
        raise RuntimeError('approved LLM log fixture must not be overlaid')
    return {relative: {'sha256': hashlib.sha256(content.encode()).hexdigest(),
                       'byteLength': len(content.encode())}
            for relative, content in fixtures.items()}


def postgres_store_setup(stores):
    """Return the isolated role/database commands for every requested store."""
    commands = []
    for family, database in stores:
        migration, runtime = f'dvaia_{family}_migration', f'dvaia_{family}_runtime'
        for role in (migration, runtime):
            commands.append(
                f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                'NOREPLICATION NOBYPASSRLS')
        commands.append(f'CREATE DATABASE {database} OWNER {migration}')
        commands.append(
            f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
            f'GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}')
    return commands


def validate_grant(grant, *, grant_id, owner, docker_host, canonical_workspace,
                   candidate_source_root, candidate_manifest_sha256, source_hashes):
    if (grant.get('grantId') != grant_id or grant.get('owner') != owner
            or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != docker_host
            or grant.get('canonicalWorkspaceRoot') != str(Path(canonical_workspace).resolve())
            or grant.get('candidateSourceRoot') != str(Path(candidate_source_root).resolve())
            or not isinstance(candidate_manifest_sha256, str) or len(candidate_manifest_sha256) != 64
            or any(c not in '0123456789abcdef' for c in candidate_manifest_sha256)
            or grant.get('candidateManifestSha256') != candidate_manifest_sha256
            or not isinstance(source_hashes, dict) or not source_hashes
            or grant.get('sourceHashes') != source_hashes):
        raise RuntimeError('exact one-use FinFlow grant is required')


def cleanup_owned(*, stop_child, remove_container, container_absent):
    """Attempt every owned cleanup step and report terminal eligibility."""
    errors = []
    try:
        child_reaped = bool(stop_child())
    except Exception as error:
        child_reaped = False
        errors.append(type(error).__name__)
    try:
        remove_return_code = remove_container()
    except Exception as error:
        remove_return_code = None
        errors.append(type(error).__name__)
    try:
        exact_container_absent = bool(container_absent())
    except Exception as error:
        exact_container_absent = False
        errors.append(type(error).__name__)
    clean = (not errors and child_reaped and exact_container_absent
             and (remove_return_code is None or remove_return_code == 0))
    return {'errors': errors, 'childReaped': child_reaped,
            'removeReturnCode': remove_return_code,
            'exactContainerAbsent': exact_container_absent, 'clean': clean}


def validate_owner_handle(value, *, consumer_pid=None):
    consumer_pid = os.getpid() if consumer_pid is None else consumer_pid
    if not isinstance(value, str) or not value.isdecimal() or int(value) <= 0 or int(value) == consumer_pid:
        raise RuntimeError('owner handle must be a positive exec session ID, not consumer PID')
    return int(value)


INVENTORY_RELATIVE = (
    'docs/modernization/drafts/'
    'finflow-route-admin-logs-v4-tracked-files-2026-09-14.json'
)

LAUNCHER_CLOSURE = (
    'tests/finflowModelDecision.test.js',
    'tests/postgres/finflowCandidateSource.test.py',
    'tests/postgres/finflow_candidate_source.py',
    'tests/postgres/finflow_native_gate.py',
    'tests/postgres/native_source_provenance.py',
    'tests/postgres/run-finflow-route-isolated.py',
)

PREFLIGHT_MODULES = (
    './server/routes/sensitiveInfoWorkshop',
    './server/database/postgres',
    './server/database/postgres/identityRepository',
    './server/database/postgres/workshopPlatformSeed',
    './server/database/postgres/sensitiveInfoWorkshopDb',
    './server/database/postgres/workshopProgressRepository',
)

_LOCAL_REQUIRE = re.compile(
    r"(?:require\(\s*|from\s+|import\s*)['\"](?P<name>\.{1,2}/[^'\"]+)['\"]"
)

def _resolve_local_module(source, importer, requested):
    base = ((source / importer).parent / requested).resolve(strict=False)
    candidates = [base, base.with_suffix('.js'), base.with_suffix('.json'), base / 'index.js']
    for candidate in candidates:
        try:
            relative = str(candidate.relative_to(source))
        except ValueError:
            continue
        try:
            return str(verified_source_file(source, relative).relative_to(source))
        except RuntimeError:
            continue
    raise RuntimeError(f'local module is absent from candidate: {importer} -> {requested}')

def _expand_local_dependencies(source, paths, *, seeds):
    expanded = set(paths)
    pending = list(seeds)
    scanned = set()
    while pending:
        relative = pending.pop()
        if relative in scanned:
            continue
        scanned.add(relative)
        content = verified_source_file(source, relative).read_text(errors='replace')
        for match in _LOCAL_REQUIRE.finditer(content):
            dependency = _resolve_local_module(source, relative, match.group('name'))
            if dependency not in expanded:
                validate_staged_path(dependency)
                expanded.add(dependency)
            if dependency.endswith(('.js', '.mjs', '.cjs')) and dependency not in scanned:
                pending.append(dependency)
    return sorted(expanded)

def finflow_executable_closure(source, *, cohort):
    """Return the complete reviewed application closure staged for the native child."""
    selected = cohort_contract(cohort)
    NATIVE_TESTS = selected['NATIVE_TESTS']
    DETERMINISTIC_TESTS = selected['DETERMINISTIC_TESTS']
    REVIEWED_PACKAGE_INPUTS = selected['REVIEWED_PACKAGE_INPUTS']
    selected_fixtures = selected['fixtures']
    source = Path(source).resolve()
    inventory = json.loads((source / INVENTORY_RELATIVE).read_text())
    tracked = inventory.get('trackedFiles')
    if inventory.get('version') != 1 or not isinstance(tracked, list) \
            or tracked != sorted(set(tracked)) or INVENTORY_RELATIVE not in tracked \
            or 'tests/postgres/run-finflow-route-isolated.py' not in tracked:
        raise RuntimeError('exact FinFlow source inventory is required')
    migrations = sorted(
        str(path.relative_to(source))
        for directory in (
            source / 'db/postgres/identity-migrations',
            source / 'db/postgres/workshop-migrations/finflow',
        )
        for path in directory.glob('*.sql')
    )
    runtime = sorted(
        str(path.relative_to(source))
        for directory in (
            source / 'server/agent-runtime',
            source / 'server/database/postgres',
            source / 'server/services',
            source / 'server/routes',
            source / 'server/middleware',
            source / 'server/config',
            source / 'server/data',
        )
        for path in directory.rglob('*.js')
    )
    closure = _expand_local_dependencies(source, sorted(set(
        tracked + migrations + runtime + list(selected_fixtures)
        + list(NATIVE_TESTS) + list(DETERMINISTIC_TESTS)
        + list(REVIEWED_PACKAGE_INPUTS) + list(LAUNCHER_CLOSURE)
    )), seeds=NATIVE_TESTS + DETERMINISTIC_TESTS + ('tests/finflowModelDecision.test.js',))
    for relative in closure:
        _validate_cohort_path(relative, selected_fixtures)
        verified_source_file(source, relative)
    for relative in NATIVE_TESTS + LAUNCHER_CLOSURE:
        if relative not in closure:
            raise RuntimeError(f'native test entrypoint is absent from closure: {relative}')
    return closure

def preflight_staged_imports(copied, *, node_binary, environment):
    """Load the actual native route/store composition while forbidding connections."""
    copied = Path(copied).resolve()
    def source_snapshot():
        return sorted(
            (str(path.relative_to(copied)), hashlib.sha256(path.read_bytes()).hexdigest())
            for path in copied.rglob('*')
            if path.is_file() and not path.is_symlink()
        )
    before = source_snapshot()
    script = r"""
const net = require('node:net');
const tls = require('node:tls');
const blocked = () => { throw new Error('preflight attempted a network connection'); };
net.connect = blocked;
net.createConnection = blocked;
net.Socket.prototype.connect = blocked;
tls.connect = blocked;
const loaded = process.argv.slice(1).map(name => [name, typeof require(name)]);
process.stdout.write(JSON.stringify(loaded));
"""
    result = subprocess.run(
        [str(node_binary), '-e', script, *PREFLIGHT_MODULES],
        cwd=copied,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError('staged FinFlow import preflight failed: ' + result.stderr[-1000:])
    after = source_snapshot()
    if after != before:
        raise RuntimeError('staged FinFlow import preflight mutated the source copy')
    return result.stdout

COHORTS = {'durable-v9': {'NATIVE_TESTS': ('tests/finflowAgentDurableWiring.test.js', 'tests/finflowLogArtifactAuthority.test.js', 'tests/postgres/finflowPolicyCandidate.integration.test.js'), 'DETERMINISTIC_TESTS': (), 'REVIEWED_PACKAGE_INPUTS': ()}, 'combined-admin-durable': {'NATIVE_TESTS': ('tests/finflowAgentDurableWiring.test.js', 'tests/finflowAdminArtifactJudge.test.js', 'tests/finflowAdminArtifacts.test.js', 'tests/finflowLogArtifactAuthority.test.js', 'tests/postgres/finflowPolicyCandidate.integration.test.js'), 'DETERMINISTIC_TESTS': ('tests/finflowDurableResources.test.js', 'tests/sensitiveInfoWorkshop.test.js', 'tests/postgres/finflowAdminArtifactDefaults.integration.test.js'), 'REVIEWED_PACKAGE_INPUTS': ('docs/modernization/drafts/finflow_durable_customer_backups_unregistered.sql', 'tests/postgres/fixtures/admin-curriculum-before.json', 'tests/postgres/fixtures/admin-curriculum-proposed.json')}, 'admin-error-r2': {'NATIVE_TESTS': ('tests/finflowLogArtifactAuthority.test.js', 'tests/postgres/finflowPolicyCandidate.integration.test.js'), 'DETERMINISTIC_TESTS': (), 'REVIEWED_PACKAGE_INPUTS': ()}}

def cohort_contract(cohort):
    if cohort not in COHORTS:
        raise RuntimeError('Explicit historical FinFlow cohort required')
    selected = dict(COHORTS[cohort])
    selected['fixtures'] = tuple(sorted(p for p in APPROVED_SOURCE_FIXTURES
        if cohort != 'durable-v9' or p.startswith('server/sensitive_files/logs/')))
    return selected
