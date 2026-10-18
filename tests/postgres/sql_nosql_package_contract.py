"""Read-only immutable ARIA/NOVA source and Node identity checks; no launches."""
import hashlib
import json
import os
from pathlib import Path
import re

SHA = re.compile(r'^[a-f0-9]{64}$')
REQUIRED = {
    'package.json', 'package-lock.json',
    'tests/postgres/run-sql-nosql-route-isolated.py',
    'tests/postgres/sql_nosql_route_contract.py',
    'tests/postgres/sql_nosql_package_contract.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/bootstrap-sql-nosql-route.js',
    'tests/postgres/sql-nosql-offline-composition-smoke.js',
    'tests/postgres/sqlNoSqlRoute.integration.test.js',
    'tests/fixtures/sqlNoSqlModelProvenance.js',
    'tests/fixtures/sqlNoSqlObservationSequence.js',
    'tests/fixtures/sqlNoSqlIndependentEffects.js',
    'tests/fixtures/sqlNoSqlNativeReferences.js',
    'tests/fixtures/sqlNoSqlQualificationReport.js',
    'tests/fixtures/sqlNoSqlResetQualification.js',
    'tests/fixtures/sqlNoSqlFixedSessionQualification.js',
    'server/routes/sqlWorkshop.js', 'server/routes/nosqlWorkshop.js',
    'server/services/ariaAgentService.js', 'server/services/novaAgentService.js',
    'server/services/workshopObjectiveGrader.js', 'server/services/objectiveCompletionService.js',
    'server/agent-runtime/objectiveJudge.js', 'server/agent-runtime/workshopRouteHandlers.js',
    'server/agent-runtime/workshopGraph.js', 'server/agent-runtime/workshopDecisions.js',
    'server/agent-runtime/workshopHistoryProjection.js', 'server/agent-runtime/runTraceStore.js',
    'server/agent-runtime/durableGeneration.js',
    'server/agent-runtime/effectAdmissionContext.js',
    'server/config/objectiveRubrics.js', 'server/config/legacyFileSsiCurriculum.js',
    'server/database/postgres/sqlWorkshopDb.js',
    'server/database/postgres/nosqlWorkshopDb.js', 'server/database/postgres/identityRepository.js',
    'server/database/postgres/xssJudgmentBindingRepository.js',
    'db/postgres/identity-migrations/0001_identity.sql',
    'db/postgres/identity-migrations/0102_graph_prompt_policy_snapshot.sql',
    'node_modules/pg/package.json', 'node_modules/@langchain/ollama/package.json',
    'node_modules/@langchain/langgraph/package.json',
}

# The credit gate runs the current route/grader graph, so its fresh database
# must apply every registered identity migration through the reviewed response
# provenance head.  These are the only intentionally absent sequence numbers.
IDENTITY_MIGRATION_HEAD = '0102_graph_prompt_policy_snapshot.sql'
IDENTITY_MIGRATION_GAPS = frozenset({21, 62, 63, 64, 68, 87})
IDENTITY_MIGRATION_IDS = frozenset(set(range(1, 103)) - IDENTITY_MIGRATION_GAPS)
JS_ENTRYPOINTS = (
    'tests/postgres/sqlNoSqlRoute.integration.test.js',
    'tests/postgres/bootstrap-sql-nosql-route.js',
    'tests/postgres/sql-nosql-offline-composition-smoke.js',
)


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def inventory(source):
    source = Path(source)
    require(source.is_absolute() and not source.is_symlink() and source.is_dir()
            and source.resolve() == source and not source.stat().st_mode & 0o222,
            'exact immutable source directory required')
    files, links, directories = {}, {}, []
    for entry in source.rglob('*'):
        relative = entry.relative_to(source).as_posix()
        require(not entry.name.startswith('.env') and not entry.name.endswith(('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'))
                and (relative.startswith('node_modules/') or not any(part in {'.git', '__pycache__', 'sensitive_files', 'workshop_data', 'uploads', 'logs', 'vector-indexes'} for part in entry.relative_to(source).parts)),
                'private/runtime material forbidden in source package')
        if entry.is_symlink():
            target = os.readlink(entry)
            require(relative.startswith('node_modules/') and not Path(target).is_absolute(), 'only relative dependency symlinks allowed')
            require(entry.resolve(strict=True).is_relative_to((source / 'node_modules').resolve()), 'external dependency symlink forbidden')
            links[relative] = target
        else:
            require(not entry.stat().st_mode & 0o222, 'writable frozen package entry forbidden')
            if entry.is_file():
                files[relative] = digest(entry)
            elif entry.is_dir():
                directories.append(relative)
            else:
                raise RuntimeError('special package entry forbidden')
    return dict(files=files, symlinks=links, directories=sorted(directories))


def validate_javascript_closure(source, files):
    """Follow every literal relative CommonJS edge reachable from both entrypoints.

    This is deliberately filesystem-only: it exercises no database, provider,
    network, or module top-level behavior. It includes conditional/lazy literal
    requires, which are the omissions that escaped earlier constructor smokes.
    Computed imports remain covered by the small explicit REQUIRED set.
    """
    pending = list(JS_ENTRYPOINTS)
    seen = set()
    pattern = re.compile(r"require\(\s*['\"](\.\.?/[^'\"]+)['\"]\s*\)")
    while pending:
        relative = pending.pop()
        if relative in seen:
            continue
        seen.add(relative)
        for requested in pattern.findall((source / relative).read_text()):
            target = (source / relative).parent.joinpath(requested).resolve()
            candidates = [target, Path(str(target) + '.js'), Path(str(target) + '.json'), target / 'index.js']
            resolved = next((entry.relative_to(source).as_posix() for entry in candidates
                             if entry.is_file() and entry.relative_to(source).as_posix() in files), None)
            require(resolved is not None, f'required relative JavaScript dependency missing: {relative} -> {requested}')
            if resolved.endswith('.js'):
                pending.append(resolved)
    return frozenset(seen)


def validate_identity_migration_closure(files):
    migrations = {relative.rsplit('/', 1)[1] for relative in files
                  if relative.startswith('db/postgres/identity-migrations/')}
    require(IDENTITY_MIGRATION_HEAD in migrations, 'reviewed identity migration head missing')
    observed_ids = []
    for name in migrations:
        match = re.fullmatch(r'(\d{4})_[^/]+\.sql', name)
        require(match is not None and name <= IDENTITY_MIGRATION_HEAD,
                'unreviewed identity migration forbidden')
        observed_ids.append(int(match.group(1)))
    require(len(observed_ids) == len(set(observed_ids)), 'duplicate identity migration sequence forbidden')
    require(frozenset(observed_ids) == IDENTITY_MIGRATION_IDS,
            'complete reviewed identity migration closure required')


def validate_package(source, manifest_path, manifest_sha256, node, node_sha256):
    source, manifest_path, node = Path(source), Path(manifest_path), Path(node)
    require(source.name == 'source' and manifest_path == source.parent / 'manifest.json'
            and set(p.name for p in source.parent.iterdir()) == {'source', 'manifest.json'}, 'exact source-plus-manifest package required')
    require(not source.parent.is_symlink() and not source.parent.stat().st_mode & 0o222, 'immutable package parent required')
    require(manifest_path.is_file() and not manifest_path.is_symlink() and not manifest_path.stat().st_mode & 0o222
            and SHA.fullmatch(manifest_sha256) and digest(manifest_path) == manifest_sha256, 'manifest identity mismatch')
    require(node.is_absolute() and node.is_file() and not node.is_symlink() and os.access(node, os.X_OK)
            and SHA.fullmatch(node_sha256) and digest(node) == node_sha256, 'pinned Node identity mismatch')
    manifest = json.loads(manifest_path.read_text())
    require(type(manifest) is dict and set(manifest) == {'version', 'scope', 'files', 'symlinks', 'directories'}
            and type(manifest['version']) is int and manifest['version'] == 1
            and manifest['scope'] == 'sql_nosql_route_actual8b', 'exact manifest schema required')
    observed = inventory(source)
    require(all(manifest[key] == value for key, value in observed.items()), 'complete immutable inventory mismatch')
    require(REQUIRED <= set(observed['files']), 'required qualification source closure missing')
    validate_javascript_closure(source, observed['files'])
    validate_identity_migration_closure(observed['files'])
    return manifest


def prepare_evidence_root(value, forbidden_roots):
    """Validate an explicitly owned empty directory before any output is written."""
    root = Path(value)
    require(root.is_absolute() and not root.is_symlink() and root.is_dir() and root.resolve() == root,
            'absolute real evidence directory required')
    require(root.stat().st_uid == os.getuid() and not any(root.iterdir()), 'empty owned evidence directory required')
    require(not any(root.is_relative_to(Path(forbidden).resolve()) for forbidden in forbidden_roots),
            'evidence directory must be outside package/workspace')
    root.chmod(0o700)
    return root
