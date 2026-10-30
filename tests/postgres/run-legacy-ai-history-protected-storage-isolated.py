#!/usr/bin/env python3
"""Strict one-use launcher for the unregistered legacy AI history draft.

The launcher accepts only an immutable reviewed package, a pinned managed Node
runtime, a pinned PostgreSQL image, and an exact root-owned one-use grant. It
creates one fresh disposable identity database, runs the draft-only integration
test, and proves process, database, and container cleanup. It never reads the
canonical workspace's environment or application databases and never registers
the draft in the canonical migration prefix.
"""

import argparse
import contextlib
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


STAGE = 'legacy-ai-history-protected-storage-source-r1'
SCOPE = 'legacy_ai_history_protected_storage_pg18'
POSTGRES_IMAGE = 'postgres:18'
POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DOCKER_HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
DOCKER_DAEMON_ID = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
NODE_VERSION = 'v26.8.2'
MIGRATION_ROLE = 'dvaia_identity_migration'
RUNTIME_ROLE = 'dvaia_identity_runtime'
TEST_PATH = 'tests/postgres/legacyAiHistoryProtectedStorage.integration.test.js'
LAUNCHER_PATH = 'tests/postgres/run-legacy-ai-history-protected-storage-isolated.py'
CONTRACT_PATH = 'tests/legacyAiHistoryProtectedStorageLauncher.test.js'
DRAFT_PATH = 'docs/modernization/drafts/legacy-ai-history-protected-storage.sql'
REPOSITORY_PATH = 'server/database/postgres/legacyAiHistoryRepository.js'
REGISTERED_IDENTITY_HEAD = '0065_ipi_email_artifacts.sql'
REVIEWED_IDENTITY_MIGRATIONS_SHA256 = '748ef0a8288da4953eecc65a00e7eeb57c0cf7f03f1b1f27250ed4e5df4ead10'
REVIEWED_IDENTITY_MIGRATIONS_TEXT = """\
0001_identity.sql:e11a3d736b95e24c63d0978276ba2db381e9ccd50e55f8250278d07d1852b290
0002_workshop_platform.sql:c66614fe96e8d083dcb5a03c05b46cce94f56bc3a4a36936e5a6c0acea2f3d16
0003_account_flows.sql:4c2b1dc14d0e569e26d96bdfd61421faf5160a21c58c1508eeaf6959ea6bbc72
0004_graph_runtime.sql:9142fc8b173fcb9811d5f002d6de3094b9c438786a11c8de86efe644773eefce
0005_attendee_email.sql:d628bc60d4fc5a56487037ad0688aa4c699cb578e7f5bcb36ea424242fa28baf
0006_graph_trace.sql:2c0172071845b9fc50ccb3e1a5dec6f018902dc3afaf8499dafb0cb64be013cf
0007_objective_judgments.sql:fc402b6b0c42db9b80cb38da5578a44e92a36e14e1755446a6a09e614a13a9fb
0008_objective_evidence.sql:a6908bc9b8e9ad2828672a7f7d565f7fe29d9645862e9cd53d606d63e41c58e9
0009_grade_recovery.sql:908a08e475f3c66dab407ff309a305cccbb112f684e6dd40bc4fb3fb0598a6ac
0010_workshop_activity.sql:2fdc3870172cdff6ab3e71df629b69ec8e324c1cfd31e89172030063652822e8
0011_dpi_practice_receipts.sql:28dae1a95a41030a58da69d3c6c46c6b53460885f367978a1d8e6ca23be45ff4
0012_historical_import_provenance.sql:c295a68e588aac2a95380403b51fb759db0ed7d3db7dae9a65de30db61549c4f
0013_import_batches.sql:3404b01cefeb17e1cabf8268f577ef204f80297c451de915914de4ac3b458d95
0014_xss_legacy_admin.sql:d37cab88f97d7d6303f551ca4827b896596184e4e45551a3f7a315e527988278
0015_identity_auxiliary_provenance.sql:acb61dfcc888432c666671c46836821bfd8c31671567f426d37830ffcf5ffa6e
0016_graph_judge_trace_metadata.sql:ae2abb8d9e0ec6f6fb22672add8a7013a08215d825a8593e542a4d9f4c177d72
0017_auxiliary_trigger_table_fields.sql:b1b23b8d62c765e8e860cba2a6655cd39dcc169f5c9683782541b7e6dd3698a8
0018_graph_provisional_event.sql:a6fa2dd54cd5ce6d4dcf3c1eb393da0574773c32bec02e834a37de8ba375f8df
0019_archive_owner_bindings.sql:f6d138ee12fc36c2c5a18fbea8bf214eeb654440667afed24783f7eea52cc6d3
0020_bootstrap_admin_permissions.sql:b8b3da6440a38152440c4a78e10a6ad559b2fbadd23ce9a8acc846a633452d79
0022_activity_log_retention.sql:d3697b5384643a891011fa627779d9b5bf5a147e66e9e15a825e463e75692922
0023_workshop_teaching_content.sql:b7fc060900c4100e27ec8558fb0ba9ab0982d7f6364af8c5a72904054b0d2d2e
0024_codebot_javascript_objective.sql:9c0df183c9a93285cf71cf24e529905dcf9313304ef266e776eba0b624c7b923
0025_secureshop_launch_authority.sql:8208ac3e570520491c9700dd2c954172484013033e5d7a16d70d0a1fd5267b3e
0026_secureshop_target_reservations.sql:ae135e65ea7d1bb641a1828f0958c0973954bb63824e7bcc22d4170f129b48d7
0027_secureshop_target_admission.sql:6cfb2f5058da5560f125a3073e129c68a796b94abc0382ccae4c64ee66a60c8b
0028_secureshop_review_target_reservation.sql:8887937a90a3071bebfd08e382df4f3344bfb44c482d2ec9546d60aa808011d2
0029_secureshop_target_reconciliation.sql:5abba71445b1ae93057d16822014cc28caa59f8c6b960903c997d7f9aadd2013
0030_secureshop_instance_objective_contributions.sql:23767a5e316729f3f4a60d8e3085138a6b56f2a78ddd929ff5d3cfd714867f0f
0031_secureshop_conversation_cleanup_checkpoint.sql:480e7b539a48e0cf44664bffc48ca971535df379f1674c4e158b69292dc0cbe7
0032_secureshop_progress_cleanup_checkpoint.sql:27547f4979fa3498f578d623dc681fc9c5a3902a339ee3e6aa0390b8a5bab6a1
0033_secureshop_product_target_reservation.sql:7038e706cccdfaa38465d54d2f9e1248e671c95ffeb77cb132ae036e991b8a22
0034_secureshop_owner_reset.sql:573ecdc97e8d364f3b1de1521aff8dda76b6de73e4def9ea74c04e9400c73970
0035_student_deletion_journal.sql:1f50e45cc81e23477c03c4bdb9e1367c44aea42ddde80fb19e3e6d641c67554f
0036_dpi_teaching_scope.sql:c8de6bc4a9bab04a37801fdc1b257be0b5fc8b1f31c209b6521fb52bff27083e
0037_nosqli9_identity_content.sql:8e3b8e86de9366beb2e066290623e6d2e35f0caad1fabaf6afaa70472c9602c5
0038_student_deletion_finalizer.sql:3172c3cdc039fd7b9c9698e331baf8d65cda2837c065d982711599af701e3d94
0039_secureshop_cleanup_catalog_independence.sql:7b83acc118e07715ee001951080cd9b2f59fe1be84e176f437799a0ff45c956a
0040_legacy_upload_lifecycle.sql:5f5f8b001b41271aeb0be3fa6614ed087eb6163a78930bab2d315eea4c16e4bf
0041_finflow_response_repair_copy.sql:92efa253ecb0537e43c081bbe64e1d29933c6a9f1f85eca342994117d3e77cee
0042_rag_upload_guidance.sql:0669b29b0b9bd37b0670aa1c5a8f5a2722ad447ae6dcdd191860dafa8a704b96
0043_dpi_evidence_guidance.sql:81750871291a64cb3fac21599653b42ab28d3dd24d3d6e6c74a7b1912ef058cc
0044_sensitive_info_aggregate_reset.sql:1485e878466a6a52b598f176832af45d8f5a7fc3ae5ec13e008abaea2c8ad186
0045_secureshop_persona_inbox_identity.sql:a7736a4dfa7277b713f19c2842418eefba376f221b94702b8bab661ed70c824c
0046_graph_judge_validation_code.sql:d5b40afc1d3c43c2371ec30fd9d1cc119a935cbc1840ef3b11c8bc4cfa6be936
0047_secureshop_persona_inbox_catalog.sql:e12496c0ebf7c3927ab2d967afa286b3e5774d88f4223527444c222c19ed3e64
0048_workshop_catalog_field_provenance.sql:96ea10297e339cc277a0c76db8dad7028f5683b1dbc1db46a3d913889fe24de2
0049_workshop_catalog_persona_adoption.sql:aa22efe7d731bbb378f6cc9d7954f109af34573773f2f0f6ade10098b02abccb
0050_mcp_conversation_history.sql:fde6cc519c887b481668d02d44bacad7976bbc8b604cf2a65e3fd5ac7dbd0d1f
0051_secureshop_mcp_trust.sql:8644c25726fdbe6b417aa9700fb8e7a54ec1062b1d8f69dcd5f90cabe6ecf508
0052_secureshop_controlled_ssrf.sql:85cbb7d4b4d6835c720e13f81092a47f414c74cc1503f82eee48544e7a3fa07e
0053_codebot_request_journal.sql:25958c7c062ea915134000eef60202fc6ec7cb187e8f93064e900c0074cfa712
0054_finflow_log_policy_defaults.sql:91db77530d1632518dedc4403d455c0b5be632309a8c607c07576f2027b7fa21
0055_finflow_admin_artifact_defaults.sql:56a19e666f359082a89995ef89d943d99b3a99e98330f680e84cc173b5812580
0056_finflow_authentic_curriculum_defaults.sql:fd0b4178a6ae181f6001c765f0963cacfc4cde814124858d7420101bc526c7d8
0057_graph_agent_outcome.sql:99b5581d9c1de403b26a696cc91f34c93e7cc81bcab4d8ef5d727bbbf55ded7c
0058_finflow_durable_log_overlay_tip.sql:49ec113eb5bd0e646e2eef6900cb54ebc8a8585e7af1ea7a225724275c449248
0059_dpi_policy_trace_metadata.sql:ed13bef886dfe7e72edeef219578148d6dc1785381426fae888c662110a7b84d
0060_finflow_description_default.sql:5532df2fd0b0a665a10089b744687cb2a2aecc895b0b1a45a1e5053ffcde56cf
0061_mcp_supply_chain_curriculum_defaults.sql:0ab4bffc3229c9a55003cbd172fec99c7ba48044494d5ea19d622a241483da1b
0065_ipi_email_artifacts.sql:9dc6820b56a261e648f2aa1d5eb7635bb61f3f91530f8251c93bdbe45a1fa30c
"""
REVIEWED_IDENTITY_MIGRATIONS = dict(
    line.split(':', 1) for line in REVIEWED_IDENTITY_MIGRATIONS_TEXT.splitlines())


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def json_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_reviewed_identity_migrations(source_root, label='identity migration source'):
    source_root = Path(source_root)
    directory = source_root / 'db/postgres/identity-migrations'
    lines = REVIEWED_IDENTITY_MIGRATIONS_TEXT.splitlines()
    if len(lines) != len(REVIEWED_IDENTITY_MIGRATIONS) \
            or json_digest(REVIEWED_IDENTITY_MIGRATIONS) != REVIEWED_IDENTITY_MIGRATIONS_SHA256:
        raise RuntimeError('reviewed identity migration pin is invalid')
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError(f'{label} directory is invalid')
    actual = {}
    for entry in directory.iterdir():
        if entry.suffix != '.sql':
            continue
        if entry.is_symlink() or not entry.is_file():
            raise RuntimeError(f'{label} contains an invalid SQL entry')
        actual[entry.name] = sha256(entry)
    if dict(sorted(actual.items())) != REVIEWED_IDENTITY_MIGRATIONS:
        raise RuntimeError(f'{label} differs from the reviewed identity migration inventory')
    return REVIEWED_IDENTITY_MIGRATIONS_SHA256


def save_json(path, value):
    path = Path(path)
    pending = Path(str(path) + f'.{os.getpid()}.pending')
    with pending.open('w') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.chmod(pending, 0o600)
    os.replace(pending, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(command, **kwargs):
    return subprocess.run(command, check=False, text=True, **kwargs)


def resolve_without_symlinks(value, label, *, must_exist=True):
    path = Path(value)
    if not path.is_absolute():
        raise RuntimeError(f'absolute {label} path required')
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if os.path.lexists(cursor) and cursor.is_symlink():
            raise RuntimeError(f'{label} symlink ancestry forbidden')
    return path.resolve(strict=must_exist)


def _dependency_path(relative):
    return relative == 'source/node_modules' or relative.startswith('source/node_modules/') \
        or relative == 'source/client/node_modules' or relative.startswith('source/client/node_modules/')


def package_inventory(package):
    package = Path(package)
    source = package / 'source'
    source_files, dependency_files, dependency_links = {}, {}, {}
    source_directories, dependency_directories = [], []
    if source.is_symlink() or not source.is_dir() or source.stat().st_mode & 0o222:
        raise RuntimeError('copied read-only package source required')
    for path in source.rglob('*'):
        relative = path.relative_to(package).as_posix()
        dependency = _dependency_path(relative)
        if path.is_symlink():
            if not dependency:
                raise RuntimeError(f'source symlink forbidden: {relative}')
            target = os.readlink(path)
            if Path(target).is_absolute():
                raise RuntimeError(f'absolute dependency symlink forbidden: {relative}')
            resolved = path.resolve(strict=True)
            roots = [source / 'node_modules', source / 'client/node_modules']
            if not any(root.is_dir() and resolved.is_relative_to(root.resolve()) for root in roots):
                raise RuntimeError(f'external dependency symlink forbidden: {relative}')
            dependency_links[relative] = target
        elif path.is_file():
            if path.stat().st_mode & 0o222:
                raise RuntimeError(f'writable frozen file forbidden: {relative}')
            (dependency_files if dependency else source_files)[relative] = sha256(path)
        elif path.is_dir():
            if path.stat().st_mode & 0o222:
                raise RuntimeError(f'writable frozen directory forbidden: {relative}')
            (dependency_directories if dependency else source_directories).append(relative)
        else:
            raise RuntimeError(f'special package leaf forbidden: {relative}')
    return {
        'sourceFiles': source_files,
        'dependencyFiles': dependency_files,
        'dependencySymlinks': dependency_links,
        'sourceDirectories': sorted(source_directories),
        'dependencyDirectories': sorted(dependency_directories),
    }


def verify_manifest(package, manifest_path):
    package, manifest_path = Path(package), Path(manifest_path)
    if package.is_symlink() or not package.is_dir() or manifest_path != package / 'manifest.json' \
            or manifest_path.is_symlink() or not manifest_path.is_file() \
            or manifest_path.stat().st_mode & 0o222:
        raise RuntimeError('exact read-only package manifest required')
    if {entry.name for entry in package.iterdir()} != {'source', 'manifest.json'}:
        raise RuntimeError('package inventory must contain only source and manifest.json')
    manifest = json.loads(manifest_path.read_text())
    expected_suite = {
        'name': 'legacyAiHistoryProtectedStorage',
        'test': TEST_PATH,
        'databaseStem': 'legacy_ai_history',
        'migrationVariable': 'PG_LEGACY_AI_HISTORY_IDENTITY_MIGRATION_URL',
        'runtimeVariable': 'PG_LEGACY_AI_HISTORY_IDENTITY_RUNTIME_URL',
        'timeoutSeconds': 180,
    }
    if manifest.get('stage') != STAGE or manifest.get('scope') != SCOPE \
            or manifest.get('qualification') != 'native-draft-candidate' \
            or manifest.get('activation') != 'unregistered-draft-only' \
            or manifest.get('registeredIdentityHead') != REGISTERED_IDENTITY_HEAD \
            or manifest.get('draftPath') != DRAFT_PATH \
            or manifest.get('suite') != expected_suite \
            or manifest.get('semanticEffectsQualified') != [] \
            or manifest.get('mutableSourcePaths') != []:
        raise RuntimeError('manifest protected-history boundary invalid')
    observed = package_inventory(package)
    for field, value in observed.items():
        if manifest.get(field) != value or manifest.get(field + 'Sha256') != json_digest(value):
            raise RuntimeError(f'manifest inventory mismatch: {field}')
    verify_reviewed_identity_migrations(package / 'source', 'candidate identity migration source')
    required = {f'source/{name}' for name in (
        TEST_PATH, LAUNCHER_PATH, CONTRACT_PATH, DRAFT_PATH, REPOSITORY_PATH,
        'tests/legacyAiHistoryProtectedStorage.test.js',
        'tests/legacyAiHistoryDraftImporter.test.js',
        'server/database/postgres/legacyAiHistoryDraftImporter.js',
        'tests/legacyAiHistoryArchiveAttestation.test.js',
        'server/database/postgres/legacyAiHistoryArchiveAttestation.js',
        'server/database/postgres/legacyAiHistoryImportTarget.js',
        'tests/legacyAiHistoryImportTarget.test.js',
        'server/services/legacyAiHistoryRequestService.js',
        'tests/legacyAiHistoryRequestService.test.js',
        'server/services/legacyAiProtectedHistoryComposition.js',
        'tests/legacyAiProtectedHistoryComposition.test.js',
        'server/services/legacyAiExperimentRunner.js',
        'tests/legacyAiExperimentRunner.test.js',
        'server/services/legacyAiExperimentPresenter.js',
        'tests/legacyAiExperimentPresenter.test.js',
        'tests/postgres/helpers/legacyAiHistoryHttpQualification.js',
        'server/routes/legacyAiProtectedHistoryDraftRouter.js',
        'tests/legacyAiProtectedHistoryDraftRouter.test.js',
        'server/services/postgresIdentityAdapter.js',
        'server/services/legacyPlatformAuthorityResolver.js',
        'server/middleware/bearerToken.js',
        'server/database/postgres/studentDeletionRepository.js',
        'server/database/postgres/identityRepository.js',
        'db/postgres/identity-migrations/0001_identity.sql',
        f'db/postgres/identity-migrations/{REGISTERED_IDENTITY_HEAD}',
        'package.json', 'package-lock.json',
    )}
    if not required.issubset(observed['sourceFiles']):
        raise RuntimeError('protected-history source closure is incomplete')
    if 'source/node_modules/pg/package.json' not in observed['dependencyFiles']:
        raise RuntimeError('frozen PostgreSQL dependency missing')
    for path in (package / 'source').rglob('.env*'):
        if path.name != '.env.example':
            raise RuntimeError('live environment files forbidden in package')
    for suffix in ('.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'):
        if any((package / 'source').rglob(f'*{suffix}')):
            raise RuntimeError('runtime data or logs forbidden in package')
    return manifest


def verify_postflight_identity(package, manifest_path, expected_manifest, expected_manifest_sha,
                               node, expected_node_sha):
    observed_manifest = verify_manifest(package, manifest_path)
    if observed_manifest != expected_manifest or sha256(manifest_path) != expected_manifest_sha \
            or sha256(node) != expected_node_sha:
        raise RuntimeError('postflight source/runtime identity changed')


def process_group_absent(pgid):
    if not isinstance(pgid, int) or pgid <= 0:
        return True
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def process_absent(pid):
    if not isinstance(pid, int) or pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def terminate_group(pgid, process=None, grace=10):
    if not isinstance(pgid, int) or pgid <= 0:
        return True
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGTERM)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=grace)
    deadline = time.monotonic() + min(grace, 3)
    while time.monotonic() < deadline:
        if process_group_absent(pgid):
            return True
        time.sleep(.1)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGKILL)
    if process is not None and process.poll() is None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
    return process_group_absent(pgid)


def docker_missing_exact_target(message, target):
    return re.search(rf'No such (?:object|container): {re.escape(target)}\r?$',
                     message or '', flags=re.MULTILINE) is not None


def docker_object_absent(docker, target):
    result = run(docker + ['inspect', target], capture_output=True, timeout=20)
    if result.returncode == 0:
        return False
    message = (result.stdout or '') + (result.stderr or '')
    if result.returncode == 1 and docker_missing_exact_target(message, target):
        return True
    raise RuntimeError('Docker object absence could not be verified')


def remove_owned_container(docker, container_name, container_id, labels):
    target = container_id or container_name
    inspected = run(docker + ['inspect', target], capture_output=True, timeout=20)
    if inspected.returncode:
        message = (inspected.stdout or '') + (inspected.stderr or '')
        if inspected.returncode == 1 and docker_missing_exact_target(message, target):
            return None
        raise RuntimeError('owned container inspection failed during cleanup')
    try:
        values = json.loads(inspected.stdout)
        info = values[0] if len(values) == 1 else None
    except (ValueError, TypeError):
        info = None
    actual_labels = ((info or {}).get('Config') or {}).get('Labels') or {}
    actual_id = (info or {}).get('Id')
    if not isinstance(actual_id, str) or not re.fullmatch(r'[0-9a-f]{64}', actual_id) \
            or (container_id is not None and actual_id != container_id) \
            or (info or {}).get('Name') != '/' + container_name \
            or any(actual_labels.get(key) != value for key, value in labels.items()):
        raise RuntimeError('unowned container cleanup refused')
    removed = run(docker + ['rm', '--force', actual_id], capture_output=True, timeout=60)
    if removed.returncode:
        raise RuntimeError('owned container removal failed')
    return actual_id


def database_name(nonce):
    if not re.fullmatch(r'[0-9a-f]{12}', nonce):
        raise ValueError('12-character lowercase hexadecimal nonce required')
    return f'owasp_ai_goat_test_legacy_ai_history_{nonce}'


def verify_tap(log_path):
    content = Path(log_path).read_text()
    for pattern in (r'(?m)^# pass 1\s*$', r'(?m)^# fail 0\s*$', r'(?m)^# skipped 0\s*$'):
        if not re.search(pattern, content):
            raise RuntimeError('protected-history TAP did not prove one pass, zero fail, zero skipped')
    return sha256(log_path)


def expected_grant(args, manifest, owner_handle, node_sha, manifest_sha):
    package = Path(args.package_root).resolve()
    handle = Path(args.owner_handle_file).resolve()
    return {
        'grantId': args.grant_id,
        'owner': '/root',
        'allowedLaunches': 1,
        'dockerHost': DOCKER_HOST,
        'containerNonce': args.container_nonce,
        'containerName': f'owasp-ai-goat-legacy-ai-history-{args.container_nonce}',
        'databaseName': database_name(args.container_nonce),
        'canonicalWorkspaceRoot': str(Path(args.canonical_workspace).resolve()),
        'candidateSourceRoot': str(package / 'source'),
        'candidateManifestSha256': manifest_sha,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'dependencySymlinksSha256': manifest['dependencySymlinksSha256'],
        'reviewedIdentityMigrationsSha256': REVIEWED_IDENTITY_MIGRATIONS_SHA256,
        'managedNodePath': str(Path(args.managed_node).resolve()),
        'managedNodeSha256': node_sha,
        'postgresImageRef': POSTGRES_IMAGE,
        'postgresImageId': POSTGRES_IMAGE_ID,
        'stage': STAGE,
        'scope': SCOPE,
        'evidenceRoot': str(Path(args.evidence_root).resolve()),
        'expectedOwnerHandle': owner_handle,
        'ownerHandlePath': str(handle),
        'ownerHandleFileSha256': sha256(handle),
        'expectedLauncherPid': os.getpid(),
        'ownerHandle': None,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    for name in ('package-root', 'manifest', 'managed-node', 'docker-host',
                 'postgres-image-id', 'container-nonce', 'evidence-root', 'grant-file',
                 'grant-id', 'owner', 'owner-handle-file', 'canonical-workspace', 'scope'):
        parser.add_argument('--' + name, required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    package = resolve_without_symlinks(args.package_root, 'package')
    source = package / 'source'
    manifest_path = resolve_without_symlinks(args.manifest, 'manifest')
    node = resolve_without_symlinks(args.managed_node, 'managed Node')
    grant_path = resolve_without_symlinks(args.grant_file, 'grant')
    handle_path = resolve_without_symlinks(args.owner_handle_file, 'owner handle')
    evidence_path = resolve_without_symlinks(args.evidence_root, 'evidence', must_exist=False)
    canonical = resolve_without_symlinks(args.canonical_workspace, 'canonical workspace')
    if args.owner != '/root' or args.scope != SCOPE or args.docker_host != DOCKER_HOST \
            or args.postgres_image_id != POSTGRES_IMAGE_ID \
            or not re.fullmatch(r'[0-9a-f]{12}', args.container_nonce):
        raise RuntimeError('root launcher binding invalid')
    if not canonical.is_dir() or canonical.is_symlink() or evidence_path.is_relative_to(package):
        raise RuntimeError('canonical/evidence path binding invalid')
    manifest = verify_manifest(package, manifest_path)
    verify_reviewed_identity_migrations(canonical, 'canonical identity migration control source')
    if node.is_symlink() or not node.is_file():
        raise RuntimeError('managed Node regular file required')
    node_version = run([str(node), '--version'], capture_output=True, timeout=10)
    if node_version.returncode or node_version.stdout.strip() != NODE_VERSION:
        raise RuntimeError('managed Node version mismatch')
    node_sha, manifest_sha = sha256(node), sha256(manifest_path)
    if handle_path.is_symlink() or not handle_path.is_file() or handle_path.stat().st_mode & 0o077:
        raise RuntimeError('private owner handle file required')
    handle_text = handle_path.read_text().strip()
    if not handle_text.isdecimal() or int(handle_text) <= 0:
        raise RuntimeError('positive opaque owner handle required')
    owner_handle = int(handle_text)
    if os.path.lexists(evidence_path):
        raise RuntimeError('fresh evidence root required')
    parent = evidence_path.parent
    parent_stat = parent.lstat()
    if parent.is_symlink() or not parent.is_dir() or parent_stat.st_uid != os.getuid() \
            or parent_stat.st_mode & 0o077:
        raise RuntimeError('private evidence parent required')
    expected = expected_grant(args, manifest, owner_handle, node_sha, manifest_sha)
    if grant_path.is_symlink() or not grant_path.is_file() or grant_path.stat().st_mode & 0o077:
        raise RuntimeError('private grant file required')
    grant = json.loads(grant_path.read_text())
    if grant.get('status') != 'granted' or any(grant.get(key) != value for key, value in expected.items()):
        raise RuntimeError('exact one-use grant binding mismatch')
    lock = Path(str(grant_path) + '.consume-lock')
    try:
        lock.mkdir(mode=0o700)
    except FileExistsError:
        raise RuntimeError('grant already consumed')
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('status') != 'granted' or any(grant.get(key) != value for key, value in expected.items()):
            raise RuntimeError('grant changed before consumption')
        grant.update(status='consumed', runStatus='waiting_owner_handle', consumedAt=utc_now(),
            consumerPid=os.getpid(), launcherPid=os.getpid(),
            evidence=str(evidence_path), containerName=expected['containerName'])
        save_json(grant_path, grant)
    finally:
        lock.rmdir()

    evidence_path.mkdir(mode=0o700)
    ownership_path = evidence_path / 'ownership.json'
    container_name = expected['containerName']
    database = expected['databaseName']
    labels = {
        'owasp-ai-goat.owner': '/root',
        'owasp-ai-goat.grant': args.grant_id,
        'owasp-ai-goat.scope': SCOPE,
        'owasp-ai-goat.nonce': args.container_nonce,
        'owasp-ai-goat.manifest': manifest_sha,
        'owasp-ai-goat.image': POSTGRES_IMAGE_ID,
    }
    state = {
        'version': 1,
        'stage': STAGE,
        'scope': SCOPE,
        'owner': '/root',
        'ownerHandle': owner_handle,
        'grantId': args.grant_id,
        'launcherPid': os.getpid(),
        'createdAt': utc_now(),
        'runStatus': 'owner_handle_pending',
        'manifestSha256': manifest_sha,
        'sourceFilesSha256': manifest['sourceFilesSha256'],
        'dependencyFilesSha256': manifest['dependencyFilesSha256'],
        'reviewedIdentityMigrationsSha256': REVIEWED_IDENTITY_MIGRATIONS_SHA256,
        'managedNodePath': str(node),
        'managedNodeSha256': node_sha,
        'postgresImageRef': POSTGRES_IMAGE,
        'postgresImageId': POSTGRES_IMAGE_ID,
        'dockerHost': DOCKER_HOST,
        'activation': 'unregistered-draft-only',
        'resourcePlan': {
            'containerName': container_name,
            'containerLabels': labels,
            'databaseName': database,
            'migrationRole': MIGRATION_ROLE,
            'runtimeRole': RUNTIME_ROLE,
            'applicationLogs': str(evidence_path / 'application-logs'),
            'applicationData': str(evidence_path / 'application-data'),
        },
        'processes': {},
        'suite': {'name': 'legacyAiHistoryProtectedStorage', 'test': TEST_PATH},
    }

    def persist():
        save_json(ownership_path, state)

    persist()
    docker = ['docker', '--host', DOCKER_HOST]
    container_id = None
    active_process = None
    active_pgid = None
    passed = False
    cleanup_errors = []

    def handle_signal(signum, _frame):
        raise InterruptedError(f'received signal {signum}')

    previous_handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    for signum in previous_handlers:
        signal.signal(signum, handle_signal)

    def psql(sql, selected_database='postgres', timeout=60):
        result = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
            '-d', selected_database, '-v', 'ON_ERROR_STOP=1', '-c', sql], capture_output=True,
            timeout=timeout)
        if result.returncode:
            raise RuntimeError('owned PostgreSQL command failed: ' + (result.stderr or '')[-1000:])
        return result.stdout

    try:
        print('WAITING_OWNER_HANDLE', flush=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            current = json.loads(grant_path.read_text())
            registered = current.get('ownerHandle')
            if registered is not None:
                if registered != owner_handle:
                    raise RuntimeError('registered owner handle mismatch')
                break
            time.sleep(.1)
        else:
            raise RuntimeError('owner handle registration timeout')
        state['runStatus'] = 'owner_registered'
        persist()

        daemon = run(docker + ['info', '--format', '{{json .}}'], capture_output=True, timeout=30)
        try:
            daemon_info = json.loads(daemon.stdout) if daemon.returncode == 0 else None
        except (TypeError, ValueError):
            daemon_info = None
        if not daemon_info or daemon_info.get('ID') != DOCKER_DAEMON_ID \
                or daemon_info.get('Name') != 'colima-owasp-ai-goat-pg-verify' \
                or daemon_info.get('Architecture') != 'aarch64':
            raise RuntimeError('exact Colima verification daemon required')
        state['dockerDaemon'] = {'id': daemon_info['ID'], 'name': daemon_info['Name'],
            'architecture': daemon_info['Architecture']}
        persist()
        image = run(docker + ['image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE],
            capture_output=True, timeout=20)
        if image.returncode or image.stdout.strip() != POSTGRES_IMAGE_ID:
            raise RuntimeError('PostgreSQL image identity mismatch')
        if not docker_object_absent(docker, container_name):
            raise RuntimeError('owned container name already exists')
        state['containerCreateAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'name': container_name, 'expectedLabels': labels}
        persist()
        created = run(docker + ['run', '--detach', '--pull', 'never', '--name', container_name,
            *sum((['--label', f'{key}={value}'] for key, value in labels.items()), []),
            '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
            '-e', 'POSTGRES_USER=owasp_ai_goat_bootstrap', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-p', '127.0.0.1::5432', POSTGRES_IMAGE,
            '-c', 'shared_buffers=24MB', '-c', 'max_connections=32'],
            capture_output=True, timeout=60)
        state['containerCreateAttempt'].update(status='returned', returnCode=created.returncode,
            stdoutSha256=hashlib.sha256((created.stdout or '').encode()).hexdigest(),
            stderrSha256=hashlib.sha256((created.stderr or '').encode()).hexdigest())
        persist()
        if created.returncode:
            raise RuntimeError('owned PostgreSQL container creation failed')
        created_id = created.stdout.strip()
        if not re.fullmatch(r'[0-9a-f]{64}', created_id):
            raise RuntimeError('invalid owned container id')
        container_id = created_id
        state.update(containerId=container_id, runStatus='container_started')
        persist()
        for _ in range(120):
            ready = run(docker + ['exec', container_id, 'pg_isready', '-h', '127.0.0.1',
                '-U', 'owasp_ai_goat_bootstrap'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('owned PostgreSQL readiness timeout')
        binding = run(docker + ['port', container_id, '5432/tcp'], capture_output=True, timeout=20)
        if binding.returncode or not re.fullmatch(r'127\.0\.0\.1:\d+\s*', binding.stdout):
            raise RuntimeError('loopback PostgreSQL binding required')
        postgres_port = int(binding.stdout.strip().rsplit(':', 1)[1])
        state['postgresLoopbackPort'] = postgres_port
        state['databaseProvisioningAttempt'] = {'status': 'started', 'startedAt': utc_now(),
            'databaseName': database, 'roles': [MIGRATION_ROLE, RUNTIME_ROLE]}
        persist()
        psql(f'CREATE ROLE {MIGRATION_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        psql(f'CREATE ROLE {RUNTIME_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        psql(f'CREATE DATABASE {database} OWNER {MIGRATION_ROLE}')
        psql(f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
             f'GRANT CONNECT ON DATABASE {database} TO {MIGRATION_ROLE},{RUNTIME_ROLE}')
        state['databaseProvisioningAttempt']['status'] = 'complete'
        persist()

        home = evidence_path / 'home'
        temporary = evidence_path / 'tmp'
        application_logs = evidence_path / 'application-logs'
        application_data = evidence_path / 'application-data'
        for directory in (home, temporary, application_logs, application_data):
            directory.mkdir(mode=0o700)
        base_env = {key: os.environ[key] for key in ('PATH',) if key in os.environ}
        base_env.update(HOME=str(home), TMPDIR=str(temporary), TMP=str(temporary), TEMP=str(temporary),
            NODE_ENV='test', PG_TEST_DISPOSABLE='yes', AWS_EC2_METADATA_DISABLED='true',
            OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(source), LOGS_DIR=str(application_logs),
            OWASP_AI_GOAT_APP_DATA_ROOT=str(application_data),
            PG_LEGACY_AI_HISTORY_IDENTITY_MIGRATION_URL=
                f'postgresql://{MIGRATION_ROLE}@127.0.0.1:{postgres_port}/{database}',
            PG_LEGACY_AI_HISTORY_IDENTITY_RUNTIME_URL=
                f'postgresql://{RUNTIME_ROLE}@127.0.0.1:{postgres_port}/{database}')
        log_path = evidence_path / 'legacyAiHistoryProtectedStorage.tap'
        state['suite'].update(status='starting', database=database, log=str(log_path),
            startedAt=utc_now())
        persist()
        with log_path.open('w') as output:
            os.chmod(log_path, 0o600)
            active_process = subprocess.Popen([str(node), '--test', '--test-concurrency=1',
                '--test-reporter=tap', TEST_PATH], cwd=source, env=base_env,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            active_pgid = os.getpgid(active_process.pid)
            state['processes']['test'] = {'pid': active_process.pid, 'pgid': active_pgid,
                'status': 'running', 'startedAt': utc_now()}
            state['suite']['status'] = 'running'
            persist()
            try:
                exit_code = active_process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                terminate_group(active_pgid, active_process, grace=8)
                raise RuntimeError('protected-history test timed out')
        group_absent = terminate_group(active_pgid, active_process, grace=3)
        state['processes']['test'].update(status='exited', exitCode=exit_code,
            groupAbsent=group_absent, completedAt=utc_now())
        active_process = None
        active_pgid = None
        if exit_code or not group_absent:
            persist()
            raise RuntimeError('protected-history test failed or left its process group')
        log_sha = verify_tap(log_path)
        os.chmod(log_path, 0o400)
        state['suite'].update(status='passed', logSha256=log_sha, completedAt=utc_now())
        state['runStatus'] = 'suite_passed'
        persist()
        passed = True
    except BaseException as error:
        state.update(runStatus='suite_failed', failure=f'{type(error).__name__}: {error}'[:1000])
        persist()
        raise
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        if active_pgid:
            try:
                absent = terminate_group(active_pgid, active_process, grace=8)
                state['processes'].setdefault('test', {}).update(groupAbsent=absent,
                    exitCode=active_process.poll() if active_process else None)
            except Exception as error:
                cleanup_errors.append(f'active process cleanup: {error}'[:500])
        if container_id or state.get('containerCreateAttempt'):
            try:
                state['databaseCleanupAttempt'] = {'status': 'started', 'startedAt': utc_now(),
                    'databaseName': database}
                persist()
                if container_id:
                    dropped = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
                        '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c',
                        f'DROP DATABASE IF EXISTS {database} WITH (FORCE)'], capture_output=True,
                        timeout=60)
                    remaining = run(docker + ['exec', container_id, 'psql', '-U', 'owasp_ai_goat_bootstrap',
                        '-d', 'postgres', '-At', '-v', 'ON_ERROR_STOP=1', '-c',
                        f"SELECT datname FROM pg_database WHERE datname='{database}'"],
                        capture_output=True, timeout=30)
                    state['databaseCleanupAttempt'].update(status='complete',
                        dropReturnCode=dropped.returncode,
                        absenceQueryReturnCode=remaining.returncode,
                        databaseAbsent=remaining.returncode == 0 and not remaining.stdout.strip())
                    if dropped.returncode or remaining.returncode or remaining.stdout.strip():
                        raise RuntimeError('owned database cleanup was not proven')
            except Exception as error:
                cleanup_errors.append(f'database cleanup: {error}'[:500])
        try:
            removed_id = remove_owned_container(docker, container_name, container_id, labels)
            state['containerCleanupId'] = removed_id
            if container_id is None and removed_id is not None:
                container_id = removed_id
        except Exception as error:
            cleanup_errors.append(f'container cleanup: {error}'[:500])
        try:
            state['containerNameAbsent'] = docker_object_absent(docker, container_name)
        except Exception as error:
            state['containerNameAbsent'] = False
            cleanup_errors.append(f'container name absence: {error}'[:500])
        if container_id:
            try:
                state['containerIdAbsent'] = docker_object_absent(docker, container_id)
            except Exception as error:
                state['containerIdAbsent'] = False
                cleanup_errors.append(f'container id absence: {error}'[:500])
        else:
            state['containerIdAbsent'] = None
        state['databaseAbsent'] = state.get('databaseCleanupAttempt', {}).get('databaseAbsent') is True \
            or state.get('containerNameAbsent') is True and state.get('containerIdAbsent') in (True, None)
        try:
            verify_postflight_identity(package, manifest_path, manifest, manifest_sha, node, node_sha)
            state['postflightManifestVerified'] = True
        except Exception as error:
            state['postflightManifestVerified'] = False
            cleanup_errors.append(f'postflight manifest: {error}'[:500])
        for process in state['processes'].values():
            if isinstance(process.get('pgid'), int):
                process['groupAbsent'] = process_group_absent(process['pgid'])
            if isinstance(process.get('pid'), int):
                process['pidAbsent'] = process_absent(process['pid'])
        state['allProcessGroupsAbsent'] = all(row.get('groupAbsent') is True
            for row in state['processes'].values())
        state['allProcessIdsAbsent'] = all(row.get('pidAbsent') is True
            for row in state['processes'].values())
        state['cleanupErrors'] = cleanup_errors
        state['applicationLogFiles'] = {
            path.relative_to(evidence_path / 'application-logs').as_posix(): sha256(path)
            for path in (evidence_path / 'application-logs').rglob('*')
            if path.is_file() and not path.is_symlink()
        } if (evidence_path / 'application-logs').is_dir() else {}
        state['completedAt'] = utc_now()
        clean = not cleanup_errors and state.get('containerNameAbsent') is True \
            and state.get('containerIdAbsent') in (True, None) \
            and state.get('databaseAbsent') is True \
            and state.get('allProcessGroupsAbsent') is True \
            and state.get('allProcessIdsAbsent') is True \
            and state.get('postflightManifestVerified') is True
        state['runStatus'] = 'terminal_pass_cleaned' if passed and clean \
            else 'terminal_fail_cleaned' if clean else 'terminal_fail_cleanup_uncertain'
        persist()
        try:
            terminal_grant = json.loads(grant_path.read_text())
            if terminal_grant.get('grantId') != args.grant_id \
                    or terminal_grant.get('status') != 'consumed' \
                    or terminal_grant.get('consumerPid') != os.getpid() \
                    or terminal_grant.get('ownerHandle') != owner_handle:
                raise RuntimeError('consumed grant ownership changed before terminal update')
            terminal_grant.update(runStatus='terminal_pass' if state['runStatus'] == 'terminal_pass_cleaned'
                else 'terminal_fail', terminalAt=state['completedAt'], evidence=str(evidence_path),
                cleanup={'clean': clean, 'errors': cleanup_errors,
                    'containerNameAbsent': state.get('containerNameAbsent'),
                    'containerIdAbsent': state.get('containerIdAbsent'),
                    'databaseAbsent': state.get('databaseAbsent'),
                    'allProcessGroupsAbsent': state.get('allProcessGroupsAbsent'),
                    'allProcessIdsAbsent': state.get('allProcessIdsAbsent')},
                containerId=container_id, resultSha256=state['suite'].get('logSha256'))
            save_json(grant_path, terminal_grant)
            state['terminalGrantRecorded'] = True
            persist()
        except Exception as error:
            state['terminalGrantRecorded'] = False
            state['cleanupErrors'].append(f'terminal grant update: {error}'[:500])
            state['runStatus'] = 'terminal_fail_cleanup_uncertain'
            persist()
            clean = False
        if not passed or not clean:
            raise RuntimeError('protected-history qualification did not pass with verified cleanup')
    print(json.dumps({'status': state['runStatus'], 'evidence': str(evidence_path),
        'logSha256': state['suite'].get('logSha256')}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'launcher failure: {error}', file=sys.stderr)
        raise SystemExit(1)
