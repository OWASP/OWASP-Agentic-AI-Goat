#!/usr/bin/env python3
"""Run the SecureShop controlled SSRF actual model/Judge qualification in one owned PostgreSQL 18 container."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote
from sensitive_info_recovery_safety import SignalGate
from native_source_provenance import verify_source_copy
from secureshop_ssrf_source_copy import copy_ssrf_source

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--grant-file', default='tasks/native-verification-slot.json')
parser.add_argument('--mounted-deterministic', action='store_true')
args = parser.parse_args()
EXPECTED_DOCKER_HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'
EXPECTED_OWNER = '/root/secureshop_architecture'
if args.docker_host != EXPECTED_DOCKER_HOST:
    raise RuntimeError('Exact owned Colima verification Docker host is required')
source = Path(__file__).resolve().parents[2]
grant_path = (source / args.grant_file).resolve() if not Path(args.grant_file).is_absolute() else Path(args.grant_file)
grant_lock = grant_path.with_suffix(grant_path.suffix + '.consume-lock')
root = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-secureshop-ssrf-live-'))
workspace = root / 'source'
workspace.mkdir()
os.chmod(root, 0o700)
base_env = {key: os.environ[key] for key in ['PATH','HOME','TMPDIR'] if key in os.environ}
managed_node = Path(base_env.get('HOME','/nonexistent')) / '.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin'
base_env['PATH'] = str(managed_node) + os.pathsep + base_env.get('PATH','')
docker = ['docker','--host',args.docker_host]
container = 'owasp-ai-goat-secureshop-ssrf-live-' + uuid.uuid4().hex[:12]
ownership_path = root / 'ownership.json'
tracked = ['agent-host/agents/summarizer/server.js', 'agent-host/agents/summarizer/tools/explain_return_policy.js', 'agent-host/agents/summarizer/tools/summarize_file.js', 'agent-host/agents/summarizer/tools/summarize_product.js', 'agent-host/agents/summarizer/tools/summarize_product.postgres.js', 'agent-host/agents/summarizer/tools/summarize_reviews.js', 'agent-host/agents/summarizer/tools/summarize_reviews.postgres.js', 'agent-host/shared/callerContext.js', 'agent-host/shared/db.js', 'agent-host/shared/graphServer.js', 'client/src/pages/secureshop/bridge/compiler.mjs', 'client/src/pages/secureshop/bridge/fetchAdapter.mjs', 'client/src/pages/secureshop/bridge/operations.mjs', 'client/src/pages/secureshop/bridge/uploads.mjs', 'db/postgres/identity-migrations/0001_identity.sql', 'db/postgres/identity-migrations/0002_workshop_platform.sql', 'db/postgres/identity-migrations/0003_account_flows.sql', 'db/postgres/identity-migrations/0004_graph_runtime.sql', 'db/postgres/identity-migrations/0005_attendee_email.sql', 'db/postgres/identity-migrations/0006_graph_trace.sql', 'db/postgres/identity-migrations/0007_objective_judgments.sql', 'db/postgres/identity-migrations/0008_objective_evidence.sql', 'db/postgres/identity-migrations/0009_grade_recovery.sql', 'db/postgres/identity-migrations/0010_workshop_activity.sql', 'db/postgres/identity-migrations/0011_dpi_practice_receipts.sql', 'db/postgres/identity-migrations/0012_historical_import_provenance.sql', 'db/postgres/identity-migrations/0013_import_batches.sql', 'db/postgres/identity-migrations/0014_xss_legacy_admin.sql', 'db/postgres/identity-migrations/0015_identity_auxiliary_provenance.sql', 'db/postgres/identity-migrations/0016_graph_judge_trace_metadata.sql', 'db/postgres/identity-migrations/0017_auxiliary_trigger_table_fields.sql', 'db/postgres/identity-migrations/0018_graph_provisional_event.sql', 'db/postgres/identity-migrations/0019_archive_owner_bindings.sql', 'db/postgres/identity-migrations/0020_bootstrap_admin_permissions.sql', 'db/postgres/identity-migrations/0022_activity_log_retention.sql', 'db/postgres/identity-migrations/0023_workshop_teaching_content.sql', 'db/postgres/identity-migrations/0024_codebot_javascript_objective.sql', 'db/postgres/identity-migrations/0025_secureshop_launch_authority.sql', 'db/postgres/identity-migrations/0026_secureshop_target_reservations.sql', 'db/postgres/identity-migrations/0027_secureshop_target_admission.sql', 'db/postgres/identity-migrations/0028_secureshop_review_target_reservation.sql', 'db/postgres/identity-migrations/0029_secureshop_target_reconciliation.sql', 'db/postgres/identity-migrations/0030_secureshop_instance_objective_contributions.sql', 'db/postgres/identity-migrations/0031_secureshop_conversation_cleanup_checkpoint.sql', 'db/postgres/identity-migrations/0032_secureshop_progress_cleanup_checkpoint.sql', 'db/postgres/identity-migrations/0033_secureshop_product_target_reservation.sql', 'db/postgres/identity-migrations/0034_secureshop_owner_reset.sql', 'db/postgres/identity-migrations/0035_student_deletion_journal.sql', 'db/postgres/identity-migrations/0036_dpi_teaching_scope.sql', 'db/postgres/identity-migrations/0037_nosqli9_identity_content.sql', 'db/postgres/identity-migrations/0038_student_deletion_finalizer.sql', 'db/postgres/identity-migrations/0039_secureshop_cleanup_catalog_independence.sql', 'db/postgres/identity-migrations/0040_legacy_upload_lifecycle.sql', 'db/postgres/identity-migrations/0041_finflow_response_repair_copy.sql', 'db/postgres/identity-migrations/0042_rag_upload_guidance.sql', 'db/postgres/identity-migrations/0043_dpi_evidence_guidance.sql', 'db/postgres/identity-migrations/0044_sensitive_info_aggregate_reset.sql', 'db/postgres/identity-migrations/0045_secureshop_persona_inbox_identity.sql', 'db/postgres/identity-migrations/0046_graph_judge_validation_code.sql', 'db/postgres/identity-migrations/0047_secureshop_persona_inbox_catalog.sql', 'db/postgres/identity-migrations/0048_workshop_catalog_field_provenance.sql', 'db/postgres/identity-migrations/0049_workshop_catalog_persona_adoption.sql', 'db/postgres/identity-migrations/0050_mcp_conversation_history.sql', 'db/postgres/identity-migrations/0051_secureshop_mcp_trust.sql', 'db/postgres/identity-migrations/0052_secureshop_controlled_ssrf.sql', 'db/postgres/identity-migrations/0053_codebot_request_journal.sql', 'db/postgres/migrate.js', 'db/postgres/seeds/secureshop.json', 'db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql', 'db/postgres/workshop-migrations/secureshop_agents/0002_vectors.sql', 'db/postgres/workshop-migrations/secureshop_agents/0003_import_history.sql', 'db/postgres/workshop-migrations/secureshop_agents/0004_embedding_identity.sql', 'db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql', 'db/postgres/workshop-migrations/secureshop_agents/0006_secureshop_turn_admission.sql', 'db/postgres/workshop-migrations/secureshop_agents/0007_secureshop_conversation_generation_retirement.sql', 'db/postgres/workshop-migrations/secureshop_agents/0008_secureshop_bound_persona_sessions.sql', 'db/postgres/workshop-migrations/secureshop_agents/0009_secureshop_bound_persona_renewal.sql', 'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql', 'db/postgres/workshop-migrations/secureshop_agents/0011_secureshop_mcp_trust.sql', 'db/postgres/workshop-migrations/secureshop_agents/0012_secureshop_controlled_ssrf.sql', 'db/postgres/workshop-migrations/secureshop_agents/0013_secureshop_conversation_purpose.sql', 'db/postgres/workshopChallengeFixtures.js', 'docs/modernization/drafts/0050_mcp_conversation_history.sql', 'docs/modernization/drafts/secureshop-controlled-ssrf-agents.sql', 'docs/modernization/drafts/secureshop-controlled-ssrf-identity.sql', 'docs/modernization/drafts/secureshop-mcp-trust-agents.sql', 'docs/modernization/drafts/secureshop-mcp-trust-identity.sql', 'package-lock.json', 'package.json', 'scripts/register-native-owner-handle.py', 'server/agent-runtime/judgeErrors.js', 'server/agent-runtime/objectiveJudge.js', 'server/agent-runtime/ownerWorkflowHttpError.js', 'server/agent-runtime/ownerWorkflowRoutes.js', 'server/agent-runtime/postgresRunLedger.js', 'server/agent-runtime/providers/finalResponseContract.js', 'server/agent-runtime/providers/langchainProvider.js', 'server/agent-runtime/providers/modelScheduler.js', 'server/agent-runtime/runCoordinator.js', 'server/agent-runtime/runTraceStore.js', 'server/agent-runtime/secureshopSupervisorGraph.js', 'server/agent-runtime/sourceComparisonVerifier.js', 'server/config/secureshopCurriculum.js', 'server/config/workshopCatalog.js', 'server/data/csrfWorkshopSolutions.js', 'server/data/excessiveAgencySolutions.js', 'server/data/indirectPromptInjectionSolutions.js', 'server/data/mcpWorkshopSolutions.js', 'server/data/nosqlInjectionWorkshopSolutions.js', 'server/data/postgres/nosqlInjectionWorkshopSolutions.js', 'server/data/postgres/sqlInjectionWorkshopSolutions.js', 'server/data/promptInjectionSolutions.js', 'server/data/secureshopAgentSeeds.js', 'server/data/sensitiveInfoSolutions.js', 'server/data/sqlInjectionWorkshopSolutions.js', 'server/data/supplyChainSolutions.js', 'server/data/workshopHints.js', 'server/data/xssWorkshopSolutions.js', 'server/database/authDb.js', 'server/database/postgres/catalogDefaultProvenance.js', 'server/database/postgres/identityRepository.js', 'server/database/postgres/identityValidation.js', 'server/database/postgres/index.js', 'server/database/postgres/objectiveJudgmentRepository.js', 'server/database/postgres/poolBudget.js', 'server/database/postgres/secureshopAgentsDb.js', 'server/database/postgres/secureshopBoundConversationsRepository.js', 'server/database/postgres/secureshopBoundPersonaRepository.js', 'server/database/postgres/secureshopBoundProductRepository.js', 'server/database/postgres/secureshopBoundReviewRepository.js', 'server/database/postgres/secureshopBoundSsrfRepository.js', 'server/database/postgres/secureshopCommerceDb.js', 'server/database/postgres/secureshopConversationCleanupCheckpointRepository.js', 'server/database/postgres/secureshopConversationLifecycleRepository.js', 'server/database/postgres/secureshopInitialization.js', 'server/database/postgres/secureshopLaunchRepository.js', 'server/database/postgres/secureshopOwnerResetRepository.js', 'server/database/postgres/secureshopPersonaInboxRepository.js', 'server/database/postgres/secureshopPools.js', 'server/database/postgres/secureshopProgressCleanupCheckpointRepository.js', 'server/database/postgres/secureshopResetCleanupAuthorityRepository.js', 'server/database/postgres/secureshopReviewDb.js', 'server/database/postgres/secureshopSeed.js', 'server/database/postgres/secureshopTargetReconciliationRepository.js', 'server/database/postgres/secureshopTurnRequestsRepository.js', 'server/database/postgres/workshopConfigRepository.js', 'server/database/postgres/workshopPlatformSeed.js', 'server/database/postgres/workshopPlatformSeedCore.js', 'server/database/postgres/workshopPlatformSupport.js', 'server/database/postgres/workshopProgressRepository.js', 'server/database/postgres/workshopRevisionRepository.js', 'server/database/sqliteTransaction.js', 'server/database/workshopConfigSchema.js', 'server/database/workshopHintSeedPolicy.js', 'server/middleware/secureshopLaunch.js', 'server/routes/secureshop/boundBrowser.js', 'server/routes/secureshop/boundGateway.js', 'server/routes/secureshop/boundPersonaInbox.js', 'server/routes/secureshop/boundReviews.js', 'server/routes/secureshop/boundSsrf.js', 'server/services/objectiveCompletionService.js', 'server/services/platformSigningConfiguration.js', 'server/services/postgresIdentityAdapter.js', 'server/services/postgresPlatformStores.js', 'server/services/promptInjectionProgressService.js', 'server/services/secureshop/providerRouter.js', 'server/services/secureshop/providers/anthropicProvider.js', 'server/services/secureshop/providers/bedrockProvider.js', 'server/services/secureshop/providers/langchainAdapter.js', 'server/services/secureshop/providers/ollamaProvider.js', 'server/services/secureshop/providers/openaiProvider.js', 'server/services/secureshop/sessionStore.js', 'server/services/secureshop/traceBuffer.js', 'server/services/secureshopBoundAgentRunner.js', 'server/services/secureshopBoundCatalog.js', 'server/services/secureshopBoundConversation.js', 'server/services/secureshopBoundGraphStore.js', 'server/services/secureshopBoundPersonaAuth.js', 'server/services/secureshopBoundReviewApplication.js', 'server/services/secureshopBoundReviewComposition.js', 'server/services/secureshopBoundReviewModeration.js', 'server/services/secureshopBoundReviewRuntime.js', 'server/services/secureshopBoundReviewTools.js', 'server/services/secureshopBoundTraceRecord.js', 'server/services/secureshopBoundTurns.js', 'server/services/secureshopCleanupComposition.js', 'server/services/secureshopConversationBinding.js', 'server/services/secureshopConversationLifecycle.js', 'server/services/secureshopFileCleanupReceiptReader.js', 'server/services/secureshopFileTargetCleanup.js', 'server/services/secureshopLaunchResetCoordinator.js', 'server/services/secureshopLoopAssessment.js', 'server/services/secureshopLoopEvidence.js', 'server/services/secureshopMcpTrustTools.js', 'server/services/secureshopModelQualification.js', 'server/services/secureshopOwnerResetService.js', 'server/services/secureshopPersonaInboxActivationPolicy.js', 'server/services/secureshopPersonaInboxApplication.js', 'server/services/secureshopPersonaInboxAssessment.js', 'server/services/secureshopPersonaInboxAvailability.js', 'server/services/secureshopPersonaInboxComposition.js', 'server/services/secureshopPersonaInboxEvidence.js', 'server/services/secureshopPersonaInboxExecutionConfig.js', 'server/services/secureshopPersonaInboxFinalResponseGate.js', 'server/services/secureshopPersonaInboxPriorAdvisoryReader.js', 'server/services/secureshopPersonaInboxRequestAuthority.js', 'server/services/secureshopPersonaInboxTools.js', 'server/services/secureshopReviewCardRenderer.js', 'server/services/secureshopReviewCleanupReceiptReader.js', 'server/services/secureshopReviewContentAssessment.js', 'server/services/secureshopReviewContentEvidence.js', 'server/services/secureshopReviewExecutionConfig.js', 'server/services/secureshopReviewResetCoordinator.js', 'server/services/secureshopReviewRunProjection.js', 'server/services/secureshopSsrfApplication.js', 'server/services/secureshopSsrfAssessment.js', 'server/services/secureshopSsrfAvailability.js', 'server/services/secureshopSsrfComposition.js', 'server/services/secureshopSsrfEvidence.js', 'server/services/secureshopSsrfExecutionConfig.js', 'server/services/secureshopRecoverableToolError.js', 'server/services/secureshopSsrfExternalAdapter.js', 'server/services/secureshopSsrfOwnedTarget.js', 'server/services/secureshopSsrfResetAdapter.js', 'server/services/secureshopSsrfTargetPool.js', 'server/services/secureshopStoredBrowserAssessment.js', 'server/services/secureshopStudentDeletionCleanup.js', 'server/services/secureshopTurnAdmission.js', 'server/services/secureshopTurnRequest.js', 'server/services/workshopModeService.js', 'server/services/workshopModeStore.js', 'server/services/xssBrowserQualification.js', 'server/utils/requestContext.js', 'tests/postgres/mcpJudgeInputCapture.js', 'tests/postgres/native_source_provenance.py', 'tests/postgres/run-secureshop-ssrf-live-isolated.py', 'tests/postgres/secureshopSsrfLive.integration.test.js', 'tests/postgres/secureshop_ssrf_source_copy.py', 'tests/postgres/sensitive_info_recovery_safety.py']
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
ownership = {'version':1,'owner':EXPECTED_OWNER,'launcherPid':os.getpid(),
    'workspace':str(root),'container':container,'grantId':args.grant_id,
    'grantFile':str(grant_path),'status':'prepared','runStatus':'preparing','cleanupStatus':'pending',
    'startedAt':datetime.now(timezone.utc).isoformat(),
    'sourceSha256':{name:digest(source / name) for name in tracked},'cleanup':None}
started = False
creation_attempted = False
child = None
frozen_hashes = None

def persist_ownership():
    pending = ownership_path.with_suffix('.json.pending')
    descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(descriptor,'w') as output: output.write(json.dumps(ownership,sort_keys=True) + '\n')
    os.replace(pending,ownership_path)

persist_ownership()
node_version=subprocess.run([str(managed_node/'node'),'--version'],check=True,env=base_env,
    capture_output=True,text=True,timeout=10).stdout.strip()
if node_version!='v26.8.2': raise RuntimeError('Managed Node 26.8.2 is required')
ownership['nodeVersion']=node_version; persist_ownership()

def consume_grant():
    global frozen_hashes
    try:
        grant_lock.mkdir(mode=0o700)
    except FileExistsError as cause:
        raise RuntimeError('Native verification grant is already being consumed') from cause
    try:
        grant = json.loads(grant_path.read_text())
        if grant.get('grantId') != args.grant_id or grant.get('status') != 'granted' \
                or grant.get('owner') != EXPECTED_OWNER or grant.get('allowedLaunches') != 1 \
                or grant.get('dockerHost') != args.docker_host:
            raise RuntimeError('Exact unconsumed native verification grant is required')
        frozen_hashes=grant.get('sourceHashes')
        if not isinstance(frozen_hashes,dict) or set(frozen_hashes)!=set(tracked) \
                or any(ownership['sourceSha256'][name]!=frozen_hashes[name] for name in tracked):
            raise RuntimeError('Frozen native verification source hashes differ')
        grant['status'] = 'consumed'
        grant['consumedAt'] = datetime.now(timezone.utc).isoformat()
        grant['consumerPid'] = os.getpid()
        grant['evidence'] = str(root)
        grant['container'] = container
        pending = grant_path.with_suffix(grant_path.suffix + '.pending')
        pending.write_text(json.dumps(grant,indent=2,sort_keys=True) + '\n')
        os.replace(pending,grant_path)
        ownership['grantConsumedAt'] = grant['consumedAt']
        ownership['status'] = 'grant_consumed'
        persist_ownership()
    finally:
        grant_lock.rmdir()

def await_owner_handle():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        grant = json.loads(grant_path.read_text())
        handle = grant.get('ownerHandle')
        if grant.get('grantId') == args.grant_id and grant.get('status') == 'consumed' \
                and grant.get('consumerPid') == os.getpid() \
                and isinstance(handle, int) and handle > 0:
            ownership['ownerHandle'] = handle
            ownership['status'] = 'owner_handle_registered'
            persist_ownership()
            return
        time.sleep(.1)
    raise RuntimeError('Actual exec owner handle was not registered before Docker use')

def persist_terminal_grant():
    try:
        grant_lock.mkdir(mode=0o700)
    except FileExistsError as cause:
        raise RuntimeError('Native verification grant ledger is busy during terminal update') from cause
    try:
        grant=json.loads(grant_path.read_text())
        if grant.get('grantId')!=args.grant_id or grant.get('status')!='consumed' \
                or grant.get('owner')!=EXPECTED_OWNER or grant.get('consumerPid')!=os.getpid() \
                or grant.get('ownerHandle')!=ownership.get('ownerHandle'):
            raise RuntimeError('Consumed native verification grant changed before terminal update')
        grant.update({'runStatus':ownership['runStatus'],'completedAt':ownership['finishedAt'],
            'cleanup':ownership['cleanup'],'resultSha256':ownership.get('resultSha256'),
            'ownershipSha256':digest(ownership_path)})
        pending=grant_path.with_suffix(grant_path.suffix+'.pending')
        descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(descriptor,'w') as output:
            json.dump(grant,output,indent=2,sort_keys=True);output.write('\n');output.flush();os.fsync(output.fileno())
        os.replace(pending,grant_path)
    finally:
        grant_lock.rmdir()

def run(command,**kwargs):
    kwargs.setdefault('timeout',60)
    return subprocess.run(command,check=True,env=base_env,**kwargs)

def ignore(_directory,names):
    denied={'.git','node_modules','build','logs','uploads','sensitive_files','workshop_data',
            'vector-indexes','coverage','.cache','__pycache__'}
    return [name for name in names if name in denied or name.startswith('.env') or
            any(name.endswith(suffix) for suffix in
                ['.db','.db-wal','.db-shm','.db-journal','.sqlite','.sqlite3','.log'])]

def stop_child():
    global child
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid),signal.SIGTERM)
        try: child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(child.pid),signal.SIGKILL)
            child.wait(timeout=5)

signal_gate = SignalGate()
signal.signal(signal.SIGTERM,signal_gate.handler)
signal.signal(signal.SIGINT,signal_gate.handler)
run_error = None
try:
    consume_grant()
    await_owner_handle()
    copy_ssrf_source(source,workspace,ignore)
    copy_tracked=[name for name in tracked if name!='scripts/register-native-owner-handle.py']
    copied=verify_source_copy(source,workspace,copy_tracked,
        granted={name:frozen_hashes[name] for name in copy_tracked})
    copied_mismatches=[]
    ownership['snapshotAudit']={'verifiedBeforeDocker':True,'copiedTrackedCount':len(copied),
        'originalHelperSha256':ownership['sourceSha256']['scripts/register-native-owner-handle.py'],
        'mismatches':copied_mismatches};persist_ownership()
    ownership['registeredSchemaOnly']=True;persist_ownership()
    (workspace / 'node_modules').symlink_to(source / 'node_modules',target_is_directory=True)
    creation_attempted=True; ownership['containerCreationAttempted']=True; persist_ownership()
    run(docker + ['run','--detach','--name',container,
        '--tmpfs','/var/lib/postgresql:rw,size=268435456',
        '-e','POSTGRES_USER=ssrf_contract_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust',
        '-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18',
        '-c','shared_buffers=16MB','-c','max_connections=48','-c','max_wal_size=16MB','-c','min_wal_size=4MB'],
        stdout=subprocess.DEVNULL)
    started=True; ownership['status']='container_started'; persist_ownership()
    deadline=time.monotonic()+25; stable=0
    while time.monotonic()<deadline:
        ready=subprocess.run(docker+['exec',container,'pg_isready','-h','127.0.0.1','-U','ssrf_contract_admin'],env=base_env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=2)
        if ready.returncode==0:
            running=run(docker+['inspect','--format','{{.State.Running}}',container],capture_output=True,text=True).stdout.strip()=='true'
            stable=stable+1 if running else 0
            if stable>=3: break
        else: stable=0
        time.sleep(.25)
    else: raise RuntimeError('Owned PostgreSQL container did not become ready')
    port=int(run(docker+['port',container,'5432'],capture_output=True,text=True).stdout.strip().rsplit(':',1)[1])
    psql=['psql','-h','127.0.0.1','-p',str(port),'-U','ssrf_contract_admin','-d','postgres','-v','ON_ERROR_STOP=1']
    stores=[('identity','dvaia_identity_migration','dvaia_identity_runtime'),
            ('agents','dvaia_secureshop_agents_migration','dvaia_secureshop_agents_runtime'),
            ('commerce','dvaia_secureshop_migration','dvaia_secureshop_runtime')]
    urls={}
    for label,migration_role,runtime_role in stores:
        for role in [migration_role,runtime_role]:
            run(psql+['-c',f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'],stdout=subprocess.DEVNULL)
        database=f'owasp_ai_goat_test_secureshop_ssrf_{label}'
        run(psql+['-c',f'CREATE DATABASE {database} OWNER {migration_role}'],stdout=subprocess.DEVNULL)
        run(psql+['-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],stdout=subprocess.DEVNULL)
        urls[label]={'migration':f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
                     'runtime':f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}'}
    env=dict(base_env,NODE_ENV='test',PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',PG_TEST_DISPOSABLE='yes',
        LIVE_OLLAMA_TEST='0' if args.mounted_deterministic else '1',
        SSRF_MOUNTED_DETERMINISTIC='1' if args.mounted_deterministic else '0',
        OLLAMA_MODEL='llama3.1:8b',OLLAMA_BASE_URL='http://127.0.0.1:11434',
        AI_PROVIDER='ollama',JUDGE_PROVIDER='ollama',JUDGE_MODEL='llama3.1:8b',
        OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace),AWS_EC2_METADATA_DISABLED='true',
        PG_SECURESHOP_SSRF_LIVE_IDENTITY_MIGRATION_URL=urls['identity']['migration'],
        PG_SECURESHOP_SSRF_LIVE_IDENTITY_RUNTIME_URL=urls['identity']['runtime'],
        PG_SECURESHOP_SSRF_LIVE_AGENTS_MIGRATION_URL=urls['agents']['migration'],
        PG_SECURESHOP_SSRF_LIVE_AGENTS_RUNTIME_URL=urls['agents']['runtime'],
        PG_SECURESHOP_SSRF_LIVE_COMMERCE_MIGRATION_URL=urls['commerce']['migration'],
        PG_SECURESHOP_SSRF_LIVE_COMMERCE_RUNTIME_URL=urls['commerce']['runtime'],
        SECURESHOP_DATABASE_URL=urls['commerce']['runtime'],SECURESHOP_MIGRATION_DATABASE_URL=urls['commerce']['migration'])
    log_path=root/'result.log'
    log_descriptor=os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(log_descriptor,'w') as log:
        ownership['status']='test_running'; ownership['runStatus']='running'; ownership['testPid']=None; persist_ownership()
        child=subprocess.Popen(['node','--test','--test-reporter=tap','--test-concurrency=1',
            'tests/postgres/secureshopSsrfLive.integration.test.js'],cwd=workspace,env=env,
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        ownership['testPid']=child.pid; persist_ownership()
        try: code=child.wait(timeout=330)
        except subprocess.TimeoutExpired:
            stop_child(); raise RuntimeError('SecureShop controlled SSRF actual-model qualification timed out')
    if code: raise RuntimeError(f'SecureShop controlled SSRF actual-model qualification failed ({code})')
    ownership['resultSha256']=digest(log_path)
    ownership['status']='terminal_pass'; ownership['runStatus']='terminal_pass'; persist_ownership()
except BaseException as error:
    run_error=error
    ownership['status']='terminal_fail'; ownership['runStatus']='terminal_fail'; ownership['errorType']=type(error).__name__
    log_path=root/'result.log'
    if log_path.exists(): ownership['resultSha256']=digest(log_path)
    persist_ownership()
    raise
finally:
    signal_gate.protect_cleanup(); cleanup_errors=[]; removed=None; exact_absent=None; absence_return_code=None
    try: stop_child()
    except Exception as error: cleanup_errors.append(f'child:{type(error).__name__}')
    if creation_attempted:
        try: removed=subprocess.run(docker+['rm','--force',container],env=base_env,stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,timeout=30,check=False)
        except Exception as error: cleanup_errors.append(f'remove:{type(error).__name__}')
    try:
        absence=subprocess.run(docker+['ps','-a','--filter',f'name=^{container}$','--format','{{.Names}}'],env=base_env,
            capture_output=True,text=True,timeout=30,check=False)
        absence_return_code=absence.returncode; exact_absent=absence.returncode==0 and absence.stdout.strip()==''
        if absence.returncode!=0: cleanup_errors.append('absence:NonZeroExit')
    except Exception as error: cleanup_errors.append(f'absence:{type(error).__name__}')
    judge_path=root/'judge-inputs.json'
    if judge_path.exists():
        os.chmod(judge_path,0o600)
        ownership['judgeInputs']={'sha256':digest(judge_path),'bytes':judge_path.stat().st_size}
    ownership['cleanup']={'removeReturnCode':None if removed is None else removed.returncode,
        'absenceQueryReturnCode':absence_return_code,'exactNameAbsent':exact_absent,
        'containerCreationAttempted':creation_attempted,'containerStarted':started,
        'signals':signal_gate.received,'errors':cleanup_errors}
    cleanup_failed=bool(cleanup_errors or exact_absent is not True or (started and (removed is None or removed.returncode!=0)))
    ownership['cleanupStatus']='failed' if cleanup_failed else 'complete'
    ownership['finishedAt']=datetime.now(timezone.utc).isoformat(); persist_ownership()
    terminal_ledger_error=None
    if ownership.get('grantConsumedAt'):
        try:
            ownership['terminalLedgerStatus']='complete';persist_ownership();persist_terminal_grant()
        except Exception as error:
            terminal_ledger_error=error;ownership['terminalLedgerStatus']='failed';ownership['terminalLedgerError']=type(error).__name__;persist_ownership()
    print(f'Run {ownership["runStatus"]}; cleanup {ownership["cleanupStatus"]}; evidence retained: {root}',flush=True)
    if run_error is None and (cleanup_failed or terminal_ledger_error is not None):
        raise RuntimeError('Owned qualifier cleanup or terminal ledger update did not complete')
