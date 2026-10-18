#!/usr/bin/env python3
"""Run PostgreSQL tests in a fresh loopback-only cluster; never connect to app databases."""
import os
import getpass
import socket
import subprocess
import tempfile
from urllib.parse import urlparse, unquote, quote

root = tempfile.mkdtemp(prefix='dvaia-pg-test-')
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

started = False
external = os.environ.get('DVAIA_PG_TEST_ADMIN_URL')
try:
    if external:
        parsed = urlparse(external)
        if (os.environ.get('DVAIA_PG_TEST_EXTERNAL_DISPOSABLE') != 'yes' or
                parsed.scheme not in ['postgres','postgresql'] or
                parsed.hostname not in ['127.0.0.1','localhost'] or parsed.path != '/postgres' or
                parsed.query or parsed.fragment or not parsed.username):
            raise ValueError('External tests require an explicit disposable loopback PostgreSQL admin URL')
        port = parsed.port or 5432
        os.environ['PGUSER'] = unquote(parsed.username)
        if parsed.password: os.environ['PGPASSWORD'] = unquote(parsed.password)
        # Refuse to operate against a cluster containing application databases.
        existing = run(['psql','-h','127.0.0.1','-p',str(port),'-d','postgres','-At','-v','ON_ERROR_STOP=1','-c',
                        "SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"],
                       stdout=subprocess.PIPE,text=True).stdout.strip()
        if existing != '0': raise ValueError('External test cluster is not empty; create a new disposable container')
    else:
        run(['initdb', '-D', root + '/data', '-A', 'trust', '--no-locale'], stdout=subprocess.DEVNULL)
        run(['pg_ctl', '-D', root + '/data', '-l', root + '/postgres.log', '-o', f'-h 127.0.0.1 -p {port} -k {root}', '-w', 'start'], stdout=subprocess.DEVNULL)
        started = True
    roles = ['dvaia_legacy_challenge_migration','dvaia_legacy_challenge_runtime','dvaia_sensitive_lookup_migration','dvaia_sensitive_lookup_runtime','dvaia_secureshop_migration','dvaia_secureshop_runtime','dvaia_secureshop_agents_migration','dvaia_secureshop_agents_runtime','dvaia_session_disclosure_migration','dvaia_session_disclosure_runtime','dvaia_secureshop_review_migration','dvaia_secureshop_review_runtime','dvaia_test', 'dvaia_aria_migration', 'dvaia_aria_runtime', 'dvaia_nova_migration', 'dvaia_nova_runtime', 'dvaia_identity_migration', 'dvaia_identity_runtime', 'dvaia_xss_migration', 'dvaia_xss_runtime', 'dvaia_mcp_migration', 'dvaia_mcp_runtime', 'dvaia_csrf_migration', 'dvaia_csrf_runtime', 'dvaia_supply_chain_migration', 'dvaia_supply_chain_runtime', 'dvaia_finflow_migration', 'dvaia_finflow_runtime', 'dvaia_ctf_migration', 'dvaia_ctf_runtime', 'dvaia_excessive_agency_migration', 'dvaia_excessive_agency_runtime']
    for role in roles:
        run(['psql', '-h', '127.0.0.1', '-p', str(port), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'], stdout=subprocess.DEVNULL)
    env = dict(os.environ, PG_TEST_DISPOSABLE='yes', WORKSHOP_DATABASE_ENGINE='postgres')
    admin_url = external or f'postgresql://{quote(getpass.getuser())}@127.0.0.1:{port}/postgres'
    env['PG_LEGACY_CHALLENGE_IMPORT_ADMIN_URL'] = admin_url
    env['PG_EMBEDDING_IDENTITY_ADMIN_URL'] = admin_url
    env['PG_WORKSHOP_COMMAND_ADMIN_URL'] = admin_url
    env['PG_ASSET_CUTOVER_ADMIN_URL'] = admin_url
    # Retired legacy SQLite archive CLI tests are preserved externally; supported PostgreSQL tests follow.
    for name, owner in [('secureshop_launch_agents','dvaia_secureshop_agents_migration'),('prompt_rag','dvaia_identity_migration'),('secureshop_bound_turns','dvaia_identity_migration'),('secureshop_conversation','dvaia_secureshop_agents_migration'),('secureshop_target','dvaia_identity_migration'),('secureshop_launch','dvaia_identity_migration'),('legacy_sensitive_move','dvaia_finflow_migration'),('legacy_sensitive_reverse','dvaia_finflow_migration'),('legacy_sensitive_import','dvaia_finflow_migration'),('secureshop_import','dvaia_secureshop_migration'),('secureshop_agents_import','dvaia_secureshop_agents_migration'),('secureshop_empty_import','dvaia_secureshop_migration'),('secureshop_agents_empty_import','dvaia_secureshop_agents_migration'),('csrf_import','dvaia_csrf_migration'),('csrf_empty_import','dvaia_csrf_migration'),('xss_import','dvaia_xss_migration'),('platform_apply','dvaia_identity_migration'),('ctf_import','dvaia_ctf_migration'),('finflow_empty_import','dvaia_finflow_migration'),('supply_chain_empty_import','dvaia_supply_chain_migration'),('mcp_empty_import','dvaia_mcp_migration'),('mcp_import','dvaia_mcp_migration'),('identity_auxiliary','dvaia_identity_migration'),('finflow_import','dvaia_finflow_migration'),('supply_chain_import','dvaia_supply_chain_migration'),('additional_solutions_import','dvaia_identity_migration'),('platform_import','dvaia_identity_migration'),('solutions_import','dvaia_identity_migration'),('import_batches','dvaia_identity_migration'),('platform_identity','dvaia_identity_migration'),('identity_atomic','dvaia_identity_migration'),('provenance','dvaia_identity_migration'),('aria_import','dvaia_aria_migration'),('nova_import','dvaia_nova_migration'),('legacy_challenge','dvaia_legacy_challenge_migration'),('sensitive_lookup','dvaia_sensitive_lookup_migration'),('secureshop_customer','dvaia_secureshop_migration'),('secureshop_merchant','dvaia_secureshop_migration'),('secureshop_tools','dvaia_secureshop_migration'),('secureshop','dvaia_secureshop_migration'),('secureshop_agents','dvaia_secureshop_agents_migration'),('session_disclosure','dvaia_session_disclosure_migration'),('secureshop_review','dvaia_secureshop_review_migration'),('excessive_agency', 'dvaia_excessive_agency_migration'), ('ctf', 'dvaia_ctf_migration'), ('finflow', 'dvaia_finflow_migration'), ('foundation', 'dvaia_test'), ('xss', 'dvaia_xss_migration'), ('mcp', 'dvaia_mcp_migration'), ('csrf', 'dvaia_csrf_migration'), ('supply_chain', 'dvaia_supply_chain_migration'), ('aria', 'dvaia_aria_migration'), ('nova', 'dvaia_nova_migration'), ('identity', 'dvaia_identity_migration'), ('platform', 'dvaia_identity_migration'), ('http', 'dvaia_identity_migration'), ('admin', 'dvaia_identity_migration'), ('email', 'dvaia_identity_migration'), ('native', 'dvaia_identity_migration'), ('graph', 'dvaia_identity_migration'), ('graph_provisional', 'dvaia_identity_migration'), ('judgments', 'dvaia_identity_migration'), ('reads', 'dvaia_identity_migration'), ('evidence', 'dvaia_identity_migration')]:
        db = 'dvaia_test_' + name
        run(['createdb', '-h', '127.0.0.1', '-p', str(port), '-O', owner, db])
        runtime = ('dvaia_identity_runtime' if name in ['prompt_rag','secureshop_bound_turns', 'secureshop_target', 'secureshop_launch', 'platform_apply', 'identity_auxiliary', 'additional_solutions_import', 'platform_import', 'solutions_import', 'import_batches', 'platform_identity', 'identity_atomic', 'provenance', 'platform', 'http', 'admin', 'email', 'native', 'graph', 'graph_provisional', 'judgments', 'reads', 'evidence'] else 'dvaia_' + name + '_runtime') if name != 'foundation' else owner
        if name in ['aria_import','nova_import','finflow_import','supply_chain_import','mcp_import','ctf_import','xss_import','csrf_import']:
            runtime = 'dvaia_' + name.removesuffix('_import') + '_runtime'
        if name in ['mcp_empty_import','finflow_empty_import','supply_chain_empty_import','csrf_empty_import']:
            runtime = 'dvaia_' + name.removesuffix('_empty_import') + '_runtime'
        if name in ['secureshop_tools','secureshop_customer','secureshop_merchant']:
            runtime = 'dvaia_secureshop_runtime'
        if name in ['secureshop_import','secureshop_empty_import']:
            runtime = 'dvaia_secureshop_runtime'
        if name in ['secureshop_launch_agents','secureshop_conversation','secureshop_agents_import','secureshop_agents_empty_import']:
            runtime = 'dvaia_secureshop_agents_runtime'
        if name in ['legacy_sensitive_import','legacy_sensitive_move','legacy_sensitive_reverse']:
            runtime = 'dvaia_finflow_runtime'
        run(['psql', '-h', '127.0.0.1', '-p', str(port), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO {owner}, {runtime};'], stdout=subprocess.DEVNULL)
        url = f'postgresql://{owner}@127.0.0.1:{port}/{db}'
        if name == 'foundation':
            env['PG_TEST_DATABASE_URL'] = url
        else:
            env[f'PG_{name.upper()}_TEST_MIGRATION_URL'] = url
            env[f'PG_{name.upper()}_TEST_RUNTIME_URL'] = f'postgresql://{runtime}@127.0.0.1:{port}/{db}'
    # Exercise the installed RAG Judge persistence contract without an LLM.
    # Its dedicated identity store prevents this cohort's reset from touching others.
    rag_db = 'dvaia_test_rag_judge'
    run(['createdb', '-h', '127.0.0.1', '-p', str(port), '-O', 'dvaia_identity_migration', rag_db])
    run(['psql', '-h', '127.0.0.1', '-p', str(port), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1',
         '-c', f'REVOKE CONNECT ON DATABASE {rag_db} FROM PUBLIC; GRANT CONNECT ON DATABASE {rag_db} TO dvaia_identity_migration,dvaia_identity_runtime;'], stdout=subprocess.DEVNULL)
    rag_env = dict(env, NODE_ENV='test', PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
                   PG_TEST_DISPOSABLE='yes', IPI_RAG_JUDGE_PG_ROUNDTRIP='1',
                   JWT_SECRET=__import__('secrets').token_urlsafe(48),
                   IDENTITY_DATABASE_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{rag_db}',
                   IDENTITY_MIGRATION_DATABASE_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{rag_db}')
    run(['node', '--test', 'tests/postgres/ipiRagJudgeDurability.integration.test.js'], env=rag_env)
    # Give CTF provenance and session ownership their own stores so both the
    # fresh and populated migration paths run in the normal PostgreSQL suite.
    ctf_env = dict(env, CTF_PROVENANCE_NATIVE='1', CTF_PROVENANCE_HEARTBEAT_NATIVE='1', CTF_REGISTRATION_CAPACITY_NATIVE='1')
    for label in ('FRESH', 'POPULATED', 'HEARTBEAT', 'REGISTRATION'):
        db = 'dvaia_test_ctf_provenance_' + label.lower()
        run(['createdb', '-h', '127.0.0.1', '-p', str(port), '-O', 'dvaia_ctf_migration', db])
        run(['psql', '-h', '127.0.0.1', '-p', str(port), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1',
             '-c', f'REVOKE CONNECT ON DATABASE {db} FROM PUBLIC; GRANT CONNECT ON DATABASE {db} TO dvaia_ctf_migration,dvaia_ctf_runtime;'], stdout=subprocess.DEVNULL)
        ctf_env[f'CTF_PROVENANCE_{label}_MIGRATION_URL'] = f'postgresql://dvaia_ctf_migration@127.0.0.1:{port}/{db}'
        ctf_env[f'CTF_PROVENANCE_{label}_RUNTIME_URL'] = f'postgresql://dvaia_ctf_runtime@127.0.0.1:{port}/{db}'
    run(['node', '--test', '--test-concurrency=1',
         'tests/postgres/ctfStageDefaultProvenance.integration.test.js',
         'tests/postgres/ctfHeartbeatOwner.integration.test.js',
         'tests/postgres/ctfRegistrationCapacity.integration.test.js'], env=ctf_env)
    # The standalone review lifecycle test keeps its historical explicit DB
    # qualifier; both names refer to this one owned aggregate database.
    env['PG_SECURESHOP_REVIEW_DB_TEST_MIGRATION_URL'] = env['PG_SECURESHOP_REVIEW_TEST_MIGRATION_URL']
    env['PG_SECURESHOP_REVIEW_DB_TEST_RUNTIME_URL'] = env['PG_SECURESHOP_REVIEW_TEST_RUNTIME_URL']
    run(['node', '--test', 'tests/postgres/secureshopReviewDb.integration.test.js', 'tests/postgres/secureshopBoundTurns.integration.test.js', 'tests/postgres/secureshopConversationBinding.integration.test.js', 'tests/postgres/secureshopTargetMigration.integration.test.js', 'tests/postgres/secureshopLaunchAuthority.integration.test.js', 'tests/postgres/legacySensitiveArchive.integration.test.js', 'tests/postgres/legacySensitiveOwnerMigration.integration.test.js', 'tests/postgres/legacySensitiveReverseImport.integration.test.js', 'tests/postgres/legacyChallengeArchive.integration.test.js', 'tests/postgres/secureshopArchive.integration.test.js', 'tests/postgres/secureshopEmbeddingIdentity.integration.test.js', 'tests/postgres/csrfArchiveImport.integration.test.js', 'tests/postgres/xssArchiveImport.integration.test.js', 'tests/platformArchiveApply.test.js', 'tests/postgres/ctfImport.integration.test.js', 'tests/postgres/mcpArchive.integration.test.js', 'tests/postgres/graphTraceMetadata.integration.test.js', 'tests/postgres/graphProvisionalTrace.integration.test.js', 'tests/postgres/identityAuxiliaryImport.integration.test.js', 'tests/postgres/agentWorkshopImport.integration.test.js', 'tests/postgres/platformAdditionalSolutions.integration.test.js', 'tests/postgres/platformImport.integration.test.js', 'tests/postgres/platformSolutions.integration.test.js', 'tests/postgres/workshopImport.integration.test.js', 'tests/postgres/importBatches.integration.test.js', 'tests/postgres/platformIdentityImport.integration.test.js', 'tests/postgres/identityImportAtomic.integration.test.js', 'tests/postgres/historicalImportProvenance.integration.test.js', 'tests/postgres/legacyChallenge.integration.test.js', 'tests/postgres/sensitiveLookup.integration.test.js', 'tests/postgres/secureshopAuth.integration.test.js', 'tests/postgres/secureshopCustomer.integration.test.js', 'tests/postgres/secureshopMerchant.integration.test.js', 'tests/postgres/secureshopAgents.integration.test.js', 'tests/postgres/secureshopVectors.integration.test.js', 'tests/postgres/secureshopCommerce.integration.test.js', 'tests/postgres/promptRagProgress.integration.test.js', 'tests/postgres/finflow.integration.test.js', 'tests/postgres/legacySensitive.integration.test.js', 'tests/postgres/ctf.integration.test.js', 'tests/postgres/excessiveAgency.integration.test.js', 'tests/postgres/xssEmailStore.integration.test.js', 'tests/postgres/foundation.test.js', 'tests/postgres/poolBudget.test.js', 'tests/postgres/objectiveDetection.test.js', 'tests/postgres/migrations.integration.test.js', 'tests/postgres/workshops.integration.test.js', 'tests/postgres/identity.integration.test.js', 'tests/postgres/workshopPlatform.integration.test.js', 'tests/postgres/authHttp.integration.test.js', 'tests/postgres/adminHttp.integration.test.js', 'tests/postgres/xss.integration.test.js', 'tests/postgres/emailStorage.integration.test.js', 'tests/postgres/nativeWorkshops.integration.test.js', 'tests/postgres/graphRuntime.integration.test.js', 'tests/postgres/objectiveJudgments.integration.test.js', 'tests/postgres/agentRunReads.integration.test.js', 'tests/postgres/objectiveEvidence.integration.test.js'], env=env)
    initializer_env = dict(env, PLATFORM_DATABASE_ENGINE='postgres')
    for schema, prefix in [('legacy_challenge','LEGACY_CHALLENGE'),('sensitive_lookup','SENSITIVE_LOOKUP'),('secureshop','SECURESHOP'),('secureshop_agents','SECURESHOP_AGENTS'),('session_disclosure','SESSION_DISCLOSURE'),('secureshop_review','SECURESHOP_REVIEW'),('identity','IDENTITY'),('aria','SQL_WORKSHOP'),('nova','NOSQL_WORKSHOP'),('xss','XSS_WORKSHOP'),('mcp','MCP_WORKSHOP'),('csrf','CSRF_WORKSHOP'),('supply_chain','SUPPLY_CHAIN_WORKSHOP'),('finflow','FINFLOW_WORKSHOP'),('excessive_agency','EXCESSIVE_AGENCY'),('ctf','CTF')]:
        initializer_env[f'{prefix}_DATABASE_URL'] = env[f'PG_{schema.upper()}_TEST_RUNTIME_URL']
        initializer_env[f'{prefix}_MIGRATION_DATABASE_URL'] = env[f'PG_{schema.upper()}_TEST_MIGRATION_URL']
    run(['node', 'db/postgres/initialize-application.js'], env=initializer_env)
    run(['node', '--test', 'tests/postgres/applicationBoot.integration.test.js'], env=env)
    run(['node', '--test', 'tests/postgres/workshopLoad.integration.test.js'], env=env)
    # Run the existing service/DB suites through the public staged module paths.
    for family, kind in [('aria', 'sql'), ('nova', 'nosql')]:
        database = f'dvaia_test_{family}_service'
        owner, runtime = f'dvaia_{family}_migration', f'dvaia_{family}_runtime'
        run(['createdb', '-h', '127.0.0.1', '-p', str(port), '-O', owner, database])
        run(['psql', '-h', '127.0.0.1', '-p', str(port), '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {owner}, {runtime};'], stdout=subprocess.DEVNULL)
        service_env = dict(env, SERVER_AVAILABLE='0')
        service_env[f'{kind.upper()}_WORKSHOP_DATABASE_URL'] = f'postgresql://{runtime}@127.0.0.1:{port}/{database}'
        service_env[f'{kind.upper()}_WORKSHOP_MIGRATION_DATABASE_URL'] = f'postgresql://{owner}@127.0.0.1:{port}/{database}'
        try:
            output = run(['node', '--require', './tests/postgres/fake-model.cjs', f'tests/{kind}Workshop.test.js'], env=service_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as error:
            print(error.stdout, flush=True)
            raise
        print(output.stdout[-1400:])
finally:
    if started:
        run(['pg_ctl', '-D', root + '/data', '-m', 'fast', '-w', 'stop'], stdout=subprocess.DEVNULL)
    print('External disposable cluster remains for owner cleanup; diagnostic files:' if external else 'Isolated cluster stopped; diagnostic files:', root)
