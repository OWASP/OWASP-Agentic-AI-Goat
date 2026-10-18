"""Import-inert frozen two-store admission contract; no providers or launches."""
import json
import os
import re
from pathlib import Path
from sql_nosql_package_contract import inventory, digest, require, SHA, prepare_evidence_root

REQUIRED = {
 'package.json', 'package-lock.json', 'tests/postgres/run-authenticated-agent-run-ownership-isolated.py',
 'tests/postgres/authenticated_run_ownership_contract.py', 'tests/postgres/sql_nosql_package_contract.py',
 'tests/postgres/sql_nosql_docker_ownership.py', 'tests/postgres/sql_nosql_process_ownership.py',
 'tests/postgres/agentRunAuthenticatedOwnership.integration.test.js',
 'server/routes/agentRuns.js', 'server/middleware/postgresAdminAuth.js',
 'server/services/postgresIdentityAdapter.js', 'server/services/secureshopConversationOwnershipResolver.js',
 'server/database/postgres/agentRunReadRepository.js', 'server/database/postgres/identityRepository.js',
 'server/database/postgres/secureshopAgentsDb.js', 'server/database/postgres/secureshopInitialization.js',
 'server/database/postgres/secureshopLaunchRepository.js',
 'db/postgres/identity-migrations/0001_identity.sql',
 'db/postgres/identity-migrations/0061_mcp_supply_chain_curriculum_defaults.sql',
 'db/postgres/workshop-migrations/secureshop_agents/0013_secureshop_conversation_purpose.sql',
 'node_modules/pg/package.json', 'node_modules/express/package.json', 'node_modules/jsonwebtoken/package.json',
}

REVIEWED_AGENTS_MIGRATIONS = {'db/postgres/workshop-migrations/secureshop_agents/0010_secureshop_persona_inbox.sql', 'db/postgres/workshop-migrations/secureshop_agents/0011_secureshop_mcp_trust.sql', 'db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql', 'db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql', 'db/postgres/workshop-migrations/secureshop_agents/0012_secureshop_controlled_ssrf.sql', 'db/postgres/workshop-migrations/secureshop_agents/0006_secureshop_turn_admission.sql', 'db/postgres/workshop-migrations/secureshop_agents/0009_secureshop_bound_persona_renewal.sql', 'db/postgres/workshop-migrations/secureshop_agents/0013_secureshop_conversation_purpose.sql', 'db/postgres/workshop-migrations/secureshop_agents/0004_embedding_identity.sql', 'db/postgres/workshop-migrations/secureshop_agents/0002_vectors.sql', 'db/postgres/workshop-migrations/secureshop_agents/0008_secureshop_bound_persona_sessions.sql', 'db/postgres/workshop-migrations/secureshop_agents/0007_secureshop_conversation_generation_retirement.sql', 'db/postgres/workshop-migrations/secureshop_agents/0003_import_history.sql'}

def validate_manifest(manifest):
 require(type(manifest) is dict and set(manifest)=={'version','scope','files','symlinks','directories'}
         and type(manifest['version']) is int and manifest['version']==1
         and manifest['scope']=='authenticated_agent_run_ownership', 'manifest schema mismatch')
 require(REQUIRED <= set(manifest['files']), 'required source closure missing')
 require(REVIEWED_AGENTS_MIGRATIONS <= set(manifest['files']), 'agents migration closure incomplete')
 for relative in manifest['files']:
  if relative.startswith('db/postgres/identity-migrations/'):
   require(re.fullmatch(r'db/postgres/identity-migrations/\d{4}_[^/]+\.sql',relative)
           and relative.rsplit('/',1)[1]<='0061_mcp_supply_chain_curriculum_defaults.sql', 'unreviewed identity migration')
  if relative.startswith('db/postgres/workshop-migrations/'):
   require(relative in REVIEWED_AGENTS_MIGRATIONS, 'unreviewed workshop migration')
 return manifest

def validate_package(source, manifest_path, manifest_sha256, node, node_sha256):
 source,manifest_path,node=map(Path,(source,manifest_path,node))
 require(source.name=='source' and manifest_path==source.parent/'manifest.json'
         and set(p.name for p in source.parent.iterdir())=={'source','manifest.json'}, 'exact source-plus-manifest required')
 require(not source.parent.is_symlink() and not source.parent.stat().st_mode & 0o222, 'immutable parent required')
 require(manifest_path.is_file() and not manifest_path.is_symlink() and not manifest_path.stat().st_mode & 0o222
         and SHA.fullmatch(manifest_sha256) and digest(manifest_path)==manifest_sha256, 'manifest identity mismatch')
 require(node.is_absolute() and node.is_file() and not node.is_symlink() and os.access(node,os.X_OK)
         and SHA.fullmatch(node_sha256) and digest(node)==node_sha256, 'Node identity mismatch')
 manifest=validate_manifest(json.loads(manifest_path.read_text()))
 require(all(manifest[key]==value for key,value in inventory(source).items()), 'complete inventory mismatch')
 require(all((source/key).stat().st_nlink==1 for key in manifest['files']), 'hardlinks forbidden')
 return manifest
