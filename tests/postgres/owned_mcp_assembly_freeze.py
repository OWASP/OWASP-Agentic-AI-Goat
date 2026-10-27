"""Owned MCP source/dependency inventory; no resources or subprocesses at import."""
import hashlib,json,os,subprocess
from pathlib import Path
SOURCE_FILES=('tests/helpers/secureshopAgentsMigrationView.js','tests/postgres/test_owned_mcp_handshake_cancellation.py','tests/fixtures/secureshopOwnedMcpHandshakeCancellation.native.js','tests/postgres/test_owned_mcp_invocation_attestation.py','tests/postgres/test_owned_mcp_procless_feasibility.py','tests/postgres/run-owned-mcp-procless-feasibility-isolated.py','tests/postgres/test_owned_mcp_procless_launcher.py','tests/secureshopOwnedMcpDiagnosticPrivacy.test.js','tests/postgres/run-owned-mcp-invocation-os-isolated.py','tests/postgres/test_owned_mcp_invocation_os_launcher.py','tests/fixtures/secureshopOwnedMcpInvocationOs.native.js','tests/secureshopOwnedMcpInvocationOsSource.test.js','tests/secureshopOwnedMcpInvocationRecovery.test.js','tests/secureshopOwnedMcpInvocationManager.test.js','tests/postgres/secureshopOwnedMcpInvocationJournal.native.js','tests/secureshopOwnedMcpInvocationJournal.test.js','tests/secureshopOwnedMcpInvocationLifecycle.test.js','package.json','package-lock.json','tests/postgres/secureshopOwnedMcpAssemblySupport.js','tests/postgres/secureshopOwnedMcpAssembly.native.js','tests/postgres/run-owned-mcp-assembly-isolated.py','tests/postgres/owned_mcp_assembly_freeze.py','tests/postgres/prepare-owned-mcp-assembly.py','tests/postgres/sql_nosql_docker_ownership.py','tests/postgres/test_owned_mcp_assembly_launcher.py','tests/secureshopOwnedMcpAssemblyContracts.test.js','tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs','tests/fixtures/secureshopOwnedMcpAssemblyCopy.js')
SOURCE_DIRECTORIES=('server','db/postgres','sidecars','agent-host','scripts/lib')
SOURCE_FILES=SOURCE_FILES+('tests/postgres/secureshop_current_host_admission.py',)
SOURCE_FILES=SOURCE_FILES+('tests/postgres/darwin_process_inventory.py','tests/postgres/trusted_process_inspector.py','tests/postgres/mcp_process_inspector.py','tests/postgres/run_mcp_with_inspector.py','tests/postgres/test_mcp_process_inspector.py')
NODE=Path(__file__).resolve().parents[2]/'tasks/runtime/node/node_modules/node/bin/node'
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def record(path):
 if path.is_symlink():return {'kind':'symlink','target':os.readlink(path)}
 return {'kind':'file','bytes':path.stat().st_size,'sha256':sha(path)}
def inventory(root):
 root=Path(root)
 if sha(NODE)!=NODE_SHA:raise RuntimeError('Pinned current-host Node required for source inventory')
 response=subprocess.run([str(NODE),str(root/'tests/fixtures/secureshopOwnedMcpAssemblyCopy.js'),str(root),json.dumps(SOURCE_FILES),json.dumps(SOURCE_DIRECTORIES)],capture_output=True,text=True,check=True,timeout=30)
 names=json.loads(response.stdout)
 return {name:record(root/name) for name in names}
def dependencies(root):
 root=Path(root);return {p.relative_to(root).as_posix():record(p) for p in sorted((root/'node_modules').rglob('*')) if p.is_symlink() or p.is_file()}
def digest(rows):return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def verify(root,source_sha,dependency_sha):
 source=inventory(root);deps=dependencies(root)
 if digest(source)!=source_sha:raise RuntimeError('Reviewed source inventory mismatch')
 if digest(deps)!=dependency_sha:raise RuntimeError('Reviewed dependency byte inventory mismatch')
 return {'sourceCount':len(source),'dependencyCount':len(deps),'sourceSha256':source_sha,'dependencySha256':dependency_sha}
