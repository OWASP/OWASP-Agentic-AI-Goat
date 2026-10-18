from pathlib import Path
import hashlib,subprocess,sys
h=Path(__file__).resolve().parent
s=(h/'run-finflow-actual8b-isolated.py').read_text()
for token in ['grant-file','grant-id','owner-handle-file','docker-host','container-nonce','package-root','manifest','managed-node','postgres-image-id','scope','PG_TEST_DISPOSABLE','postgres:18','--tmpfs','127.0.0.1::5432','CREATE DATABASE {db}','expectedOwnerHandle','ownerHandlePath','ownerHandleFileSha256','managedNodePath','managedNodeSha256','dependencySnapshotSha256','dependencySymlinks','private dependency root required','dependency symlink mismatch','expectedLauncherPid','os.killpg','terminal_pass_cleaned','FINFLOW_RECON_ACTUAL8B_EVIDENCE_PATH','DVAIA_ISOLATED_TEST_WORKSPACE','LOGS_DIR','app_data/\'logs\'','source/tests/finflowGraphEventContract.test.js','source/tests/postgres/finflowActual8bSourceClosure.test.js','source/tests/postgres/finflowReconActual8b.integration.test.js','SENSITIVE_INFO_AGGREGATE_RESET_ENABLED','JUDGE_PROVIDER','dvaia_test_finflow_recon_identity','dvaia_test_finflow_recon_store','preflight','verify_fixtures','controlled fixture inventory mismatch','ensure_private_root','e2cb44baf52a6124d812723bf775cd2d6a7fbe100e71cb2053669ce57d345eab','58dc81956934ce9fae23e65af3674f27dc6d46f07326a54404c4a874e27d027a','5265ffbe93eac180b81969b9de24ac2638ca2f98b3c8f6f06d6f0025f3bec1f2']:
 assert token in s, f'missing launcher contract: {token}'
assert 'os.kill(' not in s
assert 'ALTER DEFAULT PRIVILEGES' not in s
assert "for private_root in (app_data,app_data/'logs',app_data/'finflow-traversal-targets')" in s
assert 'if os.path.lexists(backup_root)' in s and 'application-owned backup leaf must be absent' in s
assert "app_data/'finflow-traversal-targets',app_data/'finflow-backups'" not in s
assert "if y.returncode" in s
assert "STAGE='actual8b-v3'" in s and 'actual8b-v2' not in s
predecessor=s.replace("STAGE='actual8b-v3'","STAGE='actual8b-v2'").replace("'source/tests/finflowGraphEventContract.test.js',",'').replace("'source/tests/postgres/finflowActual8bSourceClosure.test.js',",'')
assert hashlib.sha256(predecessor.encode()).hexdigest()=='4225772d51a43d6bba66ebc914c60e01d341deb022c03899f4149649eb1d6c43'
fixture_path=h/'finflowReconActual8b.integration.test.js'
if not fixture_path.is_file(): fixture_path=h.parent/'source/tests/postgres/finflowReconActual8b.integration.test.js'
fixture=fixture_path.read_text()
assert "STAGE='actual8b-v3'" in fixture and 'actual8b-v2' not in fixture
p=subprocess.run([sys.executable,str(h/'run-finflow-actual8b-isolated.py'),'--grant-file','/dev/null','--grant-id','probe','--owner','/nobody','--owner-handle-file','/dev/null','--docker-host','unix:///invalid','--container-nonce','000000000000','--canonical-workspace','/','--package-root','/','--manifest','/dev/null','--managed-node','/dev/null','--postgres-image-id','sha256:'+'0'*64,'--scope','finflow_recon_actual8b'],capture_output=True,text=True)
assert p.returncode and 'launch binding invalid' in p.stderr
print('finflow actual8b launcher static contracts passed')
