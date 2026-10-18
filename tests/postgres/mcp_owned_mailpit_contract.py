"""Import-inert MCP fixture package, control and Mailpit layout admission."""
import json
import os
from pathlib import Path
from sql_nosql_package_contract import inventory, digest, require, SHA, prepare_evidence_root

SCOPE = 'mcp_owned_resources_mailpit'
MIGRATIONS = {'db/postgres/workshop-migrations/mcp/' + name for name in
              ['0001_schema.sql', '0002_import_provenance.sql', '0003_owner_binding.sql']}
REQUIRED = MIGRATIONS | {
 'package.json', 'package-lock.json', 'node_modules/pg/package.json', 'node_modules/nodemailer/package.json',
 'tests/postgres/run-mcp-owned-resources-mailpit-isolated.py', 'tests/postgres/mcp_owned_mailpit_contract.py',
 'tests/postgres/sql_nosql_package_contract.py', 'tests/postgres/sql_nosql_docker_ownership.py',
 'tests/postgres/sql_nosql_process_ownership.py', 'tests/postgres/mcpOwnedResourcesMailpit.integration.test.js',
 'docs/modernization/drafts/mcp-owned-resources.sql', 'server/database/postgres/mcpWorkshopDb.js',
 'server/database/postgres/mcpResourceRepository.js', 'server/database/postgres/index.js',
 'server/database/postgres/workshopSupport.js', 'server/database/postgres/poolBudget.js',
 'db/postgres/migrate.js', 'server/services/mcp/config.js', 'server/services/mcp/durableMailResources.js',
 'server/services/mcp/mailClient.js', 'server/services/mcp/deliveredMailObservation.js',
 'server/services/mcp/confusedDeputyObservation.js', 'tests/fixtures/mcpMailpitAdmission.js',
}

def validate_manifest(manifest):
 require(type(manifest) is dict and set(manifest)=={'version','scope','files','symlinks','directories'}
         and type(manifest['version']) is int and manifest['version']==1
         and manifest['scope']==SCOPE, 'manifest schema mismatch')
 require(REQUIRED <= set(manifest['files']), 'required source closure missing')
 for relative in manifest['files']:
  if relative.startswith('db/postgres/') and 'migrations/' in relative:
   require(relative in MIGRATIONS, 'unreviewed migration')
 return manifest


def validate_mailpit_layout(row):
 try:
  config=row['HostConfig']
  require(config['ReadonlyRootfs'] is True and config['Tmpfs']=={'/tmp':'rw,noexec,nosuid,size=16777216'}
          and row['Mounts']==[], 'Mailpit storage mismatch')
  ports=row['NetworkSettings']['Ports']
  require(set(ports) in ({'1025/tcp','8025/tcp'},{'1025/tcp','1110/tcp','8025/tcp'})
          and ports.get('1110/tcp') is None, 'Mailpit ports mismatch')
  result=[]
  for key in ['1025/tcp','8025/tcp']:
   bindings=ports[key];require(len(bindings)==1, 'Mailpit binding count')
   binding=bindings[0];port=int(binding['HostPort'])
   require(binding['HostIp']=='127.0.0.1' and 1<=port<=65535 and port not in {5432,1025,8025}, 'Mailpit endpoint mismatch')
   result.append(port)
  require(result[0]!=result[1], 'Mailpit ports must differ')
  return tuple(result)
 except (KeyError,TypeError,ValueError):raise RuntimeError('Malformed Mailpit layout') from None


def consume_control(path, expected):
 path=Path(path)
 require(path.is_absolute() and not path.is_symlink() and path.resolve()==path and path.is_file()
         and path.stat().st_uid==os.getuid() and not path.stat().st_mode & 0o077, 'private owned control required')
 lock=path.with_name(path.name+'.consume-lock')
 lock.mkdir(mode=0o700)
 try:
  value=json.loads(path.read_text())
  require(type(value) is dict and value.get('scope')==SCOPE and value.get('status')=='granted'
          and type(value.get('allowedLaunches')) is int and value['allowedLaunches']==1
          and all(value.get(key)==wanted for key,wanted in expected.items()), 'control binding mismatch')
  value.update(status='consumed',launcherPid=os.getpid())
  pending=path.with_name(path.name+'.pending')
  with pending.open('x') as output:
   os.chmod(pending,0o600);json.dump(value,output,sort_keys=True);output.flush();os.fsync(output.fileno())
  os.replace(pending,path)
  return value
 finally:lock.rmdir()

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

def validate_docker_cli(path, expected_hash):
 path=Path(path)
 require(path.is_absolute() and path.resolve()==path and not path.is_symlink()
         and path.is_file() and os.access(path,os.X_OK)
         and isinstance(expected_hash,str) and SHA.fullmatch(expected_hash)
         and digest(path)==expected_hash, 'pinned Docker CLI identity mismatch')
 return str(path)
