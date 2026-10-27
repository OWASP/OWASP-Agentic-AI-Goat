'use strict';
// Fixed import roots include deferred V03 imports, not merely the modules that
// happened to be loaded by a caller. Importing these modules performs no native
// work; all factories and the parent CLI remain separately gated.
const fs=require('node:fs'),path=require('node:path');
const ROOT=path.resolve(__dirname,'../..');
const ROOTS=Object.freeze([
 'ownedV03PrivateExecutors','ownedV03CombinedLease','ownedV03GuestClock',
 'ownedV03DiagnosticDerivation','ownedV03ListingsDerivation','ownedV03ListingsProfile',
 'ownedV03ListingsLease','ownedV03ListingsHealth','ownedV03ListingsDriver',
 'ownedV03ListingsProducer','ownedV03ListingsBridgeHost','ownedV03MainAdmission',
 'ownedV03MainProcess','ownedV03ParentEntry','ownedV03ParentProtocol',
 'ownedV03PostWork','ownedV03PostgresOwner','ownedV03SourceInventory','ownedV03SourcePlan',
 'ownedSystemDiagnosticProducer','ownedSystemDiagnosticRuntime',
 'ownedSystemDiagnosticBuildAdapter','ownedSystemDiagnosticBuildInputs',
 'ownedSystemConfigPhaseDriver','ownedSystemPrivateHttpConsumer','ownedSystemRuntimeTransport',
 'ownedMcpOriginalBuildAdapter','ownedMcpBoundedBuild',
 '../../scripts/install/secureshop-owned-mcp-registry-setup',
 '../../scripts/local-docker-authority','../../scripts/application-data-root'
]);
const FILES=Object.freeze([
 'tests/postgres/v03_browser_start_barrier.js',
 'tests/postgres/v03_private_executors.py','tests/postgres/v03_private_process.py',
 'tests/postgres/v03_listings_bridge.py','tests/postgres/v03_listings_bridge_host.py',
 'tests/postgres/darwin_process_inventory.py','tests/postgres/owned_mcp_mux_relay.py',
 'tests/postgres/owned_system_private_http_channel.py','tests/postgres/listings_native_resources.py',
 'tests/postgres/sql_nosql_docker_ownership.py','tests/postgres/run-secureshop-agent-host-transport-main.py',
 'tests/postgres/test_v03_private_executors.py','tests/postgres/test_v03_private_process.py',
 'tests/postgres/test_v03_listings_bridge.py','tests/postgres/test_v03_listings_bridge_host.py',
 'tests/ownedV03SourceInventory.test.js','tests/ownedV03SourcePlan.test.js',
 'tests/postgres/test_v03_private_source_union.py','tests/ownedV03ParentEntry.test.js',
 'tests/ownedV03MainAdmission.test.js','tests/ownedV03PostgresOwner.test.js',
 'tests/ownedV03ParentProtocol.test.js','tests/ownedV03PostWork.test.js',
 'tests/ownedV03ListingsDriver.test.js','tests/ownedV03ListingsProducer.test.js',
 'tasks/runtime/node/node_modules/node/bin/node','tasks/runtime/container/bin/docker'
]);
function capture(){
 if(arguments.length)throw Error('V03_SOURCE_INVENTORY_OPTIONS');
 const modules=[],visited=new Set(),files=new Set(FILES);
 for(const name of ROOTS){const file=require.resolve(name.startsWith('../')?name:'./'+name);require(file);modules.push(require.cache[file]);}
 while(modules.length){
  const module=modules.pop();if(!module||visited.has(module))continue;visited.add(module);
  if(!module.filename.startsWith(ROOT+'/'))throw Error('V03_EXTERNAL_MODULE_SOURCE');
  files.add(module.filename.slice(ROOT.length+1));modules.push(...module.children);
 }
 for(const relative of files){
  const file=path.join(ROOT,relative),stat=fs.lstatSync(file);
  const nodeBinary=relative==='tasks/runtime/node/node_modules/node/bin/node';
  if(fs.realpathSync(file)!==file||!stat.isFile()||!(nodeBinary?[1,2].includes(stat.nlink):stat.nlink===1))throw Object.assign(Error('V03_SOURCE_INVENTORY_FILE'),{relative});
 }
 return Object.freeze([...files].sort());
}
module.exports={capture};
