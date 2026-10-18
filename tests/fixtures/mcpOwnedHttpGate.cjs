'use strict';
// Isolated prerequisite gate, never an application/credit authority.
const fs = require('node:fs/promises'), crypto = require('node:crypto'), assert = require('node:assert/strict'), path = require('node:path');
async function main() {
 const outerStatus=await fs.readFile('/proc/self/status','utf8');for(const key of ['CapEff','CapPrm','CapInh','CapAmb'])assert.match(outerStatus,new RegExp('^'+key+':\\s+0+$','m'));
 assert.equal(process.env.MCP_OWNED_HTTP_GATE,'yes'); assert.equal(process.getuid(),10001);
 assert.equal((await fs.readFile('/proc/self/attr/current','utf8')).trim(),'dvaia-mcp-sandbox (enforce)');
 const root=await fs.mkdtemp('/tmp/owned-http-gate-');let setup=false,hosts,nss,resolv;
 const {createMcpTargetStore}=require('/app/mcpTargets');
 const store=createMcpTargetStore({root,fixtureRoot:'/opt/lab-template',spawn(executable,args,options){
  if(executable==='/usr/bin/bwrap'&&setup){args=[...args];args.unshift('--uid','0','--gid','0','--cap-add','CAP_NET_ADMIN','--cap-add','CAP_SETPCAP');args.splice(args.indexOf('--chdir'),0,'--dir','/etc','--ro-bind',hosts,'/etc/hosts','--ro-bind',nss,'/etc/nsswitch.conf','--ro-bind',resolv,'/etc/resolv.conf');}
  return require('node:child_process').spawn(executable,args,options);
 }});
 const binding={targetId:crypto.randomUUID(),ownerId:1,platformSessionId:1,generation:1}; const allow=async()=>true;
 const records=[];let outer;let outerHits=0;
 try{
 await store.checkReadiness();const owned=await store.provisionTarget(binding,{authorize:allow});const tmp=path.join(root,'targets',binding.targetId,'rootfs','tmp');
 const manifest=JSON.parse(await fs.readFile('/usr/local/libexec/dvaia-owned-http-manifest.json','utf8'));
 hosts=path.join(tmp,'hosts');nss=path.join(tmp,'nsswitch');resolv=path.join(tmp,'resolv');
 await fs.writeFile(hosts,manifest.listeners.map(x=>`${x.address} ${x.hostname}`).join('\n')+'\n');await fs.writeFile(nss,'hosts: files\n');await fs.writeFile(resolv,'');
 outer=require('node:http').createServer((_req,res)=>{outerHits++;res.end('outer-listener');});await new Promise(resolve=>outer.listen(0,'127.0.0.1',resolve));
 setup=true;
 for(const [url,mode] of [['http://169.254.169.254/latest/meta-data/','vuln'],['http://admin.training:8080/config?raw=1','vuln'],['http://monitoring.training/health','vuln'],['http://benign.training/','fixed'],['http://benign.training/redirect-metadata','vuln'],['http://benign.training/redirect-metadata','fixed'],['http://benign.training/redirect-loop','vuln'],['http://10.200.1.1/','vuln'],['http://1.1.1.1/','vuln'],['http://unknown.training/','vuln'],['http://127.0.0.1:'+outer.address().port+'/','vuln'],['http://8.8.8.8:53/','vuln']]){
  await fs.writeFile(path.join(tmp,'input.json'),JSON.stringify({url,mode,canary:'a'.repeat(64)}));
  const result=await store.executeTarget(owned.capability,allow,'/usr/local/libexec/dvaia-owned-http-init --initialize < /tmp/input.json');
  records.push({url,mode,...result});assert.equal(result.code,0,result.stderr);const output=JSON.parse(result.stdout);assert.ok(Object.values(output.isolationAttestation).every(x=>x===true));assert.equal(output.originalUrlSha256,crypto.createHash('sha256').update(url).digest('hex'));
  if(url.includes('redirect-loop'))assert.equal(output.category,'redirect_limit');
  else if(url.includes('redirect-metadata')){assert.equal(output.hits.filter(x=>x.listener==='metadata').length,mode==='fixed'?0:1);assert.equal(output.status,mode==='fixed'?'failed':'completed');}
  else if(['10.200.1.1','1.1.1.1','unknown.training','127.0.0.1','8.8.8.8'].some(x=>url.includes(x))){assert.equal(output.status,'failed');assert.equal(output.hits.length,0);}
  else {assert.equal(output.status,'completed');assert.equal(output.hits.length,1);}
 }
 assert.equal(outerHits,0);return {productionQualified:false,records,outerListenerUnreachable:true};
 }finally{if(outer)await new Promise(resolve=>outer.close(resolve));await fs.rm(root,{recursive:true,force:true});}
}
if(require.main===module)main().then(x=>console.log(JSON.stringify(x))).catch(e=>{console.error(e.message);process.exitCode=1;});
module.exports={main};
