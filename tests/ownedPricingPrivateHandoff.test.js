'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const api=require('./postgres/ownedPricingPrivateHandoff');
const binding={runId:'a'.repeat(32),ownerId:'10000000-0000-4000-8000-000000000001',packageSha256:'b'.repeat(64),imageId:'sha256:'+'c'.repeat(64),sharedDaemonId:'shared-daemon'};
test('Pricing publication is fixed guest source with no host dispatch and strict identities',()=>{
 const source=api.program(binding);
 const result=spawnSync('/opt/homebrew/bin/python3',['-B','-c','import sys;compile(sys.stdin.read(),"<pricing-handoff>","exec")'],{input:source,encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
 for(const field of Object.keys(binding))assert.throws(()=>api.program({...binding,[field]:'../arbitrary'}));
 assert(source.includes('os.O_EXCL|os.O_NOFOLLOW'));assert(source.includes('1200000'));
 assert(source.includes("image['Config']['Entrypoint']"));assert(source.includes("terminal['binding']['target']=='v33-pricing'"));
});
test('executable publisher requires current physical identities and publishes token before handoff',()=>{
 const script=String.raw`
import ast,sys,json,io,types,stat
from unittest.mock import patch
config=json.loads(sys.stdin.readline());source=sys.stdin.read();tree=ast.parse(source)
cut=next(i for i,node in enumerate(tree.body) if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call) and isinstance(node.value.func,ast.Name) and node.value.func.id=='need')
prefix=compile(ast.Module(body=tree.body[:cut],type_ignores=[]),'<publisher>','exec')
body=compile(ast.Module(body=tree.body[cut:],type_ignores=[]),'<publisher>','exec')
for fault in (None,'owner','lease','holder','shared','image','terminal','token','token-write','handoff-write','cross-profile','reserve','expired'):
 ns={};exec(prefix,ns);B=ns['B'];writes=[]
 records={'owner':B['runId'],'pricing-lease.json':dict(version=1,target=config['target'],runId=B['runId'],clock='linux-monotonic-ms',startedAtMs=0,expiresAtMs=config['total']),'pricing-holder.seconds':str(config['total']/1000-.001),'namespace.inode':'net:[22]','terminal.json':dict(failure=None,cleanupErrors=[],result=dict(absenceVerified=True,failure=None),binding=dict(target='v33-pricing',runId=B['runId']))}
 if fault=='owner':records['owner']='f'*32
 if fault=='lease':records['pricing-lease.json']['expiresAtMs']+=1
 if fault=='cross-profile':records['pricing-lease.json']['target']='original-v33-pricing-total-lease-v1' if config['v34'] else 'original-v34-pricing-total-lease-v1'
 if fault=='holder':records['pricing-holder.seconds']='900'
 if fault=='terminal':records['terminal.json']['result']['absenceVerified']=False
 def read(directory,name,json_value=False):return records[name]
 def process(name,exe,namespace):return dict(pid=20 if name=='daemon' else 21,startTicks='123',exe=exe)
 def docker(socket,*args):
  if args[0]=='info':
   if socket=='/run/docker.sock':return B['sharedDaemonId']
   return json.dumps(dict(ID=B['sharedDaemonId'] if fault=='shared' else 'private',DockerRootDir=str(ns['mount']/'data')))
  return json.dumps([dict(Id=B['imageId'],Architecture='arm64',Os='linux',Config=dict(User='0' if fault=='image' else '10001:10001',Entrypoint=['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'],Labels={'owasp-ai-goat.pricing.package':B['packageSha256'],'owasp-ai-goat.build-run':B['runId']}))])
 def write(name,value):
  if fault=='token-write' and name=='pricing-token.json' or fault=='handoff-write' and name=='pricing-handoff.json':raise OSError('injected write')
  writes.append((name,value))
 ns.update(read=read,process=process,docker=docker,write=write)
 inp=types.SimpleNamespace(buffer=io.BytesIO(json.dumps({'token':'!' if fault=='token' else 't'*43}).encode()))
 output=io.StringIO()
 now=(config['total']-config['reserve'])/1000 if fault=='reserve' else config['total']/1000 if fault=='expired' else 1
 with patch('os.geteuid',return_value=0),patch('pathlib.Path.lstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)),patch('pathlib.Path.read_bytes',return_value=b'/usr/bin/sleep\x00'+str(config['total']/1000-.001).encode()+b'\x00'),patch('os.stat',return_value=types.SimpleNamespace(st_ino=11)),patch('time.monotonic',return_value=now),patch('sys.stdin',inp),patch('sys.stdout',output):
  error=None
  try:exec(body,ns)
  except BaseException as e:error=e
 if fault is None:
  assert error is None,error
  assert [n for n,v in writes]==['pricing-token.json','pricing-handoff.json']
  assert writes[1][1]['ownerId']==B['ownerId'] and writes[1][1]['namespaceInode']==22
  assert json.loads(output.getvalue())['published'] is True
 else:
  assert error is not None,fault
  assert [n for n,v in writes]==(['pricing-token.json'] if fault=='handoff-write' else []),(fault,writes)
  assert not output.getvalue()
 assert 't'*43 not in output.getvalue()
print('13 executable publisher cases passed')
`;
 for(const profile of ['v33','v34-browser']){
  const p=require('./postgres/ownedPricingRuntimeLease').profile(profile);
  const config={target:p.target,total:p.totalMs,reserve:p.budget.cohort+p.budget.retirement,v34:profile==='v34-browser'};
  const r=spawnSync('/opt/homebrew/bin/python3',['-B','-c',script],{input:JSON.stringify(config)+'\n'+api.program(binding,profile),encoding:'utf8'});
  assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/13 executable/);
 }
 assert.throws(()=>api.program(binding,'arbitrary'),/PROFILE/);
});
test('actual guest writer rejects fsync/close failures without a success result',()=>{
 const script=String.raw`
import ast,sys,os
from unittest.mock import patch
source=sys.stdin.read();tree=ast.parse(source)
cut=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='need')
ns={};exec(compile(ast.Module(body=tree.body[:cut],type_ignores=[]),'<writer>','exec'),ns)
for fault in (None,'write','fsync','close'):
 calls=[]
 def opened(path,flags,*args):
  calls.append(('open',str(path),flags));return 123
 def wrote(fd,raw):
  calls.append(('write',len(raw)))
  if fault=='write':return 0
  return min(3,len(raw))
 def sync(fd):
  calls.append(('fsync',fd))
  if fault=='fsync':raise OSError('sync')
 def close(fd):
  calls.append(('close',fd))
  if fault=='close':raise OSError('close')
 with patch('os.open',side_effect=opened),patch('os.write',side_effect=wrote),patch('os.fsync',side_effect=sync),patch('os.close',side_effect=close):
  error=None
  try:ns['write']('pricing-token.json',{'token':'t'*43})
  except BaseException as e:error=e
 assert bool(error)==bool(fault)
 assert calls[0][2]&os.O_EXCL and calls[0][2]&os.O_NOFOLLOW
 assert any(c[0]=='close' for c in calls)
 if not fault:assert len([c for c in calls if c[0]=='fsync'])==2
print('writer cases passed')
`;
 const r=spawnSync('/opt/homebrew/bin/python3',['-B','-c',script],{input:api.program(binding),encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/writer cases/);
});
test('actual publisher reader enforces terminal0400 and owner0600 separately',()=>{
 const script=String.raw`
import ast,sys,stat,types
from unittest.mock import patch
tree=ast.parse(sys.stdin.read());cut=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='need')
ns={};exec(compile(ast.Module(body=tree.body[:cut],type_ignores=[]),'<reader>','exec'),ns)
for name,directory,expected in [('terminal.json',ns['mount']/'pricing-closure',0o400),('owner',ns['root'],0o600),('terminal.json',ns['root'],0o600)]:
 for mode in (0o400,0o600):
  with patch('os.open',return_value=123),patch('os.fstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFREG|mode,st_uid=0,st_nlink=1,st_size=2)),patch('os.read',return_value=b'{}'),patch('os.close'):
   error=None
   try:ns['read'](directory,name,True)
   except RuntimeError as e:error=e
   assert (error is None)==(mode==expected),(name,mode)
print('exact per-file mode controls passed')
`;
 const r=spawnSync('/opt/homebrew/bin/python3',['-B','-c',script],{input:api.program(binding),encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);
});
