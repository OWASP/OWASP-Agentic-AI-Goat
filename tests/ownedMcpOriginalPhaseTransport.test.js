'use strict';
// Local harmless decoder/parser controls only. No VM, daemon or build dispatch.
const test=require('node:test'),assert=require('node:assert/strict');
const crypto=require('node:crypto'),zlib=require('node:zlib'),path=require('node:path');
const {spawnSync,spawn}=require('node:child_process'),{Readable}=require('node:stream');
const adapter=require('./postgres/ownedMcpOriginalBuildAdapter');
const producer=require('./postgres/ownedMcpOriginalServiceProducer');
const derivation=require('./postgres/ownedMcpOriginalServiceDerivation');
const {phaseTransport,PHASE_TRANSPORT,PHASE_DECODER,limaArgvEnvelope}=adapter._internals;
const root=path.resolve(__dirname,'..'),runId='e'.repeat(32),guest='/var/tmp/owasp-ai-goat-v23-build-'+runId;
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
const args=['owned-original-build',guest,runId];
const options={timeout:10000,maxBuffer:2*1024**2};
function decode(bytes,{packed=zlib.gzipSync(bytes).toString('base64'),digest=hash(bytes),argv=args}={}){
 return spawnSync('/usr/bin/python3',['-I','-S','-B','-c',PHASE_DECODER,packed,digest,...argv],options);
}
function rejects(bytes,settings){
 const result=decode(bytes,settings);assert.notEqual(result.status,0);assert.equal(result.stdout.length,0);
 assert.equal(result.error,undefined);return result;
}
test('actual decoder preserves original shell argv, binary stdin, UTF8 source and exit status',()=>{
 const script='printf \'%s\\0\' "$0" "$1" "$2" "${3:-}" "quote\'and unicode λ"; cat; exit 7';
 const original=Buffer.from([0,1,255,10,39,34,36,96]);
 for(const extra of [[],['sha256:'+'a'.repeat(64)]]){
  const wrapped=phaseTransport(script);
  const result=spawnSync('/bin/sh',['-c',wrapped.command,...args,...extra],{...options,input:original});
  assert.equal(result.status,7,result.stderr.toString());
  assert.deepEqual(result.stdout,Buffer.concat([Buffer.from([...args,extra[0]||'',"quote'and unicode λ"].join('\0')+'\0'),original]));
  assert.equal(wrapped.scriptSha256,hash(script));
 }
});
test('decoder rejects tampered, malformed, trailing, concatenated and truncated payloads before effects',()=>{
 const bytes=Buffer.from('printf must-not-execute');
 rejects(bytes,{digest:'0'.repeat(64)});
 rejects(bytes,{digest:'not-a-digest'});
 rejects(bytes,{packed:'***'});
 rejects(bytes,{packed:Buffer.concat([zlib.gzipSync(bytes),Buffer.from('trailing')]).toString('base64')});
 rejects(bytes,{packed:Buffer.concat([zlib.gzipSync(bytes),zlib.gzipSync(Buffer.from('extra'))]).toString('base64')});
 rejects(bytes,{packed:zlib.gzipSync(bytes).subarray(0,-3).toString('base64')});
 rejects(bytes,{packed:'A'.repeat(PHASE_TRANSPORT.encodedBytes+1)});
});
test('decoder enforces decompression, NUL, UTF8 and empty-source limits',()=>{
 rejects(Buffer.alloc(PHASE_TRANSPORT.decodedBytes+1,35));
 rejects(Buffer.alloc(2*1024**2,35));
 rejects(Buffer.from('printf must-not-execute\0'));
 rejects(Buffer.from([255,254]));
 rejects(Buffer.alloc(0));
 const boundary=Buffer.from('#'+'x'.repeat(PHASE_TRANSPORT.decodedBytes-1));
 const accepted=decode(boundary);assert.equal(accepted.status,0,accepted.stderr.toString());
});
test('decoder rejects changed positional contract without consuming stdin or dispatching shell',()=>{
 const bytes=Buffer.from('printf must-not-execute');
 for(const argv of [[],args.slice(0,2),['foreign',guest,runId],['owned-original-build','/foreign',runId],
  ['owned-original-build',guest,'z'.repeat(32)],[...args,'foreign-base'],[...args,'sha256:'+'a'.repeat(64),'extra']])rejects(bytes,{argv});
});
test('host transport rejects invalid or unbounded scripts before launch and preserves finite limits',async()=>{
 for(const script of [null,undefined,Buffer.from('fixed'),'', 'x\0', '\ud800', 'x'.repeat(PHASE_TRANSPORT.decodedBytes+1)])
  assert.throws(()=>phaseTransport(script),{code:'ORIGINAL_BUILD_TRANSPORT_SCRIPT'});
 const incompressible=crypto.randomBytes(60000).toString('base64');
 assert.throws(()=>phaseTransport(incompressible),{code:'ORIGINAL_BUILD_TRANSPORT_ENCODED_LIMIT'});
 let launches=0;
 const execute=adapter._internals.createPhaseExecutor({launch(){launches++;throw Error('unexpected launch');}});
 await assert.rejects(execute({commands:{inventory:'x'.repeat(131072)},spec:{root}},'inventory'),{code:'ORIGINAL_BUILD_TRANSPORT_SCRIPT'});
 assert.equal(launches,0);
 assert.deepEqual(PHASE_TRANSPORT,{version:1,kind:'gzip-sha256-shell-exec-v1',decodedBytes:131071,encodedBytes:32768,
  limaScriptBytes:65535,decoderSha256:hash(PHASE_DECODER)});
});
test('all real service commands remain byte-exact under transport and parse with actual local POSIX dash',async()=>{
 const plan=await adapter.originalBuildPlan(root,runId,{consumerMode:'original-service'});
 let oldEscapedOversize=0;
 for(const [name,script]of Object.entries(plan.commands)){
  const wrapped=phaseTransport(script);
  assert.ok(wrapped.commandEnvelopeBytes<65536,name);assert.ok(wrapped.encodedBytes<=32768,name);
  const guestArgv=['sudo','-n','timeout','--signal=TERM','--kill-after=10',
   ['metadataFetch','startArtifacts','build'].includes(name)?'310':'150','/bin/sh','-c',wrapped.command,...args,
   ...(name==='metadataFetch'?[plan.binding.base]:[])];
  assert.ok(limaArgvEnvelope(guestArgv).scriptBytes<65536,name);
  assert.equal(wrapped.scriptSha256,hash(script),name);
  const tokens=spawnSync('/usr/bin/python3',['-I','-S','-B','-c',
   'import shlex,sys,json; print(json.dumps(shlex.split(sys.stdin.read())))'],{...options,input:wrapped.command,encoding:'utf8'});
  assert.equal(tokens.status,0,tokens.stderr);const parsed=JSON.parse(tokens.stdout);
  assert.equal(parsed[5],PHASE_DECODER);
  assert.deepEqual(zlib.gunzipSync(Buffer.from(parsed[6],'base64')),Buffer.from(script),name);
  assert.equal(parsed[7],hash(script));assert.deepEqual(parsed.slice(8),['$0','$@']);
  const result=spawnSync('/bin/dash',['-n'],{...options,input:script,encoding:'utf8'});
  assert.equal(result.status,0,name+':'+result.stderr);
  if(Buffer.byteLength(quote(quote(script)))>=131072)oldEscapedOversize++;
 }
 assert.ok(oldEscapedOversize>=2,'regression must cover actual quote-heavy commands');
 assert.deepEqual(plan.scriptTransport,PHASE_TRANSPORT);
 assert.equal(plan.limits.consumerWorkMs,1320000);assert.equal(plan.limits.consumerRetirementMs,1080000);
 assert.equal(plan.limits.serviceLeaseMs,7400000);assert.equal(plan.limits.disk,6*1024**3);
});
test('actual fixed executor carries binary stdin through local decoder without changing timeout argv or phase environment',async()=>{
 for(const name of ['inventory','metadataFetch']){
  const input=Buffer.from([0,128,255,10]);let invocation;
  const script='printf \'%s\\n\' "$0" "$1" "$2" "${3:-}"; cat';
  const execute=adapter._internals.createPhaseExecutor({launch(file,argv,options){
   invocation={file,argv,options};
   // Execute only the harmless local shell+decoder tail; never launch Lima.
   const start=argv.indexOf('/bin/sh');return spawn('/bin/sh',argv.slice(start+1),options);
  }});
  const plan={commands:{[name]:script},spec:{root,guest,runId,lima:'/unreachable/limactl',limaHome:path.join(root,'tasks/l')},binding:{base:'sha256:'+'a'.repeat(64)}};
  const chunks=[];await execute(plan,name,{input:Readable.from([input]),sink:async b=>chunks.push(b)});
  assert.deepEqual(Buffer.concat(chunks),Buffer.concat([Buffer.from([...args,name==='metadataFetch'?plan.binding.base:''].join('\n')+'\n'),input]));
  assert.deepEqual(invocation.argv.slice(0,12),['shell','--workdir','/','colima-goat-q','sudo','-n','timeout','--signal=TERM','--kill-after=10',name==='metadataFetch'?'310':'150','/bin/sh','-c']);
  assert.deepEqual(invocation.argv.slice(13),[...args,...(name==='metadataFetch'?[plan.binding.base]:[])]);
  assert.deepEqual(Object.keys(invocation.options.env).sort(),['HOME','LIMA_HOME','PATH','TMPDIR']);
 }
});
test('full Lima argv envelope uses exact pinned shellescape style and rejects oversized positional arguments before spawn',async()=>{
 // Independent shellescape1.6 known vector, including the empty/safe cases.
 const vector=['safe/@_09',"'\"'",'','λ'];
 const escape=x=>"'"+x.split("'").join("'\"'\"'")+"'";
 // The explicit unsafe quoting function matches the primary-source expansion;
 // quote safe tokens only where the joined command itself requires it.
 const joined=[vector[0],escape(vector[1]),"''","'λ'"].join(' ');
 assert.deepEqual(limaArgvEnvelope(vector),{scriptBytes:Buffer.byteLength('cd / || exit 1 ; exec /bin/bash -l -c '+escape(joined))+1,
  joinedBytes:Buffer.byteLength(joined)+1});
 for(const argv of [[],['bad\0arg'],[undefined],['x'.repeat(65535)]])assert.throws(()=>limaArgvEnvelope(argv));
 let launches=0;const execute=adapter._internals.createPhaseExecutor({launch(){launches++;throw Error('unexpected launch');}});
 await assert.rejects(execute({commands:{inventory:':'},spec:{root,guest:'x'.repeat(65535),runId}},'inventory'),
  {code:'ORIGINAL_BUILD_TRANSPORT_ARG_LIMIT'});
 assert.equal(launches,0);
});
test('POSIX spaced substitution parses while exact former arithmetic ambiguity fails dash before effect',()=>{
 const script=producer.boundedPhase('','printf must-not-execute','build');
 assert.ok(script.includes('remaining=$( ('));assert.ok(!script.includes('remaining=$(('));
 const good=spawnSync('/bin/dash',['-n'],{...options,input:script,encoding:'utf8'});
 assert.equal(good.status,0,good.stderr);
 const bad=spawnSync('/bin/dash',['-n'],{...options,input:script.replace('remaining=$( (','remaining=$(('),encoding:'utf8'});
 assert.notEqual(bad.status,0);assert.equal(bad.stdout,'');
});
test('emitted remaining-time command fails closed when the real lease check denies',()=>{
 const script=producer.boundedPhase('','printf must-not-execute','build');
 const lease=derivation.leaseCommand('check-build');
 // Replace only the first exact, unquoted lease read with a denying control.
 assert.ok(script.includes(lease));const controlled=script.replace(lease,'false');
 const result=spawnSync('/bin/dash',['-c',controlled,...args],{...options,encoding:'utf8'});
 assert.notEqual(result.status,0);assert.equal(result.stdout,'');
});
