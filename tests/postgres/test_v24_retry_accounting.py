import json,re,subprocess,unittest,ast,threading
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
NAMES=['ownedMcpDependencyClosure.js','ownedSystemBoundedDerivation.js','ownedSystemConfigBuildAdapter.js']
def source(name):return (ROOT/'tests/postgres'/name).read_text()
def node(program):
    result=subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',program],cwd=ROOT,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,(result.stdout,result.stderr)
class Controls(unittest.TestCase):
    def test_generated_worker_retains_admission_ordinal_on_success_and_failure(self):
        s=source('ownedSystemBoundedDerivation.js')
        program="""const Module=require('node:module'),path=require('node:path');
        const m=new Module(process.cwd()+'/tests/postgres/ownedSystemBoundedDerivation.js');m.filename=m.id;m.paths=Module._nodeModulePaths(path.dirname(m.id));m._compile(SOURCE,m.id);
        const raw=require('./tests/postgres/ownedMcpPrivateEgress')._internals.program;
        process.stdout.write(m.exports._internals.pairChild(raw+'\\n# activeWorkers=threading.active_count()-1,\\n'));
        """.replace('SOURCE',json.dumps(s))
        result=subprocess.run([str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'-e',program],cwd=ROOT,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        tree=ast.parse(result.stdout);serve=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='serve')
        worker=next(n for n in serve.body if isinstance(n,ast.FunctionDef) and n.name=='worker')
        self.assertIn('target=worker,args=(client,budget.connections),',result.stdout)
        class Socket:
            def close(self):pass
        records=[];client=Socket();remote=Socket()
        class Gate:
            def release(self):pass
        env=dict(mode='connector',uid=1,stop=None,deadline=1,unresolved=[],budget=None,records=records,lock=threading.Lock(),active=set(),gate=Gate(),
          check_cancel=lambda *a:None,peer_uid=lambda *a:None,header=lambda *a:b'bounded',authority=lambda *a:'deb.debian.org',
          connect_public=lambda *a:remote,track=lambda *a:None,established=lambda *a:None,pump=lambda *a:None)
        exec(compile(ast.Module(body=[worker],type_ignores=[]),'<actual paired worker>','exec'),env)
        env['worker'](client,7)
        def denied(*a):raise OSError('controlled')
        env['pump']=denied;env['worker'](client,8)
        self.assertEqual(records,[dict(host='deb.debian.org',status='closed',connection=7),dict(host='deb.debian.org',status='denied',connection=8)])
    def test_all_transformed_modules_compile(self):
        for name in NAMES:node('new (require("node:vm").Script)('+json.dumps(source(name))+');')
    def test_actual_acquisition_serializes_only_existing_branded_retry(self):
        s=source('ownedMcpDependencyClosure.js')
        # Replace only socket boundary; the actual acquisition, retry WeakSet,
        # hashing, file publication and serialization execute unchanged.
        a=s.index('async function requestViaPrivateRelay(');b=s.index('async function acquireArtifacts(',a)
        s=s[:a]+'''async function requestViaPrivateRelay(url,options){
          global.calls++; if(global.calls<=global.failures){const e=Object.assign(new Error('not retained'),{code:'ECONNRESET'});
            if(global.brand)retiredPreResponseResets.add(e);throw e;}
          return {status:200,headers:{},body:Readable.from([global.payload]),closed:Promise.resolve(),destroy(){}};
        }
        '''+s[b:]
        node('''const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),Module=require('node:module');
        const m=new Module(process.cwd()+'/tests/postgres/ownedMcpDependencyClosure.js');m.filename=m.id;m.paths=Module._nodeModulePaths(path.dirname(m.id));m._compile('''+json.dumps(s)+''',m.id);
        (async()=>{const root=await fs.mkdtemp(path.join(process.cwd(),'tasks/tmp/v24-attempt-control-'));
        try{global.payload=Buffer.from('actual controlled artifact');
        const artifact={kind:'deb',algorithm:'sha256',digest:require('node:crypto').createHash('sha256').update(payload).digest('hex'),bytes:payload.length,urls:['http://deb.debian.org/debian/pool/main/f/fixture/fixture_1_arm64.deb']};
        for(const [i,brand,failures,expected] of [[0,true,1,2],[1,false,1,1],[2,true,2,2],[3,true,0,1]]){
          Object.assign(global,{brand,failures,calls:0});let receipt,error;
          try{receipt=await m.exports.acquireArtifacts({artifacts:[artifact],directory:path.join(root,String(i)),attemptProof:true});}catch(e){error=e;}
          assert.equal(calls,expected);
          if(i===0||i===3){assert.equal(receipt.artifacts[0].digest,artifact.digest);assert.equal(receipt.bytes.total,payload.length);
            assert.equal(receipt.attemptProof.attempts.length,expected);assert.equal(receipt.attemptProof.attempts.at(-1).outcome,'verified');
            if(i===0)assert.equal(receipt.attemptProof.attempts[0].outcome,'retired-pre-response-reset');}
          else{assert.equal(error.code,'ECONNRESET');assert.equal(error.closureAttempts.attempts.length,expected);assert.equal(error.closureAttempts.attempts.at(-1).outcome,'failed');}
          assert(!JSON.stringify(receipt||error.closureAttempts).includes('not retained'));
        }}finally{await fs.rm(root,{recursive:true,force:true});}})().catch(e=>{console.error(e);process.exitCode=1});''')
    def test_actual_host_proof_rejects_wrong_identity_extra_attempts_and_missing_success(self):
        s=source('ownedSystemConfigBuildAdapter.js');a=s.index('function pairAttemptProof(');b=s.index('function pairObservedAttempts(',a)
        node("const assert=require('node:assert/strict'),equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b),fail=code=>Object.assign(new Error(code),{code});"+s[a:b]+'''
        const artifacts=[{kind:'deb',digest:'a'.repeat(64)}],first={index:0,kind:'deb',digest:'a'.repeat(64),ordinal:1,outcome:'retired-pre-response-reset'},last={...first,ordinal:2,outcome:'verified'};
        const proof={version:1,attempts:[first,last]};assert.deepEqual(pairAttemptProof(artifacts,proof),{count:2,retries:1,attempts:proof.attempts});
        for(const change of [p=>p.attempts.push({...last,ordinal:3}),p=>p.attempts[0].outcome='failed',p=>p.attempts[1].digest='b'.repeat(64),p=>p.attempts.pop(),p=>p.attempts[1].index=1,p=>p.attempts[1].outcome='retired-pre-response-reset']){
          const p=structuredClone(proof);change(p);assert.throws(()=>pairAttemptProof(artifacts,p),{code:'SYSTEM_PAIR_ATTEMPTS'});
        }''')
    def test_actual_generated_controller_and_child_preserve_allocation_and_phase_bounds(self):
        s=source('ownedSystemBoundedDerivation.js')
        common=re.search(r'const PAIR_COMMON=String.raw`(.*?)`;',s,re.S).group(1)
        controller=re.search(r'const PAIR_CONTROLLER=PAIR_COMMON\+String.raw`(.*?)`;',s,re.S).group(1)
        child=re.search(r'const PAIR_CHILD=PAIR_COMMON\+String.raw`(.*?)`;',s,re.S).group(1)
        env={};exec('import json,os,stat,re,time\n'+common+controller,env)
        def require(v):
            if not v:raise ValueError('denied')
        env.update(require=require,RUN='r',ROOT='/inert',RELAY='/inert',authority=lambda:None)
        row=dict(version=1,policy='v24-pair-phase-credits-v2',runId='r',sequence=0,phase='system-overhead',allocation=32,starts=dict(adapter=0,connector=0),quota=32,artifactCount=0)
        counts=dict(adapter=14,connector=14);rejected=dict(adapter=0,connector=0)
        env.update(pair_observe=lambda:(row.copy(),counts.copy(),{}),pair_worker_rejections=lambda _:rejected.copy(),pair_candidate=lambda _:35,
          pair_publish=lambda value:row.update(value),save=lambda *a:None,read=lambda _: '{"after":{}}',print=lambda *a,**k:None)
        # Only filesystem ACK durability boundary mocked; execute real arithmetic/state checks.
        class OS:
            O_RDONLY=0;O_DIRECTORY=0
            open=staticmethod(lambda *a:3);fsync=staticmethod(lambda *a:None);close=staticmethod(lambda *a:None)
        env['os']=OS
        env['pair_advance'](1);self.assertEqual((row['allocation'],row['quota']),(67,53))
        env['pair_attempt_count']=lambda _:36;counts.update(adapter=50,connector=50)
        env['pair_advance'](2);self.assertEqual((row['allocation'],row['quota']),(99,32))
        counts.update(adapter=64,connector=64);env['pair_advance'](3);self.assertEqual((row['allocation'],row['quota']),(134,70))
        counts.update(adapter=100,connector=100);env['pair_advance'](4);self.assertEqual((row['allocation'],row['quota']),(134,0))
        # Child rejects attempts outside its fixed phase quota even if a later total exists.
        ce={};exec(common+child,ce);ce.update(Denied=ValueError,TRANSPORT_RUN='r',TRANSPORT_MODE='adapter')
        class Budget:pass
        b=Budget();b.pair_credit=dict(row,sequence=3,phase='policy-artifacts',allocation=134,starts={'adapter':64,'connector':64},quota=70,artifactCount=35);b.connections=135
        ce['pair_read']=lambda *a:row
        with self.assertRaises(ValueError):ce['pair_refresh_checked'](b)
        bad=dict(row,sequence=2,phase='policy-overhead',quota=33,artifactCount=0)
        with self.assertRaises(ValueError):env['pair_shape'](bad,'r')
    def test_actual_controller_proof_rejects_missing_duplicate_and_third_attempt(self):
        s=source('ownedSystemBoundedDerivation.js');body=re.search(r'def pair_attempt_count\(slot\):(.*?)\ndef pair_advance',s,re.S).group(1)
        def require(v):
            if not v:raise ValueError('denied')
        rows=[dict(index=0,kind='deb',digest='a'*64,ordinal=1,outcome='retired-pre-response-reset'),dict(index=0,kind='deb',digest='a'*64,ordinal=2,outcome='verified')]
        value={'acquired':{'artifacts':[dict(kind='deb',digest='a'*64)],'attemptProof':dict(version=1,attempts=rows)}}
        env={'ROOT':'/inert','require':require,'pair_read':lambda path,*a:value if 'closure' in path else {'candidate':{'selected':[{'sha256':'a'*64}]}}}
        exec('def pair_attempt_count(slot):'+body,env);self.assertEqual(env['pair_attempt_count']('system'),2)
        for altered in [rows+[dict(rows[-1],ordinal=3)],rows[:1],[dict(rows[0],digest='b'*64),rows[1]],[dict(rows[0],outcome='failed'),rows[1]]]:
            value['acquired']['attemptProof']['attempts']=altered
            with self.assertRaises(ValueError):env['pair_attempt_count']('system')
    def test_actual_terminal_requires_retry_proof_for_denied_records(self):
        s=source('ownedSystemConfigBuildAdapter.js');a=s.index('function validatePairRelayTerminal(');b=s.index('function validatePairAcquisitionBudget(',a)
        node("const assert=require('node:assert/strict'),equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b),fail=code=>Object.assign(new Error(code),{code});"+'''
        const PAIR_CREDIT_PHASES=['systemReserve','policyOverhead','policyReserve','acquisitionSeal'];
        const pairRelayQualificationFailures=new WeakSet(),caps={'registry-1.docker.io':1,'auth.docker.io':1,'deb.debian.org':1,'production.cloudfront.docker.com':1};
        const systemBounded={PAIR_WIRE_POLICY:{totalBytes:4,registryBytes:1,authBytes:1,aptBytes:1,cloudfrontBytes:1}};
        const credit={policy:'v2',starts:{adapter:5,connector:5}},validatePairCredits=()=>credit;
        let retries=1;const pairObservedAttempts=(_p,_o,slot)=>({count:slot==='system'?2:1,retries:slot==='system'?retries:0,attempts:slot==='system'?[{outcome:retries?'retired-pre-response-reset':'verified'},{outcome:'verified'}]:[{outcome:'verified'}]});
        const admission={workerLimitRejected:0,connectionLimitRejected:0,saturated:false};
        const observations=PAIR_CREDIT_PHASES.map((name,i)=>({name,value:JSON.stringify({before:{rows:Object.fromEntries(['adapter','connector'].map(m=>[m,{pairBudget:{connections:[1,3,4,5][i]}}]))},after:{rows:{adapter:{admission},connector:{admission}}}})}));
        function packet(){const files={};for(const mode of ['adapter','connector']){
          const terminal={kind:'relay-terminal',connections:5,records:[{host:'auth.docker.io',status:'closed'},{host:'deb.debian.org',status:'denied'},{host:'deb.debian.org',status:'closed'},{host:'auth.docker.io',status:'closed'},{host:'deb.debian.org',status:'closed'}],unjoinedWorkers:0,unresolvedResolverCleanup:0,cleanupVerified:true,bytes:0,hostBytes:Object.fromEntries(Object.keys(caps).map(k=>[k,0]))};
          terminal.records.forEach((row,index)=>row.connection=index+1);
          const audit={kind:'transport-audit',trigger:'terminal',pairBudget:{policy:'v2',lifetime:320,connections:5,credit},runId:'r',mode,activeWorkers:0,admission,deniedAuthorities:{hosts:{},unclassified:0,overflow:0},counts:{peerDenied:0}};
          files['relay.'+mode+'.log']=JSON.stringify(terminal)+'\\n'+JSON.stringify(audit);}
          return {runId:'r',files};}
        '''+s[a:b]+'''
        validatePairRelayTerminal({runId:'r'},observations,JSON.stringify(packet()));
        retries=0;assert.throws(()=>validatePairRelayTerminal({runId:'r'},observations,JSON.stringify(packet())),{code:'SYSTEM_PAIR_RELAY_TERMINAL'});retries=1;
        for(const mutate of [r=>{r.records[1].status='closed';r.records[2].status='denied';},r=>r.records[2].status='denied',r=>r.records[1].host='auth.docker.io',r=>r.unjoinedWorkers=1,r=>r.bytes=5,r=>r.records[2].connection=2]){
          const p=packet(),rows=p.files['relay.adapter.log'].split('\\n').map(JSON.parse);mutate(rows[0]);p.files['relay.adapter.log']=rows.map(JSON.stringify).join('\\n');
          assert.throws(()=>validatePairRelayTerminal({runId:'r'},observations,JSON.stringify(p)),{code:'SYSTEM_PAIR_RELAY_TERMINAL'});
        }
        const outOfOrder=packet();for(const key of Object.keys(outOfOrder.files)){const rows=outOfOrder.files[key].split('\\n').map(JSON.parse);rows[0].records.reverse();outOfOrder.files[key]=rows.map(JSON.stringify).join('\\n');}
        validatePairRelayTerminal({runId:'r'},observations,JSON.stringify(outOfOrder));''')
if __name__=='__main__':unittest.main()

