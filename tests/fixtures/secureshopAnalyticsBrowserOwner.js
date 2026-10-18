'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawn}=require('node:child_process'),{createHash}=require('node:crypto');
function bounded(promise,milliseconds,label){let timer;return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(label)),milliseconds);})]).finally(()=>clearTimeout(timer));}
async function retireChild(child,{timeoutMs=3000}={}){
 const ended=()=>child.exitCode!==null||child.signalCode!==null;
 const join=()=>ended()?Promise.resolve():new Promise(resolve=>child.once('exit',resolve));
 if(!ended()){child.kill('SIGTERM');try{await bounded(join(),timeoutMs,'Chrome graceful exit timeout');}catch{}}
 if(!ended()){child.kill('SIGKILL');await bounded(join(),timeoutMs,'Chrome physical exit unavailable');}
 assert(ended(),'Chrome physical exit unavailable');
}
function observeBrowserEndpoint(child,append,timeoutMs=30000){
 return new Promise((resolve,reject)=>{let text='',settled=false;
  const finish=(failure,value)=>{if(settled)return;settled=true;clearTimeout(timer);child.removeListener('exit',exit);child.removeListener('error',error);child.stderr.removeListener('data',data);failure?reject(failure):resolve(value);};
  const exit=()=>finish(Error('Owned Chrome exited before ready'));
  const error=()=>finish(Error('Owned Chrome failed before ready'));
  const data=chunk=>{if(Buffer.byteLength(text)+chunk.length>1048576)return finish(Error('Bounded Chrome stderr exhausted'));text+=chunk.toString();try{if(Buffer.byteLength(text)<=65536)append(chunk);}catch{return finish(Error('Owned Chrome diagnostic write failed'));}const match=text.match(/DevTools listening on (ws:\/\/127\.0\.0\.1:\d+\/[^\s]+)/);if(match)finish(null,match[1]);};
  const timer=setTimeout(()=>finish(Error('Owned Chrome startup deadline')),timeoutMs);child.once('exit',exit);child.once('error',error);child.stderr.on('data',data);
 });
}
async function launchOwnedAnalyticsBrowser(root,label,{admitEndpoint=()=>{}}={}){
 assert.match(label,/^[a-z]+$/);const puppeteer=require('puppeteer'),executable=process.env.ANALYTICS_BROWSER_EXECUTABLE,profile=path.join(root,label+'-profile');assert.ok(path.isAbsolute(executable));fs.accessSync(executable,fs.constants.X_OK);const executableSha256=createHash('sha256').update(fs.readFileSync(executable)).digest('hex');assert.equal(executableSha256,process.env.ANALYTICS_BROWSER_SHA256);fs.mkdirSync(profile,{mode:0o700});
 let child,browser,identity;
 try{
  const defaultArgs=await puppeteer.defaultArgs({headless:true,userDataDir:profile,args:['--remote-debugging-port=0','--disable-background-networking','--disable-component-update','--disable-domain-reliability','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1']});
  child=spawn(executable,defaultArgs,{detached:false,env:{PATH:'/usr/bin:/bin',HOME:root,TMPDIR:root},stdio:['ignore','ignore','pipe']});
  const stderrFile=path.join(root,label+'-stderr.log');fs.writeFileSync(stderrFile,'',{mode:0o600});
  const endpointReady=observeBrowserEndpoint(child,chunk=>fs.appendFileSync(stderrFile,chunk));endpointReady.catch(()=>{});
  await bounded(require('node:events').once(child,'spawn'),3000,'Chrome spawn timeout');
  identity=require('./browserProcessOwnership').captureBrowserProcessIdentity(child.pid);fs.writeFileSync(path.join(root,label+'-process.json'),JSON.stringify({...identity,profile,executableSha256}),{mode:0o600});
  const endpoint=await endpointReady;
  await admitEndpoint(endpoint);
  browser=await bounded(puppeteer.connect({browserWSEndpoint:endpoint,protocolTimeout:15000}),20000,'Chrome connection timeout');const original=browser.close.bind(browser);let closed=false;
  browser.close=async()=>{if(closed)return;closed=true;let primary;try{await bounded(original(),3000,'Chrome close timeout');}catch(error){primary=error;}try{await cleanup();}catch(error){throw new AggregateError([...(primary?[primary]:[]),error],'Chrome cleanup failed');}if(primary)throw primary;};return browser;
 }catch(error){try{await cleanup();}catch(cleanupError){throw new AggregateError([error,cleanupError],'Chrome launch cleanup failed');}throw error;}
 async function cleanup(){
  if(child){await retireChild(child);assert.throws(()=>process.kill(child.pid,0),{code:'ESRCH'});}
  fs.writeFileSync(path.join(root,label+'-cleanup.json'),JSON.stringify(profileDisposition(child?.pid??null,identity)),{mode:0o600});
 }
}
function profileDisposition(pid,identity){return {pid,pgid:identity?.pgid??null,leaderReaped:true,descendantAbsence:'unverified',profileAbsent:false,cleanupOwner:'outer-all-owned-groups'};}
async function settleOwnership(operations,timeoutMs=10000){return Promise.all(operations.map(async([name,operation])=>{try{await bounded(Promise.resolve().then(operation),timeoutMs,'Owned cleanup deadline');return {name,status:'fulfilled'};}catch(error){return {name,status:'rejected',errorType:error?.name==='TimeoutError'?'TimeoutError':'Error'};}}));}
module.exports={observeBrowserEndpoint,launchOwnedAnalyticsBrowser,bounded,retireChild,settleOwnership,profileDisposition};
