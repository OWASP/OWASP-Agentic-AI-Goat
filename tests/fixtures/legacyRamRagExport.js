'use strict';

const fs = require('node:fs');
const path = require('node:path');
const WebSocket = require('ws');

function privateOutput(file) {
  if (!path.isAbsolute(file)) throw new TypeError('Absolute archive path required');
  const parent = path.dirname(file);
  const stat = fs.statSync(parent);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
    throw new Error('Archive parent must be owner-only');
  }
  if (fs.existsSync(file) || fs.existsSync(`${file}.partial`)) throw new Error('Archive output must be new');
  return file;
}

// This expression deliberately reads one exact cached module export. It does not
// enumerate globals, environment, requests, logs, heap objects or other modules.
function expressionFor(file, { expectedPid, expectedModule }) {
  if (!Number.isSafeInteger(expectedPid) || expectedPid < 1) throw new TypeError('Expected process ID required');
  if (!path.isAbsolute(expectedModule)) throw new TypeError('Expected absolute module path required');
  const output = JSON.stringify(privateOutput(file));
  const moduleFile = JSON.stringify(fs.realpathSync(expectedModule));
  return `(()=>{
    'use strict';
    const fs=process.getBuiltinModule('fs'),path=process.getBuiltinModule('path'),crypto=process.getBuiltinModule('crypto');
    if(process.pid!==${expectedPid})throw Object.assign(new Error('Originating process mismatch'),{code:'RAG_EXPORT_PROCESS_MISMATCH'});
    const output=${output},parent=path.dirname(output),parentStat=fs.statSync(parent);
    if(!parentStat.isDirectory()||parentStat.uid!==process.getuid()||(parentStat.mode&0o077)!==0)throw Object.assign(new Error('Archive parent must be owner-only'),{code:'RAG_EXPORT_PARENT_INVALID'});
    if(fs.existsSync(output)||fs.existsSync(output+'.partial'))throw Object.assign(new Error('Archive output must be new'),{code:'RAG_EXPORT_OUTPUT_EXISTS'});
    const cache=process.getBuiltinModule('module')._cache;
    const row=cache[${moduleFile}];
    if(!row||row.filename!==${moduleFile})throw Object.assign(new Error('Legacy RAG singleton cache entry unavailable'),{code:'RAG_EXPORT_CACHE_INVALID'});
    const store=row.exports,uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,owner=/^[1-9][0-9]*$/;
    if(!(store.sessions instanceof Map)||!(store.sessionMetadata instanceof Map)||!(store.lastSessionByUser instanceof Map))throw Object.assign(new Error('Legacy RAG singleton shape invalid'),{code:'RAG_EXPORT_SHAPE_INVALID'});
    if(store.sessions.size>1024||store.sessionMetadata.size>1024||store.lastSessionByUser.size>1024)throw Object.assign(new Error('Legacy RAG archive exceeds cardinality bound'),{code:'RAG_EXPORT_TOO_LARGE'});
    let aggregateChunks=0,aggregateVectors=0,estimatedBytes=4096;
    for(const [key,value] of store.sessions){
      if(!Array.isArray(value)||value.length<1||value.length>4096)throw Object.assign(new Error('Legacy RAG session invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
      aggregateChunks+=value.length;
      for(const chunk of value){
        const length=chunk&&chunk.embedding&&Number(chunk.embedding.length);
        if(length!==384||typeof chunk.text!=='string')throw Object.assign(new Error('Legacy RAG chunk invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
        aggregateVectors+=length;estimatedBytes+=Buffer.byteLength(chunk.text)+length*24+256;
      }
    }
    if(aggregateChunks>65536||aggregateVectors>25165824||estimatedBytes>268435456)throw Object.assign(new Error('Legacy RAG archive exceeds aggregate bound'),{code:'RAG_EXPORT_TOO_LARGE'});
    const selections=[],selected=new Map();
    for(const [ownerId,value] of store.lastSessionByUser){
      if(!owner.test(ownerId)||!value||!uuid.test(value.sessionId)||typeof value.filename!=='string'||!Number.isSafeInteger(value.chunksStored)||value.chunksStored<0)throw Object.assign(new Error('Legacy RAG selection invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
      const selection={ownerId,sessionId:value.sessionId,filename:value.filename,chunksStored:value.chunksStored};selected.set(ownerId,selection);selections.push(selection);
    }
    const sessions=[];
    for(const [key,value] of store.sessions){
      if(typeof key!=='string')throw Object.assign(new Error('Legacy RAG key invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
      const split=key.lastIndexOf('::'),ownerId=key.slice(0,split),sessionId=key.slice(split+2);
      if(split<1||!owner.test(ownerId)||!uuid.test(sessionId)||!Array.isArray(value)||value.length<1||value.length>4096)throw Object.assign(new Error('Legacy RAG session invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
      const metadata=store.sessionMetadata.get(key)||{};
      if(typeof metadata.filename!=='string'||Buffer.byteLength(metadata.filename)>512)throw Object.assign(new Error('Legacy RAG metadata invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
      const chunks=value.map((chunk,index)=>{
        const embedding=Array.from(chunk&&chunk.embedding||[]);
        if(!chunk||chunk.chunkIndex!==index||typeof chunk.text!=='string'||Buffer.byteLength(chunk.text)>1048576||embedding.length!==384||!embedding.every(Number.isFinite))throw Object.assign(new Error('Legacy RAG chunk invalid'),{code:'RAG_EXPORT_DATA_INVALID'});
        return {chunkIndex:index,text:chunk.text,embedding};
      });
      sessions.push({ownerId,sessionId,filename:metadata.filename,chunks});
    }
    for(const [key] of store.sessionMetadata)if(!store.sessions.has(key))throw Object.assign(new Error('Orphan legacy RAG metadata'),{code:'RAG_EXPORT_DATA_INVALID'});
    for(const [ownerId,choice] of selected)if(!store.sessions.has(ownerId+'::'+choice.sessionId))throw Object.assign(new Error('Orphan legacy RAG selection'),{code:'RAG_EXPORT_DATA_INVALID'});
    sessions.sort((a,b)=>a.ownerId.localeCompare(b.ownerId)||a.sessionId.localeCompare(b.sessionId));
    selections.sort((a,b)=>a.ownerId.localeCompare(b.ownerId));
    const fingerprint=typeof store.runtimeFingerprint?.fingerprint==='string'&&/^[a-f0-9]{64}$/.test(store.runtimeFingerprint.fingerprint)?store.runtimeFingerprint.fingerprint:null;
    const archive={version:1,scope:'legacy-ram-rag-originating-process',process:{pid:process.pid,execPath:process.execPath,module:${moduleFile}},runtimeFingerprint:fingerprint,sessions,selections};
    const body=JSON.stringify(archive)+'\\n';
    if(Buffer.byteLength(body)>268435456)throw Object.assign(new Error('Legacy RAG archive exceeds bound'),{code:'RAG_EXPORT_TOO_LARGE'});
    const partial=output+'.partial',fd=fs.openSync(partial,'wx',0o600);
    try{fs.writeFileSync(fd,body);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
    fs.linkSync(partial,output);fs.unlinkSync(partial);const directory=fs.openSync(parent,'r');try{fs.fsyncSync(directory);}finally{fs.closeSync(directory);}
    return {version:1,pid:process.pid,sessions:sessions.length,selections:selections.length,owners:new Set(sessions.map(row=>row.ownerId)).size,chunks:aggregateChunks,vectors:aggregateVectors,bytes:Buffer.byteLength(body),sha256:crypto.createHash('sha256').update(body).digest('hex')};
  })()`;
}

function evaluateInspector({ url, expression, timeoutMs = 10000 }) {
  if (typeof url !== 'string' || !url.startsWith('ws://127.0.0.1:')) throw new TypeError('Loopback inspector URL required');
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url); let settled = false;
    const timer = setTimeout(() => finish(new Error('Inspector export timed out')), timeoutMs);
    const finish = (error, value) => {
      if (settled) return; settled = true; clearTimeout(timer); socket.close(); error ? reject(error) : resolve(value);
    };
    socket.once('error', finish);
    socket.once('open', () => socket.send(JSON.stringify({ id: 1, method: 'Runtime.evaluate',
      params: { expression, awaitPromise: true, returnByValue: true } })));
    socket.on('message', raw => {
      let message; try { message = JSON.parse(String(raw)); } catch (error) { return finish(error); }
      if (message.id !== 1) return;
      if (message.error) return finish(Object.assign(new Error('Inspector protocol rejected export'), { cause: message.error }));
      if (message.result?.exceptionDetails) return finish(Object.assign(new Error('Originating-process export failed'),
        { cause: message.result.exceptionDetails.exception?.description || message.result.exceptionDetails.text }));
      finish(null, message.result?.result?.value);
    });
  });
}

async function exportLegacyRamRag({ inspectorUrl, output, expectedPid, expectedModule }) {
  return evaluateInspector({ url: inspectorUrl, expression: expressionFor(output, { expectedPid, expectedModule }) });
}

module.exports = { exportLegacyRamRag, expressionFor, evaluateInspector };
