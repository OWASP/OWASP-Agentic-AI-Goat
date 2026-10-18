'use strict';
const fs=require('node:fs');
const path=require('node:path');
const {createEndpointIpcSender}=require('./secureShopEndpointIpc');
// The future preload wraps only AgentHostSupervisor's spawnProcess constructor
// option with this adapter. It must not replace global child_process.spawn.
// Only cwd/env/stdio are admitted; the launcher separately validates env/port pins.
function createSecureShopAgentHostIpcSpawn({sourceRoot,nodePath=process.execPath,spawnProcess,
  revokeChild,timeoutMs=3000}={}) {
  if(typeof sourceRoot!=='string'||!path.isAbsolute(sourceRoot)||fs.realpathSync(sourceRoot)!==sourceRoot
      ||!fs.statSync(sourceRoot).isDirectory()||(fs.statSync(sourceRoot).mode&0o222)!==0
      ||fs.statSync(sourceRoot).uid!==process.getuid()||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>30000
      ||nodePath!==process.execPath||typeof spawnProcess!=='function'||typeof revokeChild!=='function')throw Error('Exact owned agent-host spawn required');
  const records=[];const active=new Map();
  function spawn(command,args,options) {
    if(!options||Object.getPrototypeOf(options)!==Object.prototype
        ||Object.keys(options).sort().join(',')!=='cwd,env,stdio'
        ||command!==nodePath||JSON.stringify(args)!==JSON.stringify(['agent-host/index.js'])||options?.cwd!==sourceRoot
        ||JSON.stringify(options.stdio)!==JSON.stringify(['ignore','inherit','inherit'])
        ||typeof options.env?.SS_AGENT_HOST_INSTANCE_ID!=='string'
        ||!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(options.env.SS_AGENT_HOST_INSTANCE_ID)||!/^\d+$/.test(options.env.SS_AGENT_HOST_PORT||'')
        ||Number(options.env.SS_AGENT_HOST_PORT)<1||Number(options.env.SS_AGENT_HOST_PORT)>65535)throw Error('Exact owned agent-host spawn required');
    const child=spawnProcess(command,[...args],{...options,env:{...options.env},stdio:['ignore','inherit','inherit','ipc'],detached:false});
    const record={child,pid:child.pid,instanceId:options.env.SS_AGENT_HOST_INSTANCE_ID,sender:null};records.push(record);
    const sender=createEndpointIpcSender(child,{timeoutMs,revokeAll:()=>revokeChild(child)});record.sender=sender;active.set(child,record);
    function retire(){sender.close();active.delete(child);child.off('exit',retire);child.off('error',retire);}
    child.once('exit',retire);child.once('error',retire);
    return child;
  }
  function senderFor(child){const record=active.get(child);if(!record||record.sender.status().closed)throw Error('Owned agent-host IPC unavailable');return record.sender;}
  function close(){for(const record of active.values())record.sender.close();}
  function status(){return records.map(record=>Object.freeze({pid:record.pid,instanceId:record.instanceId,...record.sender.status()}));}
  return Object.freeze({spawn,senderFor,close,status});
}
module.exports={createSecureShopAgentHostIpcSpawn};
