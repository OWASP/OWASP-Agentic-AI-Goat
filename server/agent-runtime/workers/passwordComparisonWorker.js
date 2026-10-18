'use strict';
const { parentPort }=require('node:worker_threads');
const bcrypt=require('bcryptjs');
if(!parentPort)throw new Error('Password comparison worker requires parent port');
parentPort.on('message',async message=>{const {id,password,hash}=message||{};if(!Number.isSafeInteger(id)||id<1||typeof password!=='string'||typeof hash!=='string')return parentPort.postMessage({id:0,ok:false});try{const match=await bcrypt.compare(password,hash);if(typeof match!=='boolean')throw new Error('Invalid comparison result');parentPort.postMessage({id,ok:true,match});}catch{parentPort.postMessage({id,ok:false});}});
