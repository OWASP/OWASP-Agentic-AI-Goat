"use strict";
const {isDeepStrictEqual:equal}=require('node:util');
const GUIDED='guided-boolean-v1';
const GUIDED_V2='guided-boolean-v2';
const fail=()=>Object.assign(Error('Coupon probe request conflicts with its original admission'),{code:'COUPON_PROBE_REQUEST_CONFLICT'});
function protocol(value){if(value===undefined)return undefined;if(value===GUIDED||value===GUIDED_V2)return value;throw fail();}
function version(value){return value===GUIDED?2:value===GUIDED_V2?3:1;}
function encode(message,value){const mode=protocol(value);
 if(typeof message!=='string'||!message.trim()||!message.isWellFormed()||Buffer.byteLength(message)>65536)throw fail();
 const encoded=mode===undefined?message:JSON.stringify({version:mode===GUIDED?1:2,kind:'coupon-probe-guided-request',protocol:mode,message});
 if(Buffer.byteLength(encoded)>65536)throw fail();return encoded;
}
function saved(metadata){
 if(!metadata||typeof metadata.message!=='string')throw fail();
 if(!Object.hasOwn(metadata,'protocol')){
  if(Object.hasOwn(metadata,'originalMessage'))throw fail();
  return {protocol:undefined,message:metadata.message,originalMessage:metadata.message};
 }
 if(protocol(metadata.protocol)!==metadata.protocol||metadata.protocol===undefined||typeof metadata.originalMessage!=='string'
  ||encode(metadata.originalMessage,metadata.protocol)!==metadata.message)throw fail();
 return {protocol:metadata.protocol,message:metadata.message,originalMessage:metadata.originalMessage};
}
function assertReplay(metadata,message,value){const expected={protocol:protocol(value),message:encode(message,value),originalMessage:message};
 if(!equal(saved(metadata),expected))throw fail();return expected;
}
module.exports={GUIDED,GUIDED_V2,protocol,version,encode,saved,assertReplay};
