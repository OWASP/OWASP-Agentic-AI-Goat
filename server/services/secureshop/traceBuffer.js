'use strict';
const {randomUUID}=require('node:crypto');
function createTraceBuffer(write,{maxPending=4096}={}){
 const queue=[];let flushing;
 return {
  record(row){if(queue.length>=maxPending)throw Error('SecureShop trace queue full');const event={...row,event_id:row.event_id||randomUUID()};queue.push(event);return event;},
  flush(){if(flushing)return flushing;if(!queue.length)return Promise.resolve();flushing=(async()=>{while(queue.length){const batch=queue.slice(0,128);await write(batch);queue.splice(0,batch.length);}})().finally(()=>{flushing=undefined;});return flushing;},
  get pending(){return queue.length;},
 };
}
module.exports={createTraceBuffer};
