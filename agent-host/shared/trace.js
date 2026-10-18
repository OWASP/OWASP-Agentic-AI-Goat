'use strict';
const buffer=require('../../server/services/secureshop/traceBuffer').createTraceBuffer(rows=>require('../../server/database/postgres/secureshopAgentsDb').getSecureShopAgentsDb().appendTraces(rows));
let scheduled = false;

function schedule() {
  if (scheduled) return;
  scheduled = true;
  setImmediate(()=>{Promise.resolve(flush()).catch(error=>console.error('[SecureShop trace] persistence failed:',error.message));});
}

function flush() {
  scheduled = false;
  return buffer.flush();
}

function recordTrace(row) {
  buffer.record(row);
  schedule();
}

module.exports = { recordTrace, flush };
