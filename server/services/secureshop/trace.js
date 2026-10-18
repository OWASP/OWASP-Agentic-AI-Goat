'use strict';

const { EventEmitter } = require('node:events');
const { createTraceBuffer } = require('./traceBuffer');

const pg = () => require('../../database/postgres/secureshopAgentsDb').getSecureShopAgentsDb();

class Trace {
  constructor(sessionId) {
    this.sessionId = sessionId;
    this.emitter = new EventEmitter();
    this._pgBuffer = createTraceBuffer((rows) => pg().appendTraces(rows));
  }

  record(row) {
    const full = { session_id: this.sessionId, ...row };
    this._pgBuffer.record(full);
    this.emitter.emit('trace_event', full);
  }

  flush() {
    return this._pgBuffer.flush();
  }
}

module.exports = { Trace };
