const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { EventEmitter } = require('node:events');

const REPO = path.resolve(__dirname, '../../..');
const { ChatStream } = require(path.join(REPO, 'server/services/secureshop/streaming.js'));

function fakeRes() {
  const emit = new EventEmitter();
  const chunks = [];
  return {
    _chunks: chunks,
    setHeader(k, v) { this._headers = this._headers || {}; this._headers[k] = v; },
    writeHead(status, headers) { this._status = status; this._headers = { ...(this._headers || {}), ...headers }; },
    write(c) { chunks.push(c); },
    end() { this._ended = true; },
    on(e, fn) { emit.on(e, fn); },
    _emit: (e, ...a) => emit.emit(e, ...a),
  };
}

test('ChatStream sends proper SSE frames', () => {
  const res = fakeRes();
  const s = new ChatStream(res);
  s.send('assistant_delta', { text: 'hello' });
  s.send('done', {});
  s.close();

  const all = res._chunks.join('');
  assert.match(all, /event: assistant_delta/);
  assert.match(all, /data: \{"text":"hello"\}/);
  assert.match(all, /event: done/);
});
