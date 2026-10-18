'use strict';

// Loaded only by the offline qualification child. It is intentionally small:
// offline flags control the model loader, while these guards make an accidental
// network attempt fail closed during the offline rerun.
const net = require('node:net');
const tls = require('node:tls');
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const dgram = require('node:dgram');
const fail = () => { throw new Error('offline qualification forbids network access'); };
for (const [object, name] of [[net.Socket.prototype, 'connect'], [tls, 'connect'],
  [http, 'request'], [https, 'request'], [https, 'get'], [http, 'get']]) {
  if (object && typeof object[name] === 'function') object[name] = fail;
}
for (const name of ['lookup', 'resolve', 'resolve4', 'resolve6']) {
  if (typeof dns[name] === 'function') dns[name] = fail;
}
if (typeof dgram.createSocket === 'function') dgram.createSocket = fail;
if (typeof globalThis.fetch === 'function') globalThis.fetch = fail;
