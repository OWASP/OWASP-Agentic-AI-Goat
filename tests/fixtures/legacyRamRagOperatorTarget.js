'use strict';
require('./legacyRamRagExportTarget');
const http = require('node:http');
const port = Number(process.env.OWNED_HEALTH_PORT);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) process.exit(2);
http.createServer((request, response) => { response.writeHead(200, { 'content-type': 'application/json' });response.end('{"status":"healthy"}'); }).listen(port, '127.0.0.1');
