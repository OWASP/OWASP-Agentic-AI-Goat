'use strict';
const crypto=require('node:crypto'),fs=require('node:fs'),path=require('node:path');
const HTTP_CAPABILITY='mcp-owned-http-central-receipt.v1';
const MANIFEST_SHA256=crypto.createHash('sha256').update(fs.readFileSync(path.resolve(__dirname,'../../../sidecars/sandbox-runner/owned-http/network-manifest.json'))).digest('hex');
module.exports={HTTP_CAPABILITY,MANIFEST_SHA256};
