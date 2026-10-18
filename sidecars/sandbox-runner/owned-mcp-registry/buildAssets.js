'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),{ASSETS}=require('./executor'),ROOT='/usr/local/libexec/';
const manifest=JSON.parse(fs.readFileSync(ROOT+'dvaia-owned-mcp-registry-manifest.json'));
fs.writeFileSync(ROOT+'dvaia-owned-mcp-registry-hosts',manifest.listeners.map(value=>`${value.address} ${value.hostname}`).join('\n')+'\n');fs.writeFileSync(ROOT+'dvaia-owned-mcp-registry-nsswitch','hosts: files\n');fs.writeFileSync(ROOT+'dvaia-owned-mcp-registry-resolv','');
for(const file of ASSETS)fs.chmodSync(file,file.endsWith('/node')||file.endsWith('/bwrap')||file.endsWith('-init')||file.endsWith('-supervisor')?0o555:0o444);
fs.writeFileSync('/usr/share/dvaia/owned-mcp-registry-assets.json',JSON.stringify(Object.fromEntries(ASSETS.map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')]))));fs.chmodSync('/usr/share/dvaia/owned-mcp-registry-assets.json',0o444);
