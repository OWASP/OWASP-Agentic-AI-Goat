'use strict';
// Build-time only; registry is root-owned and read-only in the resulting image.
const fs=require('node:fs');const crypto=require('node:crypto');const {ASSETS}=require('./executor');
const root='/usr/local/libexec/';const manifest=JSON.parse(fs.readFileSync(root+'dvaia-owned-http-manifest.json'));
fs.writeFileSync(root+'dvaia-owned-http-hosts',manifest.listeners.map(x=>`${x.address} ${x.hostname}`).join('\n')+'\n');
fs.writeFileSync(root+'dvaia-owned-http-nsswitch','hosts: files\n');fs.writeFileSync(root+'dvaia-owned-http-resolv','');
for(const file of ASSETS)fs.chmodSync(file,file.endsWith('/node')||file.endsWith('/bwrap')||file.endsWith('-init')||file.endsWith('-supervisor')?0o555:0o444);
fs.writeFileSync('/usr/share/dvaia/owned-http-assets.json',JSON.stringify(Object.fromEntries(ASSETS.map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')]))));
fs.chmodSync('/usr/share/dvaia/owned-http-assets.json',0o444);
