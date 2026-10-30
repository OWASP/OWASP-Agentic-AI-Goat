'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),{ASSETS}=require('./namespace-executor'),ROOT='/usr/local/libexec/';
const manifest=JSON.parse(fs.readFileSync(ROOT+'owasp-ai-goat-owned-listings-manifest.json'));
fs.writeFileSync(ROOT+'owasp-ai-goat-owned-listings-hosts',manifest.listeners.map(value=>`${value.address} ${value.hostname}`).join('\n')+'\n');fs.writeFileSync(ROOT+'owasp-ai-goat-owned-listings-nsswitch','hosts: files\n');fs.writeFileSync(ROOT+'owasp-ai-goat-owned-listings-resolv','');
for(const file of ASSETS)fs.chmodSync(file,file.endsWith('/node')||file.endsWith('/bwrap')||file.endsWith('-init')||file.endsWith('-supervisor')?0o555:0o444);
fs.writeFileSync('/usr/share/owasp-ai-goat/owned-listings-assets.json',JSON.stringify(Object.fromEntries(ASSETS.map(file=>[file,crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')]))));fs.chmodSync('/usr/share/owasp-ai-goat/owned-listings-assets.json',0o444);
