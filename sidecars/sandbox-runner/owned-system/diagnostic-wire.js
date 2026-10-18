'use strict';
const {createHash}=require('node:crypto');
const {normalizeDiagnosticRequest,diagnosticRequestDigest}=require('./diagnostic-contract');
const {validateDiagnosticResult}=require('./diagnostic-result');
const VERSION='secureshop-owned-system-diagnostic-http.v1';
const ISOLATION='bwrap-system-diagnostic-v1';
const exact=(raw,keys)=>raw&&typeof raw==='object'&&!Array.isArray(raw)&&Object.keys(raw).sort().join(',')===keys.sort().join(',');
function targetId(value){if(typeof value!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value))throw new TypeError('Trusted diagnostic target required');return value;}
function normalizeDiagnosticWire(raw){if(!exact(raw,['targetId','request']))throw new TypeError('Closed private diagnostic request required');return Object.freeze({targetId:targetId(raw.targetId),request:normalizeDiagnosticRequest(raw.request)});}
function diagnosticHostname(id){return 'system-diag-'+targetId(id).replaceAll('-','');}
function diagnosticBindingDigest(raw){const value=normalizeDiagnosticWire(raw);return createHash('sha256').update(JSON.stringify({version:VERSION,targetId:value.targetId,requestSha256:diagnosticRequestDigest(value.request)})).digest('hex');}
function bindDiagnosticResult(raw,result){const wire=normalizeDiagnosticWire(raw);return Object.freeze({version:VERSION,targetId:wire.targetId,hostname:diagnosticHostname(wire.targetId),bindingSha256:diagnosticBindingDigest(wire),result:validateDiagnosticResult(result,wire.request)});}
function validateBoundDiagnosticResult(raw,value){const wire=normalizeDiagnosticWire(raw);if(!exact(value,['version','targetId','hostname','bindingSha256','result'])||value.version!==VERSION||value.targetId!==wire.targetId||value.hostname!==diagnosticHostname(wire.targetId)||value.bindingSha256!==diagnosticBindingDigest(wire))throw new TypeError('Diagnostic target receipt mismatch');return bindDiagnosticResult(wire,value.result);}
module.exports={VERSION,ISOLATION,normalizeDiagnosticWire,diagnosticHostname,diagnosticBindingDigest,bindDiagnosticResult,validateBoundDiagnosticResult};
