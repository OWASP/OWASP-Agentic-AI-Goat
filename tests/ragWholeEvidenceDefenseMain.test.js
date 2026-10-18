'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const entry=require('./fixtures/ragWholeEvidenceDefenseMain');
test('entry import is inert and refuses missing admission before any runtime import',()=>{assert.throws(()=>entry.admit({}));assert(!Object.keys(require.cache).some(p=>p.endsWith('/providers/langchainProvider.js')));assert(!Object.keys(require.cache).some(p=>p.endsWith('/dpiTechniqueActualTransport.js')));});
test('sealed input authority is distinct from prior singleton diagnostic and has exact expected digest',()=>{assert.equal(entry.INPUT_SHA,'dbf7f326cdfcee3221896cef0bffe1d320bcce729e9e0aa91d969511521117c5');assert(entry.INPUT.endsWith('rag-whole-evidence-fresh12-inputs-v1.json'));assert.throws(()=>entry.checkLoaded(new Map()),/Imported file not admitted/);});
