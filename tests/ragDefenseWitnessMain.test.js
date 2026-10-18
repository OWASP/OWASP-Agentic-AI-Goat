'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const entry=require('./fixtures/ragDefenseWitnessMain');
test('entry import is inert and refuses missing admission before any runtime import',()=>{assert.throws(()=>entry.admit({}));assert(!Object.keys(require.cache).some(p=>p.endsWith('/providers/langchainProvider.js')));assert(!Object.keys(require.cache).some(p=>p.endsWith('/dpiTechniqueActualTransport.js')));});
test('sealed input authority is distinct from historical RAG8 and has exact expected digest',()=>{assert.equal(entry.INPUT_SHA,'241fd3cb61b9f3a2bd4afc250671f2d297b4f2037edc060e5a8fa27d8738b01f');assert(entry.INPUT.endsWith('rag-defense-witness-prospective-inputs-v1.json'));assert.throws(()=>entry.checkLoaded(new Map()),/Imported file not admitted/);});
