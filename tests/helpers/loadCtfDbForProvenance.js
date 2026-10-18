'use strict';
const Module = require('node:module');
const path = require('node:path');
const originalLoad = Module._load;
const target = path.resolve(__dirname, '../../server/database/postgres/ctfDb.js');
Module._load = function provenanceLoad(request, parent, isMain) {
  if (parent?.filename === target && request === '../../agent-runtime/ctfStageJudge') {
    return { stageDigest: () => { throw new Error('CTF attempt grading is outside provenance qualification'); } };
  }
  return originalLoad.call(this, request, parent, isMain);
};
try { module.exports = require(target); }
finally { Module._load = originalLoad; }
