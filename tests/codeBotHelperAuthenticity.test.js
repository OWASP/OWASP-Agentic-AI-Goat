'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { executeCodeBotTool } = require('../server/services/supplyChainWorkshopAgent');

test('review_code reports only submitted JavaScript var declarations at their real lines', () => {
  const result = executeCodeBotTool('review_code', {
    language: 'javascript',
    code: [
      '// var commentedOut = true;',
      'const current = true;',
      'var legacy = getValue();',
      '/* var alsoCommentedOut = true; */',
      '  var secondLegacy = 2;',
    ].join('\n'),
  }, 'vulnerable');

  assert.equal(result.security, 'clean');
  assert.match(result.summary, /Limited non-executing text inspection only/);
  assert.deepEqual(result.issues, [
    { severity: 'low', line: 3, message: 'Prefer const or let instead of var.' },
    { severity: 'low', line: 5, message: 'Prefer const or let instead of var.' },
  ]);
});

test('review_code does not invent findings for a distinct input or unsupported language', () => {
  const javascript = executeCodeBotTool('review_code', {
    language: 'javascript', code: 'const ready = true;\nconsole.log(ready);',
  }, 'vulnerable');
  const python = executeCodeBotTool('review_code', {
    language: 'python', code: 'var legacy = 1',
  }, 'vulnerable');

  assert.deepEqual(javascript.issues, []);
  assert.deepEqual(python.issues, []);
});

test('explain_error grounds its response in the submitted error class', () => {
  const typeError = executeCodeBotTool('explain_error', {
    error_message: "TypeError: Cannot read properties of undefined (reading 'name')",
  }, 'vulnerable');
  const referenceError = executeCodeBotTool('explain_error', {
    error_message: 'ReferenceError: sessionToken is not defined',
  }, 'vulnerable');

  assert.match(typeError.explanation, /\.name was read from undefined/);
  assert.match(typeError.suggested_fix, /\.name/);
  assert.match(referenceError.explanation, /sessionToken is not defined/);
  assert.match(referenceError.suggested_fix, /sessionToken/);
  assert.notEqual(typeError.explanation, referenceError.explanation);
});

test('helper argument errors remain observed errors', () => {
  const review = executeCodeBotTool('review_code', null, 'vulnerable');
  const explanation = executeCodeBotTool('explain_error', { error_message: '   ' }, 'vulnerable');

  assert.deepEqual(review, {
    security: 'error', error: 'Invalid review_code arguments: code must be a non-empty string',
  });
  assert.deepEqual(explanation, {
    security: 'error', error: 'Invalid explain_error arguments: error_message must be a non-empty string',
  });
});
