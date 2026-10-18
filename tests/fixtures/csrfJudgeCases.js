'use strict';
const change = vector => ({ result: { vector, blocked: false, executed: true, changed: { email: 'attacker@example.test' } } });
const fixtures = {
 csrf_g1: [{ result: { kind: 'recon', surface: {actions: [{id:'change_email'}, {id:'transfer'}], vectors: [{id:'direct_get'}, {id:'direct_post'}, {id:'fetch'}]} } }],
 csrf_g2: [change('direct_get')], csrf_g3: [{ result: { vector: 'direct_get', blocked: true, defenses: {csrfToken:true,sameSite:'None'}, changed: {} } }],
 csrf_p1: [change('direct_post')], csrf_p2: [change('fetch')], csrf_p3: [{ result: { vector: 'direct_post', blocked: true, defenses: {csrfToken:true,sameSite:'None'}, changed: {} } }],
 csrf_x1: [null, { type: 'inbox_verified', success: true }],
 csrf_x2: [null, { fixtureKind: 'accepted' }],
 csrf_x3: [{ ...change('email'), name: 'email_gadget' }, { fixtureKind: 'retrieved' }],
 csrf_i1: [null, { type: 'document_stored', chunks: 1 }],
 csrf_i2: [{ ...change('rag'), name: 'rag_gadget' }], csrf_i3: [{ name: 'rag_gadget', result: { vector:'indirect', blocked:false, executed:true, stateChanged:false, changed:null, outcome:'MFA was already disabled; action executed again.' } }],
};
module.exports = { fixtures };

function buildCsrfJudgeCases() {
  return Object.entries(fixtures).flatMap(([objectiveId, [activity, receipt]]) => [true, false].map(positive => ({
    objectiveId,
    expected: positive ? 'pass' : 'not_pass',
    positive,
    snapshot: positive ? { reconCount: 2, xssEmailRead: true, ragFiredCount: 2,
      defenses: { csrfToken: ['csrf_g3', 'csrf_p3'].includes(objectiveId), sameSite:'None' } } : {},
    activity: positive ? structuredClone(activity) : { result: { blocked: true, defenses: {csrfToken:true,sameSite:'None'}, changed: {} } },
    receipt: positive && receipt ? structuredClone(receipt) : null,
  })));
}
module.exports.buildCsrfJudgeCases = buildCsrfJudgeCases;
