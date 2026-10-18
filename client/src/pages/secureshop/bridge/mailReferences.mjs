const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const HASH = /^[a-f0-9]{64}$/;
const bad = () => { throw new TypeError('Invalid mail recovery references'); };
function keys(value, allowed, required = allowed) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value,k))) bad();
}
export function decodeMailReferences(raw) {
  if (raw === null) return { version: 3, scopes: {} };
  if (typeof raw !== 'string' || raw.length > 8192 || new TextEncoder().encode(raw).length > 8192) bad();
  let value; try { value = JSON.parse(raw); } catch { bad(); }
  keys(value,['version','scopes']);
  if (![1,2,3,4,5,6].includes(value.version) || !value.scopes || Object.getPrototypeOf(value.scopes) !== Object.prototype || Object.keys(value.scopes).length > 8) bad();
  for (const [scope, refs] of Object.entries(value.scopes)) {
    if (!HASH.test(scope)) bad(); keys(refs,value.version===1?['pending','assessment']:value.version===2?['pending','assessment','headerAssessment','disclosureAssessment','browserAssessment']:value.version===3?['pending','assessment','headerAssessment','disclosureAssessment','browserAssessment','unresolved']:value.version===4?['pending','assessment','headerAssessment','disclosureAssessment','browserAssessment','unresolved','inlineTeaching','inlineSummary']:value.version===5?['pending','assessment','headerAssessment','disclosureAssessment','browserAssessment','unresolved','inlineTeaching','inlineSummary','htmlAssessment']:['pending','assessment','headerAssessment','disclosureAssessment','browserAssessment','unresolved','inlineTeaching','inlineSummary','htmlAssessment','agentReadAssessment'],['pending','assessment']);
    if (refs.pending !== null) {
      keys(refs.pending,['action','requestId','digest','chatSource'],['action','requestId','digest']);
      if (!['send','autoReply'].includes(refs.pending.action)
        || typeof refs.pending.requestId !== 'string' || !UUID.test(refs.pending.requestId)
        || typeof refs.pending.digest !== 'string' || !HASH.test(refs.pending.digest)) bad();
      if (Object.hasOwn(refs.pending, 'chatSource')) {
        if (value.version < 3) bad();
        keys(refs.pending.chatSource, ['sessionId','requestId']);
        if (typeof refs.pending.chatSource.sessionId !== 'string'
          || typeof refs.pending.chatSource.requestId !== 'string'
          || !UUID.test(refs.pending.chatSource.sessionId)
          || !UUID.test(refs.pending.chatSource.requestId)) bad();
      }
    }
    if (refs.headerAssessment != null) {
      keys(refs.headerAssessment,['requestId','sendOperationId','evaluationId'],['requestId','sendOperationId']);
      const a=refs.headerAssessment;
      if (!UUID.test(a.requestId) || !UUID.test(a.sendOperationId) || a.requestId===a.sendOperationId || (Object.hasOwn(a,'evaluationId')&&!UUID.test(a.evaluationId))) bad();
    }
    if (refs.browserAssessment != null) {
      keys(refs.browserAssessment,['requestId','sendOperationId','messageId','evaluationId'],['requestId','sendOperationId','messageId']);
      const a=refs.browserAssessment;
      if (!UUID.test(a.requestId)||!UUID.test(a.sendOperationId)||a.requestId===a.sendOperationId||!Number.isSafeInteger(a.messageId)||a.messageId<1||(Object.hasOwn(a,'evaluationId')&&!UUID.test(a.evaluationId))) bad();
    }
    if (refs.disclosureAssessment != null) {
      keys(refs.disclosureAssessment,['requestId','readOperationId','userId','confirmed','evaluationId'],['requestId','readOperationId','userId','confirmed']);
      const a=refs.disclosureAssessment;
      if (typeof a.confirmed!=='boolean'||!UUID.test(a.requestId)||!UUID.test(a.readOperationId)||a.requestId===a.readOperationId||!Number.isSafeInteger(a.userId)||a.userId<1||(Object.hasOwn(a,'evaluationId')&&!UUID.test(a.evaluationId))) bad();
    }
    if (refs.assessment !== null) {
      keys(refs.assessment,['requestId','replyOperationId','threadId','evaluationId'],['requestId','replyOperationId','threadId']);
      const a=refs.assessment;
      if (!UUID.test(a.requestId) || !UUID.test(a.replyOperationId) || a.requestId === a.replyOperationId || !Number.isSafeInteger(a.threadId) || a.threadId < 1 || a.threadId > 2147483647 || (Object.hasOwn(a,'evaluationId') && !UUID.test(a.evaluationId))) bad();
    }
    if (refs.unresolved !== undefined) {
      if (value.version < 3 || !Array.isArray(refs.unresolved) || refs.unresolved.length > 16) bad();
      const requests = new Set(), threads = new Set();
      for (const item of refs.unresolved) {
        keys(item, ['action','requestId','digest','threadId']);
        if (item.action !== 'autoReply' || !UUID.test(item.requestId) || !HASH.test(item.digest)
          || !Number.isSafeInteger(item.threadId) || item.threadId < 1 || item.threadId > 2147483647
          || requests.has(item.requestId) || threads.has(item.threadId)) bad();
        requests.add(item.requestId); threads.add(item.threadId);
      }
    }
    if (refs.htmlAssessment !== undefined) {
      if (![5,6].includes(value.version)) bad();
      if (refs.htmlAssessment !== null) {
        keys(refs.htmlAssessment,['stage','requestId','sourceSessionId','sourceRequestId','sendOperationId','messageId','startedAt']);
        const a=refs.htmlAssessment;
        if(!['ready','submitted'].includes(a.stage)||![a.requestId,a.sourceSessionId,a.sourceRequestId,a.sendOperationId].every(id=>UUID.test(id))
          ||new Set([a.requestId,a.sourceSessionId,a.sourceRequestId,a.sendOperationId]).size!==4
          ||!Number.isSafeInteger(a.messageId)||a.messageId<1||a.messageId>2147483647||!Number.isSafeInteger(a.startedAt)||a.startedAt<1)bad();
      }
    }
    if (refs.agentReadAssessment !== undefined) {
      if (value.version !== 6) bad();
      if (refs.agentReadAssessment !== null) {
        keys(refs.agentReadAssessment, ['version','shopUserId','sessionId','requestId','startedAt']);
        const a=refs.agentReadAssessment;
        if(a.version!==1||!Number.isSafeInteger(a.shopUserId)||a.shopUserId<1
          ||![a.sessionId,a.requestId].every(id=>UUID.test(id))
          ||!Number.isSafeInteger(a.startedAt)||a.startedAt<1)bad();
      }
    }
    if (refs.inlineTeaching !== undefined) {
      if (![4,5,6].includes(value.version)) bad();
      if (refs.inlineTeaching !== null) {
        keys(refs.inlineTeaching, ['requestId']);
        if (!UUID.test(refs.inlineTeaching.requestId)) bad();
      }
    }
    if (refs.inlineSummary !== undefined) {
      if (![4,5,6].includes(value.version)) bad();
      if (refs.inlineSummary !== null) {
        keys(refs.inlineSummary, ['requestId','readOperationId','messageId','assessmentAttempted'],
          ['requestId','readOperationId','messageId']);
        const a = refs.inlineSummary;
        if (!UUID.test(a.requestId) || !UUID.test(a.readOperationId)
          || a.requestId === a.readOperationId || !Number.isSafeInteger(a.messageId)
          || a.messageId < 1 || a.messageId > 2147483647
          || (Object.hasOwn(a, 'assessmentAttempted') && typeof a.assessmentAttempted !== 'boolean')) bad();
      }
    }
  }
  return value;
}
export function updateMailReference(raw,scope,kind,reference) {
  if (!HASH.test(scope) || !['pending','assessment','headerAssessment','disclosureAssessment','browserAssessment','inlineTeaching','inlineSummary','htmlAssessment','agentReadAssessment'].includes(kind)) bad();
  const value=decodeMailReferences(raw);
  value.version=kind==='agentReadAssessment'||value.version===6?6:kind==='htmlAssessment'||value.version===5?5:['inlineTeaching','inlineSummary'].includes(kind)||value.version===4?4:3;
  value.scopes[scope] ||= {pending:null,assessment:null};
  value.scopes[scope][kind]=reference;
  if(value.scopes[scope].pending===null&&value.scopes[scope].assessment===null&&value.scopes[scope].headerAssessment==null&&value.scopes[scope].disclosureAssessment==null&&value.scopes[scope].browserAssessment==null&&value.scopes[scope].inlineTeaching==null&&value.scopes[scope].inlineSummary==null&&value.scopes[scope].htmlAssessment==null&&value.scopes[scope].agentReadAssessment==null&&!(value.scopes[scope].unresolved?.length))delete value.scopes[scope];
  const encoded=JSON.stringify(value);decodeMailReferences(encoded);
  return Object.keys(value.scopes).length ? encoded : null;
}

export function keepUnresolvedMailReference(raw, scope, expected, threadId) {
  if (!HASH.test(scope) || !Number.isSafeInteger(threadId) || threadId < 1 || threadId > 2147483647) bad();
  const value = decodeMailReferences(raw);
  const refs = value.scopes[scope];
  if (!refs?.pending || Object.keys(refs.pending).length !== Object.keys(expected || {}).length
    || Object.keys(refs.pending).some(key => refs.pending[key] !== expected[key])
    || refs.pending.action !== 'autoReply') bad();
  const unresolved = refs.unresolved || [];
  if (unresolved.length >= 16 || unresolved.some(item => item.requestId === expected.requestId || item.threadId === threadId)) bad();
  refs.unresolved = [...unresolved, { ...refs.pending, threadId }];
  refs.pending = null;
  value.version = value.version === 6 ? 6 : value.version === 5 ? 5 : value.version === 4 ? 4 : 3;
  const encoded = JSON.stringify(value);
  decodeMailReferences(encoded);
  return encoded;
}
