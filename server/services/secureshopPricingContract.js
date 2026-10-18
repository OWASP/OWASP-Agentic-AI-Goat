'use strict';

const {
  createHash
} = require('node:crypto');
const {parseUrl}=require('../../sidecars/sandbox-runner/owned-pricing-http/input');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const TASK_ROLE = Object.freeze({
  'price-advisor': 'customer',
  'pricing-strategy': 'merchant'
});
const fail = code => Object.assign(new Error('Bound pricing request unavailable'), {
  code
});
function closed(value, keys) {
  return !!value && Object.getPrototypeOf(value) === Object.prototype && Reflect.ownKeys(value).length === keys.length && keys.every(k => Object.hasOwn(Object.getOwnPropertyDescriptor(value, k) || {}, 'value'));
}
function text(value, max, empty = false) {
  if (typeof value !== 'string' || !empty && !value.trim() || !value.isWellFormed() || value.includes('\0') || Buffer.byteLength(value) > max) throw fail('PRICING_INVALID_ARGUMENT');
  return value;
}
function pricingCompetitorUrl(value){
  text(value,2048);
  try{parseUrl(value);}catch{throw fail('PRICING_INVALID_ARGUMENT');}
  return value;
}
function request(value) {
  const hasExperiment=Object.hasOwn(value||{},'experiment');
  const hasCompetitorUrl=Object.hasOwn(value||{},'competitorUrl');
  if (!closed(value, ['operationId','task','productId','message',
    ...(hasExperiment?['experiment']:[]),...(hasCompetitorUrl?['competitorUrl']:[])])
    ||hasExperiment&&hasCompetitorUrl||!UUID.test(value.operationId)||!Object.hasOwn(TASK_ROLE,value.task)
    ||!Number.isSafeInteger(value.productId)||value.productId<1||value.productId>2147483647)
    throw fail('PRICING_INVALID_ARGUMENT');
  if(hasExperiment&&(!closed(value.experiment,['strategy','durationDays'])||value.task!=='pricing-strategy'
    ||!['undercut','premium','bundle'].includes(value.experiment.strategy)
    ||!Number.isInteger(value.experiment.durationDays)||value.experiment.durationDays<1||value.experiment.durationDays>90))throw fail('PRICING_INVALID_ARGUMENT');
  if(hasCompetitorUrl){
    if(value.task!=='pricing-strategy')throw fail('PRICING_INVALID_ARGUMENT');
    pricingCompetitorUrl(value.competitorUrl);
  }
  return Object.freeze({
    operationId: value.operationId,
    task: value.task,
    productId: value.productId,
    message: text(value.message, 8192),
    ...(hasExperiment?{experiment:Object.freeze({...value.experiment})}:{}),
    ...(hasCompetitorUrl?{competitorUrl:value.competitorUrl}:{})
  });
}
const hash = value => createHash('sha256').update(value).digest('hex');
const requestDigest = value => {const selected=request(value);return hash(JSON.stringify({
  version: selected.competitorUrl?'secureshop-pricing-request.v3'
    :selected.experiment?'secureshop-pricing-request.v2':'secureshop-pricing-request.v1',
  ...selected
}));};
function competitorReceipt(value, expected) {
  const keys = ['version', 'targetId', 'operationId', 'runId', 'callId', 'requestSha256', 'url', 'status', 'body', 'bodySha256', 'classification'];
  if (!closed(value, keys) || value.version !== 'secureshop-owned-competitor.v1' || !UUID.test(value.targetId) || !UUID.test(value.operationId) || !UUID.test(value.runId) || !Number.isInteger(value.status) || value.status < 100 || value.status > 599 || !['public-quote', 'protected-training-record', 'attacker-manual'].includes(value.classification)) throw fail('PRICING_RECEIPT_INVALID');
  for (const k of ['targetId', 'operationId', 'runId', 'callId', 'requestSha256', 'url']) if (value[k] !== expected[k]) throw fail('PRICING_RECEIPT_MISMATCH');
  text(value.url, 2048);
  text(value.callId, 128);
  text(value.body, 32768, true);
  if (!/^[a-f0-9]{64}$/.test(value.requestSha256) || hash(value.body) !== value.bodySha256) throw fail('PRICING_RECEIPT_MISMATCH');
  return Object.freeze({
    ...value
  });
}
module.exports = {
  UUID,
  TASK_ROLE,
  closed,
  text,
  pricingCompetitorUrl,
  request,
  requestDigest,
  competitorReceipt,
  hash,
  fail
};
