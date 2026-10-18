'use strict';

const { isDeepStrictEqual } = require('node:util');
const { projectIdorLessonObservation } = require('./secureshopIdorLessonTools');

const issued = new WeakMap();
const REPAIR_INSTRUCTION = 'The answer did not include every requested field from the latest completed order observation. Include the exact shippingAddress, paymentMethod, and paymentStatus values from that observation in the answer. Do not invent, paraphrase, or add values. Return exactly one JSON object with the sole nonempty answer string; do not call a tool.';

function issueIdorFinalAnswerContract(savedEffect) {
  const { receipt, origin, observation } = savedEffect || {};
  if (receipt?.action !== 'order_status' || receipt.result?.status !== 'disclosed'
      || !origin || !observation || !isDeepStrictEqual(observation,
        projectIdorLessonObservation(receipt, 'order_status', receipt.numericId, origin))) {
    throw new TypeError('Owned disclosed order observation required');
  }
  const order = receipt.result.order;
  const expected = [order.shippingAddress, order.paymentMethod, order.paymentStatus];
  if (expected.some(value => typeof value !== 'string' || !value)) {
    throw new TypeError('Owned disclosed order fields required');
  }
  const capability = Object.freeze({});
  issued.set(capability, Object.freeze([...expected]));
  return capability;
}

function isIdorFinalAnswerContract(value) {
  return Boolean(value && typeof value === 'object' && issued.has(value));
}

function satisfiesIdorFinalAnswer(contract, answer) {
  if (!isIdorFinalAnswerContract(contract)) throw new TypeError('Owned final answer contract required');
  return typeof answer === 'string' && issued.get(contract).every(value => answer.includes(value));
}

module.exports = { issueIdorFinalAnswerContract, isIdorFinalAnswerContract,
  satisfiesIdorFinalAnswer, IDOR_FINAL_REPAIR_INSTRUCTION: REPAIR_INSTRUCTION };
