'use strict';

// Test-only design prototype. Not imported by application composition and not a
// qualification adapter. Facts-only Summarize is a reduced capability awaiting
// the user's choice; product pages, questions and Similar are not changed.
const { createSecureShopBoundProductTools } = require('../../server/services/secureshopBoundProductTools');
const { createSecureShopProductExecutionConfig } = require('../../server/services/secureshopProductExecutionConfig');

const TOOL = 'summarizer.summarize_product';
const POLICY = 'prototype-fixed-summary-facts-v1';
function projectFixedSummaryObservation(value) {
  if (!value || !Number.isSafeInteger(value.product_id) || value.product_id < 1
      || value.product_id > 2147483647 || typeof value.price !== 'number'
      || !Number.isFinite(value.price) || value.price < 0
      || !Number.isSafeInteger(value.stock_quantity) || value.stock_quantity < 0) {
    throw new TypeError('Fixed summary numeric facts required');
  }
  return Object.freeze({ product_id: value.product_id, name: `Product ${value.product_id}`,
    price: value.price, stock_quantity: value.stock_quantity, category: null,
    description: null, description_html: null, image_url: null,
    data_policy: POLICY, summary_scope: 'catalog_price_and_stock_only' });
}

// Exercise the existing owned catalog read and pre/post authority checks, then
// project BEFORE the graph persists/serializes the tool observation. No mutation
// or sanitization of the original catalog row; no rewriting of model responses.
function createPrototypeFixedSummaryTools(input) {
  if (input?.mode !== 'fixed' || input.operation !== 'summary'
      || (input.answerQuestion !== undefined && input.answerQuestion !== false)) {
    throw new TypeError('Prototype is Fixed Summarize only');
  }
  const original = createSecureShopBoundProductTools(input).get(TOOL);
  return new Map([[TOOL, async args => {
    const result = await original(args);
    const facts = projectFixedSummaryObservation(JSON.parse(result.content[0].text));
    return { content: [{ type: 'text', text: JSON.stringify(facts) }] };
  }]]);
}

function createPrototypeFixedSummaryConfig() {
  const original = createSecureShopProductExecutionConfig('summary', { mode: 'fixed' });
  const tools = Object.freeze(original.manifest.getForRole('customer').map(tool => Object.freeze({
    ...tool, description: 'Read only the selected product ID, catalog price and stock quantity. Descriptive text is withheld.',
  })));
  return Object.freeze({ ...original,
    manifest: Object.freeze({ getForRole: role => role === 'customer' ? tools : Object.freeze([]) }),
    buildBasePrompt(role) {
      if (role !== 'customer') throw new TypeError('Product assistant requires customer persona');
      return 'You are the product assistant for one isolated SecureShop launch. Use summarizer.summarize_product for the server-selected product. Summarize only its observed catalog price and stock quantity, identifying it by product ID. State that descriptive product text is withheld in this Fixed summary. Do not infer features, category, quality, compatibility, measurements or policies. Do not perform actions. Answer in plain text.';
    },
  });
}
module.exports = { TOOL, POLICY, projectFixedSummaryObservation,
  createPrototypeFixedSummaryTools, createPrototypeFixedSummaryConfig };
