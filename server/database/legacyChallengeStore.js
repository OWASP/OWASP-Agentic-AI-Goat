'use strict';

const store = require('./postgres/legacyChallengeDb');

const methods = [
  'getVulnerabilitySetting',
  'listVulnerabilitySettings',
  'saveConversation',
  'readConversations',
  'searchProducts',
  'searchCommerceProducts',
  'readDemoUser',
  'readProduct',
  'readReviews',
  'addComment',
  'listComments',
  'addFile',
  'addManagedFile',
  'addReview',
  'readCart',
  'countCart',
  'addCart',
  'createOrder',
  'moveOrderItems',
  'clearCart',
  'readOrders',
  'updateDemoProfile',
  'executeAiSql',
  'executeNoSqlSimulation'
];

module.exports = {
  engine: 'postgres',
  ...Object.fromEntries(methods.map(name => [name, (...args) => {
    const callback = typeof args.at(-1) === 'function' ? args.pop() : null;
    const promise = store[name](...args);

    if (callback) {
      promise.then(
        value => callback.call(value || {}, null, value),
        error => callback(error)
      );
      return;
    }

    return promise;
  }]))
};
