'use strict';

const store = require('./postgres/xssWorkshopDb');

module.exports = {
  getSolutionsEnabled: () => store.getSolutionsEnabled(),
  setSolutionsEnabled: value => store.setSolutionsEnabled(value)
};
