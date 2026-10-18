'use strict';
const express = require('express');
const json = express.json({ limit: '400kb' });
// JSON escaping can expand the permitted 64 KiB HTML string sixfold. Bound
// encoded transport here and decoded HTML in the controller before execution.
function csrfBrowserBody(req, res, next) {
  if (req.method !== 'POST') return next();
  if (!req.is('application/json')) return res.status(415).json({ error: 'Browser attempts require application/json.' });
  return json(req, res, error => {
    if (!error) return next();
    return res.status(error.type === 'entity.too.large' ? 413 : 400).json({ error: 'Invalid or oversized browser attempt JSON.' });
  });
}
module.exports = { csrfBrowserBody };
