'use strict';

const { MAX_CTF_HINTS } = require('../services/ctfHintState');
const MAX_INTEGER = 2147483647;
// Three hint purchases must fit the PostgreSQL integer penalty ledger.
const MAX_HINT_COST = Math.floor(MAX_INTEGER / MAX_CTF_HINTS);

function ctfHintConfigInput(req, res, next) {
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'Configuration must be an object' });
  }
  const isCost = /^ctf_hint_cost_[123]$/.test(body.key);
  if (!isCost && body.key !== 'ctf_hint_gating_attempts') return next();
  const value = typeof body.value === 'string' ? body.value.trim() : body.value;
  const maximum = isCost ? MAX_HINT_COST : MAX_INTEGER;
  if (!['string', 'number'].includes(typeof value)
      || (typeof value === 'string' && !/^\d+$/.test(value))
      || !Number.isSafeInteger(Number(value)) || Number(value) < 0 || Number(value) > maximum) {
    return res.status(400).json({ error: `Hint setting must be a whole number between 0 and ${maximum}` });
  }
  next();
}

module.exports = { ctfHintConfigInput, MAX_HINT_COST };
