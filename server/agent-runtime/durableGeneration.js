'use strict';

// node-postgres returns bigint generations as decimal strings. Preserve their
// precision; numeric fixture/legacy values are accepted only when safe.
function canonicalDurableGeneration(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Invalid durable generation');
    return String(value);
  }
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value)
    || BigInt(value) > 9223372036854775807n) throw new TypeError('Invalid durable generation');
  return value;
}
module.exports = { canonicalDurableGeneration };
