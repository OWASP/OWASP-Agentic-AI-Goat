'use strict';
// Test-only: the real operation finishes successfully before its return is lost.
// This does not simulate a network break or prove that a server commit was uncertain.
function createSqlReturnSuppression(statement) {
  if (typeof statement !== 'string' || !statement.trim()) throw TypeError('Exact SQL statement required');
  let armed = false, consumed = false, delegated = 0, suppressed = 0;
  return Object.freeze({
    arm() { if (armed || consumed) throw Error('One-shot already armed or consumed'); armed = true; },
    wrapQuery(query) {
      if (typeof query !== 'function') throw TypeError('Real query delegate required');
      return async (...args) => {
        const selected = armed && args[0] === statement;
        // Claim before awaiting: concurrent matching queries cannot both suppress.
        if (selected) { armed = false; consumed = true; }
        const result = await query(...args);
        if (selected) {
          delegated++; suppressed++;
          throw Object.assign(Error('Controlled post-success SQL return suppression'), { code: 'TEST_SQL_RETURN_SUPPRESSED' });
        }
        return result;
      };
    },
    snapshot: () => Object.freeze({ armed, consumed, delegated, suppressed }),
  });
}
module.exports = { createSqlReturnSuppression };
