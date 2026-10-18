'use strict';
// Controlled schema/combination harness only. No provider, database or credit writer.
const { createDpiWholeTurnComparison } = require('../../server/agent-runtime/dpiWholeTurnComparison');
function runControlledWholeTurn(spec, evidence, outputs) {
  if (!Array.isArray(outputs) || outputs.length > 4) throw Error('At most four controlled stage outputs');
  const comparison = createDpiWholeTurnComparison(spec, evidence), accepted = [], wires = [];
  let calls = 0;
  for (const stage of comparison.stages) {
    let value;
    for (let attempt = 0; attempt < stage.maximumCalls; attempt++) {
      if (calls >= comparison.policy.maximumCalls || calls >= outputs.length) break;
      wires.push(stage.messages());
      const raw = outputs[calls++];
      try { value = stage.validate(typeof raw === 'string' ? raw : JSON.stringify(raw)); break; } catch {}
    }
    if (!value) return { status: 'invalid-controlled-stage', calls, actualModelCalls: 0, creditWrites: 0, wires };
    accepted.push(value);
  }
  return { status: 'controlled-result', ...comparison.combine(...accepted), calls, actualModelCalls: 0, creditWrites: 0, wires };
}
module.exports = { runControlledWholeTurn };
