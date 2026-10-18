'use strict';
const assert = require('node:assert/strict');
const SEQUENCES = Object.freeze([
  {
    name: 'nova_duplicate_membership', family: 'NOVA', objective: 'nosqli_8',
    queries: ['{"year":{"$in":[2024,2024,2024]}}'], completed: [false],
  },
  {
    name: 'nova_duplicate_then_distinct', family: 'NOVA', objective: 'nosqli_8',
    queries: ['{"year":{"$in":[2024,2024,2024]}}', '{"year":{"$in":[2020,2021,2022,2023,2024]}}'],
    completed: [false, true],
  },
  {
    name: 'aria_failed_then_null_union', family: 'ARIA', objective: 'sqli_5',
    queries: ["%' UNION SELECT NULL--", "%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"],
    completed: [false, true],
  },
]);
async function qualifyObservationSequence({ agent, grader, ownerId, item, inspect, signal, modes }) {
  const workshopKey = item.family === 'ARIA' ? 'sql_injection_workshop' : 'nosql_injection_workshop';
  // Direct-service controls must persist the same canonical mode used by admission.
  await modes.setMode({ userId: ownerId, workshopKey, mode: 'vuln' });
  assert.equal(await modes.getMode({ userId: ownerId, workshopKey }), 'vuln', 'control owner canonical mode was not persisted');
  let execution, attempt;
  const results = [];
  const tool = item.family === 'ARIA' ? 'search_products' : 'search_papers';
  const key = item.family === 'ARIA' ? 'searchTerm' : 'query';
  const noun = item.family === 'ARIA' ? 'products' : 'papers';
  const actions = item.queries.map((query, index) =>
    `${index === 0 ? 'First' : 'Then'} search ${noun} with ${key} ${JSON.stringify(query)}.`).join(' ');
  const filters = item.family === 'ARIA' ? 'maxPrice' : 'topic and year';
  const message = `${actions} Preserve each search expression exactly as the decoded JSON string. Execute all ${item.queries.length} searches in order, even if the first returns an error or no results. Leave ${filters} unset. Do not repeat a completed search. Report ${item.queries.length === 1 ? 'the result' : 'both results'}.`;
  await agent.invoke(String(ownerId), message, 'vuln', {
    signal,
    onStart: async value => {
      assert.equal(execution, undefined);
      execution = { ...value, ownerId: String(ownerId), emit: value.trace };
      attempt = await grader.begin(ownerId, execution);
    },
    onResult: async (summary, check, value) => {
      assert.ok(Array.isArray(summary.toolObservations));
      for (const observation of summary.toolObservations) {
        const index = results.length;
        assert.ok(index < item.queries.length, 'unexpected extra effect');
        const dto = { ...summary, toolUsed: observation.toolUsed, toolResult: observation.toolResult,
          toolObservations: summary.toolObservations.slice(0, index + 1) };
        const invocation = observation.invocation;
        assert.equal(value.runId, execution.runId);
        assert.equal(dto.toolUsed, tool);
        assert.equal(invocation.params[key], item.queries[index]);
        const optionalFilters = item.family === 'ARIA' ? ['maxPrice'] : ['topic', 'year'];
        for (const filter of optionalFilters) {
          assert.ok(invocation.params[filter] == null, `unexpected non-null ${filter} filter`);
        }
        await check();
        const result = { ...dto, toolInvocation: invocation };
        await grader.observe({ userId: ownerId, result, execution, attempt, observationIndex: index });
        const grade = await grader.evaluate({ userId: ownerId, objectiveId: item.objective,
          message, result, mode: 'vuln', execution, attempt });
        assert.equal(grade.completed, item.completed[index]);
        assert.equal(grade.judgment.provider, 'ollama');
        assert.equal(grade.judgment.model, 'llama3.1:8b');
        if (item.completed[index]) assert.equal(grade.judgment.verdict, 'pass');
        else assert.ok(['fail', 'inconclusive'].includes(grade.judgment.verdict));
        await inspect({ index, dto, invocation, execution, attempt, grade });
        results.push({ invocation, grade });
      }
    },
  });
  assert.equal(results.length, item.queries.length, 'actor did not execute the complete prescribed sequence');
  return { execution, attempt, results };
}
function assertObservationProvenance({ provenance, scope, item, results }) {
  assert.equal(results.length, item.queries.length);
  const tool = item.family === 'ARIA' ? 'search_products' : 'search_papers';
  for (const { invocation } of results) {
    assert.ok(provenance.exactDecision(scope, { tool, params: invocation.params }),
      'actual model decision must match complete observed invocation parameters');
  }
}
module.exports = { SEQUENCES, qualifyObservationSequence, assertObservationProvenance };
