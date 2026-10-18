 'use strict';

// This legacy route uses browser templates, not a model or an objective Judge.
// Describe only the database observation; a query returning rows is not proof
// of disclosure, ownership, a timing channel, or a second statement's effect.
function describeLegacySqlResult(attackType, results) {
  const count = Array.isArray(results) ? results.length : 0;
  const observed = `The SQL query returned ${count} row(s).`;
  const notes = {
    union: 'Inspect the returned fields to determine what the UNION exposed; row presence alone does not prove sensitive-data disclosure.',
    boolean_blind: 'A nonempty result is an observation, not a verified TRUE/FALSE inference. Compare controlled true and false conditions.',
    time_blind: 'This template does not introduce or measure a database delay, so it does not demonstrate time-based extraction.',
    error_based: 'No database error was returned for this attempt; error-based disclosure has not been established.',
    stacked: 'This response does not verify that an additional statement ran or changed data.',
    nosql: 'This is a SQL-backed simulation, not execution by a NoSQL database.',
  };
  return `${observed} ${notes[attackType] || 'Review the returned records; this response does not establish that they belong to your account.'}`;
}
function legacySqlEducationalNote(attackType, engine) {
  const base = 'This legacy demo constructs queries from templates; no LLM decision or objective Judge is used.';
  const notes = {
    union: 'UNION operands must have compatible column counts and types. Compare the baseline and injected results.',
    boolean_blind: 'Use paired controlled conditions before drawing an inference from row presence.',
    time_blind: 'The shipped template has no intentional delay and is not a timing-channel experiment.',
    error_based: 'The shipped error template uses MySQL syntax; PostgreSQL or SQLite rejection does not prove disclosure.',
    stacked: engine === 'postgres' ? 'The PostgreSQL adapter uses extended query mode, which rejects multiple statements in one query.' : 'Multiple-statement execution and its effects are not verified by this demo.',
    nosql: 'MongoDB-style concepts are illustrated using SQL; no MongoDB server executes this request.',
  };
  return `${base} ${notes[attackType] || 'User-influenced SQL is deliberately executed as a teaching sink.'}`;
}
module.exports = { describeLegacySqlResult, legacySqlEducationalNote };
