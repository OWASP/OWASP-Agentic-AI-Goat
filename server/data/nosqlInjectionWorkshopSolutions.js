'use strict';

/**
 * NoSQL Injection Workshop — Solution content for all 10 objectives
 * Used to seed nosql_injection_solutions table in users_auth.db
 */
module.exports = {
  nosqli_1: {
    title: 'Trigger NoSQL Error',
    difficulty: 'Beginner',
    hints: [
      'Try sending malformed JSON operators in the search query',
      'Use an invalid MongoDB operator like {"$": "test"} as the search term',
    ],
    examples: [
      {
        payload: 'search for papers {"$": "test"}',
        explanation: 'A bare "$" key is an invalid MongoDB operator — triggers a parser/query error',
      },
    ],
    approach: 'Send a search query containing an invalid MongoDB operator to trigger a database-level syntax or parser error. The error response reveals that the backend is passing user input directly into a NoSQL query without sanitization.',
    tips: [
      'NoSQL errors often reveal the underlying database type (MongoDB, CouchDB, etc.)',
      'Error messages may expose internal query structure or field names',
      'This is the first step in understanding the injection surface',
    ],
  },

  nosqli_2: {
    title: 'Boolean Operator Bypass ($gt)',
    difficulty: 'Beginner',
    hints: [
      '$gt with an empty string matches all non-empty values',
      'Try wrapping the search value in {"$gt": ""} to bypass exact-match filters',
    ],
    examples: [
      {
        payload: 'search for papers {"title": {"$gt": ""}}',
        explanation: 'Returns all papers where title > "" (empty string), which is every paper — bypassing the title filter',
      },
    ],
    approach: 'Replace the expected string value with a MongoDB operator object using $gt (greater-than) and an empty string. Since every non-empty string is greater than "", this matches all documents.',
    tips: [
      '$gt, $lt, $gte, $lte, $ne are all common bypass operators',
      'This works when the backend passes user-supplied objects directly into the query without type validation',
      'Mitigation: validate that query parameters are strings, not objects',
    ],
  },

  nosqli_3: {
    title: 'Regex Wildcard Injection ($regex)',
    difficulty: 'Beginner',
    hints: [
      '$regex with .* matches any string',
      'Try {"$regex": ".*"} as the search value to match all documents',
    ],
    examples: [
      {
        payload: 'search for papers {"title": {"$regex": ".*"}}',
        explanation: 'The wildcard regex .* matches every possible title — returns all papers',
      },
    ],
    approach: 'Inject a $regex operator with a wildcard pattern (.* or .*) to match every document in the collection, bypassing any search filtering.',
    tips: [
      '$regex is case-sensitive by default — add $options: "i" for case-insensitive matching',
      'Regex injection can also exfiltrate data character-by-character for blind injection',
      'Example: {"$regex": "^A"} returns only docs starting with "A"',
    ],
  },

  nosqli_4: {
    title: 'Database Version Extraction', difficulty: 'Intermediate',
    hints: ['Request metadata through the simulated $where path using db.version().'],
    examples: [{ payload: 'search for papers {"$where":"db.version()"}', explanation: 'Returns the selected storage engine version and collection metadata.' }],
    approach: 'Inspect the returned metadata rather than assuming the MongoDB-style query syntax identifies the storage engine. This is an operator simulation.',
    tips: ['Compare the server-returned version and engine fields.'],
  },
  nosqli_5: {
    title: 'Collection Schema Extraction', difficulty: 'Intermediate',
    hints: ['Request field metadata with {"$where":"Object.keys(this)"}.'],
    examples: [{ payload: 'search for papers {"$where":"Object.keys(this)"}', explanation: 'Returns collection field names, types, and index metadata.' }],
    approach: 'Use the simulator metadata path to inspect the papers and authors fields. The workshop does not execute attacker JavaScript.',
    tips: ['Inspect the returned field definitions instead of inferring schema from ordinary paper rows.'],
  },

  nosqli_6: {
    title: 'Not-Equal Operator Bypass ($ne)',
    difficulty: 'Intermediate',
    hints: [
      '$ne means "not equal to"',
      'Use {"access_level": {"$ne": "restricted"}} — but also try {"$ne": null} to match all non-null values',
    ],
    examples: [
      {
        payload: 'search for papers {"access_level": {"$ne": "restricted"}}',
        explanation: 'Returns all papers where access_level is NOT "restricted" — reveals the access_level field and exposes non-restricted papers',
      },
    ],
    approach: 'Use the $ne (not-equal) operator to invert access control logic — instead of matching a specific allowed value, reject specific disallowed values. This bypasses equality-based access checks.',
    tips: [
      '$ne: null returns all documents where the field exists and has a non-null value',
      'Combine with $exists for comprehensive results: {"access_level": {"$ne": "restricted", "$exists": true}}',
      'Mitigation: use allowlist-based access control, never blocklist-based',
    ],
  },

  nosqli_7: {
    title: 'Where Clause Injection ($where)',
    difficulty: 'Advanced',
    hints: [
      '$where executes arbitrary JavaScript on the MongoDB server',
      'Use {"$where": "true"} as the simplest always-true condition',
    ],
    examples: [
      {
        payload: 'search for papers {"$where": "this.year > 2020"}',
        explanation: '$where executes JavaScript where "this" is the current document — allows arbitrary logic injection',
      },
    ],
    approach: 'Inject a $where operator containing JavaScript code. The code runs server-side against each document, allowing arbitrary logic including data leakage via timing attacks or error channels.',
    tips: [
      '$where runs for every document — can cause significant performance impact (DoS risk)',
      '$where is disabled by default in newer MongoDB versions with --noscripting flag',
      'Use "this.fieldName" to access document fields in the JavaScript expression',
      'Timing attacks: {"$where": "sleep(1000) || true"} to confirm injection is active',
    ],
  },

  nosqli_8: {
    title: 'Array Query Injection ($in)',
    difficulty: 'Advanced',
    hints: [
      '$in matches any value from an array',
      'Try {"year": {"$in": [2021, 2022, 2023, 2024]}} to retrieve papers from multiple years at once',
    ],
    examples: [
      {
        payload: 'search for papers {"year": {"$in": [2020, 2021, 2022, 2023, 2024]}}',
        explanation: '$in returns all papers from any of the listed years — bypassing single-value year filters',
      },
    ],
    approach: 'Use the $in operator to query multiple values simultaneously. This can extract data from ranges or bypass single-value equality filters by providing a list of acceptable values.',
    tips: [
      '$nin is the inverse — "not in array" — can also bypass blocklist filters',
      'Combine with other operators: {"year": {"$in": [2020, 2021]}, "access_level": {"$ne": "restricted"}}',
      'Large $in arrays can batch-extract data without multiple requests',
    ],
  },

  nosqli_9: {
    title: 'Extract Author Contact Data',
    difficulty: 'Advanced',
    hints: [
      'Target the authors collection with regex injection',
      'Try searching authors by email pattern: {"email": {"$regex": ".*@.*"}}',
    ],
    examples: [
      {
        payload: 'find authors {"email": {"$regex": ".*@.*"}}',
        explanation: 'Regex injection against the authors collection returns synthetic author email and profile records that normal paper search does not expose',
      },
    ],
    approach: 'Apply regex injection to the authors collection to extract synthetic email addresses, institutions, expertise, and biographies. Cross-collection injection demonstrates how a query flaw can expose contact and profile data outside the normal paper-search response.',
    tips: [
      'This fixture contains email, institution, expertise, and biography fields; it does not contain passwords, tokens, or API keys',
      'The injection technique is the same — only the collection/query type changes',
      'Look for fields beyond what is normally returned in API responses',
    ],
  },

  nosqli_10: {
    title: 'Extract Restricted Research Data',
    difficulty: 'Advanced',
    hints: [
      'Look for papers with restricted access levels using $ne',
      'Chain $ne and $exists to bypass the access_level check',
    ],
    examples: [
      {
        payload: 'search for papers {"access_level": {"$ne": "public"}, "title": {"$exists": true}}',
        explanation: 'Returns all non-public papers by rejecting the "public" access level — bypasses access control to expose restricted research',
      },
    ],
    approach: 'Chain the $ne operator (to reject the allowed "public" value) with $exists (to ensure results exist) to extract documents that should be restricted. This demonstrates how a single NoSQL injection can completely bypass access control.',
    tips: [
      'Real-world impact: classified research data, proprietary methods, PII in abstracts',
      'The root cause is treating user-supplied objects as query operators',
      'Fix: use an allowlist query builder that only accepts scalar values for search fields',
      'NEVER pass request body objects directly into MongoDB query objects',
    ],
  },
};

if (process.env.WORKSHOP_DATABASE_ENGINE === 'postgres') {
  module.exports = require('./postgres/nosqlInjectionWorkshopSolutions')(module.exports);
}
