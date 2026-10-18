const Database = require('better-sqlite3');

module.exports = function seed(dbPath) {
  const db = new Database(dbPath);

  // Pre-register one legitimate external MCP server (safe filesystem-mcp scoped to product_manuals/)
  db.prepare(`
    INSERT OR IGNORE INTO mcp_registry (name, url, transport, stdio_cmd, status, added_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    'filesystem-mcp',
    null,
    'stdio',
    'npx -y @modelcontextprotocol/server-filesystem ./server/uploads/secureshop/product_manuals',
    'unknown',
    null
  );

  // Vector index metadata rows so meta queries have something to read
  for (const corpus of ['reviews','manuals','policies','products']) {
    db.prepare(`INSERT OR IGNORE INTO vector_index_meta (corpus, dim, count, embedder_model) VALUES (?, ?, 0, ?)`)
      .run(corpus, 768, 'nomic-embed-text');
  }

  // Provider state — default to ollama for all three roles
  for (const role of ['customer','merchant','admin']) {
    db.prepare(`INSERT OR IGNORE INTO agent_provider_state (role, active_provider) VALUES (?, ?)`)
      .run(role, 'ollama');
  }

  db.close();
  console.log('  \u2713 seed 18_secureshop_agents.js applied');
};
