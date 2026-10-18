const run = (db, sql, params = []) => new Promise((resolve, reject) =>
  db.run(sql, params, (error) => error ? reject(error) : resolve()));
const all = (db, sql, params = []) => new Promise((resolve, reject) =>
  db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows || [])));

async function ensureWorkshopConfigSchema(db) {
  await run(db, `CREATE TABLE IF NOT EXISTS workshop_config_revision (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(db, 'INSERT OR IGNORE INTO workshop_config_revision (id, revision) VALUES (1, 0)');
  await run(db, `CREATE TABLE IF NOT EXISTS app_change_revisions (
    scope_type TEXT NOT NULL CHECK (scope_type IN ('global', 'workshop', 'user')),
    scope_key TEXT NOT NULL,
    category TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scope_type, scope_key, category)
  )`);
  await run(db, `CREATE INDEX IF NOT EXISTS idx_app_change_revisions_scope
    ON app_change_revisions (scope_type, scope_key)`);
  await run(db, `CREATE TABLE IF NOT EXISTS workshop_user_modes (
    user_id TEXT NOT NULL,
    workshop_key TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('fixed', 'vuln', 'vulnerable')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, workshop_key)
  )`);
  await run(db, `CREATE TRIGGER IF NOT EXISTS workshop_user_modes_revision_insert
    AFTER INSERT ON workshop_user_modes
    BEGIN
      INSERT INTO app_change_revisions (scope_type, scope_key, category, revision)
      VALUES ('user', NEW.user_id, 'workshop_mode', 1)
      ON CONFLICT(scope_type, scope_key, category) DO UPDATE SET
        revision = revision + 1,
        updated_at = CURRENT_TIMESTAMP;
    END`);
  await run(db, `CREATE TRIGGER IF NOT EXISTS workshop_user_modes_revision_update
    AFTER UPDATE OF mode ON workshop_user_modes
    WHEN OLD.mode <> NEW.mode
    BEGIN
      INSERT INTO app_change_revisions (scope_type, scope_key, category, revision)
      VALUES ('user', NEW.user_id, 'workshop_mode', 1)
      ON CONFLICT(scope_type, scope_key, category) DO UPDATE SET
        revision = revision + 1,
        updated_at = CURRENT_TIMESTAMP;
    END`);
  const columns = await all(db, 'PRAGMA table_info(prompt_injection_solutions)');
  if (columns.length && !columns.some((column) => column.name === 'hints')) {
    await run(db, "ALTER TABLE prompt_injection_solutions ADD COLUMN hints TEXT DEFAULT '[]'");
  }
}

module.exports = { ensureWorkshopConfigSchema };
