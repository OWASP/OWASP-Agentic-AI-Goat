'use strict';
const { Store } = require('express-session');
const { createTeachingSessionIds } = require('./teachingSessionId');

function unavailable() {
  return Object.assign(new Error('Teaching session storage unavailable'), { code: 'TEACHING_SESSION_STORAGE_UNAVAILABLE' });
}
function positive(value) {
  if (!['number', 'string'].includes(typeof value) || !/^[1-9][0-9]*$/.test(String(value))
      || !Number.isSafeInteger(Number(value))) throw unavailable();
  return Number(value);
}
function serialize(session) {
  const ownerId = positive(session?.platformOwnerId), sessionId = positive(session?.platformSessionId);
  if (positive(session?.userId) !== ownerId || !session?.cookie || typeof session.cookie !== 'object') throw unavailable();
  const payload = JSON.stringify(session);
  if (Buffer.byteLength(payload) > 60000) throw unavailable();
  return { ownerId, sessionId, payload };
}
class PostgresTeachingSessionStore extends Store {
  constructor({ pool, effectPool, secret, now }) {
    super();
    if (typeof pool?.connect !== 'function') throw new TypeError('PostgreSQL pool required');
    if (effectPool !== undefined && (typeof effectPool?.connect !== 'function' || effectPool === pool)) {
      throw new TypeError('Teaching effects require a separate bounded connection pool');
    }
    this.pool = pool;
    this.effectPool = effectPool;
    this.ids = createTeachingSessionIds({ secret, ...(now ? { now } : {}) });
    this.genid = () => this.ids.generate();
  }
  async transaction(work, pool = this.pool) {
    const client = await pool.connect();
    let discard = false;
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => { discard = true; });
      throw error;
    } finally { client.release(discard); }
  }
  finish(promise, callback, missingOnRevocation = false) {
    promise.then(value => callback?.(null, value), error => {
      if (missingOnRevocation && error?.code === '55000') return callback?.(null, null);
      callback?.(unavailable());
    });
  }
  async #authority(sid, binding, work, pool) {
    const key = this.ids.decode(sid);
    if (!key || typeof work !== 'function') throw Object.assign(unavailable(), { code: '55000' });
    const ownerId = positive(binding?.ownerId), sessionId = positive(binding?.sessionId);
    return this.transaction(async client => {
      await client.query('SELECT identity.assert_legacy_platform_mutation($1,$2)', [ownerId, sessionId]);
      const row = (await client.query(`SELECT session_hash FROM identity.teaching_sessions
        WHERE session_hash=$1 AND owner_id=$2 AND platform_session_id=$3
          AND NOT revoked AND expires_at>clock_timestamp() FOR SHARE`, [key.hash, ownerId, sessionId])).rows[0];
      if (!row) throw Object.assign(unavailable(), { code: '55000' });
      const result = await work();
      if (!this.ids.decode(sid)) throw Object.assign(unavailable(), { code: '55000' });
      await client.query('SELECT identity.assert_legacy_platform_mutation($1,$2)', [ownerId, sessionId]);
      const current = (await client.query(`SELECT session_hash FROM identity.teaching_sessions
        WHERE session_hash=$1 AND NOT revoked AND expires_at>clock_timestamp()`, [key.hash])).rows[0];
      if (!current) throw Object.assign(unavailable(), { code: '55000' });
      return result;
    }, pool);
  }
  withAuthority(sid, binding, work) {
    if (!this.effectPool) throw new TypeError('Teaching effect lease pool is not configured');
    return this.#authority(sid, binding, work, this.effectPool);
  }
  assertSession(sid, binding) { return this.#authority(sid, binding, async () => {}, this.pool); }
  async pruneExpired(limit = 500) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('Bounded session cleanup limit required');
    return this.transaction(async client => (await client.query(`DELETE FROM identity.teaching_sessions WHERE session_hash IN
      (SELECT session_hash FROM identity.teaching_sessions WHERE expires_at<=clock_timestamp()
        ORDER BY expires_at,session_hash LIMIT $1 FOR UPDATE SKIP LOCKED)`, [limit])).rowCount);
  }
  get(sid, callback) {
    const key = this.ids.decode(sid);
    if (!key) return callback(null, null);
    this.finish(this.transaction(async client => {
      const row = (await client.query(`SELECT owner_id,platform_session_id,payload FROM identity.teaching_sessions
        WHERE session_hash=$1 AND NOT revoked AND expires_at>clock_timestamp()`, [key.hash])).rows[0];
      if (!row) return null;
      await client.query('SELECT identity.assert_legacy_platform_mutation($1,$2)', [row.owner_id, row.platform_session_id]);
      return row.payload;
    }), callback, true);
  }
  set(sid, session, callback) {
    let key, data;
    try { key = this.ids.decode(sid); if (!key) throw unavailable(); data = serialize(session); }
    catch { return callback?.(unavailable()); }
    this.finish(this.transaction(async client => {
      await client.query('SELECT identity.assert_legacy_platform_mutation($1,$2)', [data.ownerId, data.sessionId]);
      const result = await client.query(`INSERT INTO identity.teaching_sessions
        (session_hash,owner_id,platform_session_id,payload,expires_at)
        SELECT $1,$2,$3,$4::jsonb,$5 WHERE $5::timestamptz>clock_timestamp()
        ON CONFLICT(session_hash) DO UPDATE SET payload=EXCLUDED.payload,updated_at=clock_timestamp()
        WHERE NOT teaching_sessions.revoked AND teaching_sessions.expires_at>clock_timestamp()
          AND teaching_sessions.owner_id=EXCLUDED.owner_id
          AND teaching_sessions.platform_session_id=EXCLUDED.platform_session_id
        RETURNING session_hash`, [key.hash, data.ownerId, data.sessionId, data.payload, key.expiresAt]);
      if (result.rowCount !== 1) throw unavailable();
    }), callback);
  }
  destroy(sid, callback) {
    const key = this.ids.decode(sid);
    if (!key) return callback?.(null);
    this.finish(this.transaction(client => client.query(`INSERT INTO identity.teaching_sessions
      (session_hash,payload,expires_at,revoked) VALUES($1,NULL,$2,true)
      ON CONFLICT(session_hash) DO UPDATE SET payload=NULL,revoked=true,updated_at=clock_timestamp()`,
    [key.hash, key.expiresAt])), callback);
  }
  touch(sid, session, callback) {
    let key, data;
    try { key = this.ids.decode(sid); if (!key) throw unavailable(); data = serialize(session); }
    catch { return callback?.(unavailable()); }
    this.finish(this.transaction(async client => {
      await client.query('SELECT identity.assert_legacy_platform_mutation($1,$2)', [data.ownerId, data.sessionId]);
      const result = await client.query(`UPDATE identity.teaching_sessions SET updated_at=clock_timestamp()
        WHERE session_hash=$1 AND owner_id=$2 AND platform_session_id=$3 AND NOT revoked
          AND expires_at>clock_timestamp()`, [key.hash, data.ownerId, data.sessionId]);
      if (result.rowCount !== 1) throw Object.assign(unavailable(), { code: '55000' });
    // express-session touches after completing a response. Concurrent canonical
    // revocation is an expected no-op here, not a storage outage. It never
    // restores a row or grants authority; real database failures still fail.
    }), callback, true);
  }
}
module.exports = { PostgresTeachingSessionStore };
