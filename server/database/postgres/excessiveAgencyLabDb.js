'use strict';

const { randomUUID } = require('node:crypto');
const { createPool, withTransaction } = require('./index');
const { initialize, singleton } = require('./workshopSupport');
const { createExcessiveAgencyLabDb: createSeedFixture } = require('../excessiveAgencyLabDb');

const PERSONAS = ['alice', 'bob', 'charlie', 'dave', 'eve'];
let canonicalSeed;
function seedFixture() {
  if (canonicalSeed) return canonicalSeed;
  const fixture = createSeedFixture();
  canonicalSeed = {
    users: PERSONAS.map(id => fixture.getUser(id)),
    notes: fixture.getAllNotes(),
    orders: fixture.getAllOrders(),
  };
  return canonicalSeed;
}
function owner(value) {
  const id = String(value ?? '');
  if (!id || id.length > 200) throw new TypeError('Platform attendee is required');
  return id;
}
function mapUser(row) { return row ? { userId: row.user_id, username: row.username, password: row.password, email: row.email, role: row.role, createdAt: row.created_at.toISOString() } : null; }
function mapNote(row) { return row ? { id: row.id, ownerUserId: row.owner_user_id, title: row.title, body: row.body, createdAt: row.created_at.toISOString() } : null; }
function mapOrder(row) { return row ? { orderId: row.order_id, ownerUserId: row.owner_user_id, description: row.description, amountCents: row.amount_cents, status: row.status, refundableUntil: row.refundable_until?.toISOString() || null, createdAt: row.created_at.toISOString() } : null; }
function mapRefund(row) { return row ? { refundId: row.refund_id, orderId: row.order_id, amountCents: row.amount_cents, reason: row.reason, status: row.status, requestedBy: row.requested_by, createdAt: row.created_at.toISOString(), ...(row.updated_at ? { updatedAt: row.updated_at.toISOString() } : {}) } : null; }

async function seedAttendee(client, platformUserId, { restore = false } = {}) {
  const id = owner(platformUserId);
  const created = await client.query('INSERT INTO excessive_agency.attendees(platform_user_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING platform_user_id', [id]);
  // Opening a second worker must preserve the learner's mutations. The owner
  // insert and initial fixtures commit together; only explicit reset restores.
  if (!restore && created.rowCount === 0) return;
  const seed = seedFixture();
  for (const user of seed.users) await client.query(`INSERT INTO excessive_agency.users(platform_user_id,user_id,username,password,email,role,created_at)
    VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(platform_user_id,user_id) DO NOTHING`, [id,user.userId,user.username,user.password,user.email,user.role,user.createdAt]);
  for (const note of seed.notes) await client.query(`INSERT INTO excessive_agency.notes(platform_user_id,id,owner_user_id,title,body,created_at)
    VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(platform_user_id,id) DO NOTHING`, [id,note.id,note.ownerUserId,note.title,note.body,note.createdAt]);
  for (const order of seed.orders) await client.query(`INSERT INTO excessive_agency.orders(platform_user_id,order_id,owner_user_id,description,amount_cents,status,refundable_until,created_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(platform_user_id,order_id) DO NOTHING`, [id,order.orderId,order.ownerUserId,order.description,order.amountCents,order.status,order.refundableUntil,order.createdAt]);
}

function createPostgresExcessiveAgencyLabDb(pool, platformUserId) {
  const attendee = owner(platformUserId);
  const query = (text, params = []) => pool.query(text, [attendee, ...params]);
  return {
    engine: 'postgres', platformUserId: attendee,
    async ensureSeeded() { await withTransaction(pool, client => seedAttendee(client, attendee)); return this; },
    async getUser(userId) { return mapUser((await query('SELECT * FROM excessive_agency.users WHERE platform_user_id=$1 AND user_id=$2', [userId])).rows[0]); },
    async authenticateUser(username, password) { const user = mapUser((await query('SELECT * FROM excessive_agency.users WHERE platform_user_id=$1 AND username=$2 AND password=$3', [username,password])).rows[0]); return user ? {userId:user.userId,username:user.username,role:user.role}:null; },
    async getNote(noteId) { return mapNote((await query('SELECT * FROM excessive_agency.notes WHERE platform_user_id=$1 AND id=$2', [noteId])).rows[0]); },
    async getNotesByUser(userId) { return (await query('SELECT * FROM excessive_agency.notes WHERE platform_user_id=$1 AND owner_user_id=$2 ORDER BY created_at,id', [userId])).rows.map(mapNote); },
    async getAllNotes() { return (await query('SELECT * FROM excessive_agency.notes WHERE platform_user_id=$1 ORDER BY created_at,id')).rows.map(mapNote); },
    async deleteNote(noteId) { return (await query('DELETE FROM excessive_agency.notes WHERE platform_user_id=$1 AND id=$2', [noteId])).rowCount > 0; },
    async createNote(userId,title,body) { const row=(await query(`INSERT INTO excessive_agency.notes(platform_user_id,id,owner_user_id,title,body) VALUES($1,$2,$3,$4,$5) RETURNING *`,[`note-${userId}-${randomUUID()}`,userId,title,body])).rows[0];return mapNote(row); },
    async getOrder(orderId) { return mapOrder((await query('SELECT * FROM excessive_agency.orders WHERE platform_user_id=$1 AND order_id=$2',[orderId])).rows[0]); },
    async getOrdersByUser(userId) { return (await query('SELECT * FROM excessive_agency.orders WHERE platform_user_id=$1 AND owner_user_id=$2 ORDER BY created_at,order_id',[userId])).rows.map(mapOrder); },
    async getAllOrders() { return (await query('SELECT * FROM excessive_agency.orders WHERE platform_user_id=$1 ORDER BY created_at,order_id')).rows.map(mapOrder); },
    async createOrder(userId,description,amountCents) { const row=(await query(`INSERT INTO excessive_agency.orders(platform_user_id,order_id,owner_user_id,description,amount_cents,status,refundable_until) VALUES($1,$2,$3,$4,$5,'completed',now()+interval '30 days') RETURNING *`,[`order-${userId}-${randomUUID()}`,userId,description,amountCents])).rows[0];return mapOrder(row); },
    async cancelOrderWithRefund(data) {
      return withTransaction(pool, async client => {
        const current = (await client.query(
          'SELECT * FROM excessive_agency.orders WHERE platform_user_id=$1 AND order_id=$2 FOR UPDATE',
          [attendee, data.orderId],
        )).rows[0];
        if (!current) return { success: false, code: 'ORDER_NOT_FOUND' };
        if (current.status !== 'completed') {
          return { success: false, code: 'ORDER_NOT_CANCELLABLE', order: mapOrder(current) };
        }
        const order = (await client.query(
          "UPDATE excessive_agency.orders SET status='cancelled' WHERE platform_user_id=$1 AND order_id=$2 RETURNING *",
          [attendee, data.orderId],
        )).rows[0];
        const refund = (await client.query(
          `INSERT INTO excessive_agency.refunds(platform_user_id,refund_id,order_id,amount_cents,reason,status,requested_by)
           VALUES($1,$2,$3,$4,$5,'approved',$6) RETURNING *`,
          [attendee, `refund-${randomUUID()}`, order.order_id, order.amount_cents, data.reason, data.requestedBy],
        )).rows[0];
        return { success: true, order: mapOrder(order), refund: mapRefund(refund) };
      });
    },
    async createRefund(data) { const row=(await query(`INSERT INTO excessive_agency.refunds(platform_user_id,refund_id,order_id,amount_cents,reason,status,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,[`refund-${randomUUID()}`,data.orderId,data.amountCents,data.reason,data.status||'pending',data.requestedBy])).rows[0];return mapRefund(row); },
    async getRefund(refundId) { return mapRefund((await query('SELECT * FROM excessive_agency.refunds WHERE platform_user_id=$1 AND refund_id=$2',[refundId])).rows[0]); },
    async getRefundsByOrder(orderId) { return (await query('SELECT * FROM excessive_agency.refunds WHERE platform_user_id=$1 AND order_id=$2 ORDER BY created_at',[orderId])).rows.map(mapRefund); },
    async getRefundsByUser(userId) { return (await query(`SELECT r.* FROM excessive_agency.refunds r JOIN excessive_agency.orders o ON o.platform_user_id=r.platform_user_id AND o.order_id=r.order_id WHERE r.platform_user_id=$1 AND o.owner_user_id=$2 ORDER BY r.created_at`,[userId])).rows.map(mapRefund); },
    async getAllRefunds() { return (await query('SELECT * FROM excessive_agency.refunds WHERE platform_user_id=$1 ORDER BY created_at')).rows.map(mapRefund); },
    async updateRefundStatus(refundId,status) { return mapRefund((await query('UPDATE excessive_agency.refunds SET status=$3,updated_at=now() WHERE platform_user_id=$1 AND refund_id=$2 RETURNING *',[refundId,status])).rows[0]); },
    async addAuditEntry(entry) { const row=(await query(`INSERT INTO excessive_agency.audit_log(platform_user_id,session_user_id,acted_as,tool_name,args,authorization_decision,result,lab_mode,scenario) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,[entry.sessionUserId,entry.actedAs,entry.toolName,JSON.stringify(entry.args||{}),entry.authorizationDecision,JSON.stringify(entry.result||{}),entry.labMode,entry.scenario])).rows[0];return {id:String(row.id),timestamp:row.created_at.toISOString(),...entry}; },
    async getAuditLog(filters={}) { const params=[],conditions=['platform_user_id=$1'];if(filters.sessionUserId){params.push(filters.sessionUserId);conditions.push(`session_user_id=$${params.length+1}`);}if(filters.toolName){params.push(filters.toolName);conditions.push(`tool_name=$${params.length+1}`);}if(filters.authorizationDecision){params.push(filters.authorizationDecision);conditions.push(`authorization_decision=$${params.length+1}`);}return (await query(`SELECT * FROM excessive_agency.audit_log WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC,id DESC LIMIT 1000`,params)).rows.map(row=>({id:String(row.id),timestamp:row.created_at.toISOString(),sessionUserId:row.session_user_id,actedAs:row.acted_as,toolName:row.tool_name,args:row.args,authorizationDecision:row.authorization_decision,result:row.result,labMode:row.lab_mode,scenario:row.scenario})); },
    async clearAuditLog() { await query('DELETE FROM excessive_agency.audit_log WHERE platform_user_id=$1'); },
    async getUserProgress() { const rows=(await query('SELECT objective_id,completed_at FROM excessive_agency.progress WHERE platform_user_id=$1')).rows;const progress={objectives:Object.fromEntries(Array.from({length:9},(_,i)=>[i+1,false])),completedAt:{}};for(const row of rows){progress.objectives[row.objective_id]=true;progress.completedAt[row.objective_id]=row.completed_at.toISOString();}return progress; },
    async markObjectiveComplete(_progressKey,objectiveId) { if(!Number.isInteger(Number(objectiveId))||objectiveId<1||objectiveId>9)throw new TypeError('Unknown Excessive Agency objective');await query('INSERT INTO excessive_agency.progress(platform_user_id,objective_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[Number(objectiveId)]);return this.getUserProgress(); },
    async resetUserProgress() { await query('DELETE FROM excessive_agency.progress WHERE platform_user_id=$1');return this.getUserProgress(); },
    async resetAllUserProgress() { return this.resetUserProgress(); },
    async getCompletedObjectivesCount() { return Number((await query('SELECT count(*)::integer AS count FROM excessive_agency.progress WHERE platform_user_id=$1')).rows[0].count); },
    async getStats() { const row=(await query(`SELECT (SELECT count(*) FROM excessive_agency.users WHERE platform_user_id=$1)::integer users,(SELECT count(*) FROM excessive_agency.notes WHERE platform_user_id=$1)::integer notes,(SELECT count(*) FROM excessive_agency.orders WHERE platform_user_id=$1)::integer orders,(SELECT count(*) FROM excessive_agency.refunds WHERE platform_user_id=$1)::integer refunds,(SELECT count(*) FROM excessive_agency.audit_log WHERE platform_user_id=$1)::integer "auditEntries"`)).rows[0];return row; },
    async reset() { await withTransaction(pool,async client=>{await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[attendee]);for(const table of ['refunds','audit_log','progress','conversations','notes','orders'])await client.query(`DELETE FROM excessive_agency.${table} WHERE platform_user_id=$1`,[attendee]);await seedAttendee(client,attendee,{restore:true});});return this; },
    async createSession(token,labUserId) { await query('INSERT INTO excessive_agency.sessions(token,platform_user_id,lab_user_id) VALUES($2,$1,$3) ON CONFLICT(platform_user_id,token) DO UPDATE SET lab_user_id=EXCLUDED.lab_user_id',[token,labUserId]); },
    async resolveSession(token) { const row=(await query(`SELECT s.token,u.user_id,u.username,u.role FROM excessive_agency.sessions s JOIN excessive_agency.users u USING(platform_user_id) WHERE s.platform_user_id=$1 AND s.token=$2 AND u.user_id=s.lab_user_id`,[token])).rows[0];return row?{platformUserId:attendee,labUser:{userId:row.user_id,username:row.username,role:row.role}}:null; },
    async deleteSession(token) { await query('DELETE FROM excessive_agency.sessions WHERE platform_user_id=$1 AND token=$2',[token]); },
    conversations:{
      async get(userId){return (await query('SELECT messages FROM excessive_agency.conversations WHERE platform_user_id=$1 AND lab_user_id=$2',[userId])).rows[0]?.messages||undefined;},
      async set(userId,messages){await query(`INSERT INTO excessive_agency.conversations(platform_user_id,lab_user_id,messages) VALUES($1,$2,$3) ON CONFLICT(platform_user_id,lab_user_id) DO UPDATE SET messages=EXCLUDED.messages,updated_at=now()`,[userId,JSON.stringify(messages)]);},
      async delete(userId){await query('DELETE FROM excessive_agency.conversations WHERE platform_user_id=$1 AND lab_user_id=$2',[userId]);},
      async clear(){await query('DELETE FROM excessive_agency.conversations WHERE platform_user_id=$1');},
    },
  };
}

function createExcessiveAgencyDatabaseManager(pool) {
  return {
    forAttendee(platformUserId) { return createPostgresExcessiveAgencyLabDb(pool, platformUserId); },
    async initialize(migrationPool) { await initialize(pool,migrationPool,'excessive_agency',async()=>{}); },
    async resetAllProgress() { await pool.query('DELETE FROM excessive_agency.progress'); },
    // Account deletion primitive: caller must first fence the attendee's graph.
    // Unlike reset(), this removes the attendee and never recreates fixtures.
    async destroyAttendee(platformUserId) {
      const attendee = owner(platformUserId);
      return withTransaction(pool, async client => {
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [attendee]);
        const result = await client.query('DELETE FROM excessive_agency.attendees WHERE platform_user_id=$1', [attendee]);
        return { removed: result.rowCount };
      });
    },
    async resetAll() { await pool.query('DELETE FROM excessive_agency.attendees'); },
    async activeSessionCount() { return Number((await pool.query('SELECT count(*)::integer count FROM excessive_agency.sessions')).rows[0].count); },
  };
}
const lazy=singleton(createExcessiveAgencyDatabaseManager,'EXCESSIVE_AGENCY_DATABASE_URL');
async function initializeExcessiveAgencyLabDb(){const migration=createPool(process.env,'EXCESSIVE_AGENCY_MIGRATION_DATABASE_URL');try{await lazy('initialize')(migration);}finally{await migration.end();}}
module.exports={createPostgresExcessiveAgencyLabDb,createExcessiveAgencyDatabaseManager,initializeExcessiveAgencyLabDb,forAttendee:lazy('forAttendee'),destroyAttendee:lazy('destroyAttendee'),resetAllProgress:lazy('resetAllProgress'),resetAll:lazy('resetAll'),activeSessionCount:lazy('activeSessionCount')};
