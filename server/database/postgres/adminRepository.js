'use strict';

const { withTransaction } = require('./index');
const validation = require('./identityValidation');
const { workshopSurfaceSqlCondition } = require('../../config/workshopCatalog');

const publicColumns = `id,username,email,role,admin_level,full_name,phone,department,
  email_verified,is_active,account_locked_until,login_attempts,last_login,last_login_ip,
  created_at,updated_at`;
const completedDeletionExclusion = `NOT EXISTS (
  SELECT 1 FROM identity.student_deletion_jobs deletion
  WHERE deletion.subject_user_id=u.id AND deletion.state='completed'
)`;

function page(input, fallback = 20, maximum = 200) {
  const value = Number.parseInt(input, 10);
  return Number.isInteger(value) && value > 0 ? Math.min(value, maximum) : fallback;
}

function createPostgresAdminRepository(pool) {
  if (!pool?.query) throw new TypeError('PostgreSQL pool is required');

  async function revokeActiveSessions(client, userId, reason) {
    return (await client.query(`UPDATE identity.user_sessions SET is_active=0,
      revoked_at=COALESCE(revoked_at,clock_timestamp()),revoke_reason=$2
      WHERE user_id=$1 AND is_active=1`, [userId, reason])).rowCount;
  }

  // All paths that can remove administrator authority take the same transaction
  // lock. A row lock on the target alone cannot protect two different final admins.
  async function lockAdministration(client) {
    await client.query('SELECT pg_advisory_xact_lock(1743921, 1)');
  }

  async function requireActor(client, actor, level = 1) {
    if (!actor?.id || !actor?.sessionId) throw Object.assign(new Error('Administrator session required'), { statusCode: 403 });
    const authority = await client.query(`SELECT 1 FROM identity.users actor
      JOIN identity.user_sessions session ON session.user_id=actor.id
      JOIN identity.admin_permissions permission ON permission.admin_id=actor.id
      WHERE actor.id=$1 AND session.id=$2 AND actor.role IN ('admin','super_admin')
        AND actor.admin_level >= $3 AND actor.is_active=1
        AND (actor.account_locked_until IS NULL OR actor.account_locked_until<=clock_timestamp())
        AND session.is_active=1 AND session.expires_at>clock_timestamp()
        AND permission.permission_name='user_management' AND permission.is_active=1
        AND (permission.expires_at IS NULL OR permission.expires_at>clock_timestamp())
      FOR SHARE OF actor,session,permission`, [actor.id, actor.sessionId, level]);
    if (!authority.rowCount) throw Object.assign(new Error('Administrator authority changed'), { statusCode: 403 });
  }

  async function requireAdministratorContinuity(client) {
    const result = await client.query(`SELECT
      count(*) FILTER (WHERE role IN ('admin','super_admin') AND admin_level>0 AND is_active=1)::integer AS active_admins,
      count(*) FILTER (WHERE role IN ('admin','super_admin') AND admin_level=2 AND is_active=1
        AND (account_locked_until IS NULL OR account_locked_until<=clock_timestamp())
        AND EXISTS (SELECT 1 FROM identity.admin_permissions permission
          WHERE permission.admin_id=identity.users.id AND permission.permission_name='user_management'
            AND permission.is_active=1 AND permission.expires_at IS NULL))::integer AS managers
      FROM identity.users`);
    const { active_admins, managers } = result.rows[0];
    if (Number(active_admins) < 1 || Number(managers) < 1) {
      throw Object.assign(new Error('At least one active administrator with user management authority is required'),
        { statusCode: 409, code: 'LAST_ADMIN' });
    }
  }

  async function updateAccount(userId, input, actor, { studentOnly = false } = {}) {
    const id = validation.id(Number(userId));
    return withTransaction(pool, async client => {
      await lockAdministration(client);
      if (typeof actor === 'object') await requireActor(client, actor);
      const current=(await client.query('SELECT * FROM identity.users WHERE id=$1 FOR UPDATE',[id])).rows[0];
      if(!current || (studentOnly && (current.role !== 'student' || current.admin_level !== 0)))return null;
      if ((await client.query('SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=$1',
        [id])).rowCount) return null;
      if (studentOnly && ((input.role !== undefined && input.role !== 'student')
          || (input.adminLevel !== undefined && input.adminLevel !== 0))) {
        throw Object.assign(new Error('Student updates cannot assign administrator privileges'), { code: 'BAD_REQUEST' });
      }
      const role=input.role ?? current.role;
      const adminLevel=input.adminLevel ?? current.admin_level;
      const actorLevel = typeof actor === 'object' ? actor.level : actor;
      if (typeof actor === 'object' && (current.admin_level > 0 || role !== current.role || adminLevel !== current.admin_level)) {
        await requireActor(client, actor, 2);
      }
      if (current.admin_level > 0 && actorLevel < 2)
        throw Object.assign(new Error('Only super admins can modify administrators'), { statusCode: 403 });
      if((role!==current.role || adminLevel!==current.admin_level) && actorLevel<2)
        throw Object.assign(new Error('Only super admins can modify roles or admin levels'),{statusCode:403});
      if(!((role==='student' && adminLevel===0) || (role==='admin' && [1,2].includes(adminLevel)) || (role==='super_admin' && adminLevel===2)))
        throw Object.assign(new Error('Role and administrator level must be consistent'),{code:'BAD_REQUEST'});
      const field=(camel,snake)=>input[camel]!==undefined?input[camel]:input[snake]!==undefined?input[snake]:current[snake];
      const flag=(value)=>{if(![true,false,0,1].includes(value))throw Object.assign(new Error('Account flags must be boolean'),{code:'BAD_REQUEST'});return value?1:0;};
      const values=[input.username??current.username,input.email??current.email,field('fullName','full_name'),role,adminLevel,
        input.department??current.department,input.phone??current.phone,flag(field('isActive','is_active')),flag(field('emailVerified','email_verified')),id];
      const updated = (await client.query(`UPDATE identity.users SET username=$1,email=$2,full_name=$3,role=$4,
        admin_level=$5,department=$6,phone=$7,is_active=$8,email_verified=$9,updated_at=now()
        WHERE id=$10 RETURNING ${publicColumns}`,values)).rows[0];
      if (!updated.is_active) await revokeActiveSessions(client, id, 'account_deactivated');
      else if (updated.role !== current.role || updated.admin_level !== current.admin_level) {
        await revokeActiveSessions(client, id, 'account_authority_changed');
      }
      if (current.admin_level > 0 || updated.admin_level > 0) await requireAdministratorContinuity(client);
      return updated;
    });
  }

  return {
    async clearOldActivityLogs() {
      // Administrative retention affects activity history only, never audit receipts,
      // sessions, exercise data or canonical objective completions.
      return Number((await pool.query('SELECT identity.clear_old_activity_logs() AS removed')).rows[0].removed);
    },
    async listStudents() {
      const result = await pool.query(`SELECT ${publicColumns} FROM identity.users u
        WHERE role='student' AND ${completedDeletionExclusion} ORDER BY created_at DESC,id DESC`);
      return result.rows;
    },

    async getStudent(userId) {
      return (await pool.query(`SELECT ${publicColumns} FROM identity.users u
        WHERE id=$1 AND role='student' AND admin_level=0 AND ${completedDeletionExclusion}`,
      [validation.id(Number(userId))])).rows[0] || null;
    },

    async getMutableStudent(userId) {
      return (await pool.query(`SELECT ${publicColumns} FROM identity.users u
        WHERE id=$1 AND role='student' AND admin_level=0 AND NOT EXISTS (
          SELECT 1 FROM identity.student_deletion_jobs deletion
          WHERE deletion.subject_user_id=u.id
        )`, [validation.id(Number(userId))])).rows[0] || null;
    },

    async listUsers({ page: pageInput, limit: limitInput, search = '', role = '', includeInactive = false } = {}) {
      const currentPage = page(pageInput, 1, 100000);
      const limit = page(limitInput);
      const offset = (currentPage - 1) * limit;
      const searchTerm = String(search || '').trim();
      const roleName = String(role || '').trim();
      const result = await pool.query(`WITH selected_users AS (
        SELECT ${publicColumns},count(*) OVER()::integer AS result_total
        FROM identity.users WHERE ($5::boolean OR is_active=1)
          AND ($1='' OR username ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%' OR full_name ILIKE '%'||$1||'%')
          AND ($2='' OR ($2='administrators' AND admin_level>0) OR role=$2)
        ORDER BY created_at DESC,id DESC LIMIT $3 OFFSET $4
      )
      SELECT selected_users.*,
        COALESCE((SELECT array_agg(permission_name ORDER BY permission_name)
          FROM identity.admin_permissions p WHERE p.admin_id=selected_users.id AND p.is_active=1
            AND (p.expires_at IS NULL OR p.expires_at>clock_timestamp())), ARRAY[]::text[]) AS permissions,
        COALESCE(activity.recent_activity_count,0)::integer AS recent_activity_count,
        COALESCE(workshops.total_challenges,0)::integer AS total_challenges,
        COALESCE(workshops.completed_challenges,0)::integer AS completed_challenges,
        CASE WHEN COALESCE(workshops.total_challenges,0)=0 THEN 0 ELSE
          round(100.0*workshops.completed_challenges/workshops.total_challenges)::integer END AS progress_percentage
      FROM selected_users
      LEFT JOIN LATERAL (
        SELECT count(*)::integer AS recent_activity_count FROM identity.activity_logs
        WHERE user_id=selected_users.id AND timestamp>clock_timestamp()-interval '30 days'
      ) activity ON true
      LEFT JOIN LATERAL (
        SELECT count(*)::integer AS total_challenges,
          count(*) FILTER (WHERE enabled_objectives>0 AND completed_objectives=enabled_objectives)::integer AS completed_challenges
        FROM (
          SELECT CASE WHEN e.workshop_key='xss_email_builder' THEN 'xss_workshop'
            ELSE e.workshop_key END AS workshop_key,
            count(o.objective_id)::integer AS enabled_objectives,
            count(c.objective_id)::integer AS completed_objectives
          FROM workshop_platform.exercises e
          LEFT JOIN workshop_platform.objectives o ON o.workshop_key=e.workshop_key
            AND o.catalog_active=true AND o.is_enabled=true
          LEFT JOIN workshop_platform.completions c ON c.user_id=selected_users.id
            AND c.workshop_key=o.workshop_key AND c.objective_id=o.objective_id
          WHERE e.catalog_active=true AND e.is_visible=true AND ${workshopSurfaceSqlCondition('e.workshop_key')}
          GROUP BY CASE WHEN e.workshop_key='xss_email_builder' THEN 'xss_workshop'
            ELSE e.workshop_key END
        ) visible_workshops
      ) workshops ON true
      ORDER BY selected_users.created_at DESC,selected_users.id DESC`, [searchTerm, roleName, limit, offset,
        includeInactive === true || includeInactive === 'true']);
      const total = result.rows[0]?.result_total || 0;
      return { users: result.rows.map(({ result_total, ...user }) => user), pagination: {
        page: currentPage, limit, total, pages: Math.ceil(total / limit),
      } };
    },

    async listLockedUsers() {
      return (await pool.query(`SELECT ${publicColumns},
        CASE WHEN account_locked_until >= timestamptz '2099-01-01' THEN 'admin' ELSE 'auto' END AS lock_type
        FROM identity.users WHERE account_locked_until>clock_timestamp() OR login_attempts>=5
        ORDER BY account_locked_until DESC NULLS LAST,login_attempts DESC,id`)).rows;
    },

    async getUser(userId) {
      const id = validation.id(Number(userId));
      const user = (await pool.query(`SELECT ${publicColumns} FROM identity.users WHERE id=$1`, [id])).rows[0];
      if (!user) return null;
      const [activity, permissions] = await Promise.all([
        pool.query('SELECT * FROM identity.activity_logs WHERE user_id=$1 ORDER BY timestamp DESC,id DESC LIMIT 20', [id]),
        pool.query(`SELECT p.*,u.username AS granted_by_username FROM identity.admin_permissions p
          LEFT JOIN identity.users u ON u.id=p.granted_by WHERE p.admin_id=$1 ORDER BY p.granted_at DESC,p.id DESC`, [id]),
      ]);
      return { user, activities: activity.rows, permissions: permissions.rows };
    },

    async updateUser(userId, input, actor = 0) {
      return updateAccount(userId, input, actor);
    },

    async updateStudent(userId, input, actor = 0) {
      return updateAccount(userId, input, actor, { studentOnly: true });
    },

    async setStudentActive({ userId, enabled }) {
      if (typeof enabled !== 'boolean') throw Object.assign(new Error('enabled must be a boolean'), { code: 'BAD_REQUEST' });
      const id = validation.id(Number(userId));
      return withTransaction(pool, async client => {
        const student = (await client.query(`SELECT id FROM identity.users
          WHERE id=$1 AND role='student' AND admin_level=0 FOR UPDATE`, [id])).rows[0];
        if (!student) return null;
        if ((await client.query('SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=$1',
          [id])).rowCount) return null;
        const updated = (await client.query(`UPDATE identity.users SET is_active=$1,updated_at=now()
          WHERE id=$2 RETURNING ${publicColumns}`, [enabled ? 1 : 0, id])).rows[0];
        if (!enabled) await revokeActiveSessions(client, id, 'account_deactivated');
        return updated;
      });
    },

    async setUserLock({ userId, locked, actorId, actorUsername, ipAddress, sessionId }) {
      return withTransaction(pool, async client => {
        await lockAdministration(client);
        if (sessionId) await requireActor(client, { id: actorId, sessionId }, 1);
        const id = validation.id(Number(userId));
        const user = (await client.query('SELECT id,admin_level FROM identity.users WHERE id=$1 FOR UPDATE', [id])).rows[0];
        if (!user || (await client.query(
          'SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=$1', [id])).rowCount) return null;
        if (user.admin_level > 0) {
          if (!sessionId) throw Object.assign(new Error('Administrator session required'), { statusCode: 403 });
          await requireActor(client, { id: actorId, sessionId }, 2);
        }
        const result = await client.query(`UPDATE identity.users SET
          account_locked_until=CASE WHEN $1 THEN timestamptz '2099-12-31 23:59:59Z' ELSE NULL END,
          login_attempts=CASE WHEN $1 THEN login_attempts ELSE 0 END,updated_at=now()
          WHERE id=$2 RETURNING ${publicColumns}`, [Boolean(locked), id]);
        if (!result.rowCount) return null;
        if (locked) await revokeActiveSessions(client, id, 'account_locked');
        if (user.admin_level > 0) await requireAdministratorContinuity(client);
        await client.query(`INSERT INTO identity.activity_logs(user_id,action_type,action_details,ip_address)
          VALUES($1,$2,$3::jsonb,$4)`, [actorId, locked ? 'admin_lock_user' : 'admin_unlock_user',
          JSON.stringify({ targetUserId: id, [locked ? 'lockedBy' : 'unlockedBy']: actorUsername }), ipAddress || null]);
        return result.rows[0];
      });
    },

    async createUser({ username, email, passwordHash, fullName = null, role = 'student', adminLevel = 0 }) {
      validation.hash(passwordHash);
      const result = await pool.query(`INSERT INTO identity.users(username,email,password,full_name,role,admin_level,email_verified)
        VALUES($1,$2,$3,$4,$5,$6,1) RETURNING ${publicColumns}`,
      [username, email, passwordHash, fullName, role, adminLevel]);
      return result.rows[0];
    },

    async createAdministrator({ username, email, passwordHash, fullName = null, adminLevel, permissions,
      actorId, sessionId, ipAddress = null }) {
      validation.hash(passwordHash);
      validation.id(actorId);
      validation.id(sessionId);
      if (![1, 2].includes(adminLevel) || !Array.isArray(permissions) || !permissions.length ||
          new Set(permissions).size !== permissions.length ||
          permissions.some(permission => !validation.PERMISSIONS.has(permission) || permission === 'database_access')) {
        throw Object.assign(new Error('Invalid administrator level or permissions'), { code: 'BAD_REQUEST' });
      }
      return withTransaction(pool, async client => {
        await requireActor(client, { id: actorId, sessionId }, 2);
        const user = (await client.query(`INSERT INTO identity.users(username,email,password,full_name,role,admin_level,email_verified)
          VALUES($1,$2,$3,$4,'admin',$5,1) RETURNING ${publicColumns}`,
        [username, email, passwordHash, fullName, adminLevel])).rows[0];
        for (const permission of permissions) {
          await client.query(`INSERT INTO identity.admin_permissions(admin_id,permission_name,granted_by)
            VALUES($1,$2,$3)`, [user.id, permission, actorId]);
        }
        await client.query(`INSERT INTO identity.activity_logs(user_id,action_type,action_details,ip_address)
          VALUES($1,'admin_administrator_created',$2::jsonb,$3)`, [actorId,
          JSON.stringify({ targetUserId: user.id, adminLevel, permissions }), ipAddress]);
        return user;
      });
    },

    async updateAdministrator({ userId, input = {}, actorId, sessionId, ipAddress = null }) {
      const id = validation.id(Number(userId));
      const allowed = new Set(['username', 'email', 'fullName', 'adminLevel', 'permissions', 'isActive']);
      if (!input || typeof input !== 'object' || Array.isArray(input) ||
          !Object.keys(input).length || Object.keys(input).some(key => !allowed.has(key))) {
        throw Object.assign(new Error('Invalid administrator update'), { code: 'BAD_REQUEST' });
      }
      const username = input.username === undefined ? undefined :
        (typeof input.username === 'string' ? input.username.trim() : null);
      const email = input.email === undefined ? undefined :
        (typeof input.email === 'string' ? input.email.trim() : null);
      const fullName = input.fullName === undefined ? undefined :
        (input.fullName === null || input.fullName === '' ? null :
          (typeof input.fullName === 'string' ? input.fullName.trim() : false));
      if ((username !== undefined && (username === null || username.length < 3 || username.length > 50)) ||
          (email !== undefined && (email === null || email.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) ||
          (fullName !== undefined && fullName !== null && (typeof fullName !== 'string' || !fullName || fullName.length > 200)) ||
          (input.adminLevel !== undefined && ![1, 2].includes(input.adminLevel)) ||
          (input.isActive !== undefined && typeof input.isActive !== 'boolean') ||
          (input.permissions !== undefined && (!Array.isArray(input.permissions) || !input.permissions.length ||
            new Set(input.permissions).size !== input.permissions.length ||
            input.permissions.some(permission => !validation.PERMISSIONS.has(permission) || permission === 'database_access')))) {
        throw Object.assign(new Error('Invalid administrator account details'), { code: 'BAD_REQUEST' });
      }
      return withTransaction(pool, async client => {
        await lockAdministration(client);
        await requireActor(client, { id: actorId, sessionId }, 2);
        const current = (await client.query(`SELECT * FROM identity.users WHERE id=$1 FOR UPDATE`, [id])).rows[0];
        if (!current || !['admin', 'super_admin'].includes(current.role) || current.admin_level < 1) return null;
        const updated = (await client.query(`UPDATE identity.users SET username=$1,email=$2,full_name=$3,
          admin_level=$4,is_active=$5,role=$7,updated_at=now() WHERE id=$6 RETURNING ${publicColumns}`,
        [username ?? current.username, email ?? current.email, fullName === undefined ? current.full_name : fullName,
          input.adminLevel ?? current.admin_level, input.isActive === undefined ? current.is_active : Number(input.isActive),
          id, input.adminLevel === 1 ? 'admin' : current.role])).rows[0];
        if (input.permissions) {
          await client.query(`UPDATE identity.admin_permissions SET is_active=0
            WHERE admin_id=$1 AND NOT (permission_name=ANY($2::text[]))`, [id, input.permissions]);
          for (const permission of input.permissions) {
            await client.query(`INSERT INTO identity.admin_permissions(admin_id,permission_name,granted_by,is_active,expires_at)
              VALUES($1,$2,$3,1,NULL) ON CONFLICT(admin_id,permission_name)
              DO UPDATE SET is_active=1,expires_at=NULL`, [id, permission, actorId]);
          }
        }
        await requireAdministratorContinuity(client);
        if (!updated.is_active || input.adminLevel !== undefined && input.adminLevel !== current.admin_level ||
            input.permissions !== undefined) {
          await revokeActiveSessions(client, id, updated.is_active ? 'account_authority_changed' : 'account_deactivated');
        }
        await client.query(`INSERT INTO identity.activity_logs(user_id,action_type,action_details,ip_address)
          VALUES($1,$2,$3::jsonb,$4)`, [actorId,
          updated.is_active ? 'admin_administrator_updated' : 'admin_administrator_deactivated',
          JSON.stringify({ targetUserId: id, fields: Object.keys(input) }), ipAddress]);
        const permissions = (await client.query(`SELECT permission_name FROM identity.admin_permissions
          WHERE admin_id=$1 AND is_active=1 AND (expires_at IS NULL OR expires_at>clock_timestamp())
          ORDER BY permission_name`, [id])).rows.map(row => row.permission_name);
        return { user: updated, permissions };
      });
    },

    async deactivateAdministrator({ userId, actorId, sessionId, ipAddress = null }) {
      return this.updateAdministrator({ userId, input: { isActive: false }, actorId, sessionId, ipAddress });
    },

    async deleteUser(userId) {
      return (await pool.query("DELETE FROM identity.users WHERE id=$1 AND role='student' AND admin_level=0 RETURNING id", [validation.id(Number(userId))])).rows[0] || null;
    },

    async listPermissions() {
      return (await pool.query(`SELECT p.*,u.username,u.full_name,g.username AS granted_by_username
        FROM identity.admin_permissions p JOIN identity.users u ON u.id=p.admin_id
        LEFT JOIN identity.users g ON g.id=p.granted_by ORDER BY p.granted_at DESC,p.id DESC`)).rows;
    },

    async grantPermission({ userId, permission, actorId, sessionId, expiresAt = null, ipAddress = null }) {
      const id = validation.id(Number(userId));
      if (!validation.PERMISSIONS.has(permission) || permission === 'database_access') {
        throw Object.assign(new Error('Invalid administrator permission'), { code: 'BAD_REQUEST' });
      }
      const expiry = expiresAt == null || expiresAt === '' ? null : validation.timestamp(expiresAt);
      if (expiry && new Date(expiry).getTime() <= Date.now()) {
        throw Object.assign(new Error('Permission expiry must be in the future'), { code: 'BAD_REQUEST' });
      }
      return withTransaction(pool, async client => {
        await lockAdministration(client);
        await requireActor(client, { id: actorId, sessionId }, 2);
        const target = (await client.query(`SELECT id FROM identity.users WHERE id=$1
          AND role IN ('admin','super_admin') AND admin_level>0 FOR UPDATE`, [id])).rows[0];
        if (!target) return null;
        const granted = (await client.query(`INSERT INTO identity.admin_permissions
          (admin_id,permission_name,granted_by,expires_at,is_active)
          VALUES($1,$2,$3,$4,1) ON CONFLICT(admin_id,permission_name)
          DO UPDATE SET granted_by=EXCLUDED.granted_by,expires_at=EXCLUDED.expires_at,
            is_active=1,granted_at=now() RETURNING id`, [id, permission, actorId, expiry])).rows[0];
        await requireAdministratorContinuity(client);
        await revokeActiveSessions(client, id, 'account_authority_changed');
        await client.query(`INSERT INTO identity.activity_logs(user_id,action_type,action_details,ip_address)
          VALUES($1,'admin_permission_granted',$2::jsonb,$3)`, [actorId,
          JSON.stringify({ targetUserId: id, permission, expiresAt: expiry }), ipAddress]);
        return granted;
      });
    },

    async revokePermissionById(permissionId, actor = null) {
      return withTransaction(pool, async client => {
        await lockAdministration(client);
        if (actor) await requireActor(client, actor, 2);
        const permission = (await client.query(`SELECT p.id,p.admin_id,p.permission_name,u.admin_level
          FROM identity.admin_permissions p JOIN identity.users u ON u.id=p.admin_id
          WHERE p.id=$1 FOR UPDATE OF p`, [validation.id(Number(permissionId))])).rows[0];
        if (!permission) return null;
        const result = (await client.query('UPDATE identity.admin_permissions SET is_active=0 WHERE id=$1 RETURNING id',
          [permission.id])).rows[0];
        if (permission.admin_level > 0) {
          await requireAdministratorContinuity(client);
          await revokeActiveSessions(client, permission.admin_id, 'account_authority_changed');
        }
        return result;
      });
    },

    async listConfig() {
      return (await pool.query('SELECT config_key,config_value,config_type,is_public FROM identity.system_config ORDER BY config_key')).rows;
    },

    async setConfig(configKey, value, type = 'string', isPublic = false) {
      const key = validation.text(configKey, 'config key', 100);
      return (await pool.query(`INSERT INTO identity.system_config(config_key,config_value,config_type,is_public)
        VALUES($1,$2,$3,$4) ON CONFLICT(config_key) DO UPDATE SET
        config_value=EXCLUDED.config_value,config_type=EXCLUDED.config_type,is_public=EXCLUDED.is_public
        RETURNING config_key,config_value,config_type,is_public`, [key, String(value), String(type), Boolean(isPublic)])).rows[0];
    },

    async listActivity({ limit: limitInput = 100, page: pageInput = 1, userId, actionType } = {}) {
      const limit = page(limitInput, 100, 500), currentPage = page(pageInput, 1, 100000), offset = (currentPage - 1) * limit;
      const uid = userId ? validation.id(Number(userId)) : null;
      const action = String(actionType || '');
      const result = await pool.query(`SELECT l.*,u.username,count(*) OVER()::integer AS result_total
        FROM identity.activity_logs l LEFT JOIN identity.users u ON u.id=l.user_id
        WHERE ($1::integer IS NULL OR l.user_id=$1) AND ($2='' OR l.action_type=$2)
        ORDER BY l.timestamp DESC,l.id DESC LIMIT $3 OFFSET $4`, [uid, action, limit, offset]);
      const total = result.rows[0]?.result_total || 0;
      return { logs: result.rows.map(({ result_total, ...row }) => row), pagination: {
        page: currentPage, limit, total, pages: Math.ceil(total / limit),
      } };
    },

    async dashboardStats() {
      return (await pool.query(`SELECT
        count(*) FILTER(WHERE u.is_active=1)::integer AS total_users,
        count(*) FILTER(WHERE u.role='student' AND u.is_active=1)::integer AS total_students,
        count(*) FILTER(WHERE u.admin_level>0 AND u.is_active=1)::integer AS total_admins,
        count(*) FILTER(WHERE u.role='student' AND u.is_active=1
          AND u.last_login>CURRENT_TIMESTAMP-interval '24 hours')::integer AS active_students_24h,
        count(*) FILTER(WHERE u.role='student' AND u.is_active=1
          AND u.created_at>CURRENT_TIMESTAMP-interval '24 hours')::integer AS new_students_24h,
        count(*) FILTER(WHERE u.role='student' AND u.is_active=1 AND EXISTS(
          SELECT 1 FROM workshop_platform.completions c
          JOIN workshop_platform.objectives o ON o.workshop_key=c.workshop_key AND o.objective_id=c.objective_id
          JOIN workshop_platform.exercises e ON e.workshop_key=c.workshop_key
          WHERE c.user_id=u.id AND e.catalog_active=true AND e.is_visible=true AND ${workshopSurfaceSqlCondition('e.workshop_key')}
            AND o.catalog_active=true AND o.is_enabled=true
        ))::integer AS students_with_completions,
        24::integer AS activity_window_hours
        FROM identity.users u`)).rows[0];
    },

    async activityStats() {
      return (await pool.query(`SELECT
        count(*) FILTER(WHERE action_type IN ('user_login','login','login_success') AND success=1)::integer AS successful_logins,
        count(*) FILTER(WHERE action_type IN ('login_failed','login_fail') AND success=0)::integer AS failed_logins,
        count(*) FILTER(WHERE action_type='challenge_complete' AND success=1 AND timestamp::date=current_date)::integer AS challenge_completions,
        count(*)::integer AS total_activity,count(DISTINCT user_id)::integer AS active_users
        FROM identity.activity_logs WHERE timestamp>clock_timestamp()-interval '24 hours'`)).rows[0];
    },

    async llmAuditStats() {
      return (await pool.query(`SELECT count(*)::integer AS total_requests,
        count(*) FILTER(WHERE success=1)::integer AS successful_requests,
        COALESCE(avg(success),0)::float AS success_rate
        FROM identity.activity_logs WHERE action_type LIKE '%llm%'
          AND timestamp>clock_timestamp()-interval '24 hours'`)).rows[0];
    },

    async aiStatsByDay() {
      return (await pool.query(`SELECT timestamp::date::text AS date,count(*)::integer AS total_requests,
        count(*) FILTER(WHERE COALESCE(action_details->>'model',action_details->>'provider','') ILIKE '%fallback%')::integer AS fallback_requests,
        count(*) FILTER(WHERE COALESCE(action_details->>'model',action_details->>'provider','') ILIKE '%ollama%'
          OR COALESCE(action_details->>'model','') ILIKE '%llama%')::integer AS ollama_requests,
        count(*) FILTER(WHERE COALESCE(action_details->>'model',action_details->>'provider','') ILIKE '%claude%'
          OR COALESCE(action_details->>'model','') ILIKE '%anthropic%')::integer AS claude_requests,
        count(*) FILTER(WHERE COALESCE(action_details->>'model',action_details->>'provider','') ILIKE '%gpt%'
          OR COALESCE(action_details->>'model',action_details->>'provider','') ILIKE '%openai%')::integer AS openai_requests
        FROM identity.activity_logs WHERE action_type LIKE '%llm%' AND timestamp>=current_date-interval '7 days'
        GROUP BY timestamp::date ORDER BY timestamp::date DESC`)).rows;
    },

    async listAllSolutions({ includeStandaloneApps = false } = {}) {
      return (await pool.query(`SELECT e.workshop_key,e.challenge_key,e.challenge_name,e.category,
        o.objective_id,o.label,o.solution_enabled,o.solution_content
        FROM workshop_platform.exercises e JOIN workshop_platform.objectives o USING(workshop_key)
        WHERE e.catalog_active=true AND ${includeStandaloneApps ? 'true' : workshopSurfaceSqlCondition('e.workshop_key')} AND o.catalog_active=true AND o.solution_content IS NOT NULL
        ORDER BY e.ordinal,o.ordinal`)).rows;
    },

    async listExercisesWithStats({ groupDisplay = false, includeStandaloneApps = false } = {}) {
      if (groupDisplay) {
        // Dashboard counts use one row for the XSS page. The admin exercise
        // editor still reads the individual canonical rows below.
        return (await pool.query(`WITH ranked AS (
          SELECT e.workshop_key,
            CASE WHEN e.workshop_key='xss_email_builder' THEN 'xss_workshop'
              ELSE e.workshop_key END AS display_key,
            row_number() OVER (PARTITION BY CASE WHEN e.workshop_key='xss_email_builder'
              THEN 'xss_workshop' ELSE e.workshop_key END
              ORDER BY e.is_visible DESC,(e.workshop_key='xss_workshop') DESC,e.ordinal) AS display_rank
          FROM workshop_platform.exercises e WHERE e.catalog_active=true AND ${includeStandaloneApps ? 'true' : workshopSurfaceSqlCondition('e.workshop_key')}
        )
        SELECT e.*,
          (SELECT count(*)::integer FROM identity.users u
            WHERE u.role='student' AND u.is_active=1 AND EXISTS (
              SELECT 1 FROM workshop_platform.user_state s
              JOIN ranked member ON member.workshop_key=s.workshop_key
              JOIN workshop_platform.exercises member_ex ON member_ex.workshop_key=member.workshop_key
              WHERE member.display_key=representative.display_key AND member_ex.is_visible=true
                AND s.user_id=u.id AND s.started_at IS NOT NULL)) AS students_attempted,
          (SELECT count(*)::integer FROM identity.users u
            WHERE u.role='student' AND u.is_active=1
              AND EXISTS (SELECT 1 FROM workshop_platform.objectives o
                JOIN ranked member ON member.workshop_key=o.workshop_key
                JOIN workshop_platform.exercises member_ex ON member_ex.workshop_key=member.workshop_key
                WHERE member.display_key=representative.display_key AND member_ex.is_visible=true
                  AND o.catalog_active=true AND o.is_enabled=true)
              AND NOT EXISTS (SELECT 1 FROM workshop_platform.objectives o
                JOIN ranked member ON member.workshop_key=o.workshop_key
                JOIN workshop_platform.exercises member_ex ON member_ex.workshop_key=member.workshop_key
                WHERE member.display_key=representative.display_key AND member_ex.is_visible=true
                  AND o.catalog_active=true AND o.is_enabled=true
                  AND NOT EXISTS (SELECT 1 FROM workshop_platform.completions c
                    WHERE c.user_id=u.id AND c.workshop_key=o.workshop_key
                      AND c.objective_id=o.objective_id))) AS students_completed
        FROM ranked representative
        JOIN workshop_platform.exercises e ON e.workshop_key=representative.workshop_key
        WHERE representative.display_rank=1 ORDER BY e.ordinal`)).rows;
      }
      return (await pool.query(`SELECT e.*,
        (SELECT count(*)::integer FROM workshop_platform.user_state s
          JOIN identity.users u ON u.id=s.user_id
          WHERE s.workshop_key=e.workshop_key AND s.started_at IS NOT NULL
            AND u.role='student' AND u.is_active=1) AS students_attempted,
        (SELECT count(*)::integer FROM identity.users u
          WHERE u.role='student' AND u.is_active=1
          AND EXISTS(SELECT 1 FROM workshop_platform.objectives o WHERE o.workshop_key=e.workshop_key AND o.catalog_active=true AND o.is_enabled=true)
          AND NOT EXISTS(SELECT 1 FROM workshop_platform.objectives o WHERE o.workshop_key=e.workshop_key AND o.catalog_active=true AND o.is_enabled=true
            AND NOT EXISTS(SELECT 1 FROM workshop_platform.completions c WHERE c.user_id=u.id AND c.workshop_key=o.workshop_key AND c.objective_id=o.objective_id))) AS students_completed
        FROM workshop_platform.exercises e WHERE e.catalog_active=true AND ${includeStandaloneApps ? 'true' : workshopSurfaceSqlCondition('e.workshop_key')} ORDER BY e.ordinal`)).rows;
    },

    async listSolutionObjectives(workshopKey) {
      return (await pool.query(`SELECT objective_id,label AS title,
        COALESCE(solution_content->>'difficulty','') AS difficulty,hint_content,solution_content,
        solution_enabled AS solutions_enabled FROM workshop_platform.objectives
        WHERE workshop_key=$1 AND catalog_active=true ORDER BY ordinal`, [workshopKey])).rows;
    },
  };
}

module.exports = { createPostgresAdminRepository };
