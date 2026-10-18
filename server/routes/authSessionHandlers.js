'use strict';

function createAuthSessionHandlers({ authDb, authenticateToken }) {
  const status = (req, res) => authenticateToken(req, {
    status(code) {
      return { json() {
        if (code >= 500) return res.status(code).json({ authenticated: false, reason: 'session_store_unavailable' });
        return res.json({ authenticated: false, reason: 'no_valid_session' });
      } };
    },
  }, () => {
    const user = req.user;
    const token = req.headers.authorization?.split(' ')[1];
    authDb.get('SELECT expires_at, last_activity FROM user_sessions WHERE session_token = ? AND user_id = ?',
      [token, user.id], (error, session) => {
        if (error) return res.status(503).json({ authenticated: false, reason: 'session_store_unavailable' });
        if (!session) return res.json({ authenticated: false, reason: 'no_valid_session' });
        authDb.all(`SELECT permission_name FROM admin_permissions WHERE admin_id = ? AND is_active = 1
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`, [user.id], (permissionError, permissions) => {
          if (permissionError) return res.status(503).json({ authenticated: false, reason: 'session_store_unavailable' });
          return res.json({ authenticated: true, user: {
            id: user.id, username: user.username, email: user.email, role: user.role,
            adminLevel: user.admin_level || 0, fullName: user.full_name,
            emailVerified: user.email_verified || 0, isAdmin: (user.admin_level || 0) > 0,
            permissions: permissions.map(row => row.permission_name), lastLogin: user.last_login,
          }, sessionInfo: { expiresAt: session.expires_at, lastActivity: session.last_activity } });
        });
      });
  });

  const logout = (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const clearSession = () => {
      const finish = error => {
        if (error) return res.status(500).json({ error: 'Unable to clear session' });
        res.clearCookie('connect.sid');
        res.clearCookie('token');
        return res.json({ success: true, message: 'Logged out successfully', timestamp: new Date().toISOString() });
      };
      if (req.session?.destroy) req.session.destroy(finish);
      else finish();
    };
    if (!token) return clearSession();
    // Acknowledge only after durable revocation; missing tokens remain invalid.
    authDb.run('UPDATE user_sessions SET is_active = 0 WHERE session_token = ?', [token], error => {
      if (error) return res.status(503).json({ error: 'Unable to revoke session; retry logout' });
      return clearSession();
    });
  };
  return { status, logout };
}

function createPasswordChangeHandler({ authDb, bcrypt, validatePassword }) {
  const { get, withImmediateTransaction } = require('../database/sqliteTransaction');
  return async (req, res) => {
    if (!req.user?.id) return res.status(401).json({ error: 'Not authenticated' });
    const { currentPassword, newPassword } = req.body || {};
    if (typeof currentPassword !== 'string' || !currentPassword || typeof newPassword !== 'string' || !newPassword) {
      return res.status(400).json({ error: 'Current and new passwords are required' });
    }
    const validation = validatePassword(newPassword);
    if (!validation.valid) return res.status(400).json({ error: validation.error });
    try {
      const user = await get(authDb, 'SELECT password FROM users WHERE id = ?', [req.user.id]);
      if (!user) return res.status(401).json({ error: 'Not authenticated' });
      if (!await bcrypt.compare(currentPassword, user.password)) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }
      const hash = await bcrypt.hash(newPassword, 12);
      await withImmediateTransaction(authDb, async tx => {
        // Compare-and-swap rejects an older password rotation racing this one.
        const result = await tx.run('UPDATE users SET password = ? WHERE id = ? AND password = ?',
          [hash, req.user.id, user.password]);
        if (result.changes !== 1) throw new Error('Password changed concurrently');
        await tx.run('UPDATE user_sessions SET is_active = 0 WHERE user_id = ?', [req.user.id]);
      });
      return res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
      return res.status(500).json({ error: 'Failed to update password' });
    }
  };
}

module.exports = { createAuthSessionHandlers, createPasswordChangeHandler };
