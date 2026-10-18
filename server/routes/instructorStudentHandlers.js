'use strict';

function createStudentToggleHandler(authDb) {
  return (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    const { studentId } = req.params;
    const { enabled } = req.body || {};
    if (!/^[1-9]\d*$/.test(String(studentId)) || !Number.isSafeInteger(Number(studentId)) || typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'A valid student ID and boolean enabled are required' });
    }
    // This legacy endpoint manages students only, never administrators or self.
    authDb.run(`UPDATE users SET is_active = ? WHERE id = ? AND role IN ('student', 'user')
      AND COALESCE(admin_level, 0) = 0 AND id != ?`, [enabled ? 1 : 0, studentId, req.user.id], function(error) {
      if (error) return res.status(500).json({ error: 'Unable to update student' });
      if (!this.changes) return res.status(404).json({ error: 'Student not found or not eligible' });
      return res.json({ success: true, message: `Student ${enabled ? 'enabled' : 'disabled'} successfully`, studentId, enabled });
    });
  };
}

module.exports = { createStudentToggleHandler };
