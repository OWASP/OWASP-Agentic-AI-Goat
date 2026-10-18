'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { projectCanonicalSensitiveProgress } = require('../server/services/sensitiveInfoProgressProjection');

test('canonical enabled rows determine progress order, labels and totals without restoring disabled objectives', () => {
  const result = projectCanonicalSensitiveProgress({ objectives: [
    { id: 'llm_identify', label: 'Instructor identity objective', completed: true, completedAt: '2026-09-14T00:00:00Z' },
    { id: 'tool_enum', label: 'Instructor enumeration objective', completed: false },
  ] }, [
    { id: 'tool_enum', label: 'Old label', desc: 'Describe the tools' },
    { id: 'disabled', label: 'Disabled objective', desc: 'Must not return' },
  ]);
  assert.deepEqual(result, { success: true, completedCount: 1, total: 2, progress: [
    { id: 'llm_identify', label: 'Instructor identity objective', desc: '', completed: true, completed_at: '2026-09-14T00:00:00Z' },
    { id: 'tool_enum', label: 'Instructor enumeration objective', desc: 'Describe the tools', completed: false, completed_at: null },
  ] });
});
test('zero enabled objectives stays empty and unavailable canonical progress cannot fall back to static totals', () => {
  assert.deepEqual(projectCanonicalSensitiveProgress({ objectives: [] }, [{ id: 'disabled' }]),
    { success: true, progress: [], completedCount: 0, total: 0 });
  assert.throws(() => projectCanonicalSensitiveProgress(null), /Canonical/);
});
