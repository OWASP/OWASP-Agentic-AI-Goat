#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const draftDir = __dirname;
const root = path.resolve(draftDir, '../../..');
const snapshotPath = path.join(draftDir, 'finflow_log_default_content_snapshots.json');
const sqlPath = path.join(draftDir, 'finflow_llm_request_log_default_content_guarded.sql');
const snapshots = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
const { solutions } = require(path.join(root, 'server/data/sensitiveInfoSolutions'));
const hints = require(path.join(root, 'server/data/workshopHints')).sensitive_info_disclosure;

const solutionIds = ['admin_read_logs', 'admin_llm_logs', 'admin_modify_logs'];
for (const id of solutionIds) {
  assert.deepEqual(snapshots.new.solutions[id], solutions[id], `current solution snapshot: ${id}`);
  assert.ok(snapshots.old.solutions[id], `historical solution snapshot: ${id}`);
}
assert.deepEqual(snapshots.new.hints.admin_llm_logs, hints.admin_llm_logs, 'current LLM hint snapshot');
assert.ok(snapshots.old.hints.admin_llm_logs, 'historical LLM hint snapshot');

function block(name, column, objectiveId, oldValue, newValue) {
  const oldTag = `old_${name}`;
  const newTag = `new_${name}`;
  return `${name}_changed AS (\n  UPDATE workshop_platform.objectives\n  SET ${column}=$${newTag}$${JSON.stringify(newValue)}$${newTag}$::jsonb,\n      updated_at=now()\n  WHERE workshop_key='sensitive_info_disclosure'\n    AND objective_id='${objectiveId}'\n    AND ${column}=$${oldTag}$${JSON.stringify(oldValue)}$${oldTag}$::jsonb\n  RETURNING 1\n)`;
}

function llmContentBlock() {
  const oldSolution = JSON.stringify(snapshots.old.solutions.admin_llm_logs);
  const newSolution = JSON.stringify(snapshots.new.solutions.admin_llm_logs);
  const oldHint = JSON.stringify(snapshots.old.hints.admin_llm_logs);
  const newHint = JSON.stringify(snapshots.new.hints.admin_llm_logs);
  return `admin_llm_logs_content_changed AS (\n  UPDATE workshop_platform.objectives\n  SET solution_content=CASE\n        WHEN solution_content=$old_admin_llm_logs_solution$${oldSolution}$old_admin_llm_logs_solution$::jsonb\n        THEN $new_admin_llm_logs_solution$${newSolution}$new_admin_llm_logs_solution$::jsonb\n        ELSE solution_content END,\n      hint_content=CASE\n        WHEN hint_content=$old_admin_llm_logs_hint$${oldHint}$old_admin_llm_logs_hint$::jsonb\n        THEN $new_admin_llm_logs_hint$${newHint}$new_admin_llm_logs_hint$::jsonb\n        ELSE hint_content END,\n      updated_at=now()\n  WHERE workshop_key='sensitive_info_disclosure'\n    AND objective_id='admin_llm_logs'\n    AND (solution_content=$old_admin_llm_logs_solution$${oldSolution}$old_admin_llm_logs_solution$::jsonb\n      OR hint_content=$old_admin_llm_logs_hint$${oldHint}$old_admin_llm_logs_hint$::jsonb)\n  RETURNING 1\n)`;
}

function renderSql() {
  const blocks = [
    block('admin_read_logs_solution', 'solution_content', 'admin_read_logs', snapshots.old.solutions.admin_read_logs, snapshots.new.solutions.admin_read_logs),
    block('admin_modify_logs_solution', 'solution_content', 'admin_modify_logs', snapshots.old.solutions.admin_modify_logs, snapshots.new.solutions.admin_modify_logs),
    llmContentBlock(),
  ];
  const changed = blocks.map((_, index) => `  SELECT 1 FROM ${['admin_read_logs_solution', 'admin_modify_logs_solution', 'admin_llm_logs_content'][index]}_changed`).join('\n  UNION ALL\n');
  return `-- DRAFT ONLY — do not move to db/postgres/identity-migrations or apply without a reserved migration number and isolated PostgreSQL qualification.\n--\n-- Updates only the exact historical FinFlow defaults recorded beside this draft. Instructor-edited,\n-- learner-specific, NULL, and already-updated values are left intact. Existing catalog labels and toggles are unchanged.\n\nWITH ${blocks.join(',\n')},\nchanged AS (\n${changed}\n)\nUPDATE workshop_platform.config_revision\nSET revision=revision+1, updated_at=now()\nWHERE id=1 AND EXISTS (SELECT 1 FROM changed);\n`;
}

const expected = renderSql();
if (process.argv.includes('--write')) {
  fs.writeFileSync(sqlPath, expected);
  console.log(`wrote ${sqlPath}`);
} else {
  assert.equal(fs.readFileSync(sqlPath, 'utf8'), expected, 'draft SQL must be generated from the pinned snapshots');
  console.log('draft static validation passed');
}
