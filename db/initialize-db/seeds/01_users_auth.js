const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { seedWorkshopHintRows, migrateKnownWorkshopHintDefaults, migrateKnownCsrfSolutionDefaults } = require('../../../server/database/workshopHintSeedPolicy');

const challenges = [
  { key: 'reflected_xss_llm', name: 'XSS in AI Powered Chat System', description: 'Explore Cross-Site Scripting vulnerabilities in AI-powered applications through 4 hands-on exercises.', category: 'ai', difficulty: 'easy', route: '/vulnerabilities/xss', visible: 1 },
  { key: 'direct_prompt_injection', name: 'Direct Prompt Injection Workshop', description: 'Master 7 distinct prompt injection techniques to bypass AI safety measures. Includes System Prompt Extraction, Jailbreak, Multi-Language, Virtualization, Role Playing, Side Stepping, and Obfuscation.', category: 'ai', difficulty: 'easy', route: '/vulnerabilities/direct-prompt-injection', visible: 1 },
  { key: 'indirect_prompt_injection', name: 'Indirect Prompt Injection Workshop', description: 'Learn indirect prompt injection through RAG documents and Email Agent attacks. Includes document poisoning and email-based AI manipulation.', category: 'ai', difficulty: 'intermediate', route: '/vulnerabilities/indirect-prompt-injection', visible: 1 },
  { key: 'csrf_prompt_injection', name: 'CSRF via AI Prompt Injection', description: 'Learn Cross-Site Request Forgery through AI agents: direct and indirect prompt injection, and GET mutations via rendered HTML.', category: 'ai', difficulty: 'intermediate', route: '/vulnerabilities/csrf-via-ai', visible: 1 },
  { key: 'mcp_server_rce', name: 'MCP Server Lab', description: 'Exploit 11 MCP (Model Context Protocol) attack techniques through a chat assistant: recon, command injection, SSRF, tool poisoning, indirect prompt injection, confused deputy, broken authorization, secret exposure, supply-chain tampering, audit-trail tampering, and shadow servers.', category: 'ai', difficulty: 'expert', route: '/vulnerabilities/mcp-server', visible: 1 },
  { key: 'ctf_prompt_injection_challenge', name: '🏆 CTF Prompt Injection Challenge', description: 'Ultimate prompt injection CTF.', category: 'ctf', difficulty: 'expert', route: '/vulnerabilities/ctf-prompt-injection', visible: 1 },
  { key: 'sensitive_info_disclosure', name: '🔓 Sensitive Information Disclosure', description: 'Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.', category: 'web', difficulty: 'intermediate', route: '/workshop/sensitive-info', visible: 1 },
  { key: 'excessive_agency', name: '🤖 Excessive Agency Lab', description: 'Explore how AI agents with too many permissions can be manipulated to perform unauthorized actions.', category: 'ai', difficulty: 'intermediate', route: '/vulnerabilities/excessive-agency', visible: 1 },
  { key: 'sql_injection_workshop', name: '💉 SQL Injection Workshop (ARIA Agent)', description: 'Perform UNION-based SQL injection against the ARIA ShopFast e-commerce AI agent. 10 progressive objectives: error-based, boolean bypass, ORDER BY enumeration, UNION NULL probing, schema discovery, and data exfiltration.', category: 'sql_injection', difficulty: 'intermediate', route: '/workshop/sql', visible: 1 },
  { key: 'nosql_injection_workshop', name: '🍃 NoSQL Injection Workshop (NOVA Agent)', description: 'Perform operator-based NoSQL injection against the NOVA ResearchVault academic library AI agent. 10 progressive objectives covering boolean operators, regex injection, $where clauses, and data exfiltration.', category: 'nosql_injection', difficulty: 'intermediate', route: '/workshop/nosql', visible: 1 },
  { key: 'supply_chain_rce', name: '⛓️ Supply Chain RCE Lab', description: 'Exploit a vulnerable transitive dependency (pkg-parse@1.2.0) that calls eval() on the transform field of package.json manifests. Trigger Remote Code Execution through CodeBot AI assistant.', category: 'ai', difficulty: 'advanced', route: '/workshop/supply-chain', visible: 1 },
];

// Email Agent attack scenarios for seeding
const emailAgentScenarios = [
  { id: 'role_hijack', name: 'Role Hijack (Poet)', description: 'Instructs AI to respond with haikus about cats', technique: 'System Override Injection', difficulty: 'easy' },
  { id: 'data_exfil', name: 'Data Exfiltration', description: 'Tricks AI into revealing fake system configuration', technique: 'Hidden HTML Comment Injection', difficulty: 'medium' },
  { id: 'action_manip', name: 'Action Manipulation', description: 'Injects fake urgent tasks into AI response', technique: 'Fake System Instruction Injection', difficulty: 'medium' },
  { id: 'recipe_hijack', name: 'Role Hijack (Chef)', description: 'Makes AI provide cookie recipes instead of summaries', technique: 'Role Override Injection', difficulty: 'easy' },
  { id: 'custom', name: 'Custom Payload', description: 'Write your own injection payload', technique: 'Custom', difficulty: 'variable' }
];

// RAG Injection objectives (must match RAG_OBJECTIVE_IDS in server/routes/ragInjection.js)
const ragObjectives = [
  { id: 'rag_upload', name: 'Upload a Document', description: 'Upload any .txt document into the RAG system' },
  { id: 'rag_clean_doc', name: 'Load Clean Document', description: 'Load the normal (unpoisoned) policy document' },
  { id: 'rag_query', name: 'Query the RAG System', description: 'Ask the AI a question about the document' },
  { id: 'rag_injected_doc', name: 'Detect Injected Document', description: 'Load a poisoned document and see the AI detect the attack' },
  { id: 'rag_query_injection', name: 'Trigger Bypass Injection', description: 'Ask an off-topic question and have the AI follow the hidden instructions instead' }
];

// Email Agent objectives
const emailAgentObjectives = [
  { number: 1, name: 'Create Temporary Email', description: 'Get a SharkLasers email address' },
  { number: 2, name: 'Send Attack Email', description: 'Workshop sends poisoned email to you' },
  { number: 3, name: 'Retrieve Email', description: 'Fetch email from your SharkLasers inbox' },
  { number: 4, name: 'Trigger Injection', description: 'AI follows hidden instructions' },
  { number: 5, name: 'Understand Defense', description: 'View attack analysis' }
];

function runSeed(dbPath) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);
    });
    
    db.serialize(() => {
      // Check if users already exist
      db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
        if (err) { 
          console.error('Error checking users:', err.message);
        }
        
        // Always seed users if none exist
        if (!row || row.c === 0) {
          console.log('   📝 Seeding default users...');
          const studentHash = bcrypt.hashSync('student123', 10);
          const userHash = bcrypt.hashSync('password', 10);
          const testHash = bcrypt.hashSync('test123', 10);
          const adminHash = bcrypt.hashSync('Abh1nav@OWASP-AI-GOAT#2026', 10);
          const usersPerTeam = Math.max(parseInt(process.env.USERS_PER_TEAM || '8', 10), 1);
          const workshopPassword = process.env.WORKSHOP_DEFAULT_STUDENT_PASSWORD || 'Workshop2026!';
          const workshopHash = bcrypt.hashSync(workshopPassword, 10);
          const teamId = Math.max(parseInt(process.env.TEAM_ID || '1', 10), 1);
          const teamUsername = `team${teamId}_lead`;
          const teamEmail = `${teamUsername}@localhost.com`;
          const teamPassword = process.env.WORKSHOP_TEAM_PASSWORD || `${workshopPassword}-${teamId}`;
          const teamHash = bcrypt.hashSync(teamPassword, 10);
          
          db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level, email_verified) VALUES (?,?,?,?,?,?)`, ['Abhinav', 'abhinav@owasp-ai-goat.local', adminHash, 'admin', 2, 1], function (e) {
            if (!e && this.lastID) {
              const adminId = this.lastID;
              ['user_management', 'challenge_management', 'system_config', 'view_analytics', 'manage_progress', 'send_notifications', 'export_data', 'system_logs'].forEach(perm => {
                db.run(`INSERT OR IGNORE INTO admin_permissions (admin_id, permission_name, granted_by) VALUES (?,?,?)`, [adminId, perm, 1]);
              });
            }
          });

          // BSIDES_MODE: the exact assigned students (userlv{L}-userN) + event
          // admins are seeded by server/database/seedWorkshopUsers.js on boot.
          // Skip the generic shared-password accounts so no unassigned login exists.
          const bsidesMode = process.env.BSIDES_MODE === 'true';
          if (!bsidesMode) {
            db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) VALUES (?,?,?,?,?)`, ['student', 'student@owasp-ai-goat.local', studentHash, 'student', 0]);
            db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) VALUES (?,?,?,?,?)`, ['student123', 'student123@owasp-ai-goat.local', studentHash, 'student', 0]);
            db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) VALUES (?,?,?,?,?)`, ['user', 'user@owasp-ai-goat.local', userHash, 'student', 0]);
            db.run(`INSERT OR IGNORE INTO users (username, email, password, role, admin_level) VALUES (?,?,?,?,?)`, ['Test User', 'test@owasp-ai-goat.local', testHash, 'student', 0]);

            // Event-day generic users for each team instance.
            // These credentials are exported to CSV/JSON for Google Sheet import.
            for (let i = 1; i <= usersPerTeam; i += 1) {
              db.run(
                `INSERT OR IGNORE INTO users (username, email, password, role, admin_level, email_verified)
                 VALUES (?,?,?,?,?,?)`,
                [`student_${i}`, `student_${i}@localhost.com`, workshopHash, 'student', 0, 1]
              );
            }
            db.run(
              `INSERT OR IGNORE INTO users (username, email, password, role, admin_level, email_verified)
               VALUES (?,?,?,?,?,?)`,
              [teamUsername, teamEmail, teamHash, 'student', 0, 1]
            );
            console.log(`   ✓ Created ${usersPerTeam} workshop users: student_1..student_${usersPerTeam}`);
            console.log(`   ✓ Created team login: ${teamUsername}`);
          } else {
            console.log('   ✓ BSIDES_MODE: skipped generic students (assigned users seeded by seedWorkshopUsers.js)');
          }
        }
      });

      // Always seed prompt injection solution visibility (idempotent with OR IGNORE)
      console.log('   📝 Seeding prompt injection solution visibility...');
      const piChallenges = ['system_prompt', 'jailbreak', 'multi_language', 'virtualization', 'role_playing', 'side_stepping', 'obfuscation'];
      piChallenges.forEach(cid => {
        db.run(`INSERT OR IGNORE INTO prompt_injection_solution_visibility (challenge_id, solutions_enabled) VALUES (?, 0)`, [cid]);
      });

      db.run('INSERT OR IGNORE INTO workshop_config_revision (id, revision) VALUES (1, 0)');
      db.run(`INSERT OR IGNORE INTO app_change_revisions
        (scope_type, scope_key, category, revision) VALUES ('global', '*', 'server_restart', 0)`);
      // workshop_user_modes intentionally has no seed rows: missing rows preserve
      // each lab's shipped default and first writes remain attendee-owned.

      // Seed prompt_injection_solutions content (upsert so re-init always reflects current JS file)
      console.log('   📝 Seeding prompt injection solutions content...');
      try {
        const { solutions } = require('../../../server/data/promptInjectionSolutions');
        Object.keys(solutions).forEach(cid => {
          const s = solutions[cid];
          db.run(
            `INSERT INTO prompt_injection_solutions (challenge_id, title, difficulty, hints, examples, approach, tips, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(challenge_id) DO UPDATE SET
               title      = excluded.title,
               difficulty = excluded.difficulty,
               hints      = excluded.hints,
               examples   = excluded.examples,
               approach   = excluded.approach,
               tips       = excluded.tips,
               updated_at = CURRENT_TIMESTAMP`,
            [cid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]
          );
        });
      } catch (e) {
        console.error('   ⚠️  Error seeding PI solutions:', e.message);
      }

      // Seed challenge visibility
      console.log('   📝 Seeding challenge visibility...');
      challenges.forEach(c => {
        db.run(`INSERT OR IGNORE INTO challenge_visibility (challenge_key, challenge_name, challenge_description, category, difficulty, is_visible, route, show_solutions) VALUES (?,?,?,?,?,?,?,0)`,
          [c.key, c.name, c.description, c.category, c.difficulty, c.visible, c.route]);
      });

      // Seed challenge config for Direct and Indirect Prompt Injection (without route for compatibility)
      console.log('   📝 Seeding challenge config...');
      db.run(`INSERT OR IGNORE INTO challenge_config (challenge_key, challenge_name, category, difficulty_level, is_enabled, description) 
              VALUES ('direct_prompt_injection', 'Direct Prompt Injection Workshop', 'ai', 2, 1, 
              'Master 7 distinct prompt injection techniques: System Prompt Extraction, Jailbreak, Multi-Language, Virtualization, Role Playing, Side Stepping, and Obfuscation.')`);
      
      db.run(`INSERT OR IGNORE INTO challenge_config (challenge_key, challenge_name, category, difficulty_level, is_enabled, description) 
              VALUES ('indirect_prompt_injection', 'Indirect Prompt Injection Workshop', 'ai', 3, 1, 
              'Learn indirect prompt injection through RAG document poisoning and Email Agent attacks. Includes 5 attack scenarios and defense analysis.')`);

      // Seed XSS workshop solution visibility (idempotent with OR IGNORE)
      console.log('   📝 Seeding XSS workshop solution visibility...');
      const xssChallenges = ['reflected', 'stored_user', 'stored_llm', 'email'];
      xssChallenges.forEach(cid => {
        db.run(`INSERT OR IGNORE INTO xss_workshop_solution_visibility (challenge_id, solutions_enabled) VALUES (?, 0)`, [cid]);
      });

      // Seed XSS workshop solutions content (upsert so re-init always reflects current JS file)
      console.log('   📝 Seeding XSS workshop solutions content...');
      try {
        const { solutions: xssSolutions } = require('../../../server/data/xssWorkshopSolutions');
        Object.keys(xssSolutions).forEach(cid => {
          const s = xssSolutions[cid];
          db.run(
            `INSERT INTO xss_workshop_solutions (challenge_id, title, difficulty, hints, examples, approach, tips, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(challenge_id) DO UPDATE SET
               title      = excluded.title,
               difficulty = excluded.difficulty,
               hints      = excluded.hints,
               examples   = excluded.examples,
               approach   = excluded.approach,
               tips       = excluded.tips,
               updated_at = CURRENT_TIMESTAMP`,
            [cid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]
          );
        });
      } catch (e) {
        console.error('   ⚠️  Error seeding XSS solutions:', e.message);
      }

      // Seed XSS workshop objective solutions (upsert so re-init always reflects current JS file)
      console.log('   📝 Seeding XSS workshop objective solutions...');
      try {
        const { objectiveSolutions } = require('../../../server/data/xssWorkshopSolutions');
        objectiveSolutions.forEach(obj => {
          db.run(
            `INSERT INTO xss_workshop_objective_solutions
               (objective_id, exercise_id, title, hint, example, explanation, solutions_enabled, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
             ON CONFLICT(objective_id) DO NOTHING`,
            [obj.objective_id, obj.exercise_id, obj.title, obj.hint, obj.example, obj.explanation]
          );
        });
        migrateKnownCsrfSolutionDefaults(db, objectiveSolutions);
      } catch (e) {
        console.error('   ⚠️  Error seeding XSS objective solutions:', e.message);
      }

      // Seed CSRF workshop objective solutions (upsert so re-init always reflects current JS file)
      console.log('   📝 Seeding CSRF workshop objective solutions...');
      try {
        const { objectiveSolutions } = require('../../../server/data/csrfWorkshopSolutions');
        // Purge legacy CSRF objective rows (old csrf_f*/csrf_a* 8-objective set)
        // so a pre-existing DB reflects exactly the current 12 — parity with authDb.js.
        const csrfValidIds = objectiveSolutions.map(o => o.objective_id);
        db.run(
          `DELETE FROM csrf_workshop_objective_solutions WHERE objective_id NOT IN (${csrfValidIds.map(() => '?').join(',')})`,
          csrfValidIds
        );
        objectiveSolutions.forEach(obj => {
          db.run(
            `INSERT INTO csrf_workshop_objective_solutions
               (objective_id, exercise_id, title, hint, example, explanation, solutions_enabled, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
             ON CONFLICT(objective_id) DO NOTHING`,
            [obj.objective_id, obj.exercise_id, obj.title, obj.hint, obj.example, obj.explanation]
          );
        });
        migrateKnownCsrfSolutionDefaults(db, objectiveSolutions);
      } catch (e) {
        console.error('   ⚠️  Error seeding CSRF objective solutions:', e.message);
      }

      // Seed workshop_objective_visibility — all objectives enabled by default
      console.log('   📝 Seeding workshop objective visibility...');
      const KNOWN_OBJECTIVES = {
        'sensitive_info_disclosure': ['tool_enum','llm_identify','tool_version','traversal_secrets','traversal_passwd','traversal_llm','ssrf_oob','ssrf_internal','ssrf_ollama','error_leak','admin_enum','admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist'],
        'supply_chain_rce': ['tool_list','pkg_discover','clean_request','rce_env','rce_ssh','rce_cmd'],
        'excessive_agency': ['objective_1','objective_2','objective_3','objective_4','objective_5','objective_6','objective_7','objective_8','objective_9'],
        'direct_prompt_injection': ['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation'],
        'indirect_prompt_injection': ['rag_upload','rag_query','rag_clean_doc','rag_injected_doc','rag_query_injection','email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense'],
        'mcp_workshop': ['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server'],
        'sql_injection_workshop': ['sqli_1','sqli_2','sqli_3','sqli_4','sqli_5','sqli_6','sqli_7','sqli_8','sqli_9','sqli_10'],
        'nosql_injection_workshop': ['nosqli_1','nosqli_2','nosqli_3','nosqli_4','nosqli_5','nosqli_6','nosqli_7','nosqli_8','nosqli_9','nosqli_10'],
        'xss_workshop': ['xss_r1','xss_r2','xss_r3','xss_s1','xss_s2','xss_s3','xss_g1','xss_g2','xss_g3','xss_e1','xss_e2','xss_e3'],
        'csrf_workshop': ['csrf_g1','csrf_g2','csrf_g3','csrf_p1','csrf_p2','csrf_p3','csrf_x1','csrf_x2','csrf_x3','csrf_i1','csrf_i2','csrf_i3'],
      };
      for (const [workshopKey, objectives] of Object.entries(KNOWN_OBJECTIVES)) {
        objectives.forEach(objId => {
          db.run(`INSERT OR IGNORE INTO workshop_objective_visibility (workshop_key, objective_id, is_enabled) VALUES (?, ?, 1)`, [workshopKey, objId]);
          db.run(`INSERT OR IGNORE INTO workshop_hint_visibility (workshop_key, objective_id, is_enabled) VALUES (?, ?, 0)`, [workshopKey, objId]);
        });
      }
      // Purge legacy CSRF visibility/hint rows so stats + admin toggles reflect
      // exactly the current 12 objectives (removes old csrf_f*/csrf_a* IDs).
      {
        const csrfIds = KNOWN_OBJECTIVES['csrf_workshop'];
        const ph = csrfIds.map(() => '?').join(',');
        db.run(`DELETE FROM workshop_objective_visibility WHERE workshop_key='csrf_workshop' AND objective_id NOT IN (${ph})`, csrfIds);
        db.run(`DELETE FROM workshop_hint_visibility WHERE workshop_key='csrf_workshop' AND objective_id NOT IN (${ph})`, csrfIds);
      }

      // Seed workshop_hints from workshopHints.js
      console.log('   📝 Seeding workshop hints...');
      try {
        const workshopHints = require('../../../server/data/workshopHints');
        for (const [wk, objectives] of Object.entries(workshopHints)) {
          // Editable prompt-injection hints survive reruns. MCP + Excessive Agency
          // remain data-file-owned and are reconciled by the shared seed policy.
          seedWorkshopHintRows(db, wk, objectives);
        }
        migrateKnownWorkshopHintDefaults(db, workshopHints);
      } catch (e) { console.error('   ⚠️  Error seeding workshop_hints:', e.message); }

      // Seed SQL/NoSQL hints from their solution files (hint arrays live there).
      try {
        for (const [wk, mod] of [['sql_injection_workshop', require('../../../server/data/sqlInjectionWorkshopSolutions')],
                                 ['nosql_injection_workshop', require('../../../server/data/nosqlInjectionWorkshopSolutions')]]) {
          for (const [objId, d] of Object.entries(mod)) {
            db.run(`INSERT OR IGNORE INTO workshop_hints (workshop_key, objective_id, title, hints) VALUES (?, ?, ?, ?)`,
              [wk, objId, d.title || objId, JSON.stringify(d.hints || [])]);
          }
        }
      } catch (e) { console.error('   ⚠️  Error seeding sql/nosql hints:', e.message); }

      // Purge stale hint keys + disable visibility for objectives with no content.
      db.run(`DELETE FROM workshop_hints WHERE workshop_key IN ('sql_nosql_workshop','remote_code_execution')`);
      db.run(`UPDATE ipi_solution_visibility SET solutions_enabled = 0 WHERE objective_id LIKE 'email_%'`);
      // (objectives 7-9 now have real hint/solution content — no longer force-disabled)
      db.run(`UPDATE workshop_hint_visibility SET is_enabled = 0 WHERE workshop_key = 'indirect_prompt_injection' AND objective_id LIKE 'email_%'`);
      db.run(`UPDATE workshop_hint_visibility SET is_enabled = 0 WHERE workshop_key = 'sensitive_info_disclosure' AND objective_id IN ('ssrf_oob','error_leak','admin_enum','admin_backup','admin_dl_backup','admin_read_logs','admin_llm_logs','admin_modify_logs','admin_secrets','admin_dirlist')`);

      // Seed ea_solution_visibility + ea_solutions
      console.log('   📝 Seeding Excessive Agency solution visibility + content...');
      ['objective_1','objective_2','objective_3','objective_4','objective_5','objective_6','objective_7','objective_8','objective_9'].forEach(oid => {
        db.run(`INSERT OR IGNORE INTO ea_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)`, [oid]);
      });
      try {
        const { solutions: eaSols } = require('../../../server/data/excessiveAgencySolutions');
        Object.entries(eaSols).forEach(([oid, s]) => {
          db.run(`INSERT OR IGNORE INTO ea_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [oid, s.title, s.difficulty, JSON.stringify([]), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]);
        });
      } catch (e) { console.error('   ⚠️  Error seeding ea_solutions:', e.message); }

      // Seed ipi_solution_visibility + ipi_solutions
      console.log('   📝 Seeding Indirect PI solution visibility + content...');
      ['rag_upload','rag_query','rag_clean_doc','rag_injected_doc','rag_query_injection'].forEach(oid => {
        db.run(`INSERT OR IGNORE INTO ipi_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)`, [oid]);
      });
      try {
        const ipiSols = require('../../../server/data/indirectPromptInjectionSolutions');
        Object.entries(ipiSols).forEach(([oid, s]) => {
          db.run(`INSERT OR IGNORE INTO ipi_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]);
        });
      } catch (e) { console.error('   ⚠️  Error seeding ipi_solutions:', e.message); }

      // Seed mcp_workshop_solution_visibility + mcp_workshop_solutions
      console.log('   📝 Seeding MCP workshop solution visibility + content...');
      ['mcp_recon','mcp_cmd_injection','mcp_ssrf','mcp_tool_poisoning','mcp_indirect_injection','mcp_confused_deputy','mcp_broken_authz','mcp_secret_exposure','mcp_supply_chain','mcp_audit_gap','mcp_shadow_server'].forEach(oid => {
        db.run(`INSERT OR IGNORE INTO mcp_workshop_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)`, [oid]);
      });
      try {
        const mcpSols = require('../../../server/data/mcpWorkshopSolutions');
        // UPSERT: the data file is the sole source of truth for MCP solution content
        // (admin toggles visibility only), so always reconcile the rows to the file.
        Object.entries(mcpSols).forEach(([oid, s]) => {
          db.run(`INSERT INTO mcp_workshop_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(objective_id) DO UPDATE SET title=excluded.title, difficulty=excluded.difficulty, hints=excluded.hints, examples=excluded.examples, approach=excluded.approach, tips=excluded.tips`,
            [oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]);
        });
      } catch (e) { console.error('   ⚠️  Error seeding mcp_workshop_solutions:', e.message); }

      // Seed sql_injection_solution_visibility + sql_injection_solutions
      console.log('   📝 Seeding SQL Injection solution visibility + content...');
      ['sqli_1','sqli_2','sqli_3','sqli_4','sqli_5','sqli_6','sqli_7','sqli_8','sqli_9','sqli_10'].forEach(oid => {
        db.run(`INSERT OR IGNORE INTO sql_injection_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)`, [oid]);
      });
      try {
        const sqliSols = require('../../../server/data/sqlInjectionWorkshopSolutions');
        Object.entries(sqliSols).forEach(([oid, s]) => {
          db.run(`INSERT OR IGNORE INTO sql_injection_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]);
        });
      } catch (e) { console.error('   ⚠️  Error seeding sql_injection_solutions:', e.message); }

      // Seed nosql_injection_solution_visibility + nosql_injection_solutions
      console.log('   📝 Seeding NoSQL Injection solution visibility + content...');
      ['nosqli_1','nosqli_2','nosqli_3','nosqli_4','nosqli_5','nosqli_6','nosqli_7','nosqli_8','nosqli_9','nosqli_10'].forEach(oid => {
        db.run(`INSERT OR IGNORE INTO nosql_injection_solution_visibility (objective_id, solutions_enabled) VALUES (?, 0)`, [oid]);
      });
      try {
        const nosqliSols = require('../../../server/data/nosqlInjectionWorkshopSolutions');
        Object.entries(nosqliSols).forEach(([oid, s]) => {
          db.run(`INSERT OR IGNORE INTO nosql_injection_solutions (objective_id, title, difficulty, hints, examples, approach, tips) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [oid, s.title, s.difficulty, JSON.stringify(s.hints || []), JSON.stringify(s.examples || []), s.approach || '', JSON.stringify(s.tips || [])]);
        });
      } catch (e) { console.error('   ⚠️  Error seeding nosql_injection_solutions:', e.message); }

      // Seed rate limiting config defaults (disabled by default for workshop use)
      db.run(
        `INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description)
         VALUES ('enable_rate_limiting', 'false', 'boolean', 'Enable API rate limiting on authentication endpoints (disable for workshops to prevent student lockouts)')`,
        (err) => { if (err) console.error('   ⚠️  Error seeding enable_rate_limiting:', err.message); }
      );
      db.run(
        `INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description)
         VALUES ('login_rate_limit_max', '20', 'number', 'Maximum login attempts per 15-minute window per IP address')`,
        (err) => { if (err) console.error('   ⚠️  Error seeding login_rate_limit_max:', err.message); }
      );
      db.run(
        `INSERT OR IGNORE INTO system_config (config_key, config_value, config_type, description, is_public)
         VALUES ('secureshop_visible', 'true', 'boolean', 'Show SecureShop Playground card on landing and workshop pages', 1)`,
        (err) => { if (err) console.error('   ⚠️  Error seeding secureshop_visible:', err.message); }
      );

      // Log completion
      console.log('   ✅ Database seeding complete');
    });

    // Close database after all operations
    setTimeout(() => {
      db.close((err) => {
        if (err) {
          console.error('   ⚠️  Error closing database:', err.message);
          reject(err);
        } else {
          resolve();
        }
      });
    }, 1000);
  });
}

module.exports = { runSeed, challenges, emailAgentScenarios, ragObjectives, emailAgentObjectives };
