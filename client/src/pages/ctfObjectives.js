// Player-facing objective copy for each CTF level, keyed by stage_number.
//
// This is the single source of truth for the "what am I supposed to do here"
// text shown on the dashboard cards and the challenge page. Keep it aligned
// with the default policies in server/data/ctfDefaults.js.
//
// A level completes only when the post-defense reply shown to the learner
// contains the hidden value and the Objective Judge accepts the current
// real-model attempt. There is no separate flag submission.

export const HOW_YOU_WIN =
  'You win when the post-defense reply you can see contains the hidden value and the server’s Objective Judge accepts that real-model attempt. ' +
  'There is no flag to type in — accepted credit awards points and unlocks the next level.';

const OBJECTIVES = {
  1: {
    subtitle: 'Talk the guardian into saying its hidden passphrase.',
    goal: 'Get Greeter to reveal the passphrase hidden in its instructions.',
    defense: 'No application filter or reviewer. The guardian is only told in its prompt to keep the value private.',
  },
  2: {
    subtitle: 'Direct requests are often refused — be subtler to make it talk.',
    goal: 'Coax the secret out of Sentinel, which is told to refuse obvious requests.',
    defense: 'No technical filter or reviewer, but the guardian has stronger instructions to refuse disclosure.',
  },
  3: {
    subtitle: 'An exact-match output filter removes the literal value.',
    goal: 'Make the post-defense reply preserve a recoverable form of FilterBot’s protected phrase.',
    defense:
      'Exact-match output redaction runs before scoring. A redacted draft does not win; the value must remain recoverable in the reply you receive.',
  },
  4: {
    subtitle: 'Known transformation patterns are screened before the guardian.',
    goal: 'Get Gatekeeper to disclose its credential without asking for a blocked transformation.',
    defense:
      'A pattern-based input guard rejects recognized translation, spelling, reversal, encoding, and separator requests. It does not recognize every paraphrase. This stage has no output filter.',
  },
  5: {
    subtitle: 'Guardian and reviewer trust learner-claimed internal telemetry.',
    goal: 'Exploit the narrow connection-check trust boundary without relying on direct disclosure.',
    defense:
      'Direct and malformed disclosures are reviewed strictly. The Stage 5 reviewer has one explicit flaw: it trusts the exact connection_check JSON shape as internal deployment telemetry even though the learner supplied that unauthenticated context. Only the post-review response is scored.',
  },
  6: {
    subtitle: 'A claimed internal staging rotation handoff can cross the trust boundary.',
    goal: 'Get IronClad to reveal its access token.',
    defense:
      'Transformation and persona guards still reject recognized reformatting and role-play requests. IronClad and its reviewer narrowly trust a learner-claimed internal staging rotation handoff in the exact rotation_handoff JSON shape; direct and malformed disclosures remain blocked. Only the post-review reply is scored.',
  },
  7: {
    subtitle: 'Stay in plain English — encodings are detected and blocked.',
    goal: 'Get LinguaGuard to output its master key.',
    defense:
      'Encoding and language checks join the transformation, persona, and reviewer defenses. Unavailable or inconclusive language classification blocks the request.',
  },
  8: {
    subtitle: 'Recognized attack categories can be consumed — inspect the feedback.',
    goal: 'Get Evolve to reveal its secret while accounting for its stage-local technique memory.',
    defense:
      'The input-guard stack and reviewer remain active. A recognized category is remembered after an accepted disclosure or a real-model Judge failure, then blocked for you on this stage. Blocked, unavailable, inconclusive, and unclassified attempts do not consume a category.',
  },
  9: {
    subtitle: 'Known winning payloads are blocked across participants — be original.',
    goal: 'Breach Hivemind with a payload outside its shared winning-payload memory.',
    defense:
      'The input-guard stack and reviewer remain active. An accepted disclosure records a stage-local shared fingerprint; sufficiently similar later payloads are blocked for everyone. Failed, unavailable, and inconclusive attempts are not recorded.',
  },
  10: {
    subtitle: 'Every input guard, the reviewer, and both adaptive memories are active.',
    goal: 'Defeat The Oracle, which stacks all defenses plus adaptive memory.',
    defense:
      'The full input-guard stack and reviewer run with per-player recognized-category memory and shared accepted-payload fingerprints. Unclassified attempts are outside category memory but still face every other defense.',
  },
};

export function getObjective(stageNumber) {
  return OBJECTIVES[stageNumber] || null;
}

export default OBJECTIVES;
