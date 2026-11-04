'use strict';

// Candidate replacement factory. Production wiring remains unchanged until a
// separately reviewed migration and populated-store qualification are complete.
const own = (value, key) => value != null && Object.prototype.hasOwnProperty.call(value, key);
function resolveObjectiveContent({ workshopKey, objectiveId, hints, solutions }) {
  const hintGroup = hints[workshopKey]; const solutionGroup = solutions[workshopKey];
  let hintPresent = own(hintGroup, objectiveId);
  const solutionPresent = own(solutionGroup, objectiveId);
  const solution = solutionPresent ? solutionGroup[objectiveId] : undefined;
  let hint = hintPresent ? hintGroup[objectiveId] : undefined;
  if (!hintPresent && ['sql_injection_workshop','nosql_injection_workshop'].includes(workshopKey)
      && solutionPresent && solution) {
    hintPresent = true; hint = { title: solution.title, hints: solution.hints || [] };
  }
  return { hintPresent, hint, solutionPresent, solution };
}
function createWorkshopPlatformSeed({ withTransaction, bump, provenance, toChallengeKey,
  legacyXssSolutions }) {
  if (![withTransaction,bump,toChallengeKey].every(value => typeof value === 'function')
      || !provenance?.reconcileField || !provenance?.adoptInsertedField || !legacyXssSolutions) {
    throw new TypeError('provenance seed dependencies required');
  }
  const exerciseFields = ['challenge_name','challenge_description','category','difficulty','route'];
  const objectiveFields = ['label','description','category','hint_content','solution_content'];
  return async function seedWorkshopPlatform(pool, { catalog, hints, solutions, challenges,
    catalogVersion, workshopKeys } = {}) {
    if (!catalog || !hints || !solutions || !Array.isArray(challenges)
        || typeof catalogVersion !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,79}$/i.test(catalogVersion)) {
      throw new TypeError('versioned workshop catalog required');
    }
    if (workshopKeys !== undefined && (!Array.isArray(workshopKeys) || !workshopKeys.length
        || new Set(workshopKeys).size !== workshopKeys.length
        || workshopKeys.some(key => typeof key !== 'string' || !Object.hasOwn(catalog, key)))) {
      throw new TypeError('seed workshop scope must name unique catalog workshops');
    }
    const scoped = workshopKeys === undefined ? null : new Set(workshopKeys);
    return withTransaction(pool, async client => {
      await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
      let changed = 0; let ordinal = 0;
      const presentWorkshops = [];
      for (const [workshopKey, objectives] of Object.entries(catalog)) {
        const exerciseOrdinal = ordinal++;
        if (scoped && !scoped.has(workshopKey)) continue;
        presentWorkshops.push(workshopKey);
        const challengeKey = toChallengeKey(workshopKey);
        const meta = challenges.find(value => value.key === challengeKey) || {};
        const exercise = { challenge_name: meta.name || workshopKey,
          challenge_description: meta.description || '', category: meta.category || 'ai',
          difficulty: meta.difficulty || 'intermediate', route: meta.route || '' };
        const inserted = await client.query(`INSERT INTO workshop_platform.exercises
          (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal,is_visible)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
        [workshopKey,challengeKey,exercise.challenge_name,exercise.challenge_description,exercise.category,
          exercise.difficulty,exercise.route,exerciseOrdinal,meta.defaultVisible !== false]);
        if (inserted.rowCount) {
          changed += 1;
          for (const fieldName of exerciseFields) await provenance.adoptInsertedField(client,
            { entityKind:'exercise',workshopKey,fieldName,sourceValue:exercise[fieldName],sourceVersion:catalogVersion });
        } else {
          const structural = await client.query(`UPDATE workshop_platform.exercises
            SET catalog_active=true,ordinal=$2,updated_at=now() WHERE workshop_key=$1
            AND (catalog_active=false OR ordinal<>$2)`, [workshopKey, exerciseOrdinal]);
          changed += structural.rowCount;
          for (const fieldName of exerciseFields) changed += Number((await provenance.reconcileField(client,
            { entityKind:'exercise',workshopKey,fieldName,sourceValue:exercise[fieldName],
              sourceVersion:catalogVersion })).changed);
        }
        const presentObjectives = [];
        for (let index = 0; index < objectives.length; index += 1) {
          const objective = objectives[index]; presentObjectives.push(objective.id);
          const content = resolveObjectiveContent({ workshopKey, objectiveId: objective.id, hints, solutions });
          const hint = content.hintPresent ? content.hint : null;
          const solution = content.solutionPresent ? content.solution : null;
          const values = { label: objective.text,
            description: typeof objective.description === 'string' ? objective.description : '',
            category: objective.category || '',
            hint_content: hint, solution_content: solution };
          const created = await client.query(`INSERT INTO workshop_platform.objectives
            (workshop_key,objective_id,label,description,category,ordinal,hint_content,solution_content,is_enabled)
            VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9) ON CONFLICT DO NOTHING`,
          [workshopKey,objective.id,values.label,values.description,values.category,index,
            hint === null ? null : JSON.stringify(hint),
            solution === null ? null : JSON.stringify(solution),objective.defaultEnabled !== false]);
          if (created.rowCount) {
            changed += 1;
            for (const fieldName of objectiveFields) await provenance.adoptInsertedField(client,
              { entityKind:'objective',workshopKey,objectiveId:objective.id,fieldName,
                sourceValue:values[fieldName],
                sourcePresent: !['hint_content','solution_content'].includes(fieldName)
                  || (fieldName === 'hint_content' ? content.hintPresent : content.solutionPresent),
                sourceVersion:catalogVersion });
          } else {
            const structural = await client.query(`UPDATE workshop_platform.objectives
              SET catalog_active=true,ordinal=$3,updated_at=now()
              WHERE workshop_key=$1 AND objective_id=$2 AND (catalog_active=false OR ordinal<>$3)`,
            [workshopKey,objective.id,index]);
            changed += structural.rowCount;
            for (const fieldName of objectiveFields) changed += Number((await provenance.reconcileField(client,
              { entityKind:'objective',workshopKey,objectiveId:objective.id,fieldName,
                sourceValue:values[fieldName],
                sourcePresent: !['hint_content','solution_content'].includes(fieldName)
                  || (fieldName === 'hint_content' ? content.hintPresent : content.solutionPresent),
                sourceVersion:catalogVersion })).changed);
          }
        }
        changed += (await client.query(`UPDATE workshop_platform.objectives
          SET catalog_active=false,is_enabled=false,updated_at=now()
          WHERE workshop_key=$1 AND NOT(objective_id=ANY($2::text[]))
          AND (catalog_active=true OR is_enabled=true)`, [workshopKey,presentObjectives])).rowCount;
      }
      if (!scoped) changed += (await client.query(`UPDATE workshop_platform.exercises
        SET catalog_active=false,is_visible=false,updated_at=now()
        WHERE NOT(workshop_key=ANY($1::text[])) AND (catalog_active=true OR is_visible=true)`,
      [presentWorkshops])).rowCount;
      for (const challengeId of (!scoped || scoped.has('xss_workshop') ? ['reflected','stored_user','stored_llm','email'] : [])) {
        const solution = legacyXssSolutions[challengeId];
        changed += (await client.query(`INSERT INTO workshop_platform.xss_legacy_solution_visibility
          (challenge_id,solutions_enabled) VALUES($1,false) ON CONFLICT DO NOTHING`,[challengeId])).rowCount;
        changed += (await client.query(`INSERT INTO workshop_platform.xss_legacy_solutions
          (challenge_id,title,difficulty,hints,examples,approach,tips)
          VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,[challengeId,solution.title,
          solution.difficulty,JSON.stringify(solution.hints||[]),JSON.stringify(solution.examples||[]),
          solution.approach||'',JSON.stringify(solution.tips||[])])).rowCount;
      }
      if (changed) {
        await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=now() WHERE id=1');
        await bump(client,{scopeType:'global',scopeKey:'*',category:'workshop_config'});
      }
      return { changed: changed > 0,
        revision: (await client.query('SELECT revision FROM workshop_platform.config_revision WHERE id=1')).rows[0].revision };
    });
  };
}

module.exports = { resolveObjectiveContent, createWorkshopPlatformSeed };
