'use strict';

const { createLegacySensitiveObjectiveGrader } = require('./legacySensitiveObjectiveGrader');

function selectedObjective(result) {
  if (result?.decision?.action === 'read_teaching_file') return 'ai_assisted_path_traversal';
  if (result?.decision?.action === 'render_ssi_template') return 'ai_assisted_ssi';
  return null;
}

function createLegacySensitiveCandidateApplication({ agent, runs, completionService, reset, snapshot, modeAuthority,
  observationCandidates = require('./legacySensitiveAgent').legacySensitiveObservationCandidates, admit = async () => {} } = {}) {
  if (typeof agent?.run !== 'function' || typeof runs?.run !== 'function'
      || typeof reset?.reset !== 'function') throw new TypeError('Complete Legacy Sensitive candidate dependencies are required');
  const grader = createLegacySensitiveObjectiveGrader({ completionService });
  return Object.freeze({
    async begin(userId, execution) {
      await execution.check();
      await admit(Number(userId));
      await execution.check();
      return grader.begin(Number(userId), execution);
    },
    assess({ userId, objectiveId, request, result, execution, attempt }) {
      return grader.evaluate({ userId: Number(userId), objectiveId, request, result, execution, attempt });
    },
    async run({ userId, message, request = {}, signal }) {
      return runs.run(String(userId), { signal }, async execution => {
        const attempt = await this.begin(Number(userId), execution);
        const capturedMode = modeAuthority ? await modeAuthority.capture(Number(userId), execution)
          : { mode: 'vuln', check: async () => {} };
        const result = await agent.run({ message, request, execution,
          mode: capturedMode.mode, checkMode: capturedMode.check });
        await capturedMode.check();
        await execution.check();
        if (result?.status === 'unqualified_model' || result?.status === 'unqualified_response') {
          throw Object.assign(new Error('A qualified model response is unavailable'),
            { code: 'MODEL_PROVIDER_UNAVAILABLE' });
        }
        if (result?.status === 'step_limit') {
          throw Object.assign(new Error('Agent reached the tool step limit'), { code: 'AGENT_STEP_LIMIT' });
        }
        if (result?.status === 'no_operation') {
          if (result.qualified !== true || result.responseQualified !== true
              || result.decision != null || !Array.isArray(result.trajectory) || result.trajectory.length) {
            throw Object.assign(new Error('Invalid no-operation model outcome'), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
          }
          return Object.freeze({ ...result, objectiveId: null, judgment: null,
            completed: false, durableGrading: false });
        }
        if (result?.status !== 'completed') {
          throw Object.assign(new Error('Agent did not complete its decision loop'), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
        }
        const candidates=observationCandidates(result,execution);
        if(!Array.isArray(candidates)||candidates.length<1||candidates.length>3)throw Object.assign(new Error('Server-owned observation provenance is required'),{code:'MODEL_PROVIDER_UNAVAILABLE'});
        const judgments=[];
        for(const [index,candidate] of candidates.entries()){
          await execution.check();
          await capturedMode.check();
          const objectiveId=selectedObjective(candidate);
          if(!objectiveId)throw Object.assign(new Error('No canonical objective matches the selected operation'),{code:'OBJECTIVE_NOT_OBSERVED'});
          try{
            const outcome=await this.assess({userId:Number(userId),objectiveId,request:message,result:candidate,execution,attempt});
            judgments.push(Object.freeze({objectiveId,observationOrdinal:candidate.observationOrdinal||index+1,
              judgment:outcome.judgment,completed:outcome.completed===true,durableGrading:outcome.durable===true}));
          }catch(error){
            if(error.code!=='OBJECTIVE_DISABLED')throw error;
            judgments.push(Object.freeze({objectiveId,observationOrdinal:candidate.observationOrdinal||index+1,judgment:null,completed:false,durableGrading:false,code:'OBJECTIVE_DISABLED'}));
          }
        }
        await execution.check();
        const final=judgments.at(-1);
        return Object.freeze({...result,...final,judgments:Object.freeze(judgments),
          completedObjectives:Object.freeze([...new Set(judgments.filter(value=>value.completed).map(value=>value.objectiveId))])});
      });
    },
    async snapshot(ownerId) {
      if(typeof snapshot!=='function')throw Object.assign(new Error('Canonical snapshot is unavailable'),{code:'GRADE_STORE_NOT_READY'});
      await admit(Number(ownerId));return snapshot(Number(ownerId));
    },
    reset(ownerId, options) { return reset.reset(ownerId, options); },
  });
}

module.exports = { selectedObjective, createLegacySensitiveCandidateApplication };
