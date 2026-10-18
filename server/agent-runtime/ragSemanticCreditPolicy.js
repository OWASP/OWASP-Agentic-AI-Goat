'use strict';
// v7 has a known conjunction defect; v8's structural correction has not passed
// semantic qualification. Contain new credit/retries, preserving terminal history.
function gradingUnqualified(row){return row?.family==='IPI'&&row?.scenario==='document'&&row?.objective_id==='rag_injected_doc'&&['ipi-rag-defense-semantic-decomposition-v7','ipi-rag-defense-semantic-decomposition-v8'].includes(row?.rubric_version);}
module.exports={gradingUnqualified};
