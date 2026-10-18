'use strict';
const assert=require('node:assert/strict');
const id='ss_mail_header_construction';
const HINTS=["Compose uses a single-line subject input. To introduce actual CR/LF, intercept your authenticated owned POST /api/secureshop/email/send JSON and change only its subject value.","In JSON, use the escapes \\r\\n inside the subject string; the server decodes them to carriage return and line feed. Do not double-escape them into literal backslashes. Keep the original requestId and owned from/to values.","Send the source message to your own lab mailbox, refresh and select it, then use Auto-reply. Once the reply is saved, Check saved headers assesses the server-issued saved reply reference. Storage is not SMTP or BCC delivery."];
const EXAMPLE={"action":"In merchant Inbox, Compose a message to your own displayed lab address with a normal subject. Intercept its authenticated POST /api/secureshop/email/send JSON before forwarding. Preserve requestId, from, to and body_markdown; replace subject with the JSON string \"Header lesson\\r\\nX-Training: owned\" (one backslash before each r and n). Forward once. Refresh, select that source thread and choose Auto-reply. After the saved-reply confirmation, choose Check saved headers. If the response is lost, recover the existing request; do not invent a new operation ID or alter a replayed body.","explanation":"Only exact owned stored bytes and canonical Judge acceptance qualify. Ordinary header separators, literal backslashes, body-only newlines and another learner’s message do not establish the effect. This is stored header construction, not BCC delivery."};
function stageMailHeaderCandidateCatalog(source){
 assert(source.includes(id+': '+JSON.stringify(HINTS)+','),'Reviewed canonical header hints required');
 assert(source.includes(id+': '+JSON.stringify(EXAMPLE)+','),'Reviewed canonical header solution required');
 const lines=source.split('\n'),index=lines.findIndex(x=>x.includes(`{ id: '${id}',`));assert(index>=0);assert(/qualification: '(pending|native-model)'/.test(lines[index]),'Unknown header qualification');lines[index]=lines[index].replace("qualification: 'pending'","qualification: 'native-model'");
 return lines.join('\n');
}
module.exports={stageMailHeaderCandidateCatalog,HINTS,EXAMPLE};
