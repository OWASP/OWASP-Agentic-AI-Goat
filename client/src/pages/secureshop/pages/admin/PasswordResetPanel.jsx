import React, { useEffect, useRef, useState } from 'react';
import { shopStorage, flushShopStorage, SHOP_PASSWORD_RESET_KEY } from '../../utils/shopStorage.mjs';
function restore(scopeKey) {
  const raw = shopStorage.getItem(SHOP_PASSWORD_RESET_KEY);
  if (!raw) return null;
  if (raw.length > 4096) throw Error('Saved reset is invalid');
  const value = JSON.parse(raw);
  if (value.scopeKey !== scopeKey) return { foreignScope: true };
  if (Object.keys(value).sort().join(',') !== 'expectedAuthorityVersion,expectedCredentialVersion,operationId,scopeKey,targetId'
    || !Number.isSafeInteger(value.targetId) || value.targetId < 1
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value.operationId)
    || ['expectedAuthorityVersion','expectedCredentialVersion'].some(key => typeof value[key] !== 'string' || !/^[1-9]\d{0,18}$/.test(value[key]))) throw Error('Saved reset is invalid');
  return value;
}
function verify(receipt, pending) {
  if (!receipt || receipt.operationId !== pending.operationId || receipt.targetId !== pending.targetId
    || receipt.credentialVersion !== String(BigInt(pending.expectedCredentialVersion) + 1n)
    || receipt.authorityVersion !== String(BigInt(pending.expectedAuthorityVersion) + 1n)
    || !/^[a-f0-9]{64}$/.test(receipt.receiptSha256) || !Number.isFinite(Date.parse(receipt.expiresAt))) throw Error('Reset receipt not verified');
}
// Parent keys this component by exact scope+credential. Password lives only here.
export default function PasswordResetPanel({ scopeKey, target, onClose }) {
  const [pending,setPending] = useState(null), [metadata,setMetadata] = useState(null);
  const [discardable,setDiscardable] = useState(false);
  const [secret,setSecret] = useState(null), [error,setError] = useState(null), [busy,setBusy] = useState(false);
  const alive = useRef(true), lock = useRef(false), transport = globalThis.fetch;
  const current = () => alive.current && globalThis.fetch === transport;
  useEffect(() => { alive.current=true; try { const saved=restore(scopeKey); if(saved?.foreignScope){setDiscardable(true);setError('Saved reset belongs to an earlier administrator session or launch. Its outcome is unknown; dismissal does not undo it.');}else setPending(saved); } catch { setDiscardable(true);setError('Saved reset unavailable. Dismiss its local reference and reload before continuing.'); }
    return () => { alive.current=false; }; }, [scopeKey]);
  async function request(kind) {
    if(lock.current || (kind==='reset' && (pending || error || !target))) return;
    lock.current=true;setBusy(true);setError(null);setSecret(null);
    let operation=pending, dispatched=false;
    try {
      if(kind==='reset') {
        operation={scopeKey,targetId:target.id,operationId:crypto.randomUUID(),expectedCredentialVersion:target.credential_version,expectedAuthorityVersion:target.authority_version};
        shopStorage.setItem(SHOP_PASSWORD_RESET_KEY,JSON.stringify(operation));await flushShopStorage();
        if(!current()) return;setPending(operation);
      }
      const root=`/api/secureshop/admin/users/${operation.targetId}`;
      const url=kind==='reset'?`${root}/reset-password`:`${root}/password-resets/${operation.operationId}${kind==='read'?'':'/'+kind}`;
      dispatched=true;
      const response=await transport(url,kind==='read'?undefined:{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(kind==='reset'?{operationId:operation.operationId,expectedCredentialVersion:operation.expectedCredentialVersion,expectedAuthorityVersion:operation.expectedAuthorityVersion}:{})});
      if(!response.ok) { if(current() && [401,403,404,409].includes(response.status))setDiscardable(true); throw Error(response.status===401||response.status===403?'Original administrator session is no longer authorized. Reset outcome remains unknown.':response.status===404?'No committed reset observed. No reset was replayed.':'Reset outcome unavailable. Read its status before another action.'); }
      const result=await response.json();if(!current())return;
      if(result?.ok!==true)throw Error('Reset response not verified');verify(result.receipt,operation);
      if(kind==='reveal') { if(typeof result.temporaryPassword!=='string'||!/^[A-Za-z0-9_-]{32,128}$/.test(result.temporaryPassword))throw Error('Password reveal not verified');setSecret(result.temporaryPassword); }
      else setMetadata(result);
      if(kind==='acknowledge'||result.secretAvailable===false){shopStorage.removeItem(SHOP_PASSWORD_RESET_KEY);await flushShopStorage();if(current()){setPending(null);setMetadata(null);onClose();}}
    } catch(e) {
      if(kind==='reset'&&!dispatched){
        // A retired component must never erase the next scope's saved operation.
        if(current()) {
          try {
            const saved=JSON.parse(shopStorage.getItem(SHOP_PASSWORD_RESET_KEY)||'null');
            if(current() && saved?.scopeKey===operation?.scopeKey && saved?.operationId===operation?.operationId){shopStorage.removeItem(SHOP_PASSWORD_RESET_KEY);await flushShopStorage();}
          }catch{}
          if(current()){setPending(null);setError('Storage unavailable; no reset was sent.');}
        }
      }
      else if(current())setError(e.message);
    } finally {lock.current=false;if(current())setBusy(false);}
  }
  async function dismiss() {
    if(lock.current)return;
    lock.current=true;setBusy(true);setSecret(null);
    try {
      shopStorage.removeItem(SHOP_PASSWORD_RESET_KEY);await flushShopStorage();
      if(current()){setPending(null);setMetadata(null);setDiscardable(false);setError(null);onClose();}
    } catch { if(current())setError('Local recovery reference could not be cleared. Reload before continuing.'); }
    finally {lock.current=false;if(current())setBusy(false);}
  }
  if(!target&&!pending&&!error)return null;
  return <div className="ss-shelf" role="region" aria-label="Password reset recovery" style={{padding:16,marginBottom:16}}>
    <strong>Password reset</strong>
    {error&&<p role="alert">{error}</p>}
    {!pending&&target&&<><p>Reset {target.username}'s password and revoke their sessions and API keys.</p><button className="ss-btn" disabled={busy||!!error} onClick={()=>request('reset')}>Confirm password reset</button></>}
    {pending&&<><p>Keep this original administrator session to recover the temporary password.</p><button className="ss-btn" disabled={busy} onClick={()=>request('read')}>Read reset status</button>
      {metadata?.secretAvailable===true&&<button className="ss-btn" disabled={busy} onClick={()=>request('reveal')}>Reveal temporary password</button>}
      {secret&&<><output aria-label="Temporary password">{secret}</output><button className="ss-btn" disabled={busy} onClick={()=>{setSecret(null);request('acknowledge');}}>Acknowledge and clear password</button></>}
    </>}
    {discardable&&<><p>Dismissal clears only this local recovery reference. It does not undo a reset. Reload current user versions before explicitly starting a new reset.</p><button className="ss-btn" disabled={busy} onClick={dismiss}>Dismiss saved reset and reload</button></>}
    {!pending&&!discardable&&<button className="ss-btn" disabled={busy} onClick={() => { setError(null); onClose(); }}>Close</button>}
  </div>;
}
