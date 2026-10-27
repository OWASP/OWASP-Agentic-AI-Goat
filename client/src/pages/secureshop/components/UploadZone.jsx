import React, { useCallback, useEffect, useRef, useState } from 'react';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { useProductManualUpload } from './useProductManualUpload.js';
import { useAccountAvatarUpload } from './useAccountAvatarUpload.js';

/**
 * UploadZone — drag-drop file uploader with the intentionally weak UX from
 * spec §6.10:
 *   - Editable filename field (so students can craft path-traversal payloads)
 *   - "public" toggle (visual only; the backend serves everything inline)
 *   - No MIME allowlist; no size warning
 *
 * Props:
 *   kind: 'avatar' | 'product_image' | 'product_manual' | 'return_evidence'
 *   scopeId: number         — user/product/order id depending on kind
 *   onUploaded: (result) => void
 *   label?: string
 */
export default function UploadZone({ kind = 'avatar', scopeId = 1, onUploaded, label = null,
  accountAvatar = false,
  authToken, merchantId, transport = globalThis.fetch }) {
  const boundManual = kind === 'product_manual' && getBridgeFetchMetadata(transport) !== null;
  const manual = useProductManualUpload({ enabled: boundManual, productId: scopeId,
    merchantId, authToken, transport, onUploaded });
  const avatar = useAccountAvatarUpload({ enabled: accountAvatar && kind === 'avatar',
    ownerId: scopeId, authToken, transport, onUploaded });
  const [file, setFile] = useState(null);
  const [filename, setFilename] = useState('');
  const [isPublic, setIsPublic] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [lastResult, setLastResult] = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef(null);
  const requestRef = useRef(null);
  const requestGenerationRef = useRef(0);
  const mountedRef = useRef(true);

  const abortActiveRequest = useCallback(() => {
    requestGenerationRef.current += 1;
    requestRef.current?.controller.abort();
    requestRef.current = null;
    if (mountedRef.current) setUploading(false);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    requestGenerationRef.current += 1;
    requestRef.current?.controller.abort();
    requestRef.current = null;
    setFile(null);
    setFilename('');
    setLastResult(null);
    setUploading(false);
    if (inputRef.current) inputRef.current.value = '';
    return () => {
      requestGenerationRef.current += 1;
      requestRef.current?.controller.abort();
      requestRef.current = null;
    };
  }, [kind, scopeId, accountAvatar && authToken, accountAvatar && transport]);

  useEffect(() => () => {
    mountedRef.current = false;
    requestRef.current?.controller.abort();
    requestRef.current = null;
  }, []);

  const pick = useCallback((f) => {
    abortActiveRequest();
    setFile(f);
    setFilename(f.name);
    setLastResult(null);
  }, [abortActiveRequest]);

  const onDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer?.files?.[0];
    if (f) pick(f);
  }, []);

  const upload = async () => {
    if (!file || requestRef.current) return;
    if (boundManual) {
      await manual.uploadManual({ file, filename, isPublic });
      return;
    }
    if (accountAvatar) {
      await avatar.uploadAvatar({ file, filename, isPublic });
      return;
    }
    const selectedFile = file;
    const selectedScopeId = scopeId;
    const generation = ++requestGenerationRef.current;
    const controller = new AbortController();
    requestRef.current = { controller, generation };
    setUploading(true);
    try {
      const fd = new FormData();
      // The editable filename overrides the actual file name — that's the vuln.
      fd.append('file', new File([selectedFile], filename || selectedFile.name, { type: selectedFile.type }));
      fd.append('kind', kind);
      fd.append('scope_id', String(selectedScopeId));
      fd.append('mime', selectedFile.type || 'application/octet-stream');
      fd.append('public', String(isPublic));
      const r = await fetch('/api/secureshop/uploads', { method: 'POST', body: fd, signal: controller.signal });
      const responseText = await r.text();
      let j;
      try { j = JSON.parse(responseText); } catch { j = { ok: false, error: 'Upload returned invalid JSON' }; }
      const current = mountedRef.current && requestRef.current?.generation === generation
        && requestGenerationRef.current === generation && requestRef.current?.controller === controller;
      if (!current) return;
      if (!r.ok || j?.ok !== true) {
        setLastResult({ ...(j && typeof j === 'object' ? j : {}), ok: false,
          error: j?.error || `Upload failed (${r.status})` });
        return;
      }
      setLastResult(j);
      if (onUploaded) onUploaded(j);
    } catch (e) {
      const current = mountedRef.current && requestRef.current?.generation === generation
        && requestGenerationRef.current === generation && requestRef.current?.controller === controller;
      if (current && e?.name !== 'AbortError') setLastResult({ ok: false, error: e.message || 'Upload failed' });
    } finally {
      if (requestRef.current?.generation === generation) {
        requestRef.current = null;
        if (mountedRef.current) setUploading(false);
      }
    }
  };

  return (
    <div className="ss-uploadzone" style={{
      border: '1px dashed var(--rule)',
      padding: 20,
      background: dragOver ? 'var(--carbon)' : 'transparent',
      color: dragOver ? 'var(--paper)' : 'inherit',
      transition: 'background 200ms',
    }}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={onDrop}
    >
      <div className="ss-card__meta" style={{ marginBottom: 8 }}>
        {label || `Upload → ${kind}`}
      </div>
      {kind === 'product_manual' && <p aria-label="Product manual upload consequence"
        style={{ fontSize: 13, lineHeight: 1.5, margin: '0 0 12px' }}>
        Uploading stores and indexes this file for product #{scopeId} in the manuals corpus.
        Its contents may influence later product answers and recommendations.
        The public/private selection is lesson metadata, not a confidentiality guarantee.
      </p>}
      <input
        ref={inputRef}
        type="file"
        style={{ display: 'none' }}
        onChange={(e) => e.target.files?.[0] && pick(e.target.files[0])}
      />
      <div style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: 10, alignItems: 'center', marginTop: 8 }}>
        <button type="button" className="ss-btn ss-btn--ghost" onClick={() => inputRef.current?.click()} style={{ padding: '6px 12px' }}>
          {file ? file.name : 'Choose file or drop here'}
        </button>
        <label className="ss-mono" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={isPublic} onChange={(e) => setIsPublic(e.target.checked)} />
          public
        </label>
        <button type="button" className="ss-btn" onClick={upload}
          disabled={!file || uploading || manual.blocked || (accountAvatar && avatar.blocked)} style={{ padding: '6px 14px' }}>
          {uploading || (boundManual && manual.busy) || (accountAvatar && avatar.busy) ? 'Uploading…' : 'Upload'}
        </button>
      </div>

      {boundManual && manual.pending && <div role="status" className="ss-mono" style={{ marginTop: 12 }}>
        A saved upload has an unresolved outcome. Check it before any new upload.
        <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={manual.checkSaved}
          disabled={manual.busy} style={{ marginLeft: 8 }}>Check saved upload</button>
      </div>}
      {boundManual && manual.error && <div role="alert" className="ss-mono" style={{ marginTop: 8 }}>
        {manual.error}
      </div>}
      {accountAvatar && avatar.pending && <div role="status" className="ss-mono" style={{ marginTop: 12 }}>
        A saved avatar upload has an unresolved outcome. Check it before another upload.
        <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={avatar.checkSaved}
          disabled={avatar.busy} style={{ marginLeft: 8 }}>Check saved upload</button>
      </div>}
      {accountAvatar && avatar.error && <div role="alert" className="ss-mono" style={{ marginTop: 8 }}>
        {avatar.error}
      </div>}

      {file && (
        <div style={{ marginTop: 12 }}>
          <label className="ss-mono" style={{ opacity: 0.7, display: 'block', marginBottom: 4 }}>Filename (editable — this is what gets stored):</label>
          <input
            type="text"
            className="ss-mono"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            style={{
              width: '100%', padding: '6px 8px', background: 'var(--carbon)', color: 'var(--paper)',
              border: '1px solid var(--rule)', fontSize: 13, fontFamily: 'var(--mono)',
            }}
          />
        </div>
      )}

      {(boundManual ? manual.result : accountAvatar ? avatar.result : lastResult) && (
        <pre className="ss-mono" style={{
          marginTop: 12, padding: 10, background: 'var(--carbon)', color: 'var(--paper)',
          fontSize: 11, overflowX: 'auto', maxHeight: 200,
        }}>{JSON.stringify(boundManual ? manual.result : accountAvatar ? avatar.result : lastResult, null, 2)}</pre>
      )}
    </div>
  );
}
