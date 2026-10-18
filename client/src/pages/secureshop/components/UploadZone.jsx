import React, { useCallback, useEffect, useRef, useState } from 'react';

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
export default function UploadZone({ kind = 'avatar', scopeId = 1, onUploaded, label = null }) {
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
  }, [kind, scopeId]);

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
        <button type="button" className="ss-btn" onClick={upload} disabled={!file || uploading} style={{ padding: '6px 14px' }}>
          {uploading ? 'Uploading…' : 'Upload'}
        </button>
      </div>

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

      {lastResult && (
        <pre className="ss-mono" style={{
          marginTop: 12, padding: 10, background: 'var(--carbon)', color: 'var(--paper)',
          fontSize: 11, overflowX: 'auto', maxHeight: 200,
        }}>{JSON.stringify(lastResult, null, 2)}</pre>
      )}
    </div>
  );
}
