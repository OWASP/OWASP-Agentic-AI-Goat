import React, { useRef, useState } from 'react';

const TEXT_FIELDS = Object.freeze({
  title: 'Title', description: 'Description', approach: 'Approach', difficulty: 'Difficulty',
  hint: 'Short hint', example: 'Short example', explanation: 'Explanation',
  code: 'Code', estimatedTime: 'Estimated time', vulnerability: 'Vulnerability explanation',
});
const ARRAY_FIELDS = Object.freeze({
  hints: 'Steps', tips: 'Tips', examples: 'Examples', references: 'References',
  prerequisites: 'Prerequisites',
});
const SINGULAR_FIELDS = new Set(['hint', 'example', 'explanation']);

function editableFields(workshopKey) {
  const singular = ['xss_workshop', 'csrf_workshop'].includes(workshopKey);
  return [
    ...Object.keys(TEXT_FIELDS).filter(field => (singular || !SINGULAR_FIELDS.has(field))
      && (field !== 'vulnerability' || workshopKey === 'excessive_agency')),
    ...Object.keys(ARRAY_FIELDS),
  ];
}

function makeDraft(solution, fields) {
  return Object.fromEntries(fields.map(field => [field,
    Object.prototype.hasOwnProperty.call(ARRAY_FIELDS, field)
      ? solution[field] === undefined ? '' : JSON.stringify(solution[field], null, 2)
      : solution[field] ?? '',
  ]));
}

function contentPatch(solution, draft, fields) {
  const patch = {};
  for (const field of fields) {
    const isArray = Object.prototype.hasOwnProperty.call(ARRAY_FIELDS, field);
    const text = draft[field].trim();
    if (isArray && !text && solution[field] === undefined) continue;
    if (!isArray && !text && solution[field] === undefined) continue;
    const value = isArray ? JSON.parse(text || '[]') : draft[field];
    if (isArray && !Array.isArray(value)) throw new Error(`${ARRAY_FIELDS[field]} must be a JSON array`);
    if (JSON.stringify(value) !== JSON.stringify(solution[field])) patch[field] = value;
  }
  return patch;
}

export default function WorkshopSolutionEditor({ workshopKey, objectiveId, solution, onSave, onCancel }) {
  const fields = editableFields(workshopKey);
  const [draft, setDraft] = useState(() => makeDraft(solution, fields));
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const pending = useRef(false);
  const set = (field, value) => setDraft(previous => ({ ...previous, [field]: value }));
  const save = async () => {
    if (pending.current) return;
    pending.current = true; setSaving(true); setError('');
    try {
      const patch = contentPatch(solution, draft, fields);
      if (!Object.keys(patch).length) throw new Error('Change at least one field before saving');
      if (!solution.authored && (!patch.title?.trim()
          || !['approach', 'description', 'hint', 'explanation', 'code'].some(key => patch[key]?.trim())
            && !['hints', 'examples'].some(key => patch[key]?.length))) {
        throw new Error('New solutions need a title and teaching text');
      }
      await onSave(patch);
    } catch (cause) {
      setError(cause.response?.data?.error || cause.message || 'Unable to save solution');
    } finally { pending.current = false; setSaving(false); }
  };
  const close = () => { if (!pending.current) onCancel(); };
  const fieldStyle = { display: 'block', marginBottom: '0.8rem', fontSize: '0.85rem', fontWeight: 600 };
  const inputStyle = { boxSizing: 'border-box', display: 'block', width: '100%', marginTop: '0.3rem', padding: '0.6rem', border: '1px solid #cbd5e0', borderRadius: '6px', font: 'inherit' };
  const renderField = field => <label key={field} style={fieldStyle}>{TEXT_FIELDS[field] || `${ARRAY_FIELDS[field]} (JSON array)`}
    {field === 'title' || field === 'difficulty' || field === 'estimatedTime'
      ? <input value={draft[field]} disabled={saving} onChange={event => set(field, event.target.value)} style={inputStyle} />
      : <textarea rows={field === 'examples' || field === 'approach' ? 5 : 3} value={draft[field]} disabled={saving}
          onChange={event => set(field, event.target.value)} style={inputStyle} />}
  </label>;
  return <div onClick={close} style={{ position: 'fixed', inset: 0, zIndex: 2200, background: 'rgba(0,0,0,.55)', display: 'grid', placeItems: 'center', padding: '1rem' }}>
    <div role="dialog" aria-modal="true" aria-label={`Edit solution for ${objectiveId}`} onClick={event => event.stopPropagation()}
      style={{ background: 'white', borderRadius: '12px', width: 'min(720px, 100%)', maxHeight: '90vh', overflowY: 'auto', padding: '1.5rem' }}>
      <h2 style={{ marginTop: 0 }}>Edit Solution — {objectiveId}</h2>
      <p style={{ color: '#64748b', fontSize: '0.85rem' }}>Teaching content only. Objective identity, grading, and visibility are controlled separately.</p>
      {['title', 'description', 'approach'].map(renderField)}
      <details><summary style={{ cursor: 'pointer', marginBottom: '0.8rem' }}>Additional teaching fields</summary>
        {fields.filter(field => !['title', 'description', 'approach'].includes(field)).map(renderField)}
      </details>
      {error && <p role="alert" style={{ color: '#c53030' }}>{error}</p>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '1rem' }}>
        <button type="button" disabled={saving} onClick={close}>Cancel</button>
        <button type="button" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save Changes'}</button>
      </div>
    </div>
  </div>;
}

export { contentPatch, editableFields };
