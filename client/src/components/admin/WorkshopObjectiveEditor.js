import React, { useRef, useState } from 'react';

export default function WorkshopObjectiveEditor({ objective, onSave, onCancel }) {
  const [label, setLabel] = useState(objective.label || '');
  const [description, setDescription] = useState(objective.description || '');
  const [category, setCategory] = useState(objective.category || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const pending = useRef(false);
  const close = () => { if (!pending.current) onCancel(); };
  const save = async () => {
    if (pending.current) return;
    const patch = Object.fromEntries(Object.entries({ label: label.trim(), description: description.trim(), category: category.trim() })
      .filter(([field, value]) => value !== objective[field]));
    if (!patch.label && !label.trim()) { setError('Objective title is required'); return; }
    if (!Object.keys(patch).length) { close(); return; }
    pending.current = true; setSaving(true); setError('');
    try { await onSave(patch); }
    catch (cause) { setError(cause.response?.data?.error || cause.message || 'Unable to save objective'); }
    finally { pending.current = false; setSaving(false); }
  };
  const fieldStyle = { display: 'block', marginBottom: '1rem', fontWeight: 600, fontSize: '0.85rem' };
  const inputStyle = { boxSizing: 'border-box', display: 'block', width: '100%', marginTop: '0.3rem', padding: '0.6rem', border: '1px solid #cbd5e0', borderRadius: '6px', font: 'inherit' };
  return <div onClick={close} style={{ position: 'fixed', inset: 0, zIndex: 2200, background: 'rgba(0,0,0,.55)', display: 'grid', placeItems: 'center', padding: '1rem' }}>
    <div role="dialog" aria-modal="true" aria-label={`Edit objective ${objective.objectiveId}`} onClick={event => event.stopPropagation()}
      style={{ background: 'white', borderRadius: '12px', width: 'min(640px, 100%)', maxHeight: '90vh', overflowY: 'auto', padding: '1.5rem' }}>
      <h2 style={{ marginTop: 0 }}>Edit Objective — {objective.objectiveId}</h2>
      <p style={{ color: '#64748b', fontSize: '0.85rem' }}>The objective ID and grading rules stay fixed. The title, description, and category appear in learner views.</p>
      <label style={fieldStyle}>Title<input value={label} maxLength={240} disabled={saving} onChange={event => setLabel(event.target.value)} style={inputStyle} /></label>
      <label style={fieldStyle}>Description<textarea rows={5} value={description} maxLength={4000} disabled={saving} onChange={event => setDescription(event.target.value)} style={inputStyle} /></label>
      <label style={fieldStyle}>Category<input value={category} maxLength={120} disabled={saving} onChange={event => setCategory(event.target.value)} style={inputStyle} /></label>
      {error && <p role="alert" style={{ color: '#c53030' }}>{error}</p>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem' }}>
        <button type="button" disabled={saving} onClick={close}>Cancel</button>
        <button type="button" disabled={saving} onClick={save}>{saving ? 'Saving…' : 'Save Changes'}</button>
      </div>
    </div>
  </div>;
}
