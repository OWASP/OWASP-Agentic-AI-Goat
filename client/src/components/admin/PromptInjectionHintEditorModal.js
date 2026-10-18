import React, { useState } from 'react';
import { FiEdit, FiPlus, FiTrash2, FiX } from 'react-icons/fi';
import styled from 'styled-components';

const Overlay = styled.div`
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2100;
  padding: 2rem;
`;

const Content = styled.div`
  background: white;
  border-radius: 16px;
  width: 100%;
  max-width: 640px;
  max-height: 90vh;
  overflow-y: auto;
`;

const Header = styled.div`
  padding: 1.5rem 2rem 1rem;
  border-bottom: 1px solid #e2e8f0;
  display: flex;
  justify-content: space-between;
  align-items: center;

  h2 { margin: 0; color: #1a202c; font-size: 1.25rem; }
`;

const Body = styled.div`
  padding: 1.5rem 2rem;
`;

const Footer = styled.div`
  padding: 1rem 2rem;
  border-top: 1px solid #e2e8f0;
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  background: #f8fafc;
  border-bottom-left-radius: 16px;
  border-bottom-right-radius: 16px;
`;

const Field = styled.div`
  margin-bottom: 1rem;

  label { display: block; margin-bottom: 0.4rem; color: #4a5568; font-weight: 600; font-size: 0.875rem; }
  input, textarea {
    box-sizing: border-box;
    width: 100%;
    padding: 0.7rem;
    border: 2px solid #e2e8f0;
    border-radius: 8px;
    font-size: 0.95rem;
  }
  input:focus, textarea:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
  }
`;

const Button = styled.button`
  border: none;
  border-radius: 8px;
  padding: 0.55rem 1rem;
  cursor: pointer;
  font-size: 0.875rem;
  font-weight: 600;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  background: ${props => props.$secondary ? '#edf2f7' : '#667eea'};
  color: ${props => props.$secondary ? '#4a5568' : 'white'};
  opacity: ${props => props.disabled ? 0.6 : 1};
`;

function PromptInjectionHintEditorModal({ objectiveLabel, hint, onCancel, onSave, saving = false }) {
  const [title, setTitle] = useState(hint?.title || '');
  const [hints, setHints] = useState(
    Array.isArray(hint?.hints) && hint.hints.length ? [...hint.hints] : [''],
  );
  const valid = !!title.trim() && hints.length > 0 && hints.every((entry) => entry.trim());

  const updateHint = (index, value) => {
    setHints((current) => current.map((entry, currentIndex) =>
      currentIndex === index ? value : entry));
  };

  const removeHint = (index) => {
    setHints((current) => current.filter((_, currentIndex) => currentIndex !== index));
  };

  const save = () => {
    if (!valid || saving) return;
    onSave({
      title: title.trim(),
      hints: hints.map((entry) => entry.trim()),
    });
  };

  return (
    <Overlay onClick={onCancel}>
      <Content
        role="dialog"
        aria-modal="true"
        aria-labelledby="prompt-injection-hint-editor-title"
        onClick={(event) => event.stopPropagation()}
      >
        <Header>
          <h2 id="prompt-injection-hint-editor-title" style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <FiEdit style={{ color: '#667eea' }} /> Edit Hint — {objectiveLabel}
          </h2>
          <button
            type="button"
            aria-label="Close hint editor"
            onClick={onCancel}
            style={{ background: 'none', border: 'none', color: '#718096', cursor: 'pointer', padding: '0.5rem', display: 'flex' }}
          >
            <FiX size={20} />
          </button>
        </Header>
        <Body>
          <Field>
            <label htmlFor="prompt-injection-hint-title">Title</label>
            <input
              id="prompt-injection-hint-title"
              value={title}
              onChange={(event) => setTitle(event.target.value)}
            />
          </Field>

          {hints.map((entry, index) => (
            <Field key={index}>
              <label htmlFor={`prompt-injection-hint-${index}`}>Hint {index + 1}</label>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                <textarea
                  id={`prompt-injection-hint-${index}`}
                  rows={3}
                  value={entry}
                  onChange={(event) => updateHint(index, event.target.value)}
                />
                {hints.length > 1 && (
                  <button
                    type="button"
                    aria-label={`Remove hint ${index + 1}`}
                    onClick={() => removeHint(index)}
                    style={{ background: 'none', border: 'none', color: '#e53e3e', cursor: 'pointer', padding: '0.6rem 0.2rem' }}
                  >
                    <FiTrash2 size={17} />
                  </button>
                )}
              </div>
            </Field>
          ))}

          <Button
            type="button"
            onClick={() => setHints((current) => [...current, ''])}
            style={{ background: '#48bb78', padding: '0.45rem 0.8rem', fontSize: '0.8rem' }}
          >
            <FiPlus /> Add Hint
          </Button>
        </Body>
        <Footer>
          <Button type="button" $secondary onClick={onCancel}>Cancel</Button>
          <Button type="button" disabled={!valid || saving} onClick={save}>
            {saving ? 'Saving…' : 'Save Changes'}
          </Button>
        </Footer>
      </Content>
    </Overlay>
  );
}

export default PromptInjectionHintEditorModal;
