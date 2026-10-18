import React, { useState } from 'react';

const ROLES = [
  { key: 'customer', title: 'Customer', hint: 'Shop, review, checkout.' },
  { key: 'merchant', title: 'Merchant', hint: 'List, moderate, price.' },
  { key: 'admin',    title: 'Admin',    hint: 'Users, audit, policy.' },
];

export default function RoleSwitcher({ role, onChange }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="ss-nav__role" onClick={() => setOpen(true)} data-testid="role-switcher-btn">
        role: {role} ⌄
      </button>
      {open && (
        <div className="ss-role-modal-backdrop" onClick={() => setOpen(false)}>
          <div className="ss-role-modal" onClick={(e) => e.stopPropagation()}>
            <h3>Choose a lens.</h3>
            <p style={{ opacity: 0.7, fontSize: 14 }}>Each persona sees the same store through a different agent supervisor.</p>
            <div className="ss-role-cards">
              {ROLES.map(r => (
                <button key={r.key} className="ss-role-card"
                        onClick={() => { onChange(r.key); setOpen(false); }}>
                  <div className="ss-role-card__label">{r.key}</div>
                  <div className="ss-role-card__title">{r.title}</div>
                  <div className="ss-role-card__hint">{r.hint}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
