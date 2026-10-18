import React, { useRef } from 'react';

/**
 * SecureShop v2 Tabs — accessible tabs with keyboard navigation.
 *
 * Usage:
 *   <Tabs tabs={[{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }]}
 *         value={active} onChange={setActive}>
 *     {active === 'a' && <PanelA />}
 *     {active === 'b' && <PanelB />}
 *   </Tabs>
 */
export default function Tabs({ tabs, value, onChange, children }) {
  const tabRefs = useRef([]);

  const handleKey = (e, idx) => {
    let next = null;
    if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next != null) {
      e.preventDefault();
      onChange(tabs[next].id);
      tabRefs.current[next]?.focus();
    }
  };

  return (
    <div>
      <div className="ss-tabs" role="tablist">
        {tabs.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => (tabRefs.current[i] = el)}
            role="tab"
            aria-selected={value === t.id}
            aria-controls={`ss-tab-panel-${t.id}`}
            id={`ss-tab-${t.id}`}
            tabIndex={value === t.id ? 0 : -1}
            className={`ss-tabs__tab ${value === t.id ? 'ss-tabs__tab--active' : ''}`}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => handleKey(e, i)}
            type="button"
          >
            {t.label}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id={`ss-tab-panel-${value}`}
        aria-labelledby={`ss-tab-${value}`}
        className="ss-tabs__panel"
      >
        {children}
      </div>
    </div>
  );
}
