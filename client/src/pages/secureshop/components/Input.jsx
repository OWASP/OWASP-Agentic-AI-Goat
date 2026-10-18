import React, { forwardRef, useState, useId } from 'react';
import { Eye, EyeOff } from 'lucide-react';

/**
 * SecureShop v2 Input primitive.
 *
 * Supports label, error, helper text, optional icon, and password show/hide toggle.
 */
const Input = forwardRef(function Input(
  {
    label,
    error,
    helper,
    icon = null,
    type = 'text',
    id,
    className = '',
    fullWidth = true,
    ...rest
  },
  ref,
) {
  const autoId = useId();
  const inputId = id || `ss-input-${autoId}`;
  const [showPw, setShowPw] = useState(false);

  const isPassword = type === 'password';
  const effectiveType = isPassword && showPw ? 'text' : type;

  const inputClasses = ['ss-input', error ? 'ss-input--error' : '', className].filter(Boolean).join(' ');
  const wrapStyle = fullWidth ? { width: '100%' } : {};

  const inputEl = (
    <input
      ref={ref}
      id={inputId}
      type={effectiveType}
      className={inputClasses}
      aria-invalid={Boolean(error)}
      aria-describedby={error ? `${inputId}-err` : helper ? `${inputId}-help` : undefined}
      style={wrapStyle}
      {...rest}
    />
  );

  return (
    <div className="ss-input-wrap" style={wrapStyle}>
      {label && <label htmlFor={inputId} className="ss-input-label">{label}</label>}
      {icon || isPassword ? (
        <div className="ss-input-icon-wrap" style={wrapStyle}>
          {icon && <span className="ss-input-icon-wrap__icon">{icon}</span>}
          {inputEl}
          {isPassword && (
            <button
              type="button"
              className="ss-input-icon-wrap__toggle"
              onClick={() => setShowPw((v) => !v)}
              aria-label={showPw ? 'Hide password' : 'Show password'}
              tabIndex={-1}
            >
              {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          )}
        </div>
      ) : inputEl}
      {error && <span id={`${inputId}-err`} className="ss-input-error" role="alert">{error}</span>}
      {!error && helper && <span id={`${inputId}-help`} className="ss-input-helper">{helper}</span>}
    </div>
  );
});

export default Input;
