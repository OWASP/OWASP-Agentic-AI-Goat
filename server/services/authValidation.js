'use strict';
const bcrypt=require('bcryptjs');
const crypto=require('node:crypto');
// Pure validation shared by the PostgreSQL auth path; importing it opens no databases.
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required and must be a string' };
  }
  
  const trimmed = username.trim();
  
  if (trimmed.length < 3 || trimmed.length > 50) {
    return { valid: false, error: 'Username must be between 3 and 50 characters' };
  }
  
  // Only alphanumeric, underscore, hyphen
  if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
    return { valid: false, error: 'Username can only contain letters, numbers, underscore, and hyphen' };
  }
  
  // Prevent SQL injection keywords in username
  const sqlKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'UNION', '--', ';'];
  const upperUsername = trimmed.toUpperCase();
  for (const keyword of sqlKeywords) {
    if (upperUsername.includes(keyword)) {
      return { valid: false, error: 'Username contains invalid characters' };
    }
  }
  
  return { valid: true, sanitized: trimmed };
}

/**
 * Securely validate email
 * @param {string} email - Email to validate
 * @returns {object} { valid: boolean, error: string }
 */
function validateEmail(email) {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required and must be a string' };
  }
  
  const trimmed = email.trim().toLowerCase();
  
  // RFC 5322 compliant email regex (simplified)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmed)) {
    return { valid: false, error: 'Invalid email format' };
  }
  
  if (trimmed.length > 255) {
    return { valid: false, error: 'Email is too long' };
  }
  
  return { valid: true, sanitized: trimmed };
}

/**
 * Securely validate password strength
 * @param {string} password - Password to validate
 * @returns {object} { valid: boolean, error: string, strength: string }
 */
function validatePassword(password) {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required' };
  }
  
  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long' };
  }
  
  if (password.length > 128) {
    return { valid: false, error: 'Password is too long (max 128 characters)' };
  }
  
  let strength = 0;
  const checks = {
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    numbers: /[0-9]/.test(password),
    special: /[^a-zA-Z0-9]/.test(password),
    length: password.length >= 12
  };
  
  if (!checks.lowercase) {
    return { valid: false, error: 'Password must contain at least one lowercase letter' };
  }
  if (!checks.uppercase) {
    return { valid: false, error: 'Password must contain at least one uppercase letter' };
  }
  if (!checks.numbers) {
    return { valid: false, error: 'Password must contain at least one number' };
  }
  if (!checks.special) {
    return { valid: false, error: 'Password must contain at least one special character' };
  }
  
  strength = Object.values(checks).filter(Boolean).length;
  const strengthLabel = strength >= 5 ? 'strong' : strength >= 4 ? 'medium' : 'weak';
  
  return { valid: true, strength: strengthLabel };
}

/**
 * Securely hash password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} Hashed password
 */
async function secureHashPassword(password) {
  const saltRounds = 12; // Industry standard
  return await bcrypt.hash(password, saltRounds);
}

/**
 * Securely compare password with hash
 * @param {string} password - Plain text password
 * @param {string} hash - Bcrypt hash
 * @returns {Promise<boolean>} Match result
 */
async function secureComparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Generate secure session token
 * @returns {string} Secure random token
 */
function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}


module.exports={validateUsername,validateEmail,validatePassword,secureHashPassword,secureComparePassword,generateSecureToken};
