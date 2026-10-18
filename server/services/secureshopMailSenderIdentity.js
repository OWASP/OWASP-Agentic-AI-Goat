'use strict';
// Only for rows returned by canonical bound_lab_mail. Its send function binds
// this normalized address to the authenticated sender before saving the row.
// This is not a validator for arbitrary external mail or caller-supplied headers.
function savedMailSender(personas, fromAddress) {
 if (!Array.isArray(personas) || typeof fromAddress !== 'string') return null;
 const address = fromAddress.replace(/\r/g, '').split('\n')[0];
 const matches = personas.filter(persona => persona.email === address);
 return matches.length === 1 ? matches[0] : null;
}
module.exports = { savedMailSender };
