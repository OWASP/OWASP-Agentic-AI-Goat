'use strict';

function extractBearerToken(header) {
  if (typeof header !== 'string') return null;
  const match = /^Bearer ([^\s,]+)$/i.exec(header);
  return match && match[0] === header ? match[1] : null;
}

// IncomingMessage may discard later singleton Authorization field lines from
// headers. Inspect the physical fields before accepting its normalized value.
function readBearerAuthorization(req) {
  const header = req?.headers?.authorization;
  let values;
  if (Array.isArray(req?.rawHeaders)) {
    values = [];
    for (let index = 0; index < req.rawHeaders.length; index += 2) {
      if (String(req.rawHeaders[index]).toLowerCase() === 'authorization') {
        values.push(req.rawHeaders[index + 1]);
      }
    }
  } else if (req?.headersDistinct && 'authorization' in req.headersDistinct) {
    values = req.headersDistinct.authorization;
  } else {
    values = header === undefined ? [] : [header];
  }
  const present = header !== undefined || !Array.isArray(values) || values.length > 0;
  const token = Array.isArray(values) && values.length === 1
    ? extractBearerToken(values[0]) : null;
  return { present, token };
}

module.exports = { readBearerAuthorization };
