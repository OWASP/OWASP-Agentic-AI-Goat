export function requireAgentContentType(response, expected, label) {
  const contentType = response.headers?.get?.('content-type') || '';
  if (contentType.toLowerCase().split(';', 1)[0].trim() !== expected) {
    throw new Error(`${label} returned unexpected content type`);
  }
}

export function takeAgentFrame(buffer) {
  const match = /\r?\n\r?\n/.exec(buffer);
  if (!match) return null;
  return { frame: buffer.slice(0, match.index), rest: buffer.slice(match.index + match[0].length) };
}

export function parseAgentFrame(frame) {
  const lines = frame.split(/\r?\n/);
  const eventLine = lines.find((line) => line.startsWith('event:'));
  const dataLines = lines.filter((line) => line.startsWith('data:'));
  if (!eventLine || dataLines.length === 0) return null;
  const name = eventLine.slice('event:'.length).trim();
  let payload;
  try {
    payload = JSON.parse(dataLines.map((line) => line.slice('data:'.length).trimStart()).join('\n'));
  } catch {
    throw new Error('Agent stream returned invalid event data');
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('Agent stream returned invalid event data');
  }
  return { name, payload };
}
