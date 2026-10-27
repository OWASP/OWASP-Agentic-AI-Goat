// Typed upload envelope; Blob bytes never pass through JSON/base64 encoding.
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
const encoder = new TextEncoder();
const MAX_METADATA_BYTES = 24 * 1024;
const fieldNames = ['kind', 'scope_id', 'mime', 'public'];
const fail = () => { throw new TypeError('Invalid shop upload'); };
const exact = (value, keys) => {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length) fail();
  for (const key of keys) if (!Object.hasOwn(descriptors, key) || !Object.hasOwn(descriptors[key], 'value')) fail();
};

export function compileUpload(input) {
  exact(input, ['file', 'filename', 'fields']);
  const scopedManual = Object.getOwnPropertyDescriptor(input.fields ?? {}, 'kind')?.value === 'product_manual'
    && Object.hasOwn(input.fields, 'recoveryScopeKey');
  exact(input.fields, scopedManual ? [...fieldNames, 'recoveryScopeKey'] : fieldNames);
  if (!(input.file instanceof Blob) || input.file.size > MAX_UPLOAD_BYTES) fail();
  if (input.file.type.length > 1024) fail();
  if (typeof input.filename !== 'string' || input.filename.length > 4096) fail();
  let metadataBytes = encoder.encode(input.filename).byteLength + encoder.encode(input.file.type).byteLength;
  const fields = Object.create(null);
  for (const key of fieldNames) {
    if (typeof input.fields[key] !== 'string' || input.fields[key].length > 4096) fail();
    metadataBytes += encoder.encode(input.fields[key]).byteLength;
    fields[key] = input.fields[key];
  }
  if (scopedManual) {
    const key = input.fields.recoveryScopeKey;
    if (typeof key !== 'string' || !/^[a-f0-9]{64}$/.test(key)) fail();
    metadataBytes += encoder.encode(key).byteLength;
    fields.recoveryScopeKey = key;
  }
  if (metadataBytes > MAX_METADATA_BYTES) fail();
  return Object.freeze({ path: '/api/secureshop/uploads', method: 'POST', responseKind: 'json',
    bodyKind: 'multipart', body: Object.freeze({ file: input.file, filename: input.filename, fields: Object.freeze(fields) }) });
}

export function encodeUploadFormData(form) {
  if (!(form instanceof FormData)) fail();
  let file;const fields = Object.create(null);
  for (const [key, value] of form) {
    if (key === 'file' && file === undefined && value instanceof Blob) file = value;
    else if ([...fieldNames, 'recoveryScopeKey'].includes(key) && !Object.hasOwn(fields, key) && typeof value === 'string') fields[key] = value;
    else fail();
  }
  return compileUpload({ file, filename: file?.name, fields }).body;
}

export function buildUploadFormData(input) {
  const { body } = compileUpload(input);
  const form = new FormData();
  form.append('file', body.file, body.filename);
  for (const key of Object.keys(body.fields)) form.append(key, body.fields[key]);
  return form;
}

// Account avatar is a direct owner-bound upload, not the customer avatar agent lesson.
const accountAvatarFields = [...fieldNames, 'requestId'];
const accountAvatarUuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function compileAccountAvatarUpload(input) {
  exact(input, ['file', 'filename', 'fields']);
  exact(input.fields, accountAvatarFields);
  if (!(input.file instanceof Blob) || input.file.size < 1 || input.file.size > MAX_UPLOAD_BYTES
    || typeof input.filename !== 'string' || !input.filename || !input.filename.isWellFormed()
    || input.filename.length > 4096 || /[\0\r\n]/.test(input.filename)) fail();
  const fields = Object.create(null);
  let metadataBytes = encoder.encode(input.filename).byteLength + encoder.encode(input.file.type).byteLength;
  for (const key of accountAvatarFields) {
    const value = input.fields[key];
    if (typeof value !== 'string' || !value.isWellFormed() || value.length > 4096 || /[\0\r\n]/.test(value)) fail();
    metadataBytes += encoder.encode(value).byteLength;
    fields[key] = value;
  }
  if (fields.kind !== 'avatar' || !/^[1-9][0-9]*$/.test(fields.scope_id)
    || !Number.isSafeInteger(Number(fields.scope_id)) || Number(fields.scope_id) > 2147483647
    || !['true', 'false'].includes(fields.public) || !accountAvatarUuid.test(fields.requestId)
    || !fields.mime || metadataBytes > MAX_METADATA_BYTES) fail();
  return Object.freeze({ path: '/api/secureshop/uploads/avatar', method: 'POST', responseKind: 'json',
    bodyKind: 'multipart', body: Object.freeze({ file: input.file, filename: input.filename,
      fields: Object.freeze(fields) }) });
}
export function encodeAccountAvatarFormData(form) {
  if (!(form instanceof FormData)) fail();
  let file; const fields = Object.create(null);
  for (const [key, value] of form) {
    if (key === 'file' && file === undefined && value instanceof Blob) file = value;
    else if (accountAvatarFields.includes(key) && !Object.hasOwn(fields, key) && typeof value === 'string') fields[key] = value;
    else fail();
  }
  return compileAccountAvatarUpload({ file, filename: file?.name, fields }).body;
}
export function buildAccountAvatarFormData(input) {
  const { body } = compileAccountAvatarUpload(input);
  const form = new FormData();
  form.append('file', body.file, body.filename);
  for (const key of accountAvatarFields) form.append(key, body.fields[key]);
  return form;
}


const avatarFieldNames = ['sessionId', 'requestId', 'message', 'public'];
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export function compileAvatarUpload(input) {
  exact(input, ['file', 'filename', 'fields']);exact(input.fields, avatarFieldNames);
  if (!(input.file instanceof Blob) || input.file.size < 1 || input.file.size > MAX_UPLOAD_BYTES
    || input.file.type.length > 1024 || typeof input.filename !== 'string' || !input.filename
    || input.filename.length > 4096 || /[\0\r\n]/.test(input.filename)) fail();
  const fields = Object.create(null);let metadataBytes = encoder.encode(input.filename).byteLength + encoder.encode(input.file.type).byteLength;
  for (const key of avatarFieldNames) { const value=input.fields[key];
    if (typeof value !== 'string' || !value.isWellFormed() || value.includes('\0')) fail();
    metadataBytes += encoder.encode(value).byteLength;fields[key]=value;
  }
  if (!UUID.test(fields.sessionId)||!UUID.test(fields.requestId)||!fields.message.trim()
    || encoder.encode(fields.message).byteLength>8192||!['true','false'].includes(fields.public)
    || metadataBytes>MAX_METADATA_BYTES) fail();
  return Object.freeze({path:'/api/secureshop/agents/customer/avatar-upload/run',method:'POST',responseKind:'json',
    bodyKind:'multipart',body:Object.freeze({file:input.file,filename:input.filename,fields:Object.freeze(fields)})});
}
export function encodeAvatarUploadFormData(form) {
  if (!(form instanceof FormData)) fail();let file;const fields=Object.create(null);
  for (const [key,value] of form) { if(key==='file'&&file===undefined&&value instanceof Blob)file=value;
    else if(avatarFieldNames.includes(key)&&!Object.hasOwn(fields,key)&&typeof value==='string')fields[key]=value;else fail(); }
  return compileAvatarUpload({file,filename:file?.name,fields}).body;
}
export function buildAvatarUploadFormData(input) {
  const {body}=compileAvatarUpload(input);const form=new FormData();
  for(const key of avatarFieldNames)form.append(key,body.fields[key]);form.append('file',body.file,body.filename);return form;
}

const fileSummaryFieldNames=['sessionId','requestId','message'];
export function compileFileSummaryUpload(input){
 exact(input,['file','filename','fields']);exact(input.fields,fileSummaryFieldNames);
 if(!(input.file instanceof Blob)||input.file.size<1||input.file.size>8192||!['text/plain','text/markdown','','application/octet-stream'].includes(input.file.type)
  ||typeof input.filename!=='string'||!input.filename.isWellFormed()||!/^.+\.(txt|md)$/i.test(input.filename)
  ||encoder.encode(input.filename).byteLength>255||/[\0\r\n]/.test(input.filename))fail();
 const fields=Object.create(null);let metadataBytes=encoder.encode(input.filename).byteLength+encoder.encode(input.file.type).byteLength;
 for(const key of fileSummaryFieldNames){const value=input.fields[key];if(typeof value!=='string'||!value.isWellFormed()||value.includes('\0'))fail();metadataBytes+=encoder.encode(value).byteLength;fields[key]=value;}
 if(!UUID.test(fields.sessionId)||!UUID.test(fields.requestId)||!fields.message.trim()||encoder.encode(fields.message).byteLength>8192||metadataBytes>MAX_METADATA_BYTES)fail();
 return Object.freeze({path:'/api/secureshop/agents/customer/file-summary/run',method:'POST',responseKind:'json',bodyKind:'multipart',body:Object.freeze({file:input.file,filename:input.filename,fields:Object.freeze(fields)})});
}
export function encodeFileSummaryFormData(form){if(!(form instanceof FormData))fail();let file;const fields=Object.create(null);for(const[key,value]of form){if(key==='file'&&file===undefined&&value instanceof Blob)file=value;else if(fileSummaryFieldNames.includes(key)&&!Object.hasOwn(fields,key)&&typeof value==='string')fields[key]=value;else fail();}return compileFileSummaryUpload({file,filename:file?.name,fields}).body;}
export function buildFileSummaryFormData(input){const{body}=compileFileSummaryUpload(input),form=new FormData();for(const key of fileSummaryFieldNames)form.append(key,body.fields[key]);form.append('file',body.file,body.filename);return form;}


const traversalFieldNames = [...avatarFieldNames, 'logicalFilename'];
export function compileAvatarTraversalUpload(input) {
  exact(input, ['file', 'filename', 'fields']); exact(input.fields, traversalFieldNames);
  const { logicalFilename, ...avatarFields } = input.fields;
  const compiled = compileAvatarUpload({ ...input, fields: avatarFields });
  if (typeof logicalFilename !== 'string' || !logicalFilename || !logicalFilename.isWellFormed()
    || /[\0\r\n]/.test(logicalFilename) || encoder.encode(logicalFilename).byteLength > 4096) fail();
  const fields = { ...compiled.body.fields, logicalFilename };
  const metadataBytes = encoder.encode(compiled.body.filename).byteLength + encoder.encode(compiled.body.file.type).byteLength
    + Object.values(fields).reduce((sum, value) => sum + encoder.encode(value).byteLength, 0);
  if (metadataBytes > MAX_METADATA_BYTES) fail();
  return Object.freeze({ ...compiled, path: '/api/secureshop/agents/customer/avatar-upload/path-traversal/run',
    body: Object.freeze({ ...compiled.body, fields: Object.freeze(fields) }) });
}
export function encodeAvatarTraversalFormData(form) {
  if (!(form instanceof FormData)) fail(); let file; const fields = Object.create(null);
  for (const [key, value] of form) {
    if (key === 'file' && file === undefined && value instanceof Blob) file = value;
    else if (traversalFieldNames.includes(key) && !Object.hasOwn(fields, key) && typeof value === 'string') fields[key] = value;
    else fail();
  }
  return compileAvatarTraversalUpload({ file, filename: file?.name, fields }).body;
}
export function buildAvatarTraversalFormData(input) {
  const { body } = compileAvatarTraversalUpload(input), form = new FormData();
  for (const key of traversalFieldNames) form.append(key, body.fields[key]);
  form.append('file', body.file, body.filename); return form;
}
