'use strict';
const {createHash}=require('node:crypto');
const PERMISSIONS=new Set(['user_management','challenge_management','system_config','view_analytics','manage_progress','send_notifications','export_data','system_logs','database_access']);
function id(value) {if(!Number.isInteger(value)||value<1||value>2147483647)throw new Error('Identity ID must be a positive 32-bit integer');return value;}
function hash(value) {if(typeof value!=='string'||!/^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$/.test(value))throw new Error('A supported bcrypt password hash is required');return value;}
function text(value,label,max=1000) {if(typeof value!=='string'||!value.length||value.length>max)throw new Error(`Invalid ${label}`);return value;}
function flag(value,defaultValue) {value=value??defaultValue;if(value!==0&&value!==1)throw new Error('Identity flags must be 0 or 1');return value;}
function timestamp(value,nullable=true) {
  if(value==null&&nullable)return null;
  if(value instanceof Date){if(!Number.isFinite(value.getTime()))throw new Error('Invalid identity timestamp');return value.toISOString();}
  if(typeof value!=='string')throw new Error('Invalid identity timestamp');
  // SQLite's unzoned timestamp strings are UTC. Validate calendar fields before
  // Date normalization, which otherwise silently accepts February 30 or 24:00.
  const match=/^(\d{4})-(\d{2})-(\d{2})([ T])(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})?$/.exec(value);
  if(!match || (match[4]==='T'&&!match[9]))throw new Error('Invalid identity timestamp');
  const [,year,month,day,,hour,minute,second,fraction='',zone='Z']=match;
  const y=Number(year),m=Number(month),d=Number(day);
  const leap=y%4===0&&(y%100!==0||y%400===0);
  const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];
  if(y<1||m<1||m>12||d<1||d>days[m-1]||Number(hour)>23||Number(minute)>59||Number(second)>59)throw new Error('Invalid identity timestamp');
  if(zone!=='Z'&&(Number(zone.slice(1,3))>23||Number(zone.slice(4))>59))throw new Error('Invalid identity timestamp');
  const normalized=`${year}-${month}-${day}T${hour}:${minute}:${second}.${fraction.padEnd(3,'0').slice(0,3)}${zone}`;
  const parsed=new Date(normalized);
  if(!Number.isFinite(parsed.getTime()))throw new Error('Invalid identity timestamp');
  const iso=parsed.toISOString();
  // Timezone offsets have minute precision, so fractional seconds are unchanged.
  return fraction.length>3?iso.replace(/\.\d{3}Z$/,'.'+fraction+'Z'):iso;
}
function tokenHash(token) {text(token,'session token',16384);return createHash('sha256').update(token).digest('hex');}
function deviceInfo(value) {
  if(typeof value==='string'){try{value=JSON.parse(value);}catch{throw new Error('Invalid session device info');}}
  if(value==null)return {};
  if(typeof value!=='object'||Array.isArray(value))throw new Error('Invalid session device info');
  return Object.fromEntries(['userAgent','acceptLanguage','platform'].filter(key=>typeof value[key]==='string').map(key=>[key,value[key].slice(0,1000)]));
}
function auditDetails(value={}) {
  // Never retain bodies, queries, tokens, passwords, arbitrary errors, or attacker payloads.
  if(!value || typeof value!=='object' || Array.isArray(value)) return {};
  const result={};
  if(typeof value.method==='string'&&/^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$/.test(value.method))result.method=value.method;
  if(typeof value.url==='string')result.url=value.url.split('?')[0].slice(0,500);
  if(value.timestamp!=null)result.timestamp=timestamp(value.timestamp,false);
  return result;
}
module.exports={PERMISSIONS,id,hash,text,flag,timestamp,tokenHash,deviceInfo,auditDetails};
