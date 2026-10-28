/**
 * Small JSON store on disk (DATA_DIR/store.json, mode 0600, gitignored).
 *
 * What is kept, and why it may be kept:
 *   endpoints    "<authId>:<agentKey>" -> { endpointId, username }   ids only
 *   workspaces   wsKey -> { organizationId, name, settings }   one per Close organization
 *   users        "<wsKey>:<userId>" -> { name, email, admin, auth,
 *                refreshToken or apiKey (encrypted) }
 *   accountLinks authId -> [wsKey]   which Close organization a Vobiz account logs into
 *   calls        callUuid -> { wsKey, activityId, leadId, contactId, ... }  capped
 *   pending      Close writes that failed and are retried
 *
 * Never kept: a Vobiz Auth Token, a SIP password, a Close access token, and
 * never a Close refresh token or API key in clear text.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const config = require('./config');

const FILE = path.join(config.DATA_DIR, 'store.json');
const MAX_CALLS = 5000;

let data = null;
let writeTimer = null;

function empty() {
  return { endpoints: {}, workspaces: {}, users: {}, accountLinks: {}, calls: {}, pending: [] };
}

function load() {
  if (data) return data;
  try {
    data = { ...empty(), ...JSON.parse(fs.readFileSync(FILE, 'utf8')) };
  } catch {
    data = empty();
  }
  return data;
}

function flush() {
  if (!data) return;
  fs.mkdirSync(config.DATA_DIR, { recursive: true, mode: 0o700 });
  const tmp = `${FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, FILE);
  try { fs.chmodSync(FILE, 0o600); } catch { /* best effort on Windows */ }
}

/** Coalesce writes; saveNow() where durability matters. */
function save() {
  if (writeTimer) return;
  writeTimer = setTimeout(() => { writeTimer = null; flush(); }, 50);
  if (writeTimer.unref) writeTimer.unref();
}

function saveNow() {
  if (writeTimer) { clearTimeout(writeTimer); writeTimer = null; }
  flush();
}

// AES-256-GCM. Output: v1.<iv>.<tag>.<ciphertext>, all base64url.
function encrypt(plain) {
  if (plain == null || plain === '') return '';
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', config.ENC_KEY, iv);
  const ct = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}

function decrypt(boxed) {
  if (!boxed) return '';
  const [v, iv, tag, ct] = String(boxed).split('.');
  if (v !== 'v1' || !iv || !tag || ct === undefined) return '';
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', config.ENC_KEY, Buffer.from(iv, 'base64url'));
    d.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
  } catch {
    return '';
  }
}

function putCall(callUuid, rec) {
  const d = load();
  d.calls[callUuid] = { ...(d.calls[callUuid] || {}), ...rec, updatedAt: Date.now() };
  const keys = Object.keys(d.calls);
  if (keys.length > MAX_CALLS) {
    keys.sort((a, b) => (d.calls[a].updatedAt || 0) - (d.calls[b].updatedAt || 0));
    for (const k of keys.slice(0, keys.length - MAX_CALLS)) delete d.calls[k];
  }
  save();
  return d.calls[callUuid];
}

module.exports = { load, save, saveNow, encrypt, decrypt, putCall, FILE };
