/**
 * Close CRM client: who the agent is (OAuth 2.0 or the agent's own API key),
 * caller lookup, and the writes a call needs.
 *
 * From Close's API reference (developer.close.com, read October 2026):
 *  - OAuth: authorize on app.close.com/oauth2/authorize/, token and revoke on
 *    api.close.com/oauth2/{token,revoke}/ with the client secret. Access tokens
 *    last an hour (expires_in). A refresh token is issued only when the OAuth
 *    app has the offline_access scope, and every refresh returns a new one.
 *  - API keys are sent as HTTP Basic, the key as the user name and no password.
 *    A key belongs to one user in one organization, so records written with it
 *    are attributed to that user.
 *  - Calls made outside Close are logged with POST /api/v1/activity/call/.
 *    recording_url must be https.
 *  - 429 carries Retry-After (and rate_reset); limits are per endpoint group.
 *
 * Access tokens live in memory only. Refresh tokens and API keys are stored
 * encrypted (AES-256-GCM).
 */
const crypto = require('node:crypto');
const config = require('./config');
const store = require('./store');
const { state } = require('./state');
const { log, toE164, digitsOf, sleep } = require('./util');

class CloseError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status || 0;
  }
}

// Every request gets a deadline: a hung request would otherwise hold a call
// in flight forever, so it is never queued or retried.
const timedFetch = (url, opts = {}) => fetch(url, { ...opts, signal: AbortSignal.timeout(15000) });

const userKey = (wsKey, userId) => `${wsKey}:${userId}`;
// wsKey is the Close organization. The name is shared with the Vobiz modules,
// which only need "the CRM tenant a call is logged in".
const wsKeyOf = organizationId => `o${crypto.createHash('sha256').update(String(organizationId)).digest('hex').slice(0, 20)}`;
const redirectUri = () => `${config.PUBLIC_BASE_URL}/close/oauth/callback`;
const oauthEnabled = () => !!(config.CLOSE_CLIENT_ID && config.CLOSE_CLIENT_SECRET);

// Close ids are "<prefix>_<base62>". Anything else is never put into a URL.
const ID_RE = /^[a-z]+_[A-Za-z0-9]+$/;
const isCloseId = (id, prefix) => typeof id === 'string' && ID_RE.test(id) && (!prefix || id.startsWith(`${prefix}_`));

// ─── OAuth ───────────────────────────────────────────────────────────────────

function authorizeUrl(stateToken) {
  const u = new URL(`${config.CLOSE_APP_URL}/oauth2/authorize/`);
  u.searchParams.set('client_id', config.CLOSE_CLIENT_ID);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('redirect_uri', redirectUri());
  u.searchParams.set('state', stateToken);
  return u.toString();
}

async function tokenRequest(params) {
  const res = await timedFetch(`${config.CLOSE_API_BASE}/oauth2/token/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({ ...params, client_id: config.CLOSE_CLIENT_ID, client_secret: config.CLOSE_CLIENT_SECRET }).toString(),
  });
  let body = {};
  try { body = await res.json(); } catch { /* not JSON */ }
  if (!res.ok || !body.access_token) {
    throw new CloseError('token', `Close token request failed (HTTP ${res.status}${body.error ? `: ${body.error}` : ''})`, res.status);
  }
  return body;
}

const exchangeCode = code => tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: redirectUri() });

/** Best effort: tell Close to forget a refresh token we are throwing away. */
async function revoke(refreshToken) {
  if (!refreshToken || !oauthEnabled()) return;
  try {
    await timedFetch(`${config.CLOSE_API_BASE}/oauth2/revoke/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: config.CLOSE_CLIENT_ID, client_secret: config.CLOSE_CLIENT_SECRET, token: refreshToken }).toString(),
    });
  } catch (err) { log(`x Close revoke failed: ${err.message}`); }
}

const basic = apiKey => `Basic ${Buffer.from(`${apiKey}:`).toString('base64')}`;

/**
 * Who a credential belongs to. organizationId comes from the OAuth token
 * response when there is one; an API key belongs to exactly one organization,
 * which /me/ lists first when the user is in several (see README, Limitations).
 * Admin = the user's role in that organization is Close's built-in "admin".
 */
async function getMe(authorization, organizationId) {
  const res = await timedFetch(`${config.CLOSE_API_BASE}/api/v1/me/`, { headers: { Authorization: authorization, Accept: 'application/json' } });
  let me = null;
  try { me = await res.json(); } catch { /* not JSON */ }
  if (res.status === 401) throw new CloseError('unauthorized', 'Close did not accept that key.', 401);
  if (!res.ok || !me || !isCloseId(me.id, 'user')) throw new CloseError('me', `Could not read the Close user (HTTP ${res.status})`, res.status);
  const orgs = Array.isArray(me.organizations) ? me.organizations : [];
  const org = (organizationId && orgs.find(o => o.id === organizationId)) || (!organizationId && orgs[0]) || null;
  const orgId = organizationId || (org && org.id);
  if (!isCloseId(orgId, 'orga')) throw new CloseError('me', 'Close did not say which organization this user is in.');
  const membership = (Array.isArray(me.memberships) ? me.memberships : []).find(m => m.organization_id === orgId) || {};
  const name = [me.first_name, me.last_name].filter(Boolean).join(' ') || me.email || `User ${me.id}`;
  return {
    userId: String(me.id), email: me.email || '', name,
    organizationId: String(orgId), organizationName: (org && org.name) || 'Close',
    admin: membership.role_id === 'admin',
  };
}

function defaultSettings() {
  return {
    defaultCountry: config.DEFAULT_COUNTRY, createUnknown: true, missedTask: true,
    autoOpen: false, recordingTtlSeconds: config.RECORDING_LINK_TTL_SECONDS,
  };
}

/**
 * Store a freshly connected user. cred is { kind: 'oauth', tokens } or
 * { kind: 'apikey', apiKey }. The OAuth access token is kept in memory only.
 */
function saveUser(me, cred) {
  const d = store.load();
  const wsKey = wsKeyOf(me.organizationId);
  const ws = d.workspaces[wsKey] || { wsKey, organizationId: me.organizationId, settings: defaultSettings(), createdAt: Date.now() };
  ws.name = me.organizationName;
  d.workspaces[wsKey] = ws;
  const prior = d.users[userKey(wsKey, me.userId)];
  const user = {
    wsKey, userId: me.userId, name: me.name, email: me.email, admin: !!me.admin, auth: cred.kind,
    refreshToken: cred.kind === 'oauth' ? store.encrypt(cred.tokens.refresh_token || '') : '',
    apiKey: cred.kind === 'apikey' ? store.encrypt(cred.apiKey) : '',
    connectedAt: Date.now(), broken: false,
  };
  d.users[userKey(wsKey, me.userId)] = user;
  store.saveNow();
  if (cred.kind === 'oauth') {
    state.closeAccess.set(userKey(wsKey, me.userId), {
      accessToken: cred.tokens.access_token,
      exp: Date.now() + (Number(cred.tokens.expires_in || 3600) - 60) * 1000,
    });
  } else state.closeAccess.delete(userKey(wsKey, me.userId));
  if (prior && prior.auth === 'oauth' && cred.kind !== 'oauth') revoke(store.decrypt(prior.refreshToken));
  return user;
}

const getUser = (wsKey, userId) => store.load().users[userKey(wsKey, userId)] || null;
const getWorkspace = wsKey => store.load().workspaces[String(wsKey)] || null;

// One refresh in flight per user, so two parallel writes never race to use a
// refresh token the other one already traded in.
const refreshing = new Map();

/** The Authorization header to send as this user, or null when they must reconnect. */
async function authFor(wsKey, userId, { force = false } = {}) {
  const user = getUser(wsKey, userId);
  if (!user || user.broken) return null;
  if (user.auth === 'apikey') {
    const key = store.decrypt(user.apiKey);
    return key ? basic(key) : null;
  }
  const key = userKey(wsKey, userId);
  const mem = state.closeAccess.get(key);
  if (!force && mem && mem.exp > Date.now()) return `Bearer ${mem.accessToken}`;
  if (refreshing.has(key)) return refreshing.get(key);
  const p = (async () => {
    const refresh = store.decrypt(user.refreshToken);
    if (!refresh || !oauthEnabled()) return null;
    try {
      const tokens = await tokenRequest({ grant_type: 'refresh_token', refresh_token: refresh });
      user.refreshToken = store.encrypt(tokens.refresh_token || refresh);
      user.broken = false;
      store.saveNow();
      state.closeAccess.set(key, { accessToken: tokens.access_token, exp: Date.now() + (Number(tokens.expires_in || 3600) - 60) * 1000 });
      return `Bearer ${tokens.access_token}`;
    } catch (err) {
      log(`x Close refresh failed for user ${userId} of ${wsKey}: ${err.message}`);
      if (err.status === 400 || err.status === 401) { user.broken = true; store.save(); }
      return null;
    }
  })();
  refreshing.set(key, p);
  try { return await p; } finally { refreshing.delete(key); }
}

/**
 * The user to write as: the agent who handled the call when they are
 * connected, else a connected admin of the organization, else any connected user.
 */
function writerFor(wsKey, preferredUserId) {
  const d = store.load();
  const users = Object.values(d.users).filter(u => u.wsKey === String(wsKey) && !u.broken && (u.refreshToken || u.apiKey));
  const pref = preferredUserId && users.find(u => u.userId === String(preferredUserId));
  if (pref) return pref.userId;
  const admin = users.find(u => u.admin);
  return (admin || users[0] || {}).userId || null;
}

const RECONNECT = 'Reconnect Close: the connection has expired.';

/**
 * One REST call as one user. 401 refreshes an OAuth token and retries once (an
 * API key that stops working marks the user as needing to reconnect); 429
 * waits Retry-After (at most 10 s) and retries once.
 */
async function api(wsKey, userId, method, apiPath, body) {
  let auth = await authFor(wsKey, userId);
  if (!auth) throw new CloseError('not_connected', RECONNECT);
  for (let attempt = 0; ; attempt++) {
    const res = await timedFetch(`${config.CLOSE_API_BASE}/api/v1${apiPath}`, {
      method,
      headers: {
        Authorization: auth,
        Accept: 'application/json',
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
    if (res.status === 401 && attempt === 0) {
      const user = getUser(wsKey, userId);
      if (user && user.auth === 'apikey') { user.broken = true; store.save(); throw new CloseError('not_connected', RECONNECT, 401); }
      auth = await authFor(wsKey, userId, { force: true });
      if (!auth) throw new CloseError('not_connected', RECONNECT, 401);
      continue;
    }
    if (res.status === 429 && attempt === 0) {
      const wait = Math.min(10, Math.ceil(Number(parsed && parsed.error && parsed.error.rate_reset) || Number(res.headers.get('retry-after')) || 2));
      await sleep(wait * 1000);
      continue;
    }
    if (res.status < 200 || res.status >= 300) {
      const msg = parsed && (parsed.error || parsed['field-errors'] || parsed.errors);
      throw new CloseError('api', `Close ${method} ${apiPath.split('?')[0]} failed (HTTP ${res.status}${msg ? `: ${JSON.stringify(msg).slice(0, 200)}` : ''})`, res.status);
    }
    return parsed;
  }
}

// ─── contacts and leads ──────────────────────────────────────────────────────

/** Every number on a Close contact, as E.164. */
function phonesOf(contact, country) {
  const out = [];
  for (const p of (contact && Array.isArray(contact.phones) ? contact.phones : [])) {
    const e = p && p.phone ? toE164(p.phone, country) : '';
    if (e && !out.includes(e)) out.push(e);
  }
  return out;
}

const contactName = c => String((c && (c.name || c.display_name)) || '');

/**
 * Contacts with this number, on any of their phones. Close's Advanced
 * Filtering searches contact_phone records; every hit is then checked against
 * the full number, so a partial match never links the wrong lead.
 */
async function findContactsByPhone(wsKey, userId, e164, country) {
  const digits = digitsOf(e164);
  const tail = digits.slice(-Math.min(10, Math.max(6, digits.length - 1)));
  const phoneIs = (mode, value) => ({
    type: 'has_related', this_object_type: 'contact', related_object_type: 'contact_phone',
    related_query: { type: 'field_condition', field: { type: 'regular_field', object_type: 'contact_phone', field_name: 'phone' }, condition: { type: 'text', mode, value } },
  });
  const r = await api(wsKey, userId, 'POST', '/data/search/', {
    query: { type: 'and', queries: [{ type: 'object_type', object_type: 'contact' }, { type: 'or', queries: [phoneIs('exact_value', e164), phoneIs('phrase', tail)] }] },
    _fields: { contact: ['id', 'lead_id', 'name', 'display_name', 'title', 'phones'] },
    _limit: 20,
  });
  const contacts = (r && Array.isArray(r.data) ? r.data : []).filter(c => isCloseId(c.id, 'cont') && isCloseId(c.lead_id, 'lead'));
  return contacts.filter(c => phonesOf(c, country).includes(e164));
}

async function getLead(wsKey, userId, leadId) {
  if (!isCloseId(leadId, 'lead')) return null;
  return api(wsKey, userId, 'GET', `/lead/${leadId}/?_fields=id,display_name,status_label`);
}

/** An unknown caller becomes a lead with one contact, so the call is never dropped. */
async function createLead(wsKey, userId, e164) {
  const name = `Caller ${e164}`;
  const r = await api(wsKey, userId, 'POST', '/lead/', { name, contacts: [{ name, phones: [{ phone: e164, type: 'mobile' }] }] });
  const leadId = r && r.id;
  if (!isCloseId(leadId, 'lead')) throw new CloseError('api', 'Close did not return the new lead');
  let contact = Array.isArray(r.contacts) ? r.contacts[0] : null;
  if (!contact) {
    const list = await api(wsKey, userId, 'GET', `/contact/?lead_id=${leadId}&_fields=id`);
    contact = list && Array.isArray(list.data) ? list.data[0] : null;
  }
  return { leadId: String(leadId), contactId: contact && isCloseId(contact.id, 'cont') ? String(contact.id) : null, name };
}

// ─── call activities and tasks ───────────────────────────────────────────────

async function createCall(wsKey, userId, fields) {
  const r = await api(wsKey, userId, 'POST', '/activity/call/', fields);
  if (!r || !isCloseId(r.id, 'acti')) throw new CloseError('api', 'Close did not return the new call');
  return String(r.id);
}

async function updateCall(wsKey, userId, activityId, fields) {
  if (!isCloseId(activityId, 'acti')) throw new CloseError('api', 'Not a Close activity id');
  await api(wsKey, userId, 'PUT', `/activity/call/${activityId}/`, fields);
}

/**
 * With "Call using tel: links", Close logs a call (no duration) the moment the
 * agent clicks a number. That is the same call, so it is filled in rather than
 * logged a second time: the agent's own call on this lead, to this number, with
 * no duration yet, created around when the call started, not claimed already.
 */
async function findTelLinkCall(wsKey, userId, { leadId, phone, startedAt, claimed }) {
  if (!isCloseId(leadId, 'lead') || !isCloseId(userId, 'user')) return null;
  const since = new Date((startedAt || Date.now()) - 10 * 60 * 1000).toISOString();
  const r = await api(wsKey, userId, 'GET', `/activity/call/?lead_id=${leadId}&user_id=${userId}&date_created__gte=${encodeURIComponent(since)}&_fields=id,phone,remote_phone,duration,direction,date_created`);
  const hit = (r && Array.isArray(r.data) ? r.data : []).find(a => isCloseId(a.id, 'acti') && !claimed.has(a.id)
    && (a.phone === phone || a.remote_phone === phone) && !Number(a.duration) && (!a.direction || a.direction === 'outbound'));
  return hit ? String(hit.id) : null;
}

async function createTask(wsKey, userId, { leadId, contactId, text, assignedTo, date }) {
  const body = { _type: 'lead', lead_id: leadId, text, date, is_complete: false };
  if (contactId) body.contact_id = contactId;
  if (isCloseId(assignedTo, 'user')) body.assigned_to = assignedTo;
  const r = await api(wsKey, userId, 'POST', '/task/', body);
  if (!r || !isCloseId(r.id, 'task')) throw new CloseError('api', 'Close did not return the new task');
  return String(r.id);
}

const leadUrl = leadId => (isCloseId(leadId, 'lead') ? `${config.CLOSE_APP_URL}/lead/${leadId}/` : null);

const countryFor = wsKey => ((getWorkspace(wsKey) || {}).settings || {}).defaultCountry || config.DEFAULT_COUNTRY;

// ─── disconnect ──────────────────────────────────────────────────────────────

function forget(key, u) {
  if (u && u.auth === 'oauth') revoke(store.decrypt(u.refreshToken));
  state.closeAccess.delete(key);
}

function disconnectUser(wsKey, userId) {
  const d = store.load();
  const key = userKey(wsKey, userId);
  forget(key, d.users[key]);
  delete d.users[key];
  store.saveNow();
}

function disconnectWorkspace(wsKey) {
  const d = store.load();
  for (const k of Object.keys(d.users)) if (k.startsWith(`${wsKey}:`)) { forget(k, d.users[k]); delete d.users[k]; }
  delete d.workspaces[wsKey];
  for (const [authId, links] of Object.entries(d.accountLinks)) {
    d.accountLinks[authId] = links.filter(w => w !== wsKey);
    if (!d.accountLinks[authId].length) delete d.accountLinks[authId];
  }
  for (const [uuid, c] of Object.entries(d.calls)) if (c.wsKey === wsKey) delete d.calls[uuid];
  d.pending = d.pending.filter(p => p.wsKey !== wsKey);
  store.saveNow();
}

module.exports = {
  CloseError, oauthEnabled, authorizeUrl, exchangeCode, getMe, basic, saveUser, getUser, getWorkspace, authFor, writerFor,
  api, phonesOf, contactName, findContactsByPhone, getLead, createLead, createCall, updateCall, findTelLinkCall,
  createTask, leadUrl, countryFor, disconnectUser, disconnectWorkspace, wsKeyOf, defaultSettings, redirectUri, isCloseId,
};
